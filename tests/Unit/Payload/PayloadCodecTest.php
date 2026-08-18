<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Exceptions\InvalidPayloadException;
use Davmixcool\Cryptman\Exceptions\UnsupportedDriverException;
use Davmixcool\Cryptman\Exceptions\UnsupportedVersionException;
use Davmixcool\Cryptman\Keys\KeyGenerator;
use Davmixcool\Cryptman\Payload\EncryptedPayload;
use Davmixcool\Cryptman\Payload\PayloadDecoder;
use Davmixcool\Cryptman\Payload\PayloadEncoder;

function encodeFrame(string $frame): string
{
    return EncryptedPayload::PREFIX.KeyGenerator::base64UrlEncode($frame);
}

function samplePayload(int $algorithmId = EncryptedPayload::ALG_XCHACHA20_POLY1305): EncryptedPayload
{
    return new EncryptedPayload(
        algorithmId: $algorithmId,
        nonce: random_bytes(EncryptedPayload::nonceBytes($algorithmId)),
        ciphertext: random_bytes(48),
        salt: EncryptedPayload::saltBytes($algorithmId) > 0
            ? random_bytes(EncryptedPayload::saltBytes($algorithmId))
            : '',
    );
}

it('round-trips both algorithms', function (int $algorithmId) {
    $payload = samplePayload($algorithmId);
    $decoded = (new PayloadDecoder())->decode((new PayloadEncoder())->encode($payload));

    expect($decoded->algorithmId)->toBe($payload->algorithmId)
        ->and($decoded->nonce)->toBe($payload->nonce)
        ->and($decoded->ciphertext)->toBe($payload->ciphertext)
        ->and($decoded->salt)->toBe($payload->salt)
        ->and($decoded->version)->toBe(EncryptedPayload::FORMAT_VERSION);
})->with([
    EncryptedPayload::ALG_XCHACHA20_POLY1305,
    EncryptedPayload::ALG_AES_256_GCM,
]);

it('produces url-safe, copy-paste-safe output', function () {
    $encoded = (new PayloadEncoder())->encode(samplePayload());

    expect($encoded)->toStartWith('cman2.')
        ->and($encoded)->toMatch('/^cman2\.[A-Za-z0-9_-]+$/');
});

it('costs the overhead the PRD specifies', function () {
    // 42 bytes for XChaCha20, 62 for AES — the 20-byte difference is the
    // per-message salt, and a real reason to leave the default alone.
    $encoder = new PayloadEncoder();

    $decode = fn (string $s): string => (string) KeyGenerator::base64UrlDecode(
        substr($s, strlen(EncryptedPayload::PREFIX))
    );

    $xchacha = new EncryptedPayload(
        EncryptedPayload::ALG_XCHACHA20_POLY1305,
        random_bytes(24),
        random_bytes(EncryptedPayload::TAG_BYTES)
    );
    $aes = new EncryptedPayload(
        EncryptedPayload::ALG_AES_256_GCM,
        random_bytes(12),
        random_bytes(EncryptedPayload::TAG_BYTES),
        random_bytes(32)
    );

    expect(strlen($decode($encoder->encode($xchacha))))->toBe(42)
        ->and(strlen($decode($encoder->encode($aes))))->toBe(62);
});

it('detects v2 payloads without decoding them', function () {
    $decoder = new PayloadDecoder();

    expect($decoder->looksLikeV2((new PayloadEncoder())->encode(samplePayload())))->toBeTrue()
        // A v1 token: hex IV followed by base64.
        ->and($decoder->looksLikeV2('1f73df23a0e10e72df8dabc123=='))->toBeFalse()
        ->and($decoder->looksLikeV2(''))->toBeFalse();
});

describe('the header is self-describing', function () {
    it('encodes version and algorithm in two bytes', function () {
        $header = samplePayload()->header();

        expect(strlen($header))->toBe(2)
            ->and(ord($header[0]))->toBe(EncryptedPayload::FORMAT_VERSION)
            ->and(ord($header[1]))->toBe(EncryptedPayload::ALG_XCHACHA20_POLY1305);
    });

    it('is used as associated data so it cannot be altered independently', function () {
        expect(samplePayload()->associatedData())->toBe(samplePayload()->header());
    });

    it('appends caller associated data after a null separator', function () {
        $payload = samplePayload();

        expect($payload->associatedData('tenant:42'))
            ->toBe($payload->header()."\0".'tenant:42');
    });

    it('treats an empty associated data string as absent', function () {
        // Otherwise encrypt($d) and encrypt($d, '') would produce mutually
        // undecryptable payloads — a footgun with no use case.
        $payload = samplePayload();

        expect($payload->associatedData(''))->toBe($payload->associatedData(null));
    });
});

describe('malformed input fails cleanly', function () {
    $decoder = new PayloadDecoder();

    it('rejects an empty payload', function () use ($decoder) {
        expect(fn () => $decoder->decode(''))->toThrow(InvalidPayloadException::class);
    });

    it('rejects a payload with no prefix', function () use ($decoder) {
        expect(fn () => $decoder->decode('not-a-cryptman-payload'))
            ->toThrow(InvalidPayloadException::class);
    });

    it('rejects a body that is not base64url', function () use ($decoder) {
        expect(fn () => $decoder->decode('cman2.not valid base64!'))
            ->toThrow(InvalidPayloadException::class);
    });

    it('rejects a frame too short to hold a header', function () use ($decoder) {
        expect(fn () => $decoder->decode(encodeFrame("\x02")))
            ->toThrow(InvalidPayloadException::class);
    });

    it('rejects a truncated frame', function () use ($decoder) {
        $frame = "\x02\x01".random_bytes(10); // needs 24-byte nonce + 16-byte tag

        expect(fn () => $decoder->decode(encodeFrame($frame)))
            ->toThrow(InvalidPayloadException::class);
    });

    it('reports an unknown format version distinctly', function () use ($decoder) {
        $frame = "\x63\x01".random_bytes(40);

        expect(fn () => $decoder->decode(encodeFrame($frame)))
            ->toThrow(UnsupportedVersionException::class);
    });

    it('reports an unknown algorithm distinctly', function () use ($decoder) {
        $frame = "\x02\x63".random_bytes(40);

        expect(fn () => $decoder->decode(encodeFrame($frame)))
            ->toThrow(UnsupportedDriverException::class);
    });

    it('survives arbitrary mutation without ever crashing', function () use ($decoder) {
        // PRD §51: never crash, never expose plaintext, always fail safely.
        $valid = (new PayloadEncoder())->encode(samplePayload());

        for ($i = 0; $i < 300; $i++) {
            $mutated = $valid;
            $position = random_int(0, strlen($mutated) - 1);
            $mutated[$position] = chr(random_int(0, 255));

            try {
                $decoder->decode($mutated);
            } catch (\Davmixcool\Cryptman\Exceptions\CryptmanException) {
                // The only acceptable outcome besides a successful decode.
            }
        }

        expect(true)->toBeTrue();
    });

    it('survives truncation at every length', function () use ($decoder) {
        $valid = (new PayloadEncoder())->encode(samplePayload());

        for ($length = 0; $length < strlen($valid); $length++) {
            try {
                $decoder->decode(substr($valid, 0, $length));
            } catch (\Davmixcool\Cryptman\Exceptions\CryptmanException) {
            }
        }

        expect(true)->toBeTrue();
    });
});
