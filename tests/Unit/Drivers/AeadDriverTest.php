<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Contracts\DriverInterface;
use Davmixcool\Cryptman\Drivers\OpenSslGcmDriver;
use Davmixcool\Cryptman\Drivers\SodiumDriver;
use Davmixcool\Cryptman\Exceptions\DecryptionException;
use Davmixcool\Cryptman\Exceptions\InvalidKeyException;
use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/*
|--------------------------------------------------------------------------
| Both AEAD drivers, held to the same contract
|--------------------------------------------------------------------------
|
| Per §7 the two drivers are meant to be interchangeable from the caller's
| perspective, so they are tested through one shared body rather than
| separately. Anything true of one must be true of the other.
|
*/

dataset('aead-drivers', [
    'xchacha20-poly1305' => [fn () => new SodiumDriver()],
    'aes-256-gcm' => [fn () => new OpenSslGcmDriver()],
]);

function aeadKey(string $seed = 'test-key'): string
{
    return KeyDeriver::deriveEncryptionKey($seed);
}

it('is available in this environment', function (Closure $make) {
    expect($make()->isAvailable())->toBeTrue();
})->with('aead-drivers');

it('round-trips plaintext', function (Closure $make) {
    $driver = $make();
    $key = aeadKey();

    foreach ([
        '',                                   // empty round-trips to '' (PRD §30)
        'Loose lips sink ships',
        "h\u{e9}llo w\u{f6}rld \u{65e5}\u{672c}\u{8a9e} \u{1f389}",
        random_bytes(1024),
        str_repeat('x', 100_000),
    ] as $plaintext) {
        $payload = $driver->encrypt($plaintext, $key);

        expect($driver->decrypt($payload, $key))->toBe($plaintext);
    }
})->with('aead-drivers');

it('produces different ciphertext for identical plaintext', function (Closure $make) {
    $driver = $make();
    $key = aeadKey();

    $a = $driver->encrypt('hello', $key);
    $b = $driver->encrypt('hello', $key);

    expect($a->ciphertext)->not->toBe($b->ciphertext)
        ->and($a->nonce)->not->toBe($b->nonce);
})->with('aead-drivers');

it('stamps the payload with its own algorithm', function (Closure $make) {
    $driver = $make();
    $payload = $driver->encrypt('hello', aeadKey());

    expect($payload->algorithmId)->toBe($driver->algorithmId())
        ->and($payload->name())->toBe($driver->name())
        ->and(strlen($payload->nonce))->toBe(EncryptedPayload::nonceBytes($driver->algorithmId()));
})->with('aead-drivers');

describe('tamper detection', function () {
    it('rejects a modified ciphertext', function (Closure $make) {
        $driver = $make();
        $key = aeadKey();
        $payload = $driver->encrypt('Loose lips sink ships', $key);

        $ciphertext = $payload->ciphertext;
        $ciphertext[0] = chr(ord($ciphertext[0]) ^ 0x01);

        $tampered = new EncryptedPayload(
            $payload->algorithmId, $payload->nonce, $ciphertext, $payload->salt
        );

        expect(fn () => $driver->decrypt($tampered, $key))->toThrow(DecryptionException::class);
    })->with('aead-drivers');

    it('rejects a modified nonce', function (Closure $make) {
        $driver = $make();
        $key = aeadKey();
        $payload = $driver->encrypt('Loose lips sink ships', $key);

        $nonce = $payload->nonce;
        $nonce[0] = chr(ord($nonce[0]) ^ 0x01);

        $tampered = new EncryptedPayload(
            $payload->algorithmId, $nonce, $payload->ciphertext, $payload->salt
        );

        expect(fn () => $driver->decrypt($tampered, $key))->toThrow(DecryptionException::class);
    })->with('aead-drivers');

    it('rejects every single-bit flip across the whole ciphertext', function (Closure $make) {
        $driver = $make();
        $key = aeadKey();
        $payload = $driver->encrypt('Loose lips sink ships', $key);

        for ($byte = 0; $byte < strlen($payload->ciphertext); $byte++) {
            $ciphertext = $payload->ciphertext;
            $ciphertext[$byte] = chr(ord($ciphertext[$byte]) ^ 0x80);

            $tampered = new EncryptedPayload(
                $payload->algorithmId, $payload->nonce, $ciphertext, $payload->salt
            );

            expect(fn () => $driver->decrypt($tampered, $key))
                ->toThrow(DecryptionException::class);
        }
    })->with('aead-drivers');

    it('rejects a header swapped to the other algorithm', function (Closure $make) {
        // The header is authenticated, so claiming a different algorithm
        // invalidates the payload rather than silently changing interpretation.
        $driver = $make();
        $key = aeadKey();
        $payload = $driver->encrypt('Loose lips sink ships', $key);

        $otherId = $payload->algorithmId === EncryptedPayload::ALG_XCHACHA20_POLY1305
            ? EncryptedPayload::ALG_AES_256_GCM
            : EncryptedPayload::ALG_XCHACHA20_POLY1305;

        $swapped = new EncryptedPayload(
            $payload->algorithmId, $payload->nonce, $payload->ciphertext, $payload->salt
        );

        // Same driver, but associated data now claims the other algorithm.
        $forgedAad = chr(EncryptedPayload::FORMAT_VERSION).chr($otherId);

        expect(fn () => $driver->decrypt($swapped, $key, $forgedAad))
            ->toThrow(DecryptionException::class);
    })->with('aead-drivers');
});

describe('key handling', function () {
    it('fails with the wrong key', function (Closure $make) {
        $driver = $make();
        $payload = $driver->encrypt('Loose lips sink ships', aeadKey('right'));

        expect(fn () => $driver->decrypt($payload, aeadKey('wrong')))
            ->toThrow(DecryptionException::class);
    })->with('aead-drivers');

    it('rejects a key of the wrong length', function (Closure $make) {
        $driver = $make();

        expect(fn () => $driver->encrypt('hello', 'too-short'))
            ->toThrow(InvalidKeyException::class);
    })->with('aead-drivers');

    it('never leaks key or plaintext in failure messages', function (Closure $make) {
        $driver = $make();
        $plaintext = 'super-secret-plaintext';
        $payload = $driver->encrypt($plaintext, aeadKey('right'));

        try {
            $driver->decrypt($payload, aeadKey('wrong'));
            $this->fail('expected DecryptionException');
        } catch (DecryptionException $e) {
            expect($e->getMessage())->not->toContain($plaintext)
                ->and($e->getMessage())->not->toContain(aeadKey('right'));
        }
    })->with('aead-drivers');
});

describe('associated data', function () {
    it('binds ciphertext to its context', function (Closure $make) {
        $driver = $make();
        $key = aeadKey();

        $payload = $driver->encrypt('api-token', $key, 'user:123');

        expect($driver->decrypt($payload, $key, 'user:123'))->toBe('api-token');

        // Moving the value to another user must fail.
        expect(fn () => $driver->decrypt($payload, $key, 'user:456'))
            ->toThrow(DecryptionException::class);

        // As must dropping the binding entirely.
        expect(fn () => $driver->decrypt($payload, $key))
            ->toThrow(DecryptionException::class);
    })->with('aead-drivers');

    it('rejects a payload encrypted without associated data when some is supplied', function (Closure $make) {
        $driver = $make();
        $key = aeadKey();
        $payload = $driver->encrypt('api-token', $key);

        expect(fn () => $driver->decrypt($payload, $key, 'user:123'))
            ->toThrow(DecryptionException::class);
    })->with('aead-drivers');
});

describe('AES per-message subkeys', function () {
    it('uses a fresh salt per message', function () {
        $driver = new OpenSslGcmDriver();
        $key = aeadKey();

        $a = $driver->encrypt('hello', $key);
        $b = $driver->encrypt('hello', $key);

        expect(strlen($a->salt))->toBe(EncryptedPayload::SALT_BYTES)
            ->and($a->salt)->not->toBe($b->salt);
    });

    it('fails if the salt is altered', function () {
        // The salt selects the message key, so changing it changes the key.
        $driver = new OpenSslGcmDriver();
        $key = aeadKey();
        $payload = $driver->encrypt('Loose lips sink ships', $key);

        $salt = $payload->salt;
        $salt[0] = chr(ord($salt[0]) ^ 0x01);

        $tampered = new EncryptedPayload(
            $payload->algorithmId, $payload->nonce, $payload->ciphertext, $salt
        );

        expect(fn () => $driver->decrypt($tampered, $key))->toThrow(DecryptionException::class);
    });

    it('carries no salt for xchacha20, which does not need one', function () {
        expect((new SodiumDriver())->encrypt('hello', aeadKey())->salt)->toBe('');
    });
});

it('implements the driver contract', function (Closure $make) {
    expect($make())->toBeInstanceOf(DriverInterface::class);
})->with('aead-drivers');
