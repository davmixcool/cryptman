<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Contracts\DriverInterface;
use Davmixcool\Cryptman\Drivers\OpenSslAes128GcmDriver;
use Davmixcool\Cryptman\Drivers\OpenSslAes256GcmDriver;
use Davmixcool\Cryptman\Drivers\OpenSslChaCha20Poly1305Driver;
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
| The two drivers are meant to be interchangeable from the caller's
| perspective, so they are tested through one shared body rather than
| separately. Anything true of one must be true of the other.
|
*/

dataset('aead-drivers', [
    'xchacha20-poly1305' => [fn () => new SodiumDriver()],
    'aes-256-gcm' => [fn () => new OpenSslAes256GcmDriver()],
    'aes-128-gcm' => [fn () => new OpenSslAes128GcmDriver()],
    'chacha20-poly1305' => [fn () => new OpenSslChaCha20Poly1305Driver()],
]);

/** The three with 96-bit nonces, which derive a per-message subkey. */
dataset('subkey-drivers', [
    'aes-256-gcm' => [fn () => new OpenSslAes256GcmDriver()],
    'aes-128-gcm' => [fn () => new OpenSslAes128GcmDriver()],
    'chacha20-poly1305' => [fn () => new OpenSslChaCha20Poly1305Driver()],
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
        '',                                   // empty round-trips to ''
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

    it('rejects a header forged to ANY other algorithm', function (Closure $make) {
        // The header is authenticated, so claiming a different algorithm
        // invalidates the payload rather than silently changing interpretation.
        // Checked against every other registered algorithm, not just one.
        $driver = $make();
        $key = aeadKey();
        $payload = $driver->encrypt('Loose lips sink ships', $key);

        foreach (EncryptedPayload::supportedAlgorithms() as $otherId) {
            if ($otherId === $driver->algorithmId()) {
                continue;
            }

            $forgedAad = chr(EncryptedPayload::FORMAT_VERSION).chr($otherId);

            expect(fn () => $driver->decrypt($payload, $key, $forgedAad))
                ->toThrow(DecryptionException::class);
        }
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

describe('per-message subkeys', function () {
    it('uses a fresh salt per message', function (Closure $make) {
        $driver = $make();
        $key = aeadKey();

        $a = $driver->encrypt('hello', $key);
        $b = $driver->encrypt('hello', $key);

        expect(strlen($a->salt))->toBe(EncryptedPayload::SALT_BYTES)
            ->and($a->salt)->not->toBe($b->salt);
    })->with('subkey-drivers');

    it('fails if the salt is altered', function (Closure $make) {
        // The salt selects the message key, so changing it changes the key.
        $driver = $make();
        $key = aeadKey();
        $payload = $driver->encrypt('Loose lips sink ships', $key);

        $salt = $payload->salt;
        $salt[0] = chr(ord($salt[0]) ^ 0x01);

        $tampered = new EncryptedPayload(
            $payload->algorithmId, $payload->nonce, $payload->ciphertext, $salt
        );

        expect(fn () => $driver->decrypt($tampered, $key))->toThrow(DecryptionException::class);
    })->with('subkey-drivers');

    it('carries a salt exactly when its geometry says so', function (Closure $make) {
        $driver = $make();

        expect(strlen($driver->encrypt('hello', aeadKey())->salt))
            ->toBe(EncryptedPayload::saltBytes($driver->algorithmId()));
    })->with('aead-drivers');
});

it('implements the driver contract', function (Closure $make) {
    expect($make())->toBeInstanceOf(DriverInterface::class);
})->with('aead-drivers');

/*
|--------------------------------------------------------------------------
| Construction pinning
|--------------------------------------------------------------------------
|
| PHP's openssl_encrypt SILENTLY TRUNCATES an over-long key: aes-128-gcm handed
| 32 bytes produces byte-identical output to the same call with the first 16.
| No warning, no exception. So a wrong messageKeyBytes() passes every
| round-trip, tamper, AAD and interop test in this file.
|
| Worse -- and this was found by deliberately breaking the driver -- it also
| passes a naive "re-derive and decrypt with raw OpenSSL" test. HKDF output at
| length 16 is a PREFIX of output at length 32 under identical inputs, which is
| exactly the property the separate info strings exist to defend against. So
| the independently-derived 16-byte key equals the truncation of the driver's
| wrong 32-byte key, and the decrypt succeeds.
|
| Two checks are therefore needed, and both are verified to fail when
| messageKeyBytes() is wrong:
|
|   1. the OpenSSL error queue, which records "invalid key length" whenever an
|      over-long key is passed, even though the call itself succeeds
|   2. messageKeyBytes() asserted directly by reflection
|
| The raw-OpenSSL test below still earns its place: it pins the info string,
| the AAD assembly and the tag layout. It just cannot pin the key length.
|
*/

it('never hands OpenSSL a key of the wrong length', function (Closure $make) {
    // Behavioural detection of silent truncation. The queue is global, so
    // drain it first.
    while (openssl_error_string() !== false) {
    }

    $make()->encrypt('Loose lips sink ships', aeadKey(), 'ctx');

    $errors = [];
    while (($error = openssl_error_string()) !== false) {
        $errors[] = $error;
    }

    expect(implode('; ', $errors))->not->toContain('invalid key length');
})->with('subkey-drivers');

it('derives a message key of the length its cipher actually takes', function (
    Closure $make,
    int $expectedBytes
) {
    $method = new ReflectionMethod($make(), 'messageKeyBytes');

    expect($method->invoke($make()))->toBe($expectedBytes);
})->with([
    'aes-256-gcm' => [fn () => new OpenSslAes256GcmDriver(), 32],
    'aes-128-gcm' => [fn () => new OpenSslAes128GcmDriver(), 16],
    'chacha20-poly1305' => [fn () => new OpenSslChaCha20Poly1305Driver(), 32],
]);

it('pins the exact construction: subkey info, AAD assembly and tag layout', function (
    Closure $make,
    string $info,
    int $keyBytes
) {
    $driver = $make();
    $key = aeadKey();
    $payload = $driver->encrypt('Loose lips sink ships', $key, 'ctx');

    $messageKey = KeyDeriver::deriveMessageKey($key, $payload->salt, $info, $keyBytes);

    // NB: this length assertion is about the test's own derivation, not the
    // driver's. See the block comment above for why it proves nothing on its own.
    expect(strlen($messageKey))->toBe($keyBytes);

    $plaintext = openssl_decrypt(
        substr($payload->ciphertext, 0, -EncryptedPayload::TAG_BYTES),
        $driver->name(),
        $messageKey,
        OPENSSL_RAW_DATA,
        $payload->nonce,
        substr($payload->ciphertext, -EncryptedPayload::TAG_BYTES),
        $payload->associatedData('ctx')
    );

    expect($plaintext)->toBe('Loose lips sink ships');
})->with([
    'aes-256-gcm' => [fn () => new OpenSslAes256GcmDriver(), KeyDeriver::INFO_AES_MESSAGE, 32],
    'aes-128-gcm' => [fn () => new OpenSslAes128GcmDriver(), KeyDeriver::INFO_AES_128_MESSAGE, 16],
    'chacha20-poly1305' => [fn () => new OpenSslChaCha20Poly1305Driver(), KeyDeriver::INFO_CHACHA20_MESSAGE, 32],
]);

it('does not interchange xchacha20-poly1305 and chacha20-poly1305', function () {
    // One letter apart, different libraries, different nonce sizes, different
    // algorithm ids. A user WILL assume these are aliases.
    $key = aeadKey();

    $x = new SodiumDriver();
    $c = new OpenSslChaCha20Poly1305Driver();

    expect($x->algorithmId())->not->toBe($c->algorithmId())
        ->and(EncryptedPayload::nonceBytes($x->algorithmId()))->toBe(24)
        ->and(EncryptedPayload::nonceBytes($c->algorithmId()))->toBe(12);

    // A payload from one cannot be read by the other.
    expect(fn () => $c->decrypt($x->encrypt('secret', $key), $key))
        ->toThrow(DecryptionException::class);
});
