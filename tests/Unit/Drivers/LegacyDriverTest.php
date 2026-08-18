<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Contracts\DriverInterface;
use Davmixcool\Cryptman\Drivers\LegacyDriver;
use Davmixcool\Cryptman\Exceptions\InvalidConfigurationException;
use Davmixcool\Cryptman\Exceptions\LegacyDecryptionException;

/*
|--------------------------------------------------------------------------
| The legacy reader, validated against the frozen corpus
|--------------------------------------------------------------------------
|
| Every positive fixture must decrypt; every negative fixture must fail in the
| way the corpus recorded. This is what makes "v2 can still read v1 data" a
| verified claim rather than an intention.
|
*/

it('reproduces every corpus fixture, positives and negatives alike', function (array $fixture) {
    $method = $fixture['decrypt_with']['method'] ?? LegacyDriver::DEFAULT_METHOD;
    $key = base64_decode($fixture['decrypt_with']['key_b64']);

    // strict:false first, so the driver is compared against raw v1 behaviour
    // without the UTF-8 guard interfering.
    $driver = new LegacyDriver($method, strict: false);

    if ($fixture['v1_result']['type'] === 'false') {
        // v1 returned false here. v2 must raise rather than return a falsy
        // value that a caller could mistake for plaintext (PRD §28).
        expect(fn () => $driver->decrypt($fixture['token'], $key))
            ->toThrow(LegacyDecryptionException::class);

        return;
    }

    $expected = base64_decode($fixture['v1_result']['value_b64']);

    expect($driver->decrypt($fixture['token'], $key))->toBe($expected);

    // Where v1 produced non-UTF-8 output — every wrong-key and misread-method
    // fixture — the guard must fire when enabled. This is the corpus proving
    // the backstop works on real misconfigurations rather than contrived ones.
    if ($fixture['v1_result_is_utf8'] === false) {
        expect(fn () => (new LegacyDriver($method))->decrypt($fixture['token'], $key))
            ->toThrow(LegacyDecryptionException::class);
    }
})->with('v1-corpus')->group('corpus');

it('never returns false, unlike v1', function () {
    // PRD §28: a falsy return is silently mistakable for plaintext.
    $driver = new LegacyDriver();

    expect(fn () => $driver->decrypt('not-a-token', 'key'))
        ->toThrow(LegacyDecryptionException::class);
});

describe('the UTF-8 guard', function () {
    it('catches a CBC token misread under the default CTR method', function () {
        // The headline misconfiguration: CTR cannot fail, so without this
        // guard the caller receives garbage that looks like success.
        $key = 'correct horse battery staple';
        $iv = random_bytes(16);
        $token = bin2hex($iv).openssl_encrypt(
            'Loose lips sink ships', 'aes-256-cbc', openssl_digest($key, 'SHA256', true), 0, $iv
        );

        expect(fn () => (new LegacyDriver('aes-128-ctr'))->decrypt($token, $key))
            ->toThrow(LegacyDecryptionException::class);
    });

    it('tells the operator not to re-encrypt', function () {
        // Rewriting a row on a failed legacy decrypt is how recoverable data
        // becomes unrecoverable.
        $key = 'correct horse battery staple';
        $iv = random_bytes(16);
        $token = bin2hex($iv).openssl_encrypt(
            'Loose lips sink ships', 'aes-256-cbc', openssl_digest($key, 'SHA256', true), 0, $iv
        );

        try {
            (new LegacyDriver('aes-128-ctr'))->decrypt($token, $key);
            $this->fail('expected LegacyDecryptionException');
        } catch (LegacyDecryptionException $e) {
            expect(strtolower($e->getMessage()))->toContain('do not re-encrypt');
        }
    });

    it('can be disabled for genuinely binary plaintext', function () {
        $key = 'correct horse battery staple';
        $binary = "\x00\x01\xff\xfe".random_bytes(20);

        $iv = random_bytes(16);
        $token = bin2hex($iv).openssl_encrypt(
            $binary, 'aes-128-ctr', openssl_digest($key, 'SHA256', true), 0, $iv
        );

        expect(fn () => (new LegacyDriver('aes-128-ctr'))->decrypt($token, $key))
            ->toThrow(LegacyDecryptionException::class);

        expect((new LegacyDriver('aes-128-ctr', strict: false))->decrypt($token, $key))
            ->toBe($binary);
    });
});

describe('key branch handling', function () {
    it('reads data encrypted under an accented passphrase', function () {
        // "café" takes v1's RAW branch. Getting this wrong breaks migration
        // for anyone who chose an accented key.
        $key = "caf\xc3\xa9";
        $iv = random_bytes(16);
        $token = bin2hex($iv).openssl_encrypt('Loose lips sink ships', 'aes-128-ctr', $key, 0, $iv);

        expect((new LegacyDriver('aes-128-ctr'))->decrypt($token, $key))
            ->toBe('Loose lips sink ships');
    });

    it('reads data encrypted under a printable passphrase', function () {
        $key = 'correct horse battery staple';
        $iv = random_bytes(16);
        $token = bin2hex($iv).openssl_encrypt(
            'Loose lips sink ships', 'aes-128-ctr', openssl_digest($key, 'SHA256', true), 0, $iv
        );

        expect((new LegacyDriver('aes-128-ctr'))->decrypt($token, $key))
            ->toBe('Loose lips sink ships');
    });
});

it('defaults to v1s own default method', function () {
    expect(LegacyDriver::DEFAULT_METHOD)->toBe('aes-128-ctr');
});

it('rejects an unknown legacy method at construction', function () {
    expect(fn () => new LegacyDriver('not-a-cipher'))
        ->toThrow(InvalidConfigurationException::class);
});

it('has no encrypt method', function () {
    // v2 must never write unauthenticated ciphertext.
    expect(method_exists(LegacyDriver::class, 'encrypt'))->toBeFalse();
});

it('does not implement the AEAD driver contract', function () {
    // It is decrypt-only, so satisfying DriverInterface would mean throwing
    // from a method the contract promises works.
    expect(is_subclass_of(LegacyDriver::class, DriverInterface::class))
        ->toBeFalse();
});
