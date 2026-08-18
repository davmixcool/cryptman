<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Exceptions\InvalidKeyException;
use Davmixcool\Cryptman\Keys\KeyGenerator;

it('generates a prefixed, url-safe, environment-storable key', function () {
    $key = KeyGenerator::generate();

    expect($key)->toStartWith('cman_key_')
        ->and($key)->toMatch('/^cman_key_[A-Za-z0-9_-]+$/')
        // No +, / or = — safe in env files, URLs, cookies and filenames.
        ->and($key)->not->toContain('+')
        ->and($key)->not->toContain('/')
        ->and($key)->not->toContain('=');
});

it('generates keys carrying 32 bytes of entropy', function () {
    expect(strlen(KeyGenerator::toInputKeyMaterial(KeyGenerator::generate())))->toBe(32);
});

it('does not repeat itself', function () {
    $keys = array_map(fn () => KeyGenerator::generate(), range(1, 50));

    expect(array_unique($keys))->toHaveCount(50);
});

it('recognises its own keys', function () {
    expect(KeyGenerator::isGeneratedKey(KeyGenerator::generate()))->toBeTrue()
        ->and(KeyGenerator::isGeneratedKey('my-application-secret'))->toBeFalse();
});

describe('input key material', function () {
    it('decodes a generated key back to its raw bytes', function () {
        $raw = random_bytes(32);
        $key = 'cman_key_'.KeyGenerator::base64UrlEncode($raw);

        expect(KeyGenerator::toInputKeyMaterial($key))->toBe($raw);
    });

    it('passes an arbitrary passphrase through untouched', function () {
        expect(KeyGenerator::toInputKeyMaterial('my-application-secret'))
            ->toBe('my-application-secret');
    });

    it('rejects a prefixed key whose body is not base64url', function () {
        // A typo must become an error, never a silently different key.
        expect(fn () => KeyGenerator::toInputKeyMaterial('cman_key_not valid base64!'))
            ->toThrow(InvalidKeyException::class);
    });

    it('rejects a prefixed key of the wrong length', function () {
        $short = 'cman_key_'.KeyGenerator::base64UrlEncode(random_bytes(16));

        expect(fn () => KeyGenerator::toInputKeyMaterial($short))
            ->toThrow(InvalidKeyException::class);
    });

    it('rejects a bare prefix with no body', function () {
        expect(fn () => KeyGenerator::toInputKeyMaterial('cman_key_'))
            ->toThrow(InvalidKeyException::class);
    });

    it('never reveals key material in its error messages', function () {
        $secret = KeyGenerator::base64UrlEncode(random_bytes(16));

        try {
            KeyGenerator::toInputKeyMaterial('cman_key_'.$secret);
            $this->fail('expected InvalidKeyException');
        } catch (InvalidKeyException $e) {
            expect($e->getMessage())->not->toContain($secret);
        }
    });
});

describe('base64url', function () {
    it('round-trips arbitrary binary', function () {
        foreach ([random_bytes(1), random_bytes(32), "\x00\xff\x00", str_repeat("\x00", 10)] as $bytes) {
            expect(KeyGenerator::base64UrlDecode(KeyGenerator::base64UrlEncode($bytes)))->toBe($bytes);
        }
    });

    it('returns null for malformed input instead of throwing', function () {
        foreach (['', 'has spaces', 'has+plus', 'has/slash', 'has=padding'] as $bad) {
            expect(KeyGenerator::base64UrlDecode($bad))->toBeNull();
        }
    });
});
