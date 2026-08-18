<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Exceptions\InvalidKeyException;
use Davmixcool\Cryptman\Keys\Key;
use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Keys\KeyGenerator;

it('derives 32 bytes from a passphrase', function () {
    expect(strlen(Key::fromUserInput('my-application-secret')->material()))->toBe(32);
});

it('derives the same key from the same input', function () {
    expect(Key::fromUserInput('secret')->material())
        ->toBe(Key::fromUserInput('secret')->material());
});

it('runs HKDF over generated keys too, not just passphrases', function () {
    // Both paths derive; the prefix only decides what becomes the IKM.
    $raw = random_bytes(32);
    $generated = 'cman_key_'.KeyGenerator::base64UrlEncode($raw);

    expect(Key::fromUserInput($generated)->material())
        ->toBe(KeyDeriver::deriveEncryptionKey($raw))
        // The derived key is not the raw entropy handed straight through.
        ->and(Key::fromUserInput($generated)->material())->not->toBe($raw);
});

describe('validation', function () {
    it('rejects a missing key — there is no default', function () {
        // v1 fell back to php_uname() here, which made data effectively public.
        foreach (['', ' ', "\t\n"] as $empty) {
            expect(fn () => Key::fromUserInput($empty))->toThrow(InvalidKeyException::class);
        }
    });

    it('names the remedy when no key is supplied', function () {
        try {
            Key::fromUserInput('');
            $this->fail('expected InvalidKeyException');
        } catch (InvalidKeyException $e) {
            expect($e->getMessage())->toContain('generateKey');
        }
    });

    it('rejects derived material of the wrong length', function () {
        expect(fn () => Key::fromDerivedMaterial('too short'))->toThrow(InvalidKeyException::class);
    });

    it('accepts exactly 32 bytes of derived material', function () {
        $material = random_bytes(32);

        expect(Key::fromDerivedMaterial($material)->material())->toBe($material);
    });
});

describe('leak resistance', function () {
    $secretOf = fn (Key $key): string => $key->material();

    it('keeps material out of var_dump and print_r', function () use ($secretOf) {
        $key = Key::fromUserInput('my-application-secret');
        $material = $secretOf($key);

        expect(print_r($key, true))->not->toContain($material)
            ->and(print_r($key, true))->toContain('[redacted]');

        ob_start();
        var_dump($key);
        $dump = (string) ob_get_clean();

        expect($dump)->not->toContain($material);
    });

    it('keeps material out of string interpolation', function () use ($secretOf) {
        $key = Key::fromUserInput('my-application-secret');

        expect("{$key}")->not->toContain($secretOf($key))
            ->and("{$key}")->toContain('redacted');
    });

    it('refuses to serialize', function () {
        // A serialized key lands in sessions, caches and queue payloads —
        // durable stores rarely treated as secret.
        $key = Key::fromUserInput('my-application-secret');

        expect(fn () => serialize($key))->toThrow(InvalidKeyException::class);
    });

    it('keeps material out of exception messages and traces', function () use ($secretOf) {
        $key = Key::fromUserInput('my-application-secret');
        $material = $secretOf($key);

        try {
            serialize($key);
            $this->fail('expected InvalidKeyException');
        } catch (InvalidKeyException $e) {
            expect($e->getMessage())->not->toContain($material)
                ->and($e->getTraceAsString())->not->toContain($material);
        }
    });

    it('wipes material on request', function () {
        $key = Key::fromUserInput('my-application-secret');
        $key->wipe();

        expect($key->material())->toBe('');
    });
});

it('carries an optional key id for future key-id support', function () {
    expect(Key::fromUserInput('secret', '2026-08')->id())->toBe('2026-08')
        ->and(Key::fromUserInput('secret')->id())->toBeNull();
});
