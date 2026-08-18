<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Exceptions\InvalidKeyException;
use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Keys\LegacyKeyNormalizer;

it('derives 32 bytes deterministically', function () {
    $a = KeyDeriver::deriveEncryptionKey('my-application-secret');
    $b = KeyDeriver::deriveEncryptionKey('my-application-secret');

    expect(strlen($a))->toBe(32)->and($a)->toBe($b);
});

it('matches HKDF-SHA256 at the parameters fixed in the PRD', function () {
    // Pinned against the primitive directly. These parameters are part of the
    // payload compatibility contract — if this test fails, every existing v2
    // payload has become undecryptable.
    expect(KeyDeriver::deriveEncryptionKey('my-application-secret'))
        ->toBe(hash_hkdf('sha256', 'my-application-secret', 32, 'cryptman-v2-encryption', ''));
});

it('separates domains so the same input yields different keys per purpose', function () {
    $encryption = KeyDeriver::deriveEncryptionKey('same-input');
    $message = KeyDeriver::deriveMessageKey($encryption, str_repeat("\x01", 32));

    expect($encryption)->not->toBe($message);
});

it('rejects empty key material rather than leaking a ValueError', function () {
    expect(fn () => KeyDeriver::deriveEncryptionKey(''))
        ->toThrow(InvalidKeyException::class);
});

it('never collides with the legacy normalizer for the same input', function () {
    // The two paths must be incompatible by construction. Applying v2
    // derivation to legacy data — or the reverse — must produce garbage rather
    // than silently working for some inputs.
    $key = 'correct horse battery staple';

    expect(KeyDeriver::deriveEncryptionKey($key))
        ->not->toBe(LegacyKeyNormalizer::normalize($key));
});

describe('per-message subkeys', function () {
    it('derives a distinct key for each salt', function () {
        $encryptionKey = KeyDeriver::deriveEncryptionKey('secret');

        $a = KeyDeriver::deriveMessageKey($encryptionKey, str_repeat("\x00", 32));
        $b = KeyDeriver::deriveMessageKey($encryptionKey, str_repeat("\xff", 32));

        expect($a)->not->toBe($b)
            ->and(strlen($a))->toBe(32);
    });

    it('is deterministic for a given salt', function () {
        $encryptionKey = KeyDeriver::deriveEncryptionKey('secret');
        $salt = KeyDeriver::generateMessageSalt();

        expect(KeyDeriver::deriveMessageKey($encryptionKey, $salt))
            ->toBe(KeyDeriver::deriveMessageKey($encryptionKey, $salt));
    });

    it('rejects a salt of the wrong length', function () {
        $encryptionKey = KeyDeriver::deriveEncryptionKey('secret');

        expect(fn () => KeyDeriver::deriveMessageKey($encryptionKey, 'too-short'))
            ->toThrow(InvalidKeyException::class);
    });

    it('generates 32-byte salts that differ', function () {
        expect(strlen(KeyDeriver::generateMessageSalt()))->toBe(32)
            ->and(KeyDeriver::generateMessageSalt())->not->toBe(KeyDeriver::generateMessageSalt());
    });
});
