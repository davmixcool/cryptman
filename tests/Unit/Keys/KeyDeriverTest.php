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

describe('per-algorithm domain separation', function () {
    it('uses a distinct info string per algorithm', function () {
        $infos = [
            KeyDeriver::INFO_ENCRYPTION,
            KeyDeriver::INFO_AES_MESSAGE,
            KeyDeriver::INFO_AES_128_MESSAGE,
            KeyDeriver::INFO_CHACHA20_MESSAGE,
        ];

        expect($infos)->toBe(array_values(array_unique($infos)));
    });

    it('pins each frozen info string against HKDF directly', function () {
        // These are payload compatibility contracts. If one of these fails,
        // every existing payload under that algorithm has become undecryptable.
        $key = KeyDeriver::deriveEncryptionKey('secret');
        $salt = str_repeat("\x01", 32);

        foreach ([
            [KeyDeriver::INFO_AES_MESSAGE, 32],
            [KeyDeriver::INFO_AES_128_MESSAGE, 16],
            [KeyDeriver::INFO_CHACHA20_MESSAGE, 32],
        ] as [$info, $length]) {
            expect(KeyDeriver::deriveMessageKey($key, $salt, $info, $length))
                ->toBe(hash_hkdf('sha256', $key, $length, $info, $salt), "info: {$info}");
        }
    });

    it('gives each algorithm unrelated message keys for the same key and salt', function () {
        // Without distinct info strings, HKDF's prefix property would make the
        // 16-byte output a prefix of the 32-byte one, and chacha20's key
        // byte-identical to aes-256-gcm's.
        $key = KeyDeriver::deriveEncryptionKey('secret');
        $salt = str_repeat("\x01", 32);

        $aes256 = KeyDeriver::deriveMessageKey($key, $salt, KeyDeriver::INFO_AES_MESSAGE, 32);
        $aes128 = KeyDeriver::deriveMessageKey($key, $salt, KeyDeriver::INFO_AES_128_MESSAGE, 16);
        $chacha = KeyDeriver::deriveMessageKey($key, $salt, KeyDeriver::INFO_CHACHA20_MESSAGE, 32);

        expect($chacha)->not->toBe($aes256)
            ->and($aes128)->not->toBe(substr($aes256, 0, 16))
            ->and(strlen($aes128))->toBe(16);
    });

    it('demonstrates the prefix property the info strings defend against', function () {
        // Same info, two lengths: the shorter IS a prefix of the longer.
        // This is why sharing an info string across algorithms is unacceptable.
        $key = KeyDeriver::deriveEncryptionKey('secret');
        $salt = str_repeat("\x02", 32);

        $long = KeyDeriver::deriveMessageKey($key, $salt, KeyDeriver::INFO_AES_MESSAGE, 32);
        $short = KeyDeriver::deriveMessageKey($key, $salt, KeyDeriver::INFO_AES_MESSAGE, 16);

        expect($short)->toBe(substr($long, 0, 16));
    });
});

describe('derived key length', function () {
    it('derives arbitrary lengths', function () {
        $key = KeyDeriver::deriveEncryptionKey('secret');
        $salt = KeyDeriver::generateMessageSalt();

        foreach ([16, 24, 32, 64] as $length) {
            expect(strlen(KeyDeriver::deriveMessageKey($key, $salt, KeyDeriver::INFO_AES_MESSAGE, $length)))
                ->toBe($length);
        }
    });

    it('rejects a length outside HKDF-SHA256 bounds as our own exception type', function () {
        $key = KeyDeriver::deriveEncryptionKey('secret');
        $salt = KeyDeriver::generateMessageSalt();

        foreach ([0, -1, 8161] as $bad) {
            expect(fn () => KeyDeriver::deriveMessageKey($key, $salt, KeyDeriver::INFO_AES_MESSAGE, $bad))
                ->toThrow(InvalidKeyException::class);
        }
    });

    it('still defaults to 32 bytes and the AES info string', function () {
        // Guards the backwards compatibility of every existing call site.
        $key = KeyDeriver::deriveEncryptionKey('secret');
        $salt = KeyDeriver::generateMessageSalt();

        expect(KeyDeriver::deriveMessageKey($key, $salt))
            ->toBe(KeyDeriver::deriveMessageKey($key, $salt, KeyDeriver::INFO_AES_MESSAGE, 32));
    });
});
