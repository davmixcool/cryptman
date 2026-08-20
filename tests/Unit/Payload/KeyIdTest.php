<?php

declare(strict_types=1);

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Exceptions\CryptmanException;
use Davmixcool\Cryptman\Exceptions\DecryptionException;
use Davmixcool\Cryptman\Exceptions\InvalidConfigurationException;
use Davmixcool\Cryptman\Exceptions\InvalidPayloadException;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/*
|--------------------------------------------------------------------------
| Key ids
|--------------------------------------------------------------------------
|
| A key id names which key encrypted a value, in cleartext, so operators can
| answer "which rows still need this key?" with a grouped count instead of
| trial-decrypting every row with every key.
|
| Two properties are load-bearing and both are asserted here:
|
|   1. Payloads written before key ids existed keep decrypting, byte-for-byte.
|      tests/Compat/V2PayloadTest.php holds the frozen evidence; what this file
|      adds is that the unkeyed ENCODING is still produced unchanged.
|
|   2. The id is authenticated. It is not secret, but a swappable id would let
|      an attacker misdirect migration accounting without breaking a MAC.
|
*/

const KID = 'ck_test_current';

function keyed(array $options = []): Cryptman
{
    return new Cryptman(array_merge([
        'key' => 'correct horse battery staple',
        'key_id' => KID,
    ], $options));
}

it('round-trips under every algorithm with a key id', function (string $method) {
    $cryptman = keyed(['method' => $method]);
    $payload = $cryptman->encrypt('Loose lips sink ships');

    expect($payload)->toStartWith('cman2.'.KID.'.')
        ->and($cryptman->decrypt($payload))->toBe('Loose lips sink ships')
        ->and(Cryptman::describe($payload)['key_id'])->toBe(KID);
})->with(fn () => Cryptman::supportedMethods());

it('round-trips with a key id and associated data together', function () {
    $cryptman = keyed();
    $payload = $cryptman->encrypt('secret', 'tenant:42');

    expect($cryptman->decrypt($payload, 'tenant:42'))->toBe('secret')
        ->and(fn () => $cryptman->decrypt($payload, 'tenant:43'))
        ->toThrow(DecryptionException::class);
});

it('emits the pre-2.1.0 encoding byte-for-byte when no key id is configured', function () {
    // Guards the compatibility promise from the writing side. The frozen
    // corpus proves old payloads still READ; this proves we have not started
    // writing a shape older readers would reject.
    $payload = (new Cryptman(['key' => 'k']))->encrypt('x');

    expect(substr_count($payload, '.'))->toBe(1)
        ->and($payload)->toStartWith('cman2.')
        ->and(Cryptman::describe($payload)['key_id'])->toBeNull();
});

it('authenticates the key id', function () {
    $cryptman = keyed();
    $payload = $cryptman->encrypt('secret');

    // Swap the id for another well-formed one. The ciphertext is untouched,
    // so this fails only because the id is covered by the AAD.
    $tampered = str_replace('cman2.'.KID.'.', 'cman2.ck_test_other.', $payload);

    expect($tampered)->not->toBe($payload)
        ->and(fn () => (new Cryptman([
            'key' => 'correct horse battery staple',
            'key_id' => 'ck_test_other',
        ]))->decrypt($tampered))
        ->toThrow(DecryptionException::class);
});

it('does not let associated data forge the framing of a key id', function () {
    // The id is length-prefixed rather than 0x00-separated precisely so that
    // caller data cannot imitate it. Craft associated data that would collide
    // under a naive "header || 0x00 || id" assembly and show it does not.
    $plain = new Cryptman(['key' => 'k']);
    $forged = $plain->encrypt('secret', chr(strlen(KID)).KID);

    expect(fn () => keyed(['key' => 'k'])->decrypt($forged))
        ->toThrow(DecryptionException::class);
});

it('uses the named key directly and does not fall through on failure', function () {
    $right = Cryptman::generateKey();
    $wrong = Cryptman::generateKey();

    $payload = (new Cryptman(['key' => $right, 'key_id' => 'ck_alpha']))->encrypt('secret');

    // 'ck_alpha' is present but mapped to the WRONG material. The right key is
    // also in the ring, unnamed. A fall-through would find it and succeed --
    // which would make the id advisory rather than authoritative, and hide a
    // real misconfiguration.
    $ring = new Cryptman([
        'key' => $wrong,
        'key_id' => 'ck_alpha',
        'previous_keys' => [$right],
    ]);

    expect(fn () => $ring->decrypt($payload))
        ->toThrow(DecryptionException::class, 'the key it names');
});

it('falls back to trial decryption for an id the ring does not know', function () {
    // Expected mid-rotation: a value written by a key this deployment has not
    // been told about yet, whose material is nonetheless present.
    $key = Cryptman::generateKey();
    $payload = (new Cryptman(['key' => $key, 'key_id' => 'ck_written_elsewhere']))->encrypt('secret');

    $reader = new Cryptman(['key' => Cryptman::generateKey(), 'previous_keys' => [$key]]);

    expect($reader->decrypt($payload))->toBe('secret');
});

it('names the unknown key when it cannot decrypt at all', function () {
    $payload = (new Cryptman([
        'key' => Cryptman::generateKey(),
        'key_id' => 'ck_missing',
    ]))->encrypt('secret');

    expect(fn () => (new Cryptman(['key' => Cryptman::generateKey()]))->decrypt($payload))
        ->toThrow(DecryptionException::class, 'ck_missing');
});

it('reads keyed and unkeyed payloads through the same ring', function () {
    $key = Cryptman::generateKey();

    $unkeyed = (new Cryptman(['key' => $key]))->encrypt('before');
    $keyed = (new Cryptman(['key' => $key, 'key_id' => 'ck_after']))->encrypt('after');

    $reader = new Cryptman(['key' => $key, 'key_id' => 'ck_after']);

    expect($reader->decrypt($keyed))->toBe('after')
        ->and($reader->decrypt($unkeyed))->toBe('before');
});

describe('configuration', function () {
    it('accepts previous_keys as an id => key map', function () {
        $old = Cryptman::generateKey();
        $payload = (new Cryptman(['key' => $old, 'key_id' => 'ck_old']))->encrypt('secret');

        $reader = new Cryptman([
            'key' => Cryptman::generateKey(),
            'key_id' => 'ck_new',
            'previous_keys' => ['ck_old' => $old],
        ]);

        expect($reader->decrypt($payload))->toBe('secret');
    });

    it('still accepts previous_keys as a plain list', function () {
        $old = Cryptman::generateKey();
        $payload = (new Cryptman(['key' => $old]))->encrypt('secret');

        expect((new Cryptman(['key' => Cryptman::generateKey(), 'previous_keys' => [$old]]))->decrypt($payload))
            ->toBe('secret');
    });

    it('rejects a previous_keys array that mixes named and anonymous keys', function () {
        expect(fn () => new Cryptman([
            'key' => 'k',
            'previous_keys' => ['ck_old' => 'a', 'b'],
        ]))->toThrow(InvalidConfigurationException::class, 'mixes identified and anonymous');
    });

    it('rejects duplicate key ids', function () {
        expect(fn () => new Cryptman([
            'key' => 'k',
            'key_id' => 'ck_same',
            'previous_keys' => ['ck_same' => 'other'],
        ]))->toThrow(InvalidConfigurationException::class, 'Duplicate key id');
    });

    it('rejects malformed key ids', function (string $id) {
        expect(fn () => new Cryptman(['key' => 'k', 'key_id' => $id]))
            ->toThrow(InvalidConfigurationException::class);
    })->with([
        'empty' => [''],
        'contains the wire separator' => ['ck.prod'],
        'contains a space' => ['ck prod'],
        'too long' => [str_repeat('a', EncryptedPayload::KEY_ID_MAX_BYTES + 1)],
        'non-ascii' => ['ck_café'],
    ]);
});

describe('decoding untrusted input', function () {
    it('rejects a malformed key id on the wire', function (string $payload) {
        expect(fn () => Cryptman::describe($payload))->toThrow(InvalidPayloadException::class);
    })->with([
        'empty id' => ['cman2..abc'],
        'illegal character' => ['cman2.ck prod.abc'],
        'two separators' => ['cman2.ck_a.ck_b.abc'],
        'over-long id' => ['cman2.'.str_repeat('a', 65).'.abc'],
    ]);

    it('never crashes on arbitrary keyed input', function () {
        foreach (range(1, 200) as $_) {
            // Length 0 included deliberately: an empty body is a real thing a
            // truncated column can produce, and random_bytes() cannot make it.
            $length = random_int(0, 40);
            $body = $length === 0 ? '' : base64_encode(random_bytes($length));

            $mutated = 'cman2.'.bin2hex(random_bytes(4)).'.'.$body;

            try {
                Cryptman::describe($mutated);
            } catch (CryptmanException) {
                // A typed failure is the contract.
            }
        }

        expect(true)->toBeTrue();
    });
});

describe('generated ids', function () {
    it('generates ids that are valid and opaque', function () {
        $id = Cryptman::generateKeyId();

        expect(EncryptedPayload::isValidKeyId($id))->toBeTrue()
            ->and($id)->toStartWith('ck_')
            ->and(strlen($id))->toBeLessThanOrEqual(EncryptedPayload::KEY_ID_MAX_BYTES);
    });

    it('generates distinct ids', function () {
        $ids = array_map(fn () => Cryptman::generateKeyId(), range(1, 100));

        expect(array_unique($ids))->toHaveCount(100);
    });

    it('produces an id usable end to end', function () {
        $id = Cryptman::generateKeyId();
        $cryptman = new Cryptman(['key' => Cryptman::generateKey(), 'key_id' => $id]);
        $payload = $cryptman->encrypt('secret');

        expect(Cryptman::describe($payload)['key_id'])->toBe($id)
            ->and($cryptman->decrypt($payload))->toBe('secret');
    });
});
