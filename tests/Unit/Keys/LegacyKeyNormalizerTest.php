<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Keys\LegacyKeyNormalizer;

/*
|--------------------------------------------------------------------------
| The frozen normalizer, validated against the frozen corpus
|--------------------------------------------------------------------------
|
| This is the test that makes v1 compatibility real rather than asserted.
|
| It takes each corpus fixture, normalizes the key with our class, and then
| replays v1's decryption by hand using raw OpenSSL. If LegacyKeyNormalizer is
| byte-identical to v1's key handling, every fixture reproduces its frozen
| result — including the ones that legitimately return false.
|
| The replay below is a deliberate re-implementation of v1's Decrypt::token().
| Calling the real v1 class would prove nothing: it would exercise v1's own
| key handling rather than ours, which is precisely what is under test.
|
*/

/**
 * Replays Cryptman v1's decryption using externally supplied key material.
 *
 * Mirrors src/Cipher/Decrypt.php at tag v1.0.0, including the dead
 * `strlen($iv) % 2` check, which is retained so this stays a faithful replay.
 *
 * @return string|false
 */
function replayV1Decrypt(string $token, string $method, string $normalizedKey)
{
    $ivStrlen = 2 * (int) openssl_cipher_iv_length($method);

    if (preg_match('/^(.{'.$ivStrlen.'})(.+)$/', $token, $matches) === 1) {
        [, $ivHex, $ciphertext] = $matches;

        if (ctype_xdigit($ivHex) && strlen($ivHex) % 2 === 0) {
            return openssl_decrypt($ciphertext, $method, $normalizedKey, 0, (string) hex2bin($ivHex));
        }
    }

    return false;
}

it('reproduces every v1 fixture using only the frozen normalizer', function (array $fixture) {
    $key = base64_decode($fixture['decrypt_with']['key_b64']);

    // A null method means the option was omitted — v1 defaulted to aes-128-ctr.
    $method = $fixture['decrypt_with']['method'] ?? 'aes-128-ctr';

    $actual = replayV1Decrypt(
        $fixture['token'],
        $method,
        LegacyKeyNormalizer::normalize($key)
    );

    $expected = $fixture['v1_result']['type'] === 'false'
        ? false
        : base64_decode($fixture['v1_result']['value_b64']);

    expect($actual)->toBe($expected);
})->with('v1-corpus')->group('corpus');

it('agrees with the corpus on which branch each key takes', function (array $fixture) {
    $key = base64_decode($fixture['decrypt_with']['key_b64']);

    expect(LegacyKeyNormalizer::branch($key))->toBe($fixture['key_branch']);
})->with('v1-corpus')->group('corpus');

/*
|--------------------------------------------------------------------------
| The three surprising properties, pinned directly
|--------------------------------------------------------------------------
*/

it('produces an unsalted raw SHA-256 on the digest branch', function () {
    // The exact v1 expression. If this ever diverges, every v1 payload breaks.
    expect(LegacyKeyNormalizer::normalize('correct horse battery staple'))
        ->toBe(openssl_digest('correct horse battery staple', 'SHA256', true));
});

it('ignores key length on the digest branch', function () {
    // Every printable key becomes 32 bytes, however long it started.
    foreach (['x', str_repeat('k', 32), str_repeat('k', 500)] as $key) {
        expect(strlen(LegacyKeyNormalizer::normalize($key)))->toBe(32)
            ->and(LegacyKeyNormalizer::branch($key))->toBe('digest');
    }
});

it('passes non-printable keys through untouched, at their original length', function () {
    $cases = [
        "caf\xc3\xa9" => 5,   // "café" — ctype_print() is FALSE for this
        "abc\x00def" => 7,   // embedded NUL
        "\x00\x01\x02" => 3,
        '' => 0,   // empty string is also not "printable"
    ];

    foreach ($cases as $key => $expectedLength) {
        $key = (string) $key;

        expect(LegacyKeyNormalizer::normalize($key))->toBe($key)
            ->and(strlen(LegacyKeyNormalizer::normalize($key)))->toBe($expectedLength)
            ->and(LegacyKeyNormalizer::branch($key))->toBe('raw');
    }
});

it('treats an accented passphrase as non-printable', function () {
    // Called out on its own because it is the most likely cause of a botched
    // migration: an ordinary passphrase choice that silently switches branch.
    expect(ctype_print("caf\xc3\xa9"))->toBeFalse()
        ->and(LegacyKeyNormalizer::branch("caf\xc3\xa9"))->toBe('raw')
        ->and(LegacyKeyNormalizer::normalize("caf\xc3\xa9"))->toBe("caf\xc3\xa9");
});
