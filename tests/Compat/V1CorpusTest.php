<?php

declare(strict_types=1);

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Exceptions\DecryptionException;
use Davmixcool\Cryptman\Exceptions\LegacyDecryptionException;

/*
|--------------------------------------------------------------------------
| v2 compatibility suite
|--------------------------------------------------------------------------
|
| The frozen corpus records what Cryptman v1 did. This file asserts what v2
| does with the same inputs, and every place the two differ is declared below
| as a DELIBERATE divergence with a reason.
|
| That declaration is the point. Without it the only way to make this suite
| green would be to weaken assertions until they stopped noticing - which
| would destroy the guarantee the corpus exists to provide.
|
| Rule of thumb when something here fails: the corpus is right by definition.
| Either the code is wrong, or a new divergence needs justifying and adding.
|
| @see tests/Fixtures/README.md
|
*/

const CORPUS_FILE = __DIR__.'/../Fixtures/v1-corpus.json';
const CORPUS_SHA_FILE = __DIR__.'/../Fixtures/v1-corpus.sha256';

function corpus(): array
{
    static $doc = null;

    return $doc ??= json_decode(
        (string) file_get_contents(CORPUS_FILE),
        true,
        512,
        JSON_THROW_ON_ERROR
    );
}

/**
 * Build a v2 Cryptman configured to read a given fixture's legacy data.
 *
 * strict:false because the corpus deliberately contains binary and
 * wrong-key-garbage plaintexts. The UTF-8 guard is exercised separately below;
 * here we compare against raw v1 behaviour with nothing in the way.
 *
 * Note that legacy.key is deliberately NOT subject to the empty-key rejection
 * in PRD 19.1. That rule is a forward-looking control on the ENCRYPTION key.
 * Refusing to read data written under a weak or empty key would not improve
 * anything - the data is already encrypted badly - it would only block the
 * migration that fixes it. Recovery beats purity here.
 */
function cryptmanFor(array $fixture, bool $strict = false): Cryptman
{
    return new Cryptman([
        'key' => 'irrelevant-for-legacy-reads',
        'legacy' => [
            'key' => base64_decode($fixture['decrypt_with']['key_b64']),
            'method' => $fixture['decrypt_with']['method'] ?? 'aes-128-ctr',
            'strict' => $strict,
        ],
    ]);
}

it('still reads every v1 value that v1 itself could read', function (array $fixture) {
    // ---- DIVERGENCE: failure is an exception, never a falsy return -------
    // v1 returned bare `false`, which a caller can silently mistake for
    // plaintext. That is the defect PRD 28 exists to remove.
    if ($fixture['v1_result']['type'] === 'false') {
        expect(fn () => cryptmanFor($fixture)->decrypt($fixture['token']))
            ->toThrow(DecryptionException::class);

        return;
    }

    // ---- COMPATIBILITY: everything else must be byte-identical ------------
    expect(cryptmanFor($fixture)->decrypt($fixture['token']))
        ->toBe(base64_decode($fixture['v1_result']['value_b64']));
})->with('v1-corpus')->group('corpus');

it('guards values that decrypt to non-UTF-8 when strict mode is on', function (array $fixture) {
    if ($fixture['v1_result_is_utf8'] !== false) {
        expect(true)->toBeTrue();

        return;
    }

    // Every fixture v1 decrypted to garbage - wrong key, misread method, or
    // genuinely binary plaintext - must trip the guard rather than hand back
    // plausible-looking nonsense.
    expect(fn () => cryptmanFor($fixture, strict: true)->decrypt($fixture['token']))
        ->toThrow(LegacyDecryptionException::class);
})->with('v1-corpus')->group('corpus');

it('routes v1 values through the legacy path and flags them for upgrade', function (array $fixture) {
    $cryptman = new Cryptman(['key' => Cryptman::generateKey()]);

    expect($cryptman->version($fixture['token']))->toBe(1)
        ->and($cryptman->needsUpgrade($fixture['token']))->toBeTrue()
        ->and($cryptman->inspect($fixture['token']))
        ->toMatchArray(['version' => 1, 'driver' => null]);
})->with('v1-corpus')->group('corpus');

it('upgrades readable v1 values to authenticated v2 payloads', function (array $fixture) {
    if ($fixture['v1_result']['type'] === 'false') {
        expect(true)->toBeTrue();   // covered by the divergence above

        return;
    }

    $expected = base64_decode($fixture['v1_result']['value_b64']);

    $cryptman = cryptmanFor($fixture);
    $upgraded = $cryptman->upgrade($fixture['token']);

    expect($cryptman->needsUpgrade($upgraded))->toBeFalse()
        ->and($cryptman->version($upgraded))->toBe(2)
        ->and($cryptman->decrypt($upgraded))->toBe($expected)
        // Upgrading is idempotent - safe to run across a column repeatedly.
        ->and($cryptman->upgrade($upgraded))->toBe($upgraded);
})->with('v1-corpus')->group('corpus');

it('has an unmodified corpus file', function () {
    $expected = trim(explode(' ', (string) file_get_contents(CORPUS_SHA_FILE))[0]);

    expect(hash_file('sha256', CORPUS_FILE))->toBe($expected);
})->group('corpus');

it('covers every combination the compatibility contract requires', function () {
    $fixtures = corpus()['fixtures'];

    $ids = array_column($fixtures, 'id');
    $sorted = $ids;
    sort($sorted, SORT_STRING);

    expect($ids)->toBe(array_values(array_unique($ids)), 'fixture ids must be unique')
        ->and($ids)->toBe($sorted, 'fixtures must be sorted by id');

    $methods = array_unique(array_column(array_column($fixtures, 'encrypt_with'), 'method'));
    foreach (['aes-128-ctr', 'aes-256-ctr', 'aes-128-cbc', 'aes-256-cbc'] as $method) {
        expect($methods)->toContain($method);
    }

    foreach (['digest', 'raw'] as $branch) {
        $families = [];

        foreach ($fixtures as $fixture) {
            if ($fixture['key_branch'] !== $branch || $fixture['encrypt_with']['method'] === null) {
                continue;
            }
            $families[] = str_contains($fixture['encrypt_with']['method'], 'ctr') ? 'ctr' : 'cbc';
        }

        expect(in_array('ctr', $families, true))
            ->toBeTrue("key branch '{$branch}' must appear against a CTR method")
            ->and(in_array('cbc', $families, true))
            ->toBeTrue("key branch '{$branch}' must appear against a CBC method");
    }

    $keys = array_column(array_column($fixtures, 'encrypt_with'), 'key_b64');

    expect(in_array(base64_encode("caf\xc3\xa9"), $keys, true))
        ->toBeTrue('the UTF-8 "café" key must appear')
        ->and(in_array(base64_encode("abc\x00def"), $keys, true))
        ->toBeTrue('the NUL-containing key must appear');

    $plaintexts = array_map('base64_decode', array_column($fixtures, 'plaintext_b64'));
    $lengths = array_map('strlen', $plaintexts);

    expect(in_array(0, $lengths, true))->toBeTrue('an empty plaintext must appear')
        ->and(in_array(16, $lengths, true))->toBeTrue('a block-boundary plaintext must appear')
        ->and(max($lengths))->toBeGreaterThan(16, 'a multi-block plaintext must appear');

    $hasUtf8 = false;
    $hasBinary = false;

    foreach ($plaintexts as $plaintext) {
        if ($plaintext === '') {
            continue;
        }
        if (! mb_check_encoding($plaintext, 'UTF-8')) {
            $hasBinary = true;
        } elseif (strlen($plaintext) !== mb_strlen($plaintext, 'UTF-8')) {
            $hasUtf8 = true;
        }
    }

    expect($hasUtf8)->toBeTrue('a multi-byte UTF-8 plaintext must appear')
        ->and($hasBinary)->toBeTrue('a binary plaintext must appear');

    $falses = array_filter($fixtures, fn (array $f): bool => $f['v1_result']['type'] === 'false');
    $garbage = array_filter($fixtures, fn (array $f): bool => $f['v1_result_is_utf8'] === false);

    expect($falses)->not->toBeEmpty('at least one fixture must return strict false')
        ->and($garbage)->not->toBeEmpty('at least one fixture must return non-UTF-8 garbage');

    $ctrWrongKey = array_filter($fixtures, fn (array $f): bool => str_starts_with($f['id'], 'neg/wrong-key-ctr/'));
    $cbcWrongKey = array_filter($fixtures, fn (array $f): bool => str_starts_with($f['id'], 'neg/wrong-key-cbc/'));

    expect($ctrWrongKey)->not->toBeEmpty()->and($cbcWrongKey)->not->toBeEmpty();

    foreach ($ctrWrongKey as $fixture) {
        expect($fixture['v1_result']['type'])
            ->toBe('string', "{$fixture['id']}: a wrong key under CTR must return a garbage string, never false");
    }

    foreach ($cbcWrongKey as $fixture) {
        expect($fixture['v1_result']['type'])
            ->toBe('false', "{$fixture['id']}: a wrong key under CBC is caught by the padding check");
    }
})->group('corpus');
