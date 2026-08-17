<?php

declare(strict_types=1);

use Davmixcool\Cryptman;

/*
|--------------------------------------------------------------------------
| v1 compatibility suite
|--------------------------------------------------------------------------
|
| This file is NOT scaffolding. It feeds frozen v1 tokens to whatever
| Davmixcool\Cryptman the autoloader provides:
|
|   today  — that is v1, so this proves the corpus is a faithful record
|   later  — that is v2, so the same unchanged file becomes v2's compat suite
|
| Only the provenance test below is v1-specific; it is grouped 'v1-only' so it
| can be retired in one line when v2 rewrites src/.
|
| The corpus is frozen — read tests/Fixtures/README.md before changing anything
| here that asserts against it.
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

it('reproduces the frozen v1 result', function (array $fixture) {
    $options = ['key' => base64_decode($fixture['decrypt_with']['key_b64'])];

    // A null method means the option was OMITTED, exercising v1's aes-128-ctr default.
    if ($fixture['decrypt_with']['method'] !== null) {
        $options['method'] = $fixture['decrypt_with']['method'];
    }

    $actual = (new Cryptman($options))->cipher($fixture['token'])->decrypt();

    if ($fixture['v1_result']['type'] === 'false') {
        // Strict false, NOT ''. Empty plaintext under CTR returns false while
        // under CBC it returns '' — a loose assertion would conflate them.
        expect($actual)->toBeFalse();

        return;
    }

    expect($actual)->toBeString()
        ->and($actual)->toBe(base64_decode($fixture['v1_result']['value_b64']))
        ->and(mb_check_encoding($actual, 'UTF-8'))->toBe($fixture['v1_result_is_utf8']);
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

    // All four v1 cipher methods appear.
    $methods = array_unique(array_column(array_column($fixtures, 'encrypt_with'), 'method'));
    foreach (['aes-128-ctr', 'aes-256-ctr', 'aes-128-cbc', 'aes-256-cbc'] as $method) {
        expect($methods)->toContain($method);
    }

    // Both key-normalization branches appear against at least one CTR AND one
    // CBC method — the PRD 49.2 requirement that is easiest to lose silently.
    foreach (['digest', 'raw'] as $branch) {
        $families = [];

        foreach ($fixtures as $fixture) {
            if ($fixture['key_branch'] !== $branch) {
                continue;
            }
            if ($fixture['encrypt_with']['method'] === null) {
                continue;
            }
            $families[] = str_contains($fixture['encrypt_with']['method'], 'ctr') ? 'ctr' : 'cbc';
        }

        expect(in_array('ctr', $families, true))
            ->toBeTrue("key branch '{$branch}' must appear against a CTR method")
            ->and(in_array('cbc', $families, true))
            ->toBeTrue("key branch '{$branch}' must appear against a CBC method");
    }

    // The two keys that silently switch branch.
    $keys = array_column(array_column($fixtures, 'encrypt_with'), 'key_b64');

    expect(in_array(base64_encode("caf\xc3\xa9"), $keys, true))
        ->toBeTrue('the UTF-8 "café" key must appear')
        ->and(in_array(base64_encode("abc\x00def"), $keys, true))
        ->toBeTrue('the NUL-containing key must appear');

    // Every plaintext shape.
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

    // The two behaviours that justify AEAD in v2 must be recorded as data.
    $falses = array_filter($fixtures, fn (array $f): bool => $f['v1_result']['type'] === 'false');
    $garbage = array_filter($fixtures, fn (array $f): bool => $f['v1_result_is_utf8'] === false);

    expect($falses)->not->toBeEmpty('at least one fixture must return strict false')
        ->and($garbage)->not->toBeEmpty('at least one fixture must return non-UTF-8 garbage');

    // Wrong-key behaviour, split by family: CTR cannot fail, CBC usually does.
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

it('is running against released v1 source', function () {
    $blobs = corpus()['source']['blobs'];

    foreach ($blobs as $path => $expected) {
        $full = __DIR__.'/../../'.$path;

        expect($full)->toBeReadableFile();

        $contents = (string) file_get_contents($full);

        // Reproduces `git hash-object` with no git dependency.
        $actual = sha1('blob '.strlen($contents)."\0".$contents);

        expect($actual)->toBe($expected, "{$path} differs from the v1.0.0 release");
    }
})->group('v1-only');
