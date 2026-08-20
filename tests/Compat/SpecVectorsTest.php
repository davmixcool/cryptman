<?php

declare(strict_types=1);

use Davmixcool\Cryptman;

/*
|--------------------------------------------------------------------------
| SPEC.md test vectors
|--------------------------------------------------------------------------
|
| SPEC.md is a promise to people writing Cryptman in other languages: implement
| this and you will interoperate. The vectors are the executable part of that
| promise, and a published vector that no longer decrypts is worse than none --
| an implementer would chase a bug in their own code that does not exist.
|
| So this reads the payloads out of the SHIPPED document rather than out of the
| generator, and decrypts them through the public API. If the format changes
| without SPEC.md being regenerated, this fails.
|
| Regenerate with: composer spec:vectors
|
*/

const SPEC_FILE = __DIR__.'/../../SPEC.md';

/** The key SPEC.md publishes. Non-secret, committed, test-only. */
const SPEC_KEY = 'cman_key_KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio';

/**
 * Pull each vector block out of SPEC.md.
 *
 * @return list<array{payload:string,plaintext:string,aad:?string,key_id:?string}>
 */
function specVectors(): array
{
    $markdown = (string) file_get_contents(SPEC_FILE);

    preg_match_all('/```text\n(.*?)```/s', $markdown, $blocks);

    $vectors = [];

    foreach ($blocks[1] as $block) {
        if (! str_contains($block, 'payload             ')) {
            continue;
        }

        $field = static function (string $name) use ($block): ?string {
            if (preg_match('/^'.preg_quote($name, '/').'\s+(.*)$/m', $block, $m) !== 1) {
                return null;
            }

            $value = trim($m[1]);

            if ($value === 'NULL') {
                return null;
            }

            // Values are var_export()ed, so strings arrive single-quoted.
            return preg_match("/^'(.*)'$/s", $value, $q) === 1 ? $q[1] : $value;
        };

        $vectors[] = [
            'payload' => (string) $field('payload'),
            'plaintext' => (string) $field('plaintext'),
            'aad' => $field('associated data'),
            'key_id' => $field('key id'),
        ];
    }

    return $vectors;
}

it('publishes vectors that still decrypt', function () {
    $vectors = specVectors();

    expect($vectors)->not->toBeEmpty('SPEC.md must contain test vectors');

    foreach ($vectors as $i => $vector) {
        $options = ['key' => SPEC_KEY];

        if ($vector['key_id'] !== null) {
            $options['key_id'] = $vector['key_id'];
        }

        expect((new Cryptman($options))->decrypt($vector['payload'], $vector['aad']))
            ->toBe($vector['plaintext'], "SPEC.md vector #{$i} no longer decrypts");
    }
})->group('corpus');

it('covers every algorithm in the spec', function () {
    $payloads = array_column(specVectors(), 'payload');

    foreach (Cryptman::supportedMethods() as $method) {
        $found = false;

        foreach ($payloads as $payload) {
            if (Cryptman::describe($payload)['driver'] === $method) {
                $found = true;
                break;
            }
        }

        expect($found)->toBeTrue("SPEC.md must publish a vector for {$method}");
    }
})->group('corpus');

it('covers the key id and associated data cases', function () {
    $vectors = specVectors();

    $keyed = array_filter($vectors, fn (array $v): bool => $v['key_id'] !== null);
    $withAad = array_filter($vectors, fn (array $v): bool => $v['aad'] !== null);
    $both = array_filter($vectors, fn (array $v): bool => $v['key_id'] !== null && $v['aad'] !== null);
    $empty = array_filter($vectors, fn (array $v): bool => $v['plaintext'] === '');

    // The combined case matters most: it is the only one that exercises the
    // full AAD assembly, length-prefixed id and 0x00-separated caller data
    // together, which is where an independent implementation is most likely to
    // diverge.
    expect($keyed)->not->toBeEmpty('a keyed vector must be published')
        ->and($withAad)->not->toBeEmpty('an associated-data vector must be published')
        ->and($both)->not->toBeEmpty('a vector with BOTH a key id and associated data must be published')
        ->and($empty)->not->toBeEmpty('an empty-plaintext vector must be published');
})->group('corpus');
