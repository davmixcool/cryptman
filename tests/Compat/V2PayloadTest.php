<?php

declare(strict_types=1);

use Davmixcool\Cryptman;

/*
|--------------------------------------------------------------------------
| Frozen v2 payload corpus
|--------------------------------------------------------------------------
|
| The v1 corpus proves Cryptman can still read data written by v1. This is its
| forward-looking twin: it proves Cryptman can still read data written by
| ITSELF, under every method, after any future refactor.
|
| Nothing else covers that. Round-trip tests encrypt and decrypt with the same
| build, so a change to an HKDF info string, the derived key length, the AAD
| assembly or the frame layout leaves every one of them green while silently
| making every payload in production unreadable.
|
| FROZEN and APPEND-ONLY. If a payload here stops decrypting, the code is
| wrong -- the fixture is the specification. Never regenerate to go green.
|
*/

it('still decrypts every frozen v2 payload', function (array $case, string $key) {
    $cryptman = new Cryptman(['key' => $key, 'method' => $case['method']]);

    expect($cryptman->decrypt($case['payload'], $case['associated_data']))
        ->toBe(base64_decode($case['plaintext_b64']), $case['id']);
})->with(function (): iterable {
    $doc = json_decode(
        (string) file_get_contents(__DIR__.'/../Fixtures/v2-payloads.json'),
        true,
        512,
        JSON_THROW_ON_ERROR
    );

    foreach ($doc['payloads'] as $case) {
        yield $case['id'] => [$case, $doc['key']];
    }
});

it('covers every supported method', function () {
    $doc = json_decode(
        (string) file_get_contents(__DIR__.'/../Fixtures/v2-payloads.json'),
        true,
        512,
        JSON_THROW_ON_ERROR
    );

    // A new method must arrive with frozen payloads, or it has no forward
    // compatibility guarantee at all.
    expect(array_values(array_unique(array_column($doc['payloads'], 'method'))))
        ->toEqualCanonicalizing(Cryptman::supportedMethods());
});

it('is readable with associated data intact', function () {
    // Guards the AAD assembly specifically: header || 0x00 || caller data.
    $doc = json_decode(
        (string) file_get_contents(__DIR__.'/../Fixtures/v2-payloads.json'),
        true,
        512,
        JSON_THROW_ON_ERROR
    );

    $bound = array_values(array_filter(
        $doc['payloads'],
        fn (array $c): bool => $c['associated_data'] !== null
    ));

    expect($bound)->not->toBeEmpty();

    foreach ($bound as $case) {
        $cryptman = new Cryptman(['key' => $doc['key'], 'method' => $case['method']]);

        // Right context works, wrong context must not.
        expect($cryptman->decrypt($case['payload'], $case['associated_data']))
            ->toBe(base64_decode($case['plaintext_b64']))
            ->and(fn () => $cryptman->decrypt($case['payload'], 'wrong-context'))
            ->toThrow(\Davmixcool\Cryptman\Exceptions\DecryptionException::class);
    }
});
