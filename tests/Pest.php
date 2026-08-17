<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Datasets
|--------------------------------------------------------------------------
|
| The v1 compatibility corpus is a frozen artifact — see
| tests/Fixtures/README.md before touching it or anything that reads it.
|
| Every fixture is yielded keyed by its id, so a failure names the exact
| fixture (e.g. "ctr128/key-ascii-printable/pt-empty") rather than an index.
|
*/

dataset('v1-corpus', function (): iterable {
    $path = __DIR__.'/Fixtures/v1-corpus.json';

    $doc = json_decode(
        (string) file_get_contents($path),
        true,
        512,
        JSON_THROW_ON_ERROR
    );

    foreach ($doc['fixtures'] as $fixture) {
        yield $fixture['id'] => [$fixture];
    }
});
