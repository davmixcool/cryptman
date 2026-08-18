<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Contracts\DriverInterface;
use Davmixcool\Cryptman\Drivers\DriverRegistry;
use Davmixcool\Cryptman\Exceptions\UnsupportedDriverException;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/*
|--------------------------------------------------------------------------
| Registry / wire-format agreement
|--------------------------------------------------------------------------
|
| Two lists are derived independently: DriverRegistry knows name -> class, and
| EncryptedPayload::GEOMETRY knows id -> name/geometry. Neither is generated
| from the other, so either could drift.
|
| These tests assert they describe the same set. A driver registered without a
| geometry row would produce payloads the decoder rejects; a geometry row
| without a driver would decode into nothing that can decrypt it.
|
*/

it('registers exactly the algorithms the wire format knows', function () {
    $fromRegistry = DriverRegistry::names();
    $fromGeometry = array_map(
        EncryptedPayload::algorithmName(...),
        EncryptedPayload::supportedAlgorithms()
    );

    expect($fromRegistry)->toEqualCanonicalizing($fromGeometry);
});

it('agrees with the wire format on every id and name', function (string $method) {
    $driver = DriverRegistry::make($method);

    expect($driver)->toBeInstanceOf(DriverInterface::class)
        ->and($driver->name())->toBe($method)
        ->and($driver->algorithmId())->toBe(EncryptedPayload::algorithmId($method))
        ->and(EncryptedPayload::algorithmName($driver->algorithmId()))->toBe($method);
})->with(fn () => DriverRegistry::names());

it('resolves a driver from a payload algorithm id', function (int $id) {
    expect(DriverRegistry::forAlgorithm($id)->algorithmId())->toBe($id);
})->with(fn () => EncryptedPayload::supportedAlgorithms());

it('assigns every driver a distinct id and name', function () {
    $ids = array_map(
        fn (string $n): int => DriverRegistry::make($n)->algorithmId(),
        DriverRegistry::names()
    );

    expect($ids)->toBe(array_values(array_unique($ids)))
        ->and(DriverRegistry::names())->toBe(array_values(array_unique(DriverRegistry::names())));
});

it('has a default that is actually registered', function () {
    expect(DriverRegistry::names())->toContain(DriverRegistry::DEFAULT_METHOD);
});

it('reports every registered driver as available on this build', function () {
    // All four are deliberately chosen to be universally available, so a
    // payload written on one host always decrypts on another.
    expect(DriverRegistry::availableNames())->toEqualCanonicalizing(DriverRegistry::names());
});

it('rejects an unknown method by name', function () {
    expect(fn () => DriverRegistry::make('rot13'))->toThrow(UnsupportedDriverException::class);
});

it('rejects an unknown algorithm id', function () {
    expect(fn () => DriverRegistry::forAlgorithm(0xFF))->toThrow(UnsupportedDriverException::class);
});

it('exposes the same set through the facade', function () {
    expect(Davmixcool\Cryptman::supportedMethods())->toBe(DriverRegistry::names());
});
