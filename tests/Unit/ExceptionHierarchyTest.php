<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Exceptions\CryptmanException;
use Davmixcool\Cryptman\Exceptions\DecryptionException;
use Davmixcool\Cryptman\Exceptions\EncryptionException;
use Davmixcool\Cryptman\Exceptions\EnvironmentException;
use Davmixcool\Cryptman\Exceptions\InvalidConfigurationException;
use Davmixcool\Cryptman\Exceptions\InvalidKeyException;
use Davmixcool\Cryptman\Exceptions\InvalidPayloadException;
use Davmixcool\Cryptman\Exceptions\LegacyDecryptionException;
use Davmixcool\Cryptman\Exceptions\UnsupportedDriverException;
use Davmixcool\Cryptman\Exceptions\UnsupportedVersionException;

const ALL_EXCEPTIONS = [
    EncryptionException::class,
    DecryptionException::class,
    LegacyDecryptionException::class,
    InvalidKeyException::class,
    InvalidPayloadException::class,
    InvalidConfigurationException::class,
    UnsupportedDriverException::class,
    UnsupportedVersionException::class,
    EnvironmentException::class,
];

it('lets one catch block cover everything the library throws', function (string $class) {
    try {
        throw new $class('boom');
    } catch (CryptmanException $e) {
        expect($e)->toBeInstanceOf($class);
    }
})->with(ALL_EXCEPTIONS);

it('catches the legacy case as a decryption failure', function () {
    // Callers who only care that a value did not decrypt catch the parent;
    // migration tooling catches the subclass to distinguish a wrong
    // legacy.method from genuinely bad data.
    try {
        throw new LegacyDecryptionException('legacy');
    } catch (DecryptionException $e) {
        expect($e)->toBeInstanceOf(LegacyDecryptionException::class);
    }
});

it('extends the SPL type that actually describes each failure', function () {
    // Argument problems are InvalidArgumentException; runtime failures are
    // RuntimeException. This is why the root is an interface, not a base class.
    foreach ([
        InvalidKeyException::class,
        InvalidPayloadException::class,
        InvalidConfigurationException::class,
    ] as $class) {
        expect(new $class('x'))->toBeInstanceOf(InvalidArgumentException::class);
    }

    foreach ([
        EncryptionException::class,
        DecryptionException::class,
        UnsupportedDriverException::class,
        UnsupportedVersionException::class,
        EnvironmentException::class,
    ] as $class) {
        expect(new $class('x'))->toBeInstanceOf(RuntimeException::class);
    }
});

it('is final everywhere except where subclassing is intended', function () {
    // DecryptionException must stay open for LegacyDecryptionException.
    expect((new ReflectionClass(DecryptionException::class))->isFinal())->toBeFalse();

    foreach (array_diff(ALL_EXCEPTIONS, [DecryptionException::class]) as $class) {
        expect((new ReflectionClass($class))->isFinal())
            ->toBeTrue("{$class} should be final");
    }
});

it('exposes the root as an interface so SPL types stay available', function () {
    expect((new ReflectionClass(CryptmanException::class))->isInterface())->toBeTrue();
});
