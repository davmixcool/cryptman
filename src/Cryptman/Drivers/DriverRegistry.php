<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Drivers;

use Davmixcool\Cryptman\Contracts\DriverInterface;
use Davmixcool\Cryptman\Exceptions\UnsupportedDriverException;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/**
 * The closed set of Cryptman v2 encryption methods.
 *
 * Deliberately static and non-extensible. That is not a "small library"
 * shortcut -- a pluggable registry here would be a BROKEN extension point. A
 * driver is only usable if EncryptedPayload::GEOMETRY carries its algorithm id,
 * and that is a private const: register a driver with an unknown id and
 * PayloadDecoder rejects the payload before the driver is ever consulted. An
 * extension point that appears to exist but cannot work is worse than none.
 *
 * The set is closed by the wire format. This class says so out loud.
 *
 * Adding a method: a driver class, a GEOMETRY row, an ALG_* constant, and a
 * frozen HKDF info string if it uses per-message subkeys. Unauthenticated
 * ciphers are never eligible (PRD §23.1).
 *
 * @see EncryptedPayload  the id/name/geometry authority this must agree with
 */
final class DriverRegistry
{
    public const DEFAULT_METHOD = 'xchacha20-poly1305';

    /** @var array<string,class-string<DriverInterface>> */
    private const DRIVERS = [
        'xchacha20-poly1305' => SodiumDriver::class,
        'aes-256-gcm' => OpenSslAes256GcmDriver::class,
        'aes-128-gcm' => OpenSslAes128GcmDriver::class,
        'chacha20-poly1305' => OpenSslChaCha20Poly1305Driver::class,
    ];

    /**
     * Every method this build knows, available or not.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return array_keys(self::DRIVERS);
    }

    /**
     * Methods whose extension is actually present here.
     *
     * @return list<string>
     */
    public static function availableNames(): array
    {
        return array_values(array_filter(
            self::names(),
            static fn (string $name): bool => self::make($name)->isAvailable()
        ));
    }

    public static function supports(string $method): bool
    {
        return isset(self::DRIVERS[$method]);
    }

    public static function make(string $method): DriverInterface
    {
        if (! self::supports($method)) {
            throw new UnsupportedDriverException(sprintf(
                'Unknown method "%s". Supported: %s.',
                $method,
                implode(', ', self::names())
            ));
        }

        $class = self::DRIVERS[$method];

        return new $class();
    }

    /**
     * Resolve the driver for a payload's algorithm id.
     *
     * Routed through EncryptedPayload rather than instantiating and polling, so
     * the id-to-name mapping has exactly one owner and the two cannot disagree.
     */
    public static function forAlgorithm(int $algorithmId): DriverInterface
    {
        return self::make(EncryptedPayload::algorithmName($algorithmId));
    }
}
