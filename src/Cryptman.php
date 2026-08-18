<?php

declare(strict_types=1);

namespace Davmixcool;

use Davmixcool\Cryptman\Contracts\DriverInterface;
use Davmixcool\Cryptman\Drivers\LegacyDriver;
use Davmixcool\Cryptman\Drivers\OpenSslGcmDriver;
use Davmixcool\Cryptman\Drivers\SodiumDriver;
use Davmixcool\Cryptman\Exceptions\DecryptionException;
use Davmixcool\Cryptman\Exceptions\EnvironmentException;
use Davmixcool\Cryptman\Exceptions\InvalidConfigurationException;
use Davmixcool\Cryptman\Exceptions\InvalidPayloadException;
use Davmixcool\Cryptman\Exceptions\UnsupportedDriverException;
use Davmixcool\Cryptman\Keys\Key;
use Davmixcool\Cryptman\Keys\KeyGenerator;
use Davmixcool\Cryptman\Keys\KeyRing;
use Davmixcool\Cryptman\Payload\PayloadDecoder;
use Davmixcool\Cryptman\Payload\PayloadEncoder;

/**
 * Dead-simple authenticated encryption for PHP.
 *
 *     $cryptman = new Cryptman(['key' => $_ENV['CRYPTMAN_KEY']]);
 *
 *     $encrypted = $cryptman->encrypt('Loose lips sink ships');
 *     $plain     = $cryptman->decrypt($encrypted);
 *
 * That is roughly 90% of usage. Everything else exists so the remaining 10%
 * does not require reaching for a different library.
 *
 * ## Configuration
 *
 *     [
 *         'key'    => string,          // required - there is NO default
 *         'method' => string,          // optional, defaults to xchacha20-poly1305
 *
 *         'previous_keys' => string[], // optional, rotation (v2 payloads only)
 *
 *         'legacy' => [                // optional, migration only
 *             'key'    => string,      // defaults to 'key'
 *             'method' => string,      // defaults to aes-128-ctr, v1's default
 *             'strict' => bool,        // defaults to true
 *         ],
 *     ]
 *
 * The `legacy` block is scaffolding with a defined end: delete it once
 * migration completes and the configuration returns to a single key.
 *
 * ## Upgrading from v1
 *
 * Existing v1 configuration keeps working untouched. A v1 algorithm name in
 * `method` is unambiguous - v2 never encrypts with an unauthenticated cipher -
 * so it is read as a description of existing data. Old values stay readable,
 * new writes are authenticated automatically.
 *
 * Reading is fully compatible: every cipher v1 accepted, which is anything
 * openssl_get_cipher_methods() returns, not just the common four. Writing is
 * deliberately not - v2 has no way to produce v1 format, because unauthenticated
 * ciphertext is the defect this release exists to remove.
 *
 * ## Known limitation: mixed v1/v2 fleets
 *
 * If two applications share an encrypted column and only one is upgraded, the
 * one still on v1 CANNOT read what v2 writes - and v1 returns bare `false` on
 * every failure, so it will quietly treat a live secret as an empty value.
 *
 * Upgrade every reader of a shared column before any writer. There is no
 * opt-in to keep writing v1 format; see PRD 23.2 for why that was declined.
 */
class Cryptman
{
    private readonly KeyRing $keys;

    private readonly DriverInterface $driver;

    private readonly LegacyDriver $legacy;

    private readonly string $legacyKey;

    private readonly PayloadEncoder $encoder;

    private readonly PayloadDecoder $decoder;

    /** Pending value set by cipher(), cleared after every operation. */
    private ?string $data = null;

    /**
     * @param  array<string,mixed>  $options
     */
    public function __construct(array $options = [])
    {
        $this->encoder = new PayloadEncoder();
        $this->decoder = new PayloadDecoder();

        // No default key. v1 fell back to php_uname(), which made data
        // effectively public - Key::fromUserInput() throws instead.
        $key = self::stringOption($options, 'key', '');

        $this->keys = new KeyRing(
            Key::fromUserInput($key),
            array_map(
                static fn (mixed $previous): Key => Key::fromUserInput(self::asString($previous, 'previous_keys')),
                array_values((array) ($options['previous_keys'] ?? []))
            )
        );

        [$encryptionMethod, $inferredLegacyMethod] = $this->resolveMethod(
            isset($options['method']) ? self::stringOption($options, 'method', '') : null
        );

        $this->driver = $this->makeDriver($encryptionMethod);

        /** @var array<string,mixed> $legacyOptions */
        $legacyOptions = (array) ($options['legacy'] ?? []);

        $explicitLegacyMethod = isset($legacyOptions['method'])
            ? strtolower(self::asString($legacyOptions['method'], 'legacy.method'))
            : null;

        if ($inferredLegacyMethod !== null
            && $explicitLegacyMethod !== null
            && $explicitLegacyMethod !== $inferredLegacyMethod) {
            throw new InvalidConfigurationException(sprintf(
                'Ambiguous configuration: method "%s" is a Cryptman v1 algorithm and was read as '
                .'legacy configuration, but legacy.method says "%s". Supply only one.',
                $inferredLegacyMethod,
                $explicitLegacyMethod
            ));
        }

        // legacy.key defaults to the main key, covering the common case where
        // the same key carries across the upgrade.
        $this->legacyKey = isset($legacyOptions['key'])
            ? self::asString($legacyOptions['key'], 'legacy.key')
            : $key;

        $this->legacy = new LegacyDriver(
            method: $inferredLegacyMethod ?? $explicitLegacyMethod ?? LegacyDriver::DEFAULT_METHOD,
            strict: (bool) ($legacyOptions['strict'] ?? true),
        );
    }

    /** Generate a key safe to store as an environment variable. */
    public static function generateKey(): string
    {
        return KeyGenerator::generate();
    }

    /**
     * Set the value for a following encrypt() or decrypt().
     *
     * Retained from v1 so existing code keeps working. New code should pass the
     * value directly instead.
     */
    public function cipher(?string $data): static
    {
        $this->data = $data;

        return $this;
    }

    public function encrypt(?string $data = null, ?string $associatedData = null): string
    {
        $plaintext = $this->resolveInput($data);

        return $this->encoder->encode(
            $this->driver->encrypt($plaintext, $this->keys->current()->material(), $associatedData)
        );
    }

    public function decrypt(?string $payload = null, ?string $associatedData = null): string
    {
        $value = $this->resolveInput($payload);

        if ($value === '') {
            // Structurally nothing, rather than a legacy token that failed to
            // parse. Routing this to the legacy driver would report a
            // misleading cause (PRD 29).
            throw new InvalidPayloadException('Cannot decrypt an empty payload.');
        }

        if (! $this->decoder->looksLikeV2($value)) {
            // Legacy payloads use a single designated key and never iterate:
            // v1 is unauthenticated, so a wrong key returns garbage rather than
            // failing, and a key ring could not tell the difference.
            return $this->legacy->decrypt($value, $this->legacyKey);
        }

        $decoded = $this->decoder->decode($value);
        $driver = $this->driverForAlgorithm($decoded->algorithmId);

        $failure = null;

        foreach ($this->keys->all() as $key) {
            try {
                return $driver->decrypt($decoded, $key->material(), $associatedData);
            } catch (DecryptionException $e) {
                $failure = $e;
            }
        }

        throw new DecryptionException(
            $this->keys->count() > 1
                ? sprintf('Payload failed authentication under all %d configured keys.', $this->keys->count())
                : 'Payload failed authentication: it was modified, encrypted under a different '
                    .'key, or bound to different associated data.',
            0,
            $failure
        );
    }

    /**
     * Encrypt a structure as JSON.
     *
     * JSON only - never serialize()/unserialize(), which would turn decryption
     * into an object-injection surface (PRD 39).
     */
    public function encryptJson(mixed $data, ?string $associatedData = null): string
    {
        return $this->encrypt(json_encode($data, JSON_THROW_ON_ERROR), $associatedData);
    }

    public function decryptJson(?string $payload = null, ?string $associatedData = null): mixed
    {
        return json_decode($this->decrypt($payload, $associatedData), true, 512, JSON_THROW_ON_ERROR);
    }

    /** Payload format version: 1 for Cryptman v1 ciphertext, 2 for current. */
    public function version(string $payload): int
    {
        return $this->decoder->looksLikeV2($payload) ? 2 : 1;
    }

    /**
     * Describe a payload without decrypting it.
     *
     * Never reveals plaintext - nothing here requires a key.
     *
     * @return array{version:int,driver:?string,key_id:?string}
     */
    public function inspect(string $payload): array
    {
        if (! $this->decoder->looksLikeV2($payload)) {
            return ['version' => 1, 'driver' => null, 'key_id' => null];
        }

        return [
            'version' => 2,
            'driver' => $this->decoder->decode($payload)->name(),
            'key_id' => $this->keys->current()->id(),
        ];
    }

    /** Whether a payload predates the current format and should be re-encrypted. */
    public function needsUpgrade(string $payload): bool
    {
        return ! $this->decoder->looksLikeV2($payload);
    }

    /**
     * Re-encrypt a payload under the current method and key.
     *
     * Returns v2 payloads unchanged rather than churning ciphertext, so this is
     * safe to run repeatedly across a whole column.
     */
    public function upgrade(string $payload, ?string $associatedData = null): string
    {
        if (! $this->needsUpgrade($payload)) {
            return $payload;
        }

        return $this->encrypt($this->decrypt($payload, $associatedData), $associatedData);
    }

    /** The algorithm new payloads are written with. */
    public function method(): string
    {
        return $this->driver->name();
    }

    /**
     * Resolve the configured `method` into an encryption algorithm, and
     * possibly an inferred legacy method (PRD 12.1).
     *
     * @return array{0:?string,1:?string}
     */
    private function resolveMethod(?string $method): array
    {
        if ($method === null || $method === '') {
            return [null, null];
        }

        $normalised = strtolower($method);

        // v2 algorithms are checked FIRST because aes-256-gcm appears in both
        // this list and openssl_get_cipher_methods().
        foreach ([new SodiumDriver(), new OpenSslGcmDriver()] as $driver) {
            if ($driver->name() === $normalised) {
                return [$normalised, null];
            }
        }

        // Anything else OpenSSL recognises could have been configured in v1,
        // which accepted any entry from openssl_get_cipher_methods() - well
        // over a hundred ciphers, not just the four the test corpus covers.
        // Matching against the live list rather than a hardcoded subset is what
        // makes "existing v1 configuration keeps working" true in general
        // rather than only for the common cases (PRD 62.1).
        //
        // A v1 cipher name here is still unambiguous: v2 never encrypts with an
        // unauthenticated cipher, so it can only be describing existing data.
        if (in_array($normalised, openssl_get_cipher_methods(), true)) {
            trigger_error(
                sprintf(
                    'Cryptman: "%s" is a Cryptman v1 cipher and cannot be used for new encryption. '
                    .'It has been read as legacy configuration, so existing v1 data remains '
                    .'readable and new data is authenticated. Make this explicit with '
                    ."legacy => ['method' => '%s'].",
                    $method,
                    $normalised
                ),
                E_USER_DEPRECATED
            );

            return [null, $normalised];
        }

        // Not a v2 algorithm and not something this OpenSSL build knows. If it
        // is a cipher OpenSSL 3 retired rather than one that never existed, say
        // so - the remedy is at the OpenSSL level, not in Cryptman config.
        if (LegacyDriver::isRetiredCipher($normalised)) {
            throw new EnvironmentException(sprintf(
                'Cipher "%s" is not available in this OpenSSL build (%s). It was moved to the '
                .'OpenSSL legacy provider, so Cryptman v1 data encrypted with it cannot be read '
                .'here. Enable the legacy provider in your openssl.cnf, or decrypt on a host with '
                .'an older OpenSSL, then re-encrypt.',
                $method,
                OPENSSL_VERSION_TEXT
            ));
        }

        // Genuinely unknown - let makeDriver() report it with supported methods.
        return [$normalised, null];
    }

    private function makeDriver(?string $method): DriverInterface
    {
        $sodium = new SodiumDriver();
        $openssl = new OpenSslGcmDriver();

        if ($method === null) {
            if ($sodium->isAvailable()) {
                return $sodium;
            }

            // No silent fallback. Absence of ext-sodium almost always means a
            // deliberately stripped build, and switching algorithm based on the
            // host makes it impossible to reason about which algorithm protects
            // which record (PRD 35.1).
            if (! $openssl->isAvailable()) {
                throw new EnvironmentException(
                    'Neither ext-sodium nor OpenSSL AES-256-GCM is available. Cryptman will not '
                    .'fall back to an unauthenticated cipher.'
                );
            }

            throw new UnsupportedDriverException(
                'ext-sodium is not available, so the default xchacha20-poly1305 driver cannot be '
                ."used. Install ext-sodium, or choose AES explicitly with method => 'aes-256-gcm'."
            );
        }

        foreach ([$sodium, $openssl] as $driver) {
            if ($driver->name() !== $method) {
                continue;
            }

            if (! $driver->isAvailable()) {
                throw new EnvironmentException(sprintf(
                    'Method "%s" was requested but its extension is not available in this build.',
                    $method
                ));
            }

            return $driver;
        }

        throw new InvalidConfigurationException(sprintf(
            'Unknown method "%s". Supported: %s. Cryptman v1 algorithms belong under '
            .'legacy.method instead.',
            $method,
            implode(', ', [$sodium->name(), $openssl->name()])
        ));
    }

    private function driverForAlgorithm(int $algorithmId): DriverInterface
    {
        foreach ([new SodiumDriver(), new OpenSslGcmDriver()] as $driver) {
            if ($driver->algorithmId() !== $algorithmId) {
                continue;
            }

            if (! $driver->isAvailable()) {
                throw new EnvironmentException(sprintf(
                    'This payload uses %s, which is not available in this build.',
                    $driver->name()
                ));
            }

            return $driver;
        }

        throw new UnsupportedDriverException(sprintf(
            'Payload uses unknown algorithm id 0x%02X.',
            $algorithmId
        ));
    }

    /**
     * Take the argument if given, otherwise the pending cipher() value.
     *
     * The pending value is cleared either way, so a stale value cannot leak
     * into a later operation (PRD 9.1).
     */
    private function resolveInput(?string $argument): string
    {
        $value = $argument ?? $this->data;
        $this->data = null;

        if ($value === null) {
            throw new InvalidPayloadException(
                'No value supplied. Pass it directly, e.g. $cryptman->encrypt($data), or set it '
                .'first with $cryptman->cipher($data).'
            );
        }

        return $value;
    }

    /** @param array<string,mixed> $options */
    private static function stringOption(array $options, string $name, string $default): string
    {
        return isset($options[$name]) ? self::asString($options[$name], $name) : $default;
    }

    private static function asString(mixed $value, string $name): string
    {
        if (! is_string($value)) {
            throw new InvalidConfigurationException(sprintf(
                'Option "%s" must be a string, %s given.',
                $name,
                get_debug_type($value)
            ));
        }

        return $value;
    }
}
