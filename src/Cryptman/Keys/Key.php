<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Keys;

use Davmixcool\Cryptman\Exceptions\InvalidKeyException;

/**
 * A derived encryption key.
 *
 * Holds 32 bytes of key material produced by KeyDeriver. Construction is
 * deliberately the only place user input is validated, so nothing downstream
 * has to re-check it.
 *
 * The class goes to some length to keep key material out of places developers
 * accidentally send it — var_dump(), print_r(), stack traces, session storage,
 * caches. None of this defends against an attacker who can already read
 * process memory; it defends against the routine leaks that put secrets into
 * log aggregators and crash reporters.
 */
final class Key
{
    /** Null once wiped -- see wipe(). */
    private ?string $material;

    private function __construct(string $material, private readonly ?string $id = null)
    {
        $this->material = $material;
    }

    /**
     * Build a key from whatever the developer configured.
     *
     * Accepts either a generated `cman_key_...` value or an arbitrary
     * passphrase; both are run through HKDF.
     *
     * There is NO default. v1 fell back to php_uname() when no key was given,
     * which made the data effectively public.
     */
    public static function fromUserInput(string $key, ?string $id = null): self
    {
        if (trim($key) === '') {
            throw new InvalidKeyException(
                'No encryption key supplied. Cryptman has no default key — '
                .'generate one with Cryptman::generateKey() and store it as '
                .'an environment variable.'
            );
        }

        $ikm = KeyGenerator::toInputKeyMaterial($key);

        return new self(KeyDeriver::deriveEncryptionKey($ikm), $id);
    }

    /** Wrap already-derived 32-byte material, e.g. from a key provider. */
    public static function fromDerivedMaterial(string $material, ?string $id = null): self
    {
        if (strlen($material) !== KeyDeriver::KEY_BYTES) {
            throw new InvalidKeyException(sprintf(
                'Derived key material must be %d bytes, got %d.',
                KeyDeriver::KEY_BYTES,
                strlen($material)
            ));
        }

        return new self($material, $id);
    }

    /**
     * The raw 32-byte key. Do not log, store, or serialize the result.
     *
     * Throws rather than returning an empty string once the key is wiped. An
     * empty key would otherwise travel onward and fail deep inside a driver as
     * "requires a 32-byte key, got 0", which says nothing about the real cause.
     */
    public function material(): string
    {
        if ($this->material === null) {
            throw new InvalidKeyException('This key has been wiped and can no longer be used.');
        }

        return $this->material;
    }

    /** Whether wipe() has been called. */
    public function isWiped(): bool
    {
        return $this->material === null;
    }

    /** Optional key identifier, for future key-id support. */
    public function id(): ?string
    {
        return $this->id;
    }

    /**
     * Best-effort wipe of the key material.
     *
     * sodium_memzero() overwrites in place where available. Without ext-sodium
     * this degrades to dropping the reference, which is genuinely weaker — PHP
     * may retain copies regardless. Documented honestly rather than oversold.
     */
    public function wipe(): void
    {
        if ($this->material !== null && function_exists('sodium_memzero')) {
            // Passed by reference deliberately: memzero overwrites the string's
            // own memory. Handing it a copy would separate first and zero the
            // copy, leaving the secret intact. PHP considers the variable
            // destroyed afterwards, which is why $material is nullable.
            sodium_memzero($this->material);
        }

        $this->material = null;
    }

    /** Redacted — keeps key material out of var_dump() and print_r(). */
    public function __debugInfo(): array
    {
        return [
            'id' => $this->id,
            'material' => '[redacted]',
        ];
    }

    /** Redacted — keeps key material out of accidental string interpolation. */
    public function __toString(): string
    {
        return 'Cryptman\Key[redacted]';
    }

    /**
     * Refuse serialization outright.
     *
     * A serialized key ends up in sessions, caches, and queue payloads —
     * durable stores that are rarely treated as secret. Failing loudly is
     * better than a key quietly landing in Redis.
     */
    public function __serialize(): array
    {
        throw new InvalidKeyException('Cryptman keys must not be serialized.');
    }

    public function __sleep(): array
    {
        throw new InvalidKeyException('Cryptman keys must not be serialized.');
    }
}
