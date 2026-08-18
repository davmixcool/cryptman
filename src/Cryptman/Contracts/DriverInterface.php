<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Contracts;

use Davmixcool\Cryptman\Payload\EncryptedPayload;

/**
 * An authenticated encryption driver (PRD §32).
 *
 * Drivers work with raw derived key material rather than Key objects, keeping
 * them at the level of the primitives they wrap. Turning configuration into
 * key material is the facade's job.
 *
 * Note that LegacyDriver deliberately does NOT implement this interface: it is
 * decrypt-only and works on v1 tokens rather than EncryptedPayload, so forcing
 * it to satisfy encrypt() would mean throwing from a method the contract says
 * works.
 */
interface DriverInterface
{
    /**
     * @param  string  $key  32 bytes of derived key material
     */
    public function encrypt(string $plaintext, string $key, ?string $associatedData = null): EncryptedPayload;

    /**
     * @param  string  $key  32 bytes of derived key material
     *
     * @throws \Davmixcool\Cryptman\Exceptions\DecryptionException on tampering or wrong key
     */
    public function decrypt(EncryptedPayload $payload, string $key, ?string $associatedData = null): string;

    /** Wire name, e.g. "xchacha20-poly1305". */
    public function name(): string;

    /** Algorithm id as stored in the payload header. */
    public function algorithmId(): int;

    /** Whether the required extension is present in this build. */
    public function isAvailable(): bool;
}
