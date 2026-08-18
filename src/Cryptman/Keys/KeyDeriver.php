<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Keys;

use Davmixcool\Cryptman\Exceptions\InvalidKeyException;

/**
 * Derives fixed-size cryptographic keys via HKDF-SHA256.
 *
 * This is the v2 path. It must never be applied to a legacy payload, and
 * LegacyKeyNormalizer must never be applied to a v2 payload.
 *
 * Parameters are fixed here rather than left to implementation because they
 * are part of the payload compatibility contract — changing any of them makes
 * every existing v2 payload undecryptable (PRD §17.2).
 *
 * @see \Davmixcool\Cryptman\Keys\LegacyKeyNormalizer  the frozen v1 path
 */
final class KeyDeriver
{
    /** Derived key length in bytes. */
    public const KEY_BYTES = 32;

    /** Domain separation for the main encryption key. */
    public const INFO_ENCRYPTION = 'cryptman-v2-encryption';

    /**
     * Domain separation for AES-256-GCM per-message subkeys.
     *
     * AES-GCM's 96-bit nonce carries a ~2^32 message bound under random
     * nonces, and a collision leaks the authentication subkey rather than
     * failing gracefully. Deriving a fresh key per message removes the bound
     * entirely (PRD §7).
     */
    public const INFO_AES_MESSAGE = 'cryptman-v2-aesgcm-message';

    /** Salt for per-message AES subkeys, in bytes. */
    public const MESSAGE_SALT_BYTES = 32;

    /**
     * Derive the main encryption key from user-supplied key material.
     *
     * The salt is intentionally empty: the derived key must be reproducible
     * from configuration alone, with no per-payload state to store. Domain
     * separation is carried entirely by `info`.
     */
    public static function deriveEncryptionKey(string $inputKeyMaterial): string
    {
        return self::hkdf($inputKeyMaterial, self::INFO_ENCRYPTION, '');
    }

    /**
     * Derive a single-use AES-256-GCM message key.
     *
     * Here the salt IS the random per-message value, which is what removes the
     * nonce-collision bound. It is stored in the payload alongside the nonce.
     */
    public static function deriveMessageKey(string $encryptionKey, string $salt): string
    {
        if (strlen($salt) !== self::MESSAGE_SALT_BYTES) {
            throw new InvalidKeyException(sprintf(
                'Message salt must be %d bytes, got %d.',
                self::MESSAGE_SALT_BYTES,
                strlen($salt)
            ));
        }

        return self::hkdf($encryptionKey, self::INFO_AES_MESSAGE, $salt);
    }

    /** Generate a fresh per-message salt. */
    public static function generateMessageSalt(): string
    {
        return random_bytes(self::MESSAGE_SALT_BYTES);
    }

    private static function hkdf(string $ikm, string $info, string $salt): string
    {
        if ($ikm === '') {
            // hash_hkdf() raises a ValueError on empty input key material.
            // Catch it here so callers only ever see Cryptman's own exception
            // type, and so the message does not leak into a stack trace
            // alongside the key.
            throw new InvalidKeyException('Cannot derive a key from empty key material.');
        }

        return hash_hkdf('sha256', $ikm, self::KEY_BYTES, $info, $salt);
    }
}
