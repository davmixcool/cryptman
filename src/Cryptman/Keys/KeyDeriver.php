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
    /**
     * Derived key length in bytes, and the default HKDF output length.
     *
     * DO NOT CHANGE. This value is simultaneously the HKDF default, the
     * invariant Key::fromDerivedMaterial() enforces, and what every driver's
     * guardKey() checks. A driver needing shorter key material derives it
     * internally by passing an explicit $length below; it does not change this.
     */
    public const KEY_BYTES = 32;

    /** Domain separation for the main encryption key. */
    public const INFO_ENCRYPTION = 'cryptman-v2-encryption';

    /**
     * Domain separation for per-message subkeys, one string per algorithm.
     *
     * Any AEAD with a 96-bit nonce carries a ~2^32 message bound under random
     * nonces, and a collision is catastrophic rather than graceful -- it leaks
     * the authentication subkey. Deriving a fresh key per message removes the
     * bound entirely (PRD §7).
     *
     * ------------------------------------------------------------------------
     *  FROZEN. Each string is part of the payload compatibility contract.
     * ------------------------------------------------------------------------
     *
     * Changing one makes every existing payload under that algorithm
     * undecryptable (PRD §17.2).
     *
     * They are distinct PER ALGORITHM for a specific reason: HKDF output at
     * length 16 is a byte-for-byte prefix of output at length 32 under
     * identical (ikm, salt, info). Sharing one string would give aes-128-gcm a
     * prefix of aes-256-gcm's message key, and chacha20-poly1305 an identical
     * one -- the same bytes used as two different algorithms' keys.
     */
    public const INFO_AES_MESSAGE = 'cryptman-v2-aesgcm-message';

    public const INFO_AES_128_MESSAGE = 'cryptman-v2-aes128gcm-message';

    public const INFO_CHACHA20_MESSAGE = 'cryptman-v2-chacha20poly1305-message';

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
     * Derive a single-use message key for one payload.
     *
     * Here the salt IS the random per-message value, which is what removes the
     * nonce-collision bound. It is stored in the payload alongside the nonce.
     *
     * $length exists for AES-128, which takes a 16-byte key. That shorter value
     * never crosses a public boundary -- it lives inside one driver method --
     * so Key and DriverInterface keep their 32-byte contract.
     *
     * The defaults preserve every pre-existing two-argument call site exactly.
     */
    public static function deriveMessageKey(
        string $encryptionKey,
        string $salt,
        string $info = self::INFO_AES_MESSAGE,
        int $length = self::KEY_BYTES
    ): string {
        if (strlen($salt) !== self::MESSAGE_SALT_BYTES) {
            throw new InvalidKeyException(sprintf(
                'Message salt must be %d bytes, got %d.',
                self::MESSAGE_SALT_BYTES,
                strlen($salt)
            ));
        }

        return self::hkdf($encryptionKey, $info, $salt, $length);
    }

    /** Generate a fresh per-message salt. */
    public static function generateMessageSalt(): string
    {
        return random_bytes(self::MESSAGE_SALT_BYTES);
    }

    private static function hkdf(
        string $ikm,
        string $info,
        string $salt,
        int $length = self::KEY_BYTES
    ): string {
        if ($ikm === '') {
            // hash_hkdf() raises a ValueError on empty input key material.
            // Catch it here so callers only ever see Cryptman's own exception
            // type, and so the message does not leak into a stack trace
            // alongside the key.
            throw new InvalidKeyException('Cannot derive a key from empty key material.');
        }

        // Same reasoning: turn hash_hkdf()'s ValueError into our own type.
        // 8160 is HKDF-SHA256's maximum output (255 * 32).
        if ($length < 1 || $length > 8160) {
            throw new InvalidKeyException(sprintf(
                'Derived key length must be between 1 and 8160 bytes, got %d.',
                $length
            ));
        }

        return hash_hkdf('sha256', $ikm, $length, $info, $salt);
    }
}
