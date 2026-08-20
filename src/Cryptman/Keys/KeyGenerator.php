<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Keys;

use Davmixcool\Cryptman\Exceptions\InvalidKeyException;

/**
 * Generates and parses Cryptman keys.
 *
 * A generated key is self-identifying:
 *
 *     cman_key_<base64url(32 random bytes)>
 *
 * The prefix exists so that a key found in an environment file, a paste, or a
 * log is recognisable as a Cryptman key, and so that a malformed one can be
 * rejected instead of being silently treated as a passphrase.
 */
final class KeyGenerator
{
    public const PREFIX = 'cman_key_';

    /** Key id prefix, so an id is recognisable in a database column. */
    public const ID_PREFIX = 'ck_';

    public const ID_BYTES = 16;

    /** Raw entropy behind a generated key, in bytes. */
    public const KEY_BYTES = 32;

    /**
     * Generate a new key, safe to store as an environment variable.
     *
     *     CRYPTMAN_KEY=cman_key_...
     */
    public static function generate(): string
    {
        return self::PREFIX.self::base64UrlEncode(random_bytes(self::KEY_BYTES));
    }

    /**
     * Generate an opaque key id.
     *
     * Deliberately meaningless. A key id travels in cleartext next to every
     * value it encrypted, so a descriptive one like "ck_prod_2026_08" tells
     * anyone who can read the column which environment they are looking at and
     * roughly how old the key is -- free reconnaissance for deciding what is
     * worth attacking. Map opaque ids to human labels somewhere that is not the
     * ciphertext.
     *
     * 16 bytes: collision-safe for any realistic number of keys, and short
     * enough that the id costs little beside the payload.
     */
    public static function generateId(): string
    {
        return self::ID_PREFIX.self::base64UrlEncode(random_bytes(self::ID_BYTES));
    }

    /** Whether a value carries the Cryptman key prefix. */
    public static function isGeneratedKey(string $key): bool
    {
        return str_starts_with($key, self::PREFIX);
    }

    /**
     * Turn user-supplied key input into input key material for HKDF.
     *
     * Both paths run HKDF afterwards — the prefix determines only WHAT becomes
     * the IKM, not whether derivation happens. Running HKDF over already
     * uniform material costs one hash and buys a single code path to audit
     * plus domain separation for every key.
     *
     * A malformed `cman_key_` value throws rather than falling through to the
     * passphrase path, so a typo cannot silently become a different key.
     */
    public static function toInputKeyMaterial(string $key): string
    {
        if (! self::isGeneratedKey($key)) {
            // An arbitrary developer passphrase. Used as-is; HKDF handles the
            // non-uniformity.
            return $key;
        }

        $body = substr($key, strlen(self::PREFIX));
        $decoded = self::base64UrlDecode($body);

        if ($decoded === null) {
            throw new InvalidKeyException(
                'Key carries the '.self::PREFIX.' prefix but its body is not valid base64url. '
                .'Generate a new key with Cryptman::generateKey().'
            );
        }

        if (strlen($decoded) !== self::KEY_BYTES) {
            throw new InvalidKeyException(sprintf(
                'Key carries the %s prefix but decodes to %d bytes, expected %d. '
                .'Generate a new key with Cryptman::generateKey().',
                self::PREFIX,
                strlen($decoded),
                self::KEY_BYTES
            ));
        }

        return $decoded;
    }

    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** Returns null when the input is not valid base64url. */
    public static function base64UrlDecode(string $value): ?string
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            return null;
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
