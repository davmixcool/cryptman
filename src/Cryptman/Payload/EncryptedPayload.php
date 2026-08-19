<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Payload;

use Davmixcool\Cryptman\Exceptions\UnsupportedDriverException;

/**
 * A decoded Cryptman v2 payload, and the single source of truth for the wire
 * format.
 *
 * The format is a compact binary frame, not encoded JSON. The primary use case
 * is encrypted database columns, where a JSON envelope would cost 60-80 bytes
 * of constant overhead per value before the ciphertext is counted — a heavy
 * tax on a column holding short secrets like API tokens.
 *
 *     cman2.<base64url( header || salt? || nonce || ciphertext_with_tag )>
 *
 * Header, 2 bytes:
 *
 *     byte 0   format version   (0x02)
 *     byte 1   algorithm id     (see the table below)
 *
 * Per-algorithm geometry — every field length is implied by the algorithm id,
 * so no length prefixes are encoded:
 *
 *     0x01  xchacha20-poly1305  header(2) || nonce(24) || ct||tag              42 B
 *     0x02  aes-256-gcm         header(2) || salt(32) || nonce(12) || ct||tag  62 B
 *     0x03  aes-128-gcm         header(2) || salt(32) || nonce(12) || ct||tag  62 B
 *     0x04  chacha20-poly1305   header(2) || salt(32) || nonce(12) || ct||tag  62 B
 *
 * The salt is present for every algorithm with a 96-bit nonce, where it seeds
 * the per-message subkey derivation that removes the ~2^32 message
 * bound. That is why those frames are 20 bytes heavier: a real cost, and the
 * reason the default is the one algorithm that does not need it.
 *
 * Note that 0x01 and 0x04 are DIFFERENT algorithms despite similar names.
 * XChaCha20-Poly1305 (sodium, 192-bit nonce) and ChaCha20-Poly1305 (OpenSSL,
 * RFC 8439, 96-bit nonce) are not interchangeable on the wire.
 *
 * The `cman2.` prefix stays in cleartext so version detection and legacy
 * discrimination are a prefix comparison requiring no decoding of untrusted
 * input.
 */
final class EncryptedPayload
{
    public const PREFIX = 'cman2.';

    public const FORMAT_VERSION = 0x02;

    public const ALG_XCHACHA20_POLY1305 = 0x01;

    public const ALG_AES_256_GCM = 0x02;

    public const ALG_AES_128_GCM = 0x03;

    public const ALG_CHACHA20_POLY1305 = 0x04;

    public const HEADER_BYTES = 2;

    /** Poly1305 and GCM both produce a 16-byte tag. */
    public const TAG_BYTES = 16;

    /** Salt length for algorithms using per-message subkeys. */
    public const SALT_BYTES = 32;

    /**
     * The wire format's authority on what each algorithm id means.
     *
     * APPEND-ONLY. An id, once published, is a permanent commitment: somewhere
     * a payload exists carrying it, and that payload must stay decryptable
     * forever. Adding a row is cheap; changing or removing one
     * strands data.
     *
     * @var array<int,array{name:string,nonce:positive-int,salt:int<0,max>}>
     */
    private const GEOMETRY = [
        self::ALG_XCHACHA20_POLY1305 => ['name' => 'xchacha20-poly1305', 'nonce' => 24, 'salt' => 0],
        self::ALG_AES_256_GCM => ['name' => 'aes-256-gcm', 'nonce' => 12, 'salt' => self::SALT_BYTES],
        self::ALG_AES_128_GCM => ['name' => 'aes-128-gcm', 'nonce' => 12, 'salt' => self::SALT_BYTES],
        self::ALG_CHACHA20_POLY1305 => ['name' => 'chacha20-poly1305', 'nonce' => 12, 'salt' => self::SALT_BYTES],
    ];

    public function __construct(
        public readonly int $algorithmId,
        public readonly string $nonce,
        public readonly string $ciphertext,
        public readonly string $salt = '',
        public readonly int $version = self::FORMAT_VERSION,
    ) {}

    /** @return list<int> */
    public static function supportedAlgorithms(): array
    {
        return array_keys(self::GEOMETRY);
    }

    public static function isKnownAlgorithm(int $algorithmId): bool
    {
        return isset(self::GEOMETRY[$algorithmId]);
    }

    public static function algorithmName(int $algorithmId): string
    {
        return self::geometry($algorithmId)['name'];
    }

    public static function algorithmId(string $name): int
    {
        foreach (self::GEOMETRY as $id => $spec) {
            if ($spec['name'] === $name) {
                return $id;
            }
        }

        throw new UnsupportedDriverException(sprintf(
            'Unknown algorithm "%s". Supported: %s.',
            $name,
            implode(', ', array_column(self::GEOMETRY, 'name'))
        ));
    }

    /** @return positive-int */
    public static function nonceBytes(int $algorithmId): int
    {
        return self::geometry($algorithmId)['nonce'];
    }

    /** @return int<0,max> */
    public static function saltBytes(int $algorithmId): int
    {
        return self::geometry($algorithmId)['salt'];
    }

    public function name(): string
    {
        return self::algorithmName($this->algorithmId);
    }

    /** The 2-byte header, which is also the authenticated associated data. */
    public function header(): string
    {
        return chr($this->version).chr($this->algorithmId);
    }

    /**
     * Associated data for the AEAD call.
     *
     * The header is always authenticated, so version and algorithm cannot be
     * altered independently of the ciphertext. Caller-supplied
     * associated data is appended after a 0x00 separator, which prevents
     * ambiguity between the two components.
     *
     * An empty string is treated as no associated data. Distinguishing the two
     * would mean encrypt($d) and encrypt($d, '') produced mutually
     * undecryptable payloads, which is a footgun with no use case.
     */
    public function associatedData(?string $callerData = null): string
    {
        if ($callerData === null || $callerData === '') {
            return $this->header();
        }

        return $this->header()."\0".$callerData;
    }

    /** @return array{name:string,nonce:positive-int,salt:int<0,max>} */
    private static function geometry(int $algorithmId): array
    {
        if (! isset(self::GEOMETRY[$algorithmId])) {
            throw new UnsupportedDriverException(sprintf(
                'Unknown algorithm id 0x%02X. This payload may have been written by a newer '
                .'version of Cryptman.',
                $algorithmId
            ));
        }

        return self::GEOMETRY[$algorithmId];
    }
}
