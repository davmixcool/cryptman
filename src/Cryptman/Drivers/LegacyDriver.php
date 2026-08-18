<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Drivers;

use Davmixcool\Cryptman\Exceptions\EnvironmentException;
use Davmixcool\Cryptman\Exceptions\InvalidConfigurationException;
use Davmixcool\Cryptman\Exceptions\LegacyDecryptionException;
use Davmixcool\Cryptman\Keys\LegacyKeyNormalizer;

/**
 * Reads Cryptman v1 tokens. DECRYPT ONLY (PRD §22, §23).
 *
 * Deliberately does not implement DriverInterface. It has no encrypt() — v2
 * never writes unauthenticated ciphertext — and it operates on raw v1 token
 * strings rather than EncryptedPayload. Satisfying the interface would mean
 * throwing from a method the contract promises works.
 *
 * ---------------------------------------------------------------------------
 *  Nothing here is authenticated.
 * ---------------------------------------------------------------------------
 *
 * v1 ciphertext carries no MAC. The UTF-8 guard below is a usability backstop
 * for a misconfigured method, NOT a security control, and it must never be
 * described as one. Measured false-negative rate is ~0.02% on short values
 * (PRD §22.2). This is the argument for completing migration rather than
 * leaving legacy data in place indefinitely.
 *
 * The cipher method cannot be recovered from a token: all four v1 methods use
 * a 16-byte IV, so the hex prefix does not discriminate. It must be supplied.
 */
final class LegacyDriver
{
    /** v1's default when no method was configured. */
    public const DEFAULT_METHOD = 'aes-128-ctr';

    /**
     * Cipher families OpenSSL 3 moved into its legacy provider, which is not
     * loaded by default.
     *
     * v1 accepted any cipher openssl_get_cipher_methods() returned, and on
     * OpenSSL 1.x that included these. Data encrypted with them years ago is
     * still out there, but a modern build cannot read it without configuration
     * changes at the OpenSSL level. That is an environment problem with a real
     * remedy, not a Cryptman configuration mistake, and the error must say so.
     */
    private const RETIRED_CIPHER_PREFIXES = [
        'bf-', 'blowfish', 'rc2-', 'rc4', 'cast5-', 'desx-', 'seed-', 'idea-',
    ];

    public function __construct(
        private readonly string $method = self::DEFAULT_METHOD,
        private readonly bool $strict = true,
    ) {
        if (! in_array(strtolower($this->method), openssl_get_cipher_methods(), true)) {
            if (self::isRetiredCipher($this->method)) {
                throw new EnvironmentException(sprintf(
                    'Cipher "%s" is not available in this OpenSSL build (%s). It was moved to '
                    .'the OpenSSL legacy provider, so data encrypted with it cannot be read here. '
                    .'Enable the legacy provider in your openssl.cnf, or decrypt on a host with '
                    .'an older OpenSSL, then re-encrypt.',
                    $this->method,
                    OPENSSL_VERSION_TEXT
                ));
            }

            throw new InvalidConfigurationException(sprintf(
                'Unknown legacy cipher method "%s". v1 defaulted to "%s".',
                $this->method,
                self::DEFAULT_METHOD
            ));
        }
    }

    /** Whether a cipher is one this OpenSSL build has retired rather than never known. */
    public static function isRetiredCipher(string $method): bool
    {
        $method = strtolower($method);

        foreach (self::RETIRED_CIPHER_PREFIXES as $prefix) {
            if (str_starts_with($method, $prefix)) {
                return true;
            }
        }

        return false;
    }

    public function name(): string
    {
        return 'legacy:'.$this->method;
    }

    /** Whether a value looks like a v1 token: hex IV prefix, no v2 marker. */
    public function looksLikeLegacy(string $token): bool
    {
        $ivLength = 2 * (int) openssl_cipher_iv_length($this->method);

        return strlen($token) > $ivLength && ctype_xdigit(substr($token, 0, $ivLength));
    }

    /**
     * Decrypt a v1 token.
     *
     * $key is the ORIGINAL user key, not derived material — it goes through
     * LegacyKeyNormalizer, which reproduces v1's conditional SHA-256 exactly.
     * v2's KeyDeriver must never be applied here.
     */
    public function decrypt(string $token, string $key): string
    {
        $ivLength = 2 * (int) openssl_cipher_iv_length($this->method);

        // Mirrors v1's Decrypt::token() regex, which requires at least one
        // body character after the IV. This is why v1 could not round-trip an
        // empty plaintext under CTR: encryption produced a bare hex IV.
        if (preg_match('/^(.{'.$ivLength.'})(.+)$/', $token, $matches) !== 1) {
            throw new LegacyDecryptionException(
                'Value is not a well-formed Cryptman v1 token: too short to contain an IV and body.'
            );
        }

        [, $ivHex, $ciphertext] = $matches;

        if (! ctype_xdigit($ivHex)) {
            throw new LegacyDecryptionException(
                'Value is not a well-formed Cryptman v1 token: IV prefix is not hexadecimal.'
            );
        }

        // v1 produced its body with openssl_encrypt($data, $method, $key, 0, $iv),
        // and options=0 means base64 output. A body that is not valid base64
        // therefore cannot have come from v1.
        //
        // This check matters more than it looks. Without it, PHP's lenient
        // base64 handling turns junk into an empty string, openssl_decrypt
        // happily "decrypts" that to '', and the caller receives '' as though
        // it were real plaintext -- precisely the silent-wrong-answer failure
        // this release exists to remove (PRD 28).
        if (base64_decode($ciphertext, true) === false) {
            throw new LegacyDecryptionException(
                'Value is not a well-formed Cryptman v1 token: body is not valid base64.'
            );
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            $this->method,
            LegacyKeyNormalizer::normalize($key),
            0,
            (string) hex2bin($ivHex)
        );

        // CBC reports a padding failure here. CTR cannot fail at all, which is
        // what the guard below exists for.
        if ($plaintext === false) {
            throw new LegacyDecryptionException(sprintf(
                'Could not decrypt Cryptman v1 value using method "%s". The legacy method or '
                .'key is probably wrong. Do NOT re-encrypt this value until that is resolved.',
                $this->method
            ));
        }

        if ($this->strict && ! mb_check_encoding($plaintext, 'UTF-8')) {
            throw new LegacyDecryptionException(sprintf(
                'Cryptman v1 value decrypted to non-UTF-8 bytes using method "%s", which usually '
                .'means the legacy method is wrong — a stream cipher returns garbage rather than '
                .'failing. Do NOT re-encrypt this value. If the plaintext really is binary, set '
                .'legacy.strict => false.',
                $this->method
            ));
        }

        return $plaintext;
    }
}
