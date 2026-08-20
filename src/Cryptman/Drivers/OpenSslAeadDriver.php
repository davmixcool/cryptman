<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Drivers;

use Davmixcool\Cryptman\Contracts\DriverInterface;
use Davmixcool\Cryptman\Exceptions\DecryptionException;
use Davmixcool\Cryptman\Exceptions\EncryptionException;
use Davmixcool\Cryptman\Exceptions\InvalidKeyException;
use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/**
 * OpenSSL AEAD with a 96-bit nonce and per-message subkeys.
 *
 * Every OpenSSL driver shares exactly one construction:
 *
 *     random 32-byte salt -> HKDF-SHA256(key, salt, info) -> message key
 *     random 96-bit nonce -> AEAD(message key, nonce, header || 0x00 || aad)
 *
 * A 96-bit nonce limits a single key to roughly 2^32 messages under random
 * nonces, and a collision is catastrophic rather than graceful: under GCM it
 * leaks the authentication subkey, under ChaCha20-Poly1305 the Poly1305
 * one-time key. Deriving a fresh key per message removes the bound entirely,
 * so no caller ever has to know a usage ceiling exists.
 *
 * The cost is one HKDF invocation and 32 payload bytes per value. That is what
 * makes these drivers interchangeable with the default from the caller's
 * perspective, and why the default -- which has a 192-bit nonce and needs none
 * of this -- is the cheaper one.
 *
 * @internal
 *
 * Not an extension point. This generalises over ONE named construction, not
 * over "OpenSSL ciphers". A future algorithm with a different nonce size, or
 * without per-message subkeys, gets its own class rather than another abstract
 * hook here.
 */
abstract class OpenSslAeadDriver implements DriverInterface
{
    /** The OpenSSL cipher name, which is also the Cryptman wire name. */
    abstract protected function cipher(): string;

    /** Frozen HKDF domain separator for this algorithm's message keys. */
    abstract protected function messageKeyInfo(): string;

    /**
     * Length of the derived message key.
     *
     * Only AES-128 overrides this. Getting it wrong is invisible to behavioural
     * tests -- see the note in guardKey().
     */
    protected function messageKeyBytes(): int
    {
        return KeyDeriver::KEY_BYTES;
    }

    final public function name(): string
    {
        return $this->cipher();
    }

    /**
     * Cipher availability, memoised for the process.
     *
     * openssl_get_cipher_methods() builds an array of ~135 strings and costs
     * around 30 microseconds. isAvailable() is on the per-operation path --
     * Cryptman::decrypt() calls it for every payload -- so rebuilding that
     * array each time made decryption roughly ten times slower than encryption
     * for the OpenSSL methods, entirely in bookkeeping.
     *
     * Caching is safe because the set cannot change within a process: PHP
     * offers no way to load an OpenSSL provider at runtime.
     *
     * @var array<string,bool>|null
     */
    private static ?array $available = null;

    final public function isAvailable(): bool
    {
        if (self::$available === null) {
            if (! extension_loaded('openssl')) {
                self::$available = [];
            } else {
                self::$available = array_fill_keys(openssl_get_cipher_methods(), true);
            }
        }

        return self::$available[$this->cipher()] ?? false;
    }

    final public function encrypt(
        string $plaintext,
        string $key,
        ?string $associatedData = null,
        ?string $keyId = null
    ): EncryptedPayload {
        $this->guardKey($key);

        $salt = KeyDeriver::generateMessageSalt();
        $messageKey = $this->deriveMessageKey($key, $salt);
        $nonce = random_bytes(EncryptedPayload::nonceBytes($this->algorithmId()));

        $header = new EncryptedPayload(
            algorithmId: $this->algorithmId(),
            nonce: $nonce,
            ciphertext: '',
            salt: $salt,
            keyId: $keyId,
        );

        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            $this->cipher(),
            $messageKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $header->associatedData($associatedData),
            EncryptedPayload::TAG_BYTES
        );

        if ($ciphertext === false) {
            throw new EncryptionException(sprintf('%s encryption failed.', $this->name()));
        }

        // The tag is appended so the frame layout matches libsodium's, which
        // returns ciphertext and tag as one buffer.
        return new EncryptedPayload(
            algorithmId: $this->algorithmId(),
            nonce: $nonce,
            ciphertext: $ciphertext.$tag,
            salt: $salt,
            keyId: $keyId,
        );
    }

    final public function decrypt(EncryptedPayload $payload, string $key, ?string $associatedData = null): string
    {
        $this->guardKey($key);

        // ---------------------------------------------------------------
        //  ORDERING IS LOAD-BEARING.
        // ---------------------------------------------------------------
        // openssl_encrypt/decrypt raise a PHP WARNING for a bad nonce length
        // ("Setting of IV length for AEAD mode failed") and return false.
        // phpunit.xml sets failOnWarning="true", so reaching OpenSSL with an
        // unvalidated nonce turns a tamper test into a suite failure instead of
        // a clean exception. Every geometry guard runs BEFORE the call.

        if (strlen($payload->salt) !== EncryptedPayload::saltBytes($this->algorithmId())) {
            throw new DecryptionException('Payload salt has the wrong length.');
        }

        if (strlen($payload->nonce) !== EncryptedPayload::nonceBytes($this->algorithmId())) {
            throw new DecryptionException('Payload nonce has the wrong length.');
        }

        if (strlen($payload->ciphertext) < EncryptedPayload::TAG_BYTES) {
            throw new DecryptionException('Payload is too short to contain an authentication tag.');
        }

        $ciphertext = substr($payload->ciphertext, 0, -EncryptedPayload::TAG_BYTES);
        $tag = substr($payload->ciphertext, -EncryptedPayload::TAG_BYTES);

        $plaintext = openssl_decrypt(
            $ciphertext,
            $this->cipher(),
            $this->deriveMessageKey($key, $payload->salt),
            OPENSSL_RAW_DATA,
            $payload->nonce,
            $tag,
            $payload->associatedData($associatedData)
        );

        if ($plaintext === false) {
            // Whether the cause was tampering, a wrong key, or wrong associated
            // data is deliberately not reported -- distinguishing them would
            // tell an attacker whether a guess was getting closer.
            throw new DecryptionException(
                'Payload failed authentication: it was modified, encrypted under a different '
                .'key, or bound to different associated data.'
            );
        }

        return $plaintext;
    }

    private function deriveMessageKey(string $key, string $salt): string
    {
        return KeyDeriver::deriveMessageKey(
            $key,
            $salt,
            $this->messageKeyInfo(),
            $this->messageKeyBytes()
        );
    }

    /**
     * Validate the INPUT key, which is always 32 bytes for every driver.
     *
     * Note this checks KeyDeriver::KEY_BYTES, NOT messageKeyBytes(). The input
     * key is the caller's derived key material and is method-independent; the
     * message key is derived from it internally. Confusing the two is easy and
     * consequential: PHP's openssl_encrypt SILENTLY TRUNCATES an over-long key
     * with no warning, so an aes-128 driver handed 32 bytes would round-trip
     * perfectly and hide the mistake from every behavioural test.
     */
    private function guardKey(string $key): void
    {
        if (strlen($key) !== KeyDeriver::KEY_BYTES) {
            throw new InvalidKeyException(sprintf(
                '%s requires a %d-byte key, got %d.',
                strtoupper($this->name()),
                KeyDeriver::KEY_BYTES,
                strlen($key)
            ));
        }
    }
}
