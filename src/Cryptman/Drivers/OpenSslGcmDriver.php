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
 * AES-256-GCM via OpenSSL, with per-message subkeys (PRD §7).
 *
 * GCM's 96-bit nonce limits a single key to roughly 2^32 messages under random
 * nonces (NIST SP 800-38D). A collision there is catastrophic rather than
 * graceful: it leaks the authentication subkey, not merely one message.
 *
 * So this driver never encrypts directly under the configured key. Each
 * message gets a fresh 32-byte random salt, and the actual AES key is
 * HKDF(configured key, salt). Because every message uses a distinct key,
 * nonce collisions across messages stop mattering and the per-key message
 * bound disappears.
 *
 * The cost is one HKDF invocation and 32 bytes of payload per value. That buys
 * a driver the caller can use interchangeably with the default, with no usage
 * ceiling to know about — which is the product principle in §65 applied
 * literally: "rotate your key before 2^32 writes" is exactly the kind of
 * cryptographic decision a developer should not have to make.
 */
final class OpenSslGcmDriver implements DriverInterface
{
    private const CIPHER = 'aes-256-gcm';

    public function name(): string
    {
        return self::CIPHER;
    }

    public function algorithmId(): int
    {
        return EncryptedPayload::ALG_AES_256_GCM;
    }

    public function isAvailable(): bool
    {
        return extension_loaded('openssl')
            && in_array(self::CIPHER, openssl_get_cipher_methods(), true);
    }

    public function encrypt(string $plaintext, string $key, ?string $associatedData = null): EncryptedPayload
    {
        $this->guardKey($key);

        $salt = KeyDeriver::generateMessageSalt();
        $messageKey = KeyDeriver::deriveMessageKey($key, $salt);
        $nonce = random_bytes(EncryptedPayload::nonceBytes($this->algorithmId()));

        $header = new EncryptedPayload(
            algorithmId: $this->algorithmId(),
            nonce: $nonce,
            ciphertext: '',
            salt: $salt,
        );

        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $messageKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $header->associatedData($associatedData),
            EncryptedPayload::TAG_BYTES
        );

        if ($ciphertext === false) {
            throw new EncryptionException('AES-256-GCM encryption failed.');
        }

        // The tag is appended so the frame layout matches libsodium's, which
        // returns ciphertext and tag as one buffer.
        return new EncryptedPayload(
            algorithmId: $this->algorithmId(),
            nonce: $nonce,
            ciphertext: $ciphertext.$tag,
            salt: $salt,
        );
    }

    public function decrypt(EncryptedPayload $payload, string $key, ?string $associatedData = null): string
    {
        $this->guardKey($key);

        if (strlen($payload->salt) !== EncryptedPayload::SALT_BYTES) {
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

        $messageKey = KeyDeriver::deriveMessageKey($key, $payload->salt);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $messageKey,
            OPENSSL_RAW_DATA,
            $payload->nonce,
            $tag,
            $payload->associatedData($associatedData)
        );

        if ($plaintext === false) {
            throw new DecryptionException(
                'Payload failed authentication: it was modified, encrypted under a different '
                .'key, or bound to different associated data.'
            );
        }

        return $plaintext;
    }

    private function guardKey(string $key): void
    {
        if (strlen($key) !== KeyDeriver::KEY_BYTES) {
            throw new InvalidKeyException(sprintf(
                'AES-256-GCM requires a %d-byte key, got %d.',
                KeyDeriver::KEY_BYTES,
                strlen($key)
            ));
        }
    }
}
