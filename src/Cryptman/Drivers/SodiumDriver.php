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
 * XChaCha20-Poly1305 via libsodium — the default driver (PRD §7).
 *
 * Chosen for its 24-byte nonce: random nonces are safe essentially without
 * bound, so no per-message key derivation is needed and no usage ceiling has
 * to be tracked. Compare OpenSslAes256GcmDriver, where a 96-bit nonce forces exactly
 * that machinery.
 */
final class SodiumDriver implements DriverInterface
{
    public function name(): string
    {
        return 'xchacha20-poly1305';
    }

    public function algorithmId(): int
    {
        return EncryptedPayload::ALG_XCHACHA20_POLY1305;
    }

    public function isAvailable(): bool
    {
        return extension_loaded('sodium')
            && function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt');
    }

    public function encrypt(string $plaintext, string $key, ?string $associatedData = null): EncryptedPayload
    {
        $this->guardKey($key);

        $nonce = random_bytes(EncryptedPayload::nonceBytes($this->algorithmId()));

        // Built before encrypting so the header is available as associated
        // data — the version and algorithm are authenticated alongside the
        // ciphertext and cannot be altered independently (PRD §13.2).
        $payload = new EncryptedPayload(
            algorithmId: $this->algorithmId(),
            nonce: $nonce,
            ciphertext: '',
        );

        try {
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                $payload->associatedData($associatedData),
                $nonce,
                $key
            );
        } catch (\SodiumException $e) {
            // Message deliberately omits the exception text, which could
            // contain key or plaintext fragments.
            throw new EncryptionException('XChaCha20-Poly1305 encryption failed.', 0, $e);
        }

        return new EncryptedPayload(
            algorithmId: $this->algorithmId(),
            nonce: $nonce,
            ciphertext: $ciphertext,
        );
    }

    public function decrypt(EncryptedPayload $payload, string $key, ?string $associatedData = null): string
    {
        $this->guardKey($key);

        if (strlen($payload->nonce) !== EncryptedPayload::nonceBytes($this->algorithmId())) {
            throw new DecryptionException('Payload nonce has the wrong length.');
        }

        try {
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $payload->ciphertext,
                $payload->associatedData($associatedData),
                $payload->nonce,
                $key
            );
        } catch (\SodiumException $e) {
            throw new DecryptionException('Payload could not be decrypted.', 0, $e);
        }

        if ($plaintext === false) {
            // Authentication failed. Whether the cause was tampering, a wrong
            // key, or wrong associated data is deliberately not reported —
            // distinguishing them would tell an attacker whether a guess was
            // getting closer.
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
                'XChaCha20-Poly1305 requires a %d-byte key, got %d.',
                KeyDeriver::KEY_BYTES,
                strlen($key)
            ));
        }
    }
}
