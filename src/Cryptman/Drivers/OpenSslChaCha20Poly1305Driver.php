<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Drivers;

use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/**
 * ChaCha20-Poly1305 (RFC 8439) via OpenSSL.
 *
 * NOT the same algorithm as the default xchacha20-poly1305, despite the names
 * differing by one letter:
 *
 *     xchacha20-poly1305   libsodium   192-bit nonce   algorithm id 0x01
 *     chacha20-poly1305    OpenSSL      96-bit nonce   algorithm id 0x04
 *
 * They are not interchangeable on the wire and a payload written by one cannot
 * be read by the other.
 *
 * Worth choosing when ChaCha20 is wanted but ext-sodium is unavailable, when
 * the host lacks AES-NI (where ChaCha20 outruns AES), or for interoperability
 * with another language: RFC 8439 is in most standard libraries, whereas
 * XChaCha20 generally requires libsodium.
 */
final class OpenSslChaCha20Poly1305Driver extends OpenSslAeadDriver
{
    public function algorithmId(): int
    {
        return EncryptedPayload::ALG_CHACHA20_POLY1305;
    }

    protected function cipher(): string
    {
        return 'chacha20-poly1305';
    }

    protected function messageKeyInfo(): string
    {
        return KeyDeriver::INFO_CHACHA20_MESSAGE;
    }
}
