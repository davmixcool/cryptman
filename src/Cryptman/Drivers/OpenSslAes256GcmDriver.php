<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Drivers;

use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/**
 * AES-256-GCM via OpenSSL.
 *
 * The AES option for environments where policy or compliance names AES
 * specifically. Functionally interchangeable with the default; costs 20 more
 * payload bytes for the per-message salt.
 */
final class OpenSslAes256GcmDriver extends OpenSslAeadDriver
{
    public function algorithmId(): int
    {
        return EncryptedPayload::ALG_AES_256_GCM;
    }

    protected function cipher(): string
    {
        return 'aes-256-gcm';
    }

    protected function messageKeyInfo(): string
    {
        return KeyDeriver::INFO_AES_MESSAGE;
    }
}
