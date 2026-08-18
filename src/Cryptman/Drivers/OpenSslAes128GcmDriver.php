<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Drivers;

use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/**
 * AES-128-GCM via OpenSSL.
 *
 * Present for external profiles that mandate AES at 128 bits specifically.
 * There is no reason to prefer it over aes-256-gcm otherwise -- it is not
 * meaningfully faster for payload sizes this library targets, and 128 is not
 * a feature.
 */
final class OpenSslAes128GcmDriver extends OpenSslAeadDriver
{
    public function algorithmId(): int
    {
        return EncryptedPayload::ALG_AES_128_GCM;
    }

    protected function cipher(): string
    {
        return 'aes-128-gcm';
    }

    protected function messageKeyInfo(): string
    {
        return KeyDeriver::INFO_AES_128_MESSAGE;
    }

    /**
     * AES-128 takes a 16-byte key.
     *
     * This MUST be explicit and MUST be correct, because the failure is
     * invisible: PHP's openssl_encrypt silently truncates an over-long key with
     * no warning at all. Handing this driver a 32-byte message key would
     * round-trip perfectly, pass every tamper and interop test, and quietly use
     * the first 16 bytes. The construction-pinning test in AeadDriverTest is
     * the only thing that catches a mistake here.
     */
    protected function messageKeyBytes(): int
    {
        return 16;
    }
}
