<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Payload;

use Davmixcool\Cryptman\Keys\KeyGenerator;

/**
 * Serialises an EncryptedPayload to its wire form.
 *
 * Base64url rather than standard base64 so payloads are safe in URLs, cookies,
 * query strings and filenames without escaping — no +, / or = characters.
 *
 * @see EncryptedPayload for the frame layout
 * @see PayloadDecoder for the inverse
 */
final class PayloadEncoder
{
    public function encode(EncryptedPayload $payload): string
    {
        $frame = $payload->header()
            .$payload->salt
            .$payload->nonce
            .$payload->ciphertext;

        // Without a key id the output is exactly what pre-2.1.0 produced, so
        // adopting this version does not silently rewrite the shape of values
        // already in a database column.
        $prefix = $payload->keyId === null
            ? EncryptedPayload::PREFIX
            : EncryptedPayload::PREFIX.$payload->keyId.'.';

        return $prefix.KeyGenerator::base64UrlEncode($frame);
    }
}
