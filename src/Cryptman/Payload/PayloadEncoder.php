<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Payload;

use Davmixcool\Cryptman\Keys\KeyGenerator;

/**
 * Serialises an EncryptedPayload to its wire form (PRD §13.1, §14).
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

        return EncryptedPayload::PREFIX.KeyGenerator::base64UrlEncode($frame);
    }
}
