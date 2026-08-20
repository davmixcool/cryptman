<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Payload;

use Davmixcool\Cryptman\Exceptions\InvalidPayloadException;
use Davmixcool\Cryptman\Exceptions\UnsupportedVersionException;
use Davmixcool\Cryptman\Keys\KeyGenerator;

/**
 * Parses a Cryptman v2 payload from its wire form.
 *
 * Everything here operates on untrusted input, so the contract is strict: any
 * malformed value produces an exception and never a crash, an uninitialised
 * read, or a partially decoded frame. No plaintext is revealed by
 * any failure path, because no decryption has happened yet.
 *
 * Field lengths are implied by the algorithm id rather than encoded, which
 * removes a whole class of length-confusion bugs: there is no attacker-supplied
 * length to disagree with the actual data.
 */
final class PayloadDecoder
{
    /** Whether a value looks like a Cryptman v2 payload, without decoding it. */
    public function looksLikeV2(string $payload): bool
    {
        return str_starts_with($payload, EncryptedPayload::PREFIX);
    }

    public function decode(string $payload): EncryptedPayload
    {
        if ($payload === '') {
            throw new InvalidPayloadException('Payload is empty.');
        }

        if (! $this->looksLikeV2($payload)) {
            throw new InvalidPayloadException(sprintf(
                'Payload does not carry the "%s" prefix.',
                EncryptedPayload::PREFIX
            ));
        }

        $body = substr($payload, strlen(EncryptedPayload::PREFIX));

        // Base64url emits no ".", so the separator count alone distinguishes a
        // keyed payload from an unkeyed one with no ambiguity and no lookahead.
        $keyId = null;

        if (str_contains($body, '.')) {
            [$keyId, $body] = explode('.', $body, 2);

            // Validated before it is used for anything. This is attacker-
            // controlled text that will be echoed back by inspect() and used
            // to select a key, so a hostile id must be rejected outright
            // rather than carried around and sanitised at each use.
            if (! EncryptedPayload::isValidKeyId($keyId)) {
                throw new InvalidPayloadException(sprintf(
                    'Payload carries a malformed key id. Expected 1-%d characters '
                    .'matching [A-Za-z0-9_-].',
                    EncryptedPayload::KEY_ID_MAX_BYTES
                ));
            }

            // A second separator means the remaining body still holds one, and
            // base64url cannot. Caught here rather than as "not valid base64url",
            // which would misdescribe the cause.
            if (str_contains($body, '.')) {
                throw new InvalidPayloadException('Payload carries more than one key id separator.');
            }
        }

        $frame = KeyGenerator::base64UrlDecode($body);

        if ($frame === null) {
            throw new InvalidPayloadException('Payload body is not valid base64url.');
        }

        if (strlen($frame) < EncryptedPayload::HEADER_BYTES) {
            throw new InvalidPayloadException('Payload is truncated: no header.');
        }

        $version = ord($frame[0]);
        $algorithmId = ord($frame[1]);

        // Version is checked before algorithm: a future format may reuse
        // algorithm ids with different meanings, so reporting "unknown
        // algorithm" for a cman3 frame would be misleading.
        if ($version !== EncryptedPayload::FORMAT_VERSION) {
            throw new UnsupportedVersionException(sprintf(
                'Payload declares format version 0x%02X, this build supports 0x%02X. '
                .'It may have been written by a newer version of Cryptman.',
                $version,
                EncryptedPayload::FORMAT_VERSION
            ));
        }

        // Throws UnsupportedDriverException for an unknown id.
        $saltBytes = EncryptedPayload::saltBytes($algorithmId);
        $nonceBytes = EncryptedPayload::nonceBytes($algorithmId);

        // Every frame must carry a header, salt, nonce and at least a tag.
        // Ciphertext itself may legitimately be empty — encrypt('') is valid.
        $minimum = EncryptedPayload::HEADER_BYTES + $saltBytes + $nonceBytes + EncryptedPayload::TAG_BYTES;

        if (strlen($frame) < $minimum) {
            throw new InvalidPayloadException(sprintf(
                'Payload is truncated: %s frame needs at least %d bytes, got %d.',
                EncryptedPayload::algorithmName($algorithmId),
                $minimum,
                strlen($frame)
            ));
        }

        $offset = EncryptedPayload::HEADER_BYTES;

        $salt = $saltBytes > 0 ? substr($frame, $offset, $saltBytes) : '';
        $offset += $saltBytes;

        $nonce = substr($frame, $offset, $nonceBytes);
        $offset += $nonceBytes;

        return new EncryptedPayload(
            algorithmId: $algorithmId,
            nonce: $nonce,
            ciphertext: substr($frame, $offset),
            salt: $salt,
            version: $version,
            keyId: $keyId,
        );
    }
}
