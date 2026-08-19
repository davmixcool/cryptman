<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use InvalidArgumentException;

/**
 * The payload is structurally malformed: empty, truncated, not valid
 * base64url, or too short to contain a header, nonce and tag.
 *
 * This is distinct from DecryptionException, which means the payload was
 * well-formed but did not authenticate. The split matters because a malformed
 * payload usually indicates a plumbing bug — a truncated column, a
 * double-encoded value — while a failed authentication indicates tampering or
 * the wrong key.
 *
 * Decoding untrusted input must never crash the process. Any malformed input
 * produces this exception.
 */
final class InvalidPayloadException extends InvalidArgumentException implements CryptmanException {}
