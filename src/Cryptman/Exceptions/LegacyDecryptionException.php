<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

/**
 * Decryption of a Cryptman v1 payload failed, or produced output that does not
 * look like plaintext.
 *
 * Extends DecryptionException so callers who only care that a value did not
 * decrypt can catch the parent, while migration tooling can distinguish the
 * legacy case — which usually means `legacy.method` is wrong, not that the data
 * is bad.
 *
 * That distinction matters operationally: on this exception the correct
 * response is to STOP and fix configuration, never to re-encrypt the row.
 * Rewriting on a failed legacy decrypt is how recoverable data becomes
 * unrecoverable.
 *
 * Note that the UTF-8 guard which raises this is a usability backstop, not
 * authentication. v1 ciphertext is unauthenticated; the guard reduces the
 * probability of an undetected misread (measured ~0.02% false negatives on
 * short values) but cannot eliminate it.
 */
final class LegacyDecryptionException extends DecryptionException {}
