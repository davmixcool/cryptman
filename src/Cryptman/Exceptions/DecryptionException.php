<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use RuntimeException;

/**
 * Decryption failed: the payload was modified, the key is wrong, or both.
 *
 * Cryptman never returns false or corrupted plaintext on failure (PRD §28).
 * Authentication failure and wrong-key failure are deliberately
 * indistinguishable — reporting which one occurred would tell an attacker
 * whether a guessed key was closer.
 *
 * Not final: LegacyDecryptionException extends this so that
 * `catch (DecryptionException $e)` covers both the v2 and legacy paths.
 */
class DecryptionException extends RuntimeException implements CryptmanException
{
}
