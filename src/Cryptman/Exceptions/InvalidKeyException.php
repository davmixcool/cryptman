<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use InvalidArgumentException;

/**
 * The supplied key is missing, empty, or malformed.
 *
 * Unlike Cryptman v1, there is NO default key. v1 fell back to php_uname(),
 * a publicly guessable description of the host, which meant data encrypted
 * without an explicit key was effectively unencrypted (PRD §2.5, §19.1).
 *
 * Also raised when a value carries the `cman_key_` prefix but its body does not
 * decode, or decodes to the wrong length — so that a typo becomes an error
 * rather than a silently different key.
 *
 * Messages must never include the key, or any part of it.
 */
final class InvalidKeyException extends InvalidArgumentException implements CryptmanException {}
