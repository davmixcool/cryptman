<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use InvalidArgumentException;

/**
 * The constructor options are contradictory or unusable.
 *
 * Raised for, among others:
 *
 *   - a v1 algorithm in `method` together with a conflicting `legacy.method`,
 *     which is ambiguous about what the old data actually used
 *   - an unrecognised `method` value
 *   - a `previous_keys` entry that fails validation
 *
 * Separate from InvalidKeyException because the remedy differs: this one is
 * fixed by changing configuration, not by supplying a valid key.
 */
final class InvalidConfigurationException extends InvalidArgumentException implements CryptmanException {}
