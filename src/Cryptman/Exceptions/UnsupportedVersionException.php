<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use RuntimeException;

/**
 * The payload declares a format version this build cannot read.
 *
 * Typically a value written by a future Cryptman, e.g. a `cman3.` payload
 * reaching a v2 install. Old payloads always remain readable; the
 * reverse is not possible, and failing loudly is the only safe response.
 */
final class UnsupportedVersionException extends RuntimeException implements CryptmanException {}
