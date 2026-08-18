<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use RuntimeException;

/**
 * The requested algorithm cannot be used in this environment.
 *
 * Two cases:
 *
 *   - encryption was requested with no explicit `method` and ext-sodium is
 *     unavailable. Cryptman does NOT silently fall back to AES (PRD §35.1);
 *     the message names both remedies — install ext-sodium, or set
 *     `method => 'aes-256-gcm'` deliberately.
 *   - a payload carries an algorithm id this build does not know, which
 *     usually means it was written by a newer Cryptman.
 *
 * Distinct from EnvironmentException: this is fixable by configuration, that
 * one requires rebuilding PHP.
 */
final class UnsupportedDriverException extends RuntimeException implements CryptmanException {}
