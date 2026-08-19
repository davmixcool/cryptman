<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console\Exceptions;

use InvalidArgumentException;

/**
 * The invocation is wrong -- exits 2.
 *
 * Deliberately does NOT implement Davmixcool\Cryptman\Exceptions\CryptmanException.
 * That interface is a documented library contract (see docs/configuration.md);
 * a console concern has no business appearing in that table, and an application
 * catching CryptmanException should never catch a CLI argument error.
 */
final class UsageException extends InvalidArgumentException {}
