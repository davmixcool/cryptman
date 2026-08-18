<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use RuntimeException;

/**
 * Neither libsodium nor OpenSSL authenticated encryption is available.
 *
 * Cryptman throws rather than falling back to an unauthenticated cipher
 * (PRD §36, §65.4). There is no configuration that resolves this — the PHP
 * build itself lacks the primitives — which is why it is separate from
 * UnsupportedDriverException.
 */
final class EnvironmentException extends RuntimeException implements CryptmanException {}
