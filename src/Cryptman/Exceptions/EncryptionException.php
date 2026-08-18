<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use RuntimeException;

/**
 * Encryption failed.
 *
 * This should be rare — encryption has no untrusted input to reject. It
 * signals that a primitive itself failed, e.g. libsodium or OpenSSL refusing
 * to encrypt.
 *
 * Messages must never include plaintext or key material.
 */
final class EncryptionException extends RuntimeException implements CryptmanException
{
}
