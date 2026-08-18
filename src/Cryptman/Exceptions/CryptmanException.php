<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Exceptions;

use Throwable;

/**
 * Root of the Cryptman exception hierarchy.
 *
 * This is an interface rather than a base class so that each concrete
 * exception can extend the SPL type that actually describes it — a bad
 * configuration value is an InvalidArgumentException, a failed decryption is a
 * RuntimeException — while still being catchable as one family:
 *
 *     try {
 *         $plain = $cryptman->decrypt($payload);
 *     } catch (CryptmanException $e) {
 *         // anything this library throws
 *     }
 *
 * Every catch pattern in the PRD still works. `catch (DecryptionException $e)`
 * continues to catch LegacyDecryptionException, because that relationship is
 * real inheritance (see LegacyDecryptionException).
 */
interface CryptmanException extends Throwable
{
}
