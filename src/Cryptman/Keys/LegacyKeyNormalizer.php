<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Keys;

/**
 * ============================================================================
 *  FROZEN COMPATIBILITY CODE — DO NOT "FIX" THIS.
 * ============================================================================
 *
 * This reproduces Cryptman v1's key handling exactly, quirks included. It is
 * NOT a security control and must never be improved, hardened, or tidied. Its
 * only job is to be bit-identical to v1.0.0 forever.
 *
 * Changing anything here silently breaks decryption of every value ever
 * written by Cryptman v1 — the failure is not a crash but wrong plaintext, and
 * under CTR it will not even be detected (see LegacyDecryptionException).
 *
 * v1's implementation, verbatim from src/Cryptman.php at tag v1.0.0:
 *
 *     $this->key = ctype_print($key)
 *         ? openssl_digest($key, 'SHA256', TRUE)
 *         : $key;
 *
 * Three properties of that line matter, and all three are surprising:
 *
 *  1. The digest is UNSALTED and has NO domain separation. That is why v2's
 *     real key derivation (KeyDeriver, HKDF-SHA256) is a completely separate
 *     class. The two must never be interchanged: v2 derivation applied to a
 *     legacy payload produces garbage, and vice versa.
 *
 *  2. The branch is conditional on ctype_print(), so key LENGTH is irrelevant
 *     on the digest branch — every printable key becomes the same 32 bytes
 *     regardless of input length — but decisive on the raw branch, where
 *     OpenSSL silently zero-pads or truncates whatever it receives.
 *
 *  3. ctype_print() is ASCII-only. "café" is NOT printable by its definition,
 *     so an accented passphrase — an entirely ordinary choice — takes the raw
 *     branch. So does an empty string, and so does any key containing a NUL.
 *     This is the single most likely cause of a botched migration.
 *
 * Verified against the frozen 54-fixture corpus in tests/Fixtures, which
 * covers both branches across all four v1 cipher methods.
 *
 * @see \Davmixcool\Cryptman\Keys\KeyDeriver  the v2 path — use that for new data
 * @see tests/Fixtures/README.md
 */
final class LegacyKeyNormalizer
{
    /**
     * Normalize a key exactly as Cryptman v1 did.
     *
     * Returns raw bytes suitable for passing straight to openssl_decrypt().
     * The result is 32 bytes on the digest branch and strlen($key) bytes on
     * the raw branch — including zero bytes for an empty key, which OpenSSL
     * then pads. That is v1's behaviour and it is reproduced deliberately.
     */
    public static function normalize(string $key): string
    {
        if (ctype_print($key)) {
            // openssl_digest(..., true) returns raw binary, not hex.
            // The `true` is load-bearing; dropping it doubles the length and
            // changes the key.
            return (string) openssl_digest($key, 'SHA256', true);
        }

        return $key;
    }

    /**
     * Which branch a given key takes.
     *
     * Exposed for diagnostics and for the migration tooling in PRD §44.1 —
     * "your key takes the raw branch" is the single most useful thing to tell
     * someone whose legacy decryption is producing garbage.
     *
     * @return 'digest'|'raw'
     */
    public static function branch(string $key): string
    {
        return ctype_print($key) ? 'digest' : 'raw';
    }
}
