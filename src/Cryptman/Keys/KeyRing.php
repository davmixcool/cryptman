<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Keys;

use Davmixcool\Cryptman\Exceptions\InvalidConfigurationException;

/**
 * The current encryption key plus any previous keys still needed for reading.
 *
 * Encryption always uses the current key. Decryption tries the current key
 * first, then each previous key in order (PRD §20).
 *
 * ---------------------------------------------------------------------------
 *  This applies to v2 payloads ONLY.
 * ---------------------------------------------------------------------------
 *
 * Trial decryption is sound only when a wrong key fails unambiguously. AEAD
 * gives that: authentication fails, the driver throws, the next key is tried.
 *
 * v1 payloads have no such property. Their dominant mode is CTR, a stream
 * cipher with no integrity check, where a wrong key returns plaintext-shaped
 * garbage rather than an error — so a key ring cannot tell the right key from
 * the wrong one and would hand back corrupted data as if it had succeeded
 * (PRD §20.1).
 *
 * The legacy path therefore uses a single designated key and never iterates.
 * Nothing in this class is reachable from it.
 */
final class KeyRing
{
    /** @var list<Key> */
    private readonly array $previous;

    /**
     * @param  list<Key>  $previous  older keys, newest first
     */
    public function __construct(
        private readonly Key $current,
        array $previous = []
    ) {
        foreach ($previous as $index => $key) {
            if (! $key instanceof Key) {
                throw new InvalidConfigurationException(sprintf(
                    'previous_keys[%s] must be a %s instance, %s given.',
                    (string) $index,
                    Key::class,
                    get_debug_type($key)
                ));
            }
        }

        $this->previous = array_values($previous);
    }

    /** The key new payloads are encrypted with. */
    public function current(): Key
    {
        return $this->current;
    }

    /**
     * Every key to try when decrypting, current first.
     *
     * @return list<Key>
     */
    public function all(): array
    {
        return [$this->current, ...$this->previous];
    }

    /** @return list<Key> */
    public function previous(): array
    {
        return $this->previous;
    }

    public function count(): int
    {
        return 1 + count($this->previous);
    }

    /** Wipe every key in the ring. */
    public function wipe(): void
    {
        foreach ($this->all() as $key) {
            $key->wipe();
        }
    }

    public function __debugInfo(): array
    {
        return [
            'current' => '[redacted]',
            'previous_count' => count($this->previous),
        ];
    }
}
