<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console;

/**
 * Environment reads, overridable.
 *
 * The override array exists so tests never call putenv() -- that mutates
 * process state for the whole suite and is commonly listed in disable_functions.
 */
final class Environment
{
    /** @param array<string,string>|null $overrides */
    public function __construct(private readonly ?array $overrides = null) {}

    /**
     * An empty value counts as absent.
     *
     * `CRYPTMAN_KEY=` in a compose file or a CI settings page yields '', which
     * is a configuration mistake rather than an intentional empty key. Treating
     * it as unset lets the caller produce an error naming the variable, which
     * is more useful than the library's "no key supplied".
     */
    public function get(string $name): ?string
    {
        if ($this->overrides !== null) {
            $value = $this->overrides[$name] ?? '';

            return trim($value) === '' ? null : $value;
        }

        $value = getenv($name);

        if ($value === false) {
            // getenv() reads the real process environment regardless of
            // variables_order; $_SERVER is the fallback for SAPIs that populate
            // it separately. $_ENV is deliberately not consulted -- it is empty
            // under the common variables_order=GPCS.
            $fromServer = $_SERVER[$name] ?? null;
            $value = is_string($fromServer) ? $fromServer : '';
        }

        return trim($value) === '' ? null : $value;
    }

    /** @return list<string> */
    public function list(string $name): array
    {
        $value = $this->get($name);

        if ($value === null) {
            return [];
        }

        return array_values(array_filter(
            array_map(trim(...), explode(',', $value)),
            static fn (string $item): bool => $item !== ''
        ));
    }
}
