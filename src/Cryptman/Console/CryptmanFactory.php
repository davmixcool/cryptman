<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console;

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Console\Exceptions\UsageException;

/**
 * Environment + flags -> a configured Cryptman.
 *
 * Everything secret comes from the environment; everything else may be a flag,
 * with flag > env > library default.
 */
final class CryptmanFactory
{
    public static function forUpgrade(Environment $env, Input $input): Cryptman
    {
        $key = $env->get('CRYPTMAN_KEY');

        if ($key === null) {
            throw new UsageException(
                "CRYPTMAN_KEY is not set.\n\n"
                ."Cryptman never accepts a key as a command-line argument: process arguments\n"
                ."are visible to every user on the host via ps and /proc.\n\n"
                ."    export CRYPTMAN_KEY='cman_key_...'\n"
                ."    php vendor/bin/cryptman upgrade --dry-run --in=payloads.txt\n\n"
                .'Use the key this data was encrypted with. Generating a fresh one would make '
                .'every v2 row in the file unreadable.'
            );
        }

        $options = ['key' => $key, 'previous_keys' => $env->list('CRYPTMAN_PREVIOUS_KEYS')];

        $method = $input->option('method') ?? $env->get('CRYPTMAN_METHOD');

        if ($method !== null) {
            // Validate here rather than letting Cryptman infer. A v1 cipher in
            // `method` is valid library input -- it is read as legacy config --
            // but it fires trigger_error(E_USER_DEPRECATED), and on a CLI that
            // is a diagnostic the user did not ask for during a bulk job. Say
            // it plainly instead, and point at the flag that means it.
            if (! in_array($method, Cryptman::supportedMethods(), true)) {
                throw new UsageException(sprintf(
                    'Unknown --method "%s". Supported: %s.%s',
                    $method,
                    implode(', ', Cryptman::supportedMethods()),
                    in_array(strtolower($method), openssl_get_cipher_methods(), true)
                        ? ' That looks like a Cryptman v1 cipher — pass it as --legacy-method instead.'
                        : ''
                ));
            }

            $options['method'] = $method;
        }

        $legacy = array_filter([
            'key' => $env->get('CRYPTMAN_LEGACY_KEY'),
            'method' => $input->option('legacy-method') ?? $env->get('CRYPTMAN_LEGACY_METHOD'),
        ], static fn (?string $value): bool => $value !== null);

        $strict = $input->option('legacy-strict') ?? $env->get('CRYPTMAN_LEGACY_STRICT');

        if ($strict !== null) {
            // The library takes a real bool and rejects strings deliberately,
            // so the string->bool conversion belongs here, where the string
            // came from.
            $legacy['strict'] = match (strtolower($strict)) {
                'true', '1', 'yes', 'on' => true,
                'false', '0', 'no', 'off' => false,
                default => throw new UsageException(sprintf(
                    'legacy-strict must be true or false, got "%s".',
                    $strict
                )),
            };
        }

        if ($legacy !== []) {
            $options['legacy'] = $legacy;
        }

        return new Cryptman($options);
    }
}
