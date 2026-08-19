<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console;

use Davmixcool\Cryptman\Console\Exceptions\UsageException;

/**
 * argv, parsed.
 *
 * Grammar, kept deliberately small:
 *
 *     cryptman <command> [--flag] [--option=value] [argument]
 *
 * Long options only, `=` required for values. `--in file` is rejected rather
 * than supported: a space-separated form makes `--in --dry-run` silently
 * consume the next flag as a filename, and this tool writes to files.
 *
 * Unknown flags are REJECTED, unlike tools/generate-v1-corpus.php which
 * silently ignores them. There, a typo means a no-op; here it could mean a
 * --dry-run that was not honoured.
 */
final class Input
{
    /**
     * @param  array<string,string>  $options
     * @param  list<string>  $flags
     * @param  list<string>  $arguments
     */
    private function __construct(
        private readonly ?string $command,
        private readonly array $options,
        private readonly array $flags,
        private readonly array $arguments,
    ) {}

    /**
     * @param  array<array-key,mixed>  $argv  raw $_SERVER['argv'], script name included
     */
    public static function fromArgv(array $argv): self
    {
        $tokens = array_values(array_slice(array_map(
            static fn (mixed $token): string => is_string($token) ? $token : '',
            $argv
        ), 1));

        $command = null;
        $options = [];
        $flags = [];
        $arguments = [];
        $literal = false;

        foreach ($tokens as $token) {
            if ($token === '--') {
                $literal = true;

                continue;
            }

            // '-' is a legitimate value meaning stdin/stdout, never a flag.
            if ($literal || $token === '-' || ! str_starts_with($token, '-')) {
                if ($command === null && ! $literal && $token !== '-') {
                    $command = $token;
                } else {
                    $arguments[] = $token;
                }

                continue;
            }

            if (! str_starts_with($token, '--')) {
                throw new UsageException(sprintf(
                    'Unknown option "%s". Cryptman uses long options only, e.g. --dry-run.',
                    $token
                ));
            }

            $body = substr($token, 2);

            if ($body === '') {
                continue;
            }

            if (! str_contains($body, '=')) {
                $flags[] = $body;

                continue;
            }

            [$name, $value] = explode('=', $body, 2);

            if (array_key_exists($name, $options)) {
                throw new UsageException(sprintf('Option --%s was given more than once.', $name));
            }

            $options[$name] = $value;
        }

        return new self($command, $options, array_values(array_unique($flags)), $arguments);
    }

    public function command(): ?string
    {
        return $this->command;
    }

    public function flag(string $name): bool
    {
        return in_array($name, $this->flags, true);
    }

    public function option(string $name): ?string
    {
        return $this->options[$name] ?? null;
    }

    /** @return list<string> */
    public function arguments(): array
    {
        return $this->arguments;
    }

    /**
     * Reject anything the command does not declare.
     *
     * @param  list<string>  $flags
     * @param  list<string>  $options
     */
    public function validate(array $flags, array $options): void
    {
        foreach ($this->flags as $flag) {
            if ($flag === 'help' || in_array($flag, $flags, true)) {
                continue;
            }

            // A value-bearing option written without '=' lands here, and the
            // generic "unknown flag" message would send the user hunting for a
            // typo that is not there.
            if (in_array($flag, $options, true)) {
                throw new UsageException(sprintf(
                    'Option --%s needs a value: write --%s=VALUE.',
                    $flag,
                    $flag
                ));
            }

            throw new UsageException(sprintf('Unknown option --%s.', $flag));
        }

        foreach (array_keys($this->options) as $option) {
            if (! in_array($option, $options, true)) {
                throw new UsageException(in_array($option, $flags, true)
                    ? sprintf('Option --%s takes no value.', $option)
                    : sprintf('Unknown option --%s.', $option));
            }
        }
    }

    /**
     * Refuse secrets on the command line, loudly and by name.
     *
     * PRD §44.1. Falling through to "unknown option" would be a missed
     * opportunity: someone who reaches for --key and gets a generic error
     * reaches next for a wrapper script that does the same thing worse.
     */
    public function rejectSecretOptions(): void
    {
        foreach (['key', 'legacy-key', 'previous-keys'] as $secret) {
            if ($this->option($secret) === null && ! $this->flag($secret)) {
                continue;
            }

            throw new UsageException(sprintf(
                '--%s is not supported and never will be. Process arguments are visible to '
                .'other users on the host via ps and /proc. Set %s in the environment instead.',
                $secret,
                'CRYPTMAN_'.strtoupper(str_replace('-', '_', $secret))
            ));
        }
    }
}
