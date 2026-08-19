<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console;

use Davmixcool\Cryptman\Console\Commands\InspectCommand;
use Davmixcool\Cryptman\Console\Commands\KeyGenerateCommand;
use Davmixcool\Cryptman\Console\Commands\UpgradeCommand;
use Davmixcool\Cryptman\Console\Exceptions\UsageException;
use Throwable;

/**
 * Dispatch, without a framework.
 *
 * The constraint that shapes this class: nothing here may call exit().
 * bin/cryptman owns the only exit() in the package, so main() returns an int
 * and every failure path is a return. That is what makes the whole CLI
 * testable inside a PHPUnit process rather than only by shelling out.
 */
final class Application
{
    public function __construct(
        private readonly Streams $streams,
        private readonly Environment $env,
    ) {}

    /**
     * Called only from bin/cryptman.
     *
     * @param  array<array-key,mixed>  $argv
     */
    public static function main(array $argv): int
    {
        // Under the CLI SAPI display_errors defaults to on and routes to
        // STDOUT. A PHP warning or deprecation would therefore be interleaved
        // into the payload stream and land inside --out=upgraded.txt -- silent
        // corruption of a migration artifact. Redirect before any library code
        // runs; the handler below is the belt to this braces.
        ini_set('display_errors', 'stderr');

        return (new self(Streams::standard(), new Environment()))->run($argv);
    }

    /**
     * @param  array<array-key,mixed>  $argv
     */
    public function run(array $argv): int
    {
        // Cryptman::resolveMethod() calls trigger_error(E_USER_DEPRECATED) when
        // a v1 cipher is passed as `method`. Commands validate before that can
        // happen, but only a handler GUARANTEES no diagnostic reaches stdout.
        set_error_handler(function (int $severity, string $message): bool {
            // Respect suppression. A custom handler is invoked even for
            // expressions written with @, so without this check the handler
            // itself becomes a source of the noise it exists to contain.
            if ((error_reporting() & $severity) === 0) {
                return true;
            }

            $this->streams->error(sprintf("warning: %s\n", $message));

            return true;
        });

        try {
            $input = Input::fromArgv($argv);
            $command = $input->command();

            if ($input->flag('help') || $command === 'help' || $command === null) {
                $wanted = $input->flag('help') || $command === 'help';
                $wanted ? $this->streams->line($this->usage()) : $this->streams->error($this->usage());

                return $wanted ? ExitCode::OK : ExitCode::USAGE;
            }

            return $this->resolve($command)->run($input, $this->streams);
        } catch (UsageException $e) {
            $this->streams->error('FAILED: '.$e->getMessage()."\n");

            return ExitCode::USAGE;
        } catch (Throwable $e) {
            // House format, from tools/generate-v1-corpus.php. No stack trace:
            // library messages are contractually free of key material and
            // plaintext, a trace is not -- arguments appear in PHP traces.
            $this->streams->error('FAILED: '.$e->getMessage()."\n");

            return ExitCode::FAILURE;
        } finally {
            restore_error_handler();
        }
    }

    private function resolve(string $command): Command
    {
        return match ($command) {
            'key:generate' => new KeyGenerateCommand(),
            'inspect' => new InspectCommand(),
            'upgrade' => new UpgradeCommand($this->env),
            default => throw new UsageException(sprintf(
                'Unknown command "%s". Available: key:generate, inspect, upgrade.',
                $command
            )),
        };
    }

    private function usage(): string
    {
        return <<<'TXT'
            cryptman — Cryptman v2 command line tool

            USAGE
                php vendor/bin/cryptman <command> [--option=value]

            COMMANDS
                key:generate    Print a new encryption key
                inspect         Describe payloads without decrypting them
                upgrade         Re-encrypt Cryptman v1 payloads as v2

            KEYS COME FROM THE ENVIRONMENT, NEVER FROM ARGUMENTS
                CRYPTMAN_KEY             primary key                    (upgrade)
                CRYPTMAN_PREVIOUS_KEYS   comma-separated, for rotation  (upgrade)
                CRYPTMAN_LEGACY_KEY      v1 key, defaults to the above  (upgrade)
                CRYPTMAN_METHOD          v2 write method                (upgrade)
                CRYPTMAN_LEGACY_METHOD   v1 cipher                      (upgrade)
                CRYPTMAN_LEGACY_STRICT   true|false                     (upgrade)

            EXIT CODES
                0  success     1  data or runtime failure     2  usage error

            TXT;
    }
}
