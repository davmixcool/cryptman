<?php

declare(strict_types=1);

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Console\ExitCode;

/*
|--------------------------------------------------------------------------
| The one shelled-out test
|--------------------------------------------------------------------------
|
| Everything else runs in-process, because exit() lives only in bin/cryptman
| and streams are injected. This file exists to prove exactly the three things
| that cannot be proved that way:
|
|   1. the autoloader discovery in bin/cryptman actually resolves
|   2. Application::main() is wired to a real process exit status
|   3. the file is a valid PHP entry point at all
|
| Nothing else belongs here. If you are tempted to test behaviour, it belongs
| in tests/Unit/Console/ where it runs a hundred times faster.
|
*/

/**
 * @param  list<string>  $args
 * @param  array<string,string>  $env
 * @return array{code:int,out:string,err:string}
 */
function runBinary(array $args, array $env = [], string $stdin = ''): array
{
    $descriptors = [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']];

    // PHP_BINARY + the script path, not './bin/cryptman'. This keeps the exec
    // bit and the shebang out of the test's reliability, and works on Windows.
    //
    // The env array is passed EXPLICITLY, which replaces the environment
    // wholesale. That is load-bearing: without it a developer's exported
    // CRYPTMAN_KEY would make these pass locally and fail in CI.
    $process = proc_open(
        [PHP_BINARY, dirname(__DIR__, 2).'/bin/cryptman', ...$args],
        $descriptors,
        $pipes,
        null,
        $env
    );

    if (! is_resource($process)) {
        throw new RuntimeException('Could not start the CLI.');
    }

    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);

    // Outputs here are small, so sequential reads cannot deadlock.
    $out = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    return ['code' => proc_close($process), 'out' => $out, 'err' => $err];
}

it('runs as a real process and reports its status', function () {
    $r = runBinary(['--help']);

    expect($r['code'])->toBe(ExitCode::OK)->and($r['out'])->toContain('cryptman');
})->skip(fn () => ! function_exists('proc_open'), 'proc_open unavailable');

it('generates a key end to end', function () {
    $r = runBinary(['key:generate']);

    expect($r['code'])->toBe(ExitCode::OK)
        ->and($r['out'])->toMatch('/^cman_key_[A-Za-z0-9_-]+\n$/')
        ->and($r['err'])->toBe('');
})->skip(fn () => ! function_exists('proc_open'), 'proc_open unavailable');

it('propagates a non-zero exit status', function () {
    // Proves main()'s return value actually reaches the shell, which is the
    // whole contract between Application and bin/cryptman.
    $r = runBinary(['no-such-command']);

    expect($r['code'])->toBe(ExitCode::USAGE);
})->skip(fn () => ! function_exists('proc_open'), 'proc_open unavailable');

it('reads a key from the environment it is given, and only that one', function () {
    $token = (new Cryptman(['key' => 'smoke-test-key']))->encrypt('x');

    $r = runBinary(['upgrade', '--dry-run'], ['CRYPTMAN_KEY' => 'smoke-test-key'], $token."\n");

    expect($r['code'])->toBe(ExitCode::OK)->and($r['out'])->toContain('already v2     1');
})->skip(fn () => ! function_exists('proc_open'), 'proc_open unavailable');
