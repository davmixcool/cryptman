<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console\Commands;

use Davmixcool\Cryptman\Console\Command;
use Davmixcool\Cryptman\Console\CryptmanFactory;
use Davmixcool\Cryptman\Console\Environment;
use Davmixcool\Cryptman\Console\Exceptions\UsageException;
use Davmixcool\Cryptman\Console\ExitCode;
use Davmixcool\Cryptman\Console\Input;
use Davmixcool\Cryptman\Console\Streams;
use Davmixcool\Cryptman\Exceptions\CryptmanException;
use ReflectionClass;
use RuntimeException;

/**
 * Bulk re-encryption -- PRD §24.1 step 3 and §44.1.
 *
 * Two invariants hold every line of this class together.
 *
 * 1. OUTPUT IS LINE-ALIGNED WITH INPUT, ALWAYS.
 *    Callers zip results back to primary keys by line index, so a row that
 *    fails must still occupy its line. It is written back as its ORIGINAL
 *    ciphertext -- not omitted, not a sentinel -- which makes the write-back a
 *    no-op for failures. A misapplied zip therefore cannot destroy data, and
 *    upgrade() is idempotent, so re-running after fixing config is safe. This
 *    is docs/upgrading.md's "do not re-encrypt a value whose legacy read
 *    failed" implemented as a data-flow property rather than as advice.
 *
 * 2. NOTHING DERIVED FROM PLAINTEXT REACHES ANY STREAM.
 *    Failures are reported by line number and exception class only. No payload
 *    is echoed either: a ciphertext in a CI log is a durable copy of the thing
 *    you were trying to protect.
 */
final class UpgradeCommand implements Command
{
    /** Beyond this, failures are counted but not printed. */
    private const FAILURES_SHOWN = 20;

    public function __construct(private readonly Environment $env) {}

    public function run(Input $input, Streams $streams): int
    {
        $input->rejectSecretOptions();
        $input->validate(
            flags: ['dry-run', 'continue-on-error', 'force', 'skip-v2-check'],
            options: ['in', 'out', 'method', 'legacy-method', 'legacy-strict'],
        );

        $dryRun = $input->flag('dry-run');

        // A dry run always continues. It writes nothing and cannot cause
        // damage, and its entire purpose is to survey the file BEFORE you
        // commit to anything -- stopping at the first bad row would report
        // "1 failure" on a file where every row is broken, which is exactly
        // the misconfiguration it exists to reveal.
        $keepGoing = $dryRun || $input->flag('continue-on-error');
        $cryptman = CryptmanFactory::forUpgrade($this->env, $input);

        $in = $this->openInput($input->option('in'), $streams);
        [$out, $partial, $target] = $dryRun
            ? [null, null, null]
            : $this->openOutput($input->option('in'), $input->option('out'), $input, $streams);

        $counts = ['total' => 0, 'already v2' => 0, 'legacy' => 0,
            'empty' => 0, 'failed' => 0, 'v2 unreadable' => 0];
        $shown = 0;
        /** @var array<string,int> $byClass */
        $byClass = [];
        $aborted = false;

        try {
            while (($line = fgets($in)) !== false) {
                $payload = rtrim($line, "\r\n");
                $counts['total']++;

                if (trim($payload) === '') {
                    $counts['empty']++;
                    $this->emit($out, $payload, $streams, $dryRun);

                    continue;
                }

                $legacy = $cryptman->needsUpgrade($payload);
                $counts[$legacy ? 'legacy' : 'already v2']++;

                try {
                    if ($dryRun) {
                        // A dry run legitimately DECRYPTS. The risk being
                        // managed is writing, not reading, and §44.1's "how
                        // many fail to decrypt" is unobtainable otherwise -- a
                        // run that only counted needsUpgrade() would report
                        // "26,200 legacy / 0 failed" on a completely wrong
                        // legacy method. Plaintext is bound here and nowhere
                        // else, and never leaves this scope.
                        if ($legacy || ! $input->flag('skip-v2-check')) {
                            $cryptman->decrypt($payload);
                        }
                    } else {
                        $this->emit($out, $cryptman->upgrade($payload), $streams, $dryRun);
                    }
                } catch (CryptmanException $e) {
                    $counts[$legacy ? 'failed' : 'v2 unreadable']++;
                    $class = (new ReflectionClass($e))->getShortName();
                    $byClass[$class] = ($byClass[$class] ?? 0) + 1;

                    if ($shown < self::FAILURES_SHOWN) {
                        $shown++;
                        $streams->error(sprintf(
                            "line %d: %s: %s\n", $counts['total'], $class, $e->getMessage()
                        ));
                    }

                    if (! $keepGoing) {
                        $aborted = true;
                        $streams->error(
                            "\nAborted; nothing was written. Fix the configuration and re-run — "
                            ."upgrade() is idempotent, so repeating a partial migration is safe.\n"
                            ."Pass --continue-on-error to process the rest of the file anyway.\n"
                        );

                        return ExitCode::FAILURE;
                    }

                    // Invariant 1: the ORIGINAL, unchanged, on its own line.
                    $this->emit($out, $payload, $streams, $dryRun);
                }
            }

            if ($out !== null && $partial !== null && $target !== null) {
                fclose($out);
                $out = null;

                if (! rename($partial, $target)) {
                    throw new RuntimeException(sprintf('Could not move %s into place.', $partial));
                }

                $partial = null;
            }
        } finally {
            if ($out !== null) {
                fclose($out);
            }

            // Never leave a half-written migration artifact behind: zipped back
            // by line index it would be worse than no file at all.
            if ($partial !== null && is_file($partial)) {
                unlink($partial);
            }

            fclose($in);
        }

        return $this->report($counts, $byClass, $shown, $dryRun, $aborted, $streams);
    }

    /**
     * @param  array<string,int>  $counts
     * @param  array<string,int>  $byClass
     */
    private function report(
        array $counts,
        array $byClass,
        int $shown,
        bool $dryRun,
        bool $aborted,
        Streams $streams
    ): int {
        $failed = $counts['failed'] + $counts['v2 unreadable'];

        if ($shown < $failed) {
            $streams->error(sprintf("… %d further failures suppressed\n", $failed - $shown));

            foreach ($byClass as $class => $n) {
                $streams->error(sprintf("  %-28s %d\n", $class, $n));
            }
        }

        $report = '';

        foreach ($counts as $label => $n) {
            $report .= sprintf("%-14s %d\n", $label, $n);
        }

        // The dry run's report IS its artifact, so it belongs on STDOUT. A real
        // run's summary is narration about a file written elsewhere, so it goes
        // to STDERR and leaves STDOUT a clean payload stream.
        $dryRun ? $streams->line($report) : $streams->error($report);

        if ($counts['v2 unreadable'] > 0) {
            $streams->error(
                "\nSome payloads already in v2 format could not be decrypted. Either CRYPTMAN_KEY "
                .'is wrong for this data, or the column uses associated data, which this command '
                ."cannot supply — pass --skip-v2-check for that case.\n\n"
                .'A real run would pass these rows through untouched without noticing, because '
                ."upgrade() short-circuits on v2. Finding them is what the dry run is for.\n"
            );
        }

        return ($failed > 0 || $aborted) ? ExitCode::FAILURE : ExitCode::OK;
    }

    /** @return resource */
    private function openInput(?string $path, Streams $streams)
    {
        if ($path === null || $path === '-') {
            return $streams->stdin();
        }

        if (! is_file($path) || ! is_readable($path)) {
            throw new UsageException(sprintf('Cannot read --in=%s.', $path));
        }

        $handle = fopen($path, 'r');

        if ($handle === false) {
            throw new UsageException(sprintf('Cannot open --in=%s.', $path));
        }

        return $handle;
    }

    /**
     * @return array{0:resource|null,1:string|null,2:string|null}
     */
    private function openOutput(?string $in, ?string $path, Input $input, Streams $streams): array
    {
        if ($path === null || $path === '-') {
            return [null, null, null];
        }

        // A typo'd --out=payloads.txt would otherwise destroy the input while
        // reading it. Fatal even with --force: there is no version of this that
        // the user meant.
        if ($in !== null && $in !== '-' && is_file($in) && realpath($in) === realpath($path)) {
            throw new UsageException('--out is the same file as --in; that would destroy the input.');
        }

        if (is_file($path) && ! $input->flag('force')) {
            throw new UsageException(sprintf(
                '%s already exists. Pass --force to overwrite it.',
                $path
            ));
        }

        $partial = $path.'.cryptman-partial';
        $handle = fopen($partial, 'w');

        if ($handle === false) {
            throw new UsageException(sprintf('Cannot write to %s.', $partial));
        }

        // Written to a partial and renamed on success, so an interrupted run
        // never leaves a truncated file that looks complete.
        return [$handle, $partial, $path];
    }

    /**
     * Write one output line.
     *
     * $out === null is ambiguous on its own -- it means both "dry run" and
     * "--out=-, write to stdout" -- so $dryRun is passed explicitly. A dry run
     * must write NO payload anywhere; leaking even a blank line would corrupt
     * the report that is its actual artifact.
     *
     * @param  resource|null  $out
     */
    private function emit($out, string $payload, Streams $streams, bool $dryRun): void
    {
        if ($dryRun) {
            return;
        }

        $out === null ? $streams->line($payload."\n") : $this->writeTo($out, $payload."\n");
    }

    /** @param resource $handle */
    private function writeTo($handle, string $text): void
    {
        $written = fwrite($handle, $text);

        if ($written === false || $written !== strlen($text)) {
            throw new RuntimeException('Could not write output (disk full?).');
        }
    }
}
