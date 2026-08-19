<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console;

/**
 * The three standard streams, injected rather than assumed.
 *
 * Commands never touch the STDOUT/STDERR constants directly. Two reasons: those
 * constants are undefined outside the CLI SAPI (an undefined-constant warning
 * would fail the suite under phpunit.xml's failOnWarning), and injecting them
 * is what lets every command be asserted against in-memory buffers instead of
 * being shelled out.
 *
 * The house discipline, from tools/generate-v1-corpus.php, with one refinement:
 * STDOUT carries the primary ARTIFACT, STDERR carries narration. For a filter
 * like `upgrade` that distinction matters more than "success vs failure" --
 * a summary printed to STDOUT would corrupt the payload stream it describes.
 */
final class Streams
{
    /** @var resource */
    private $in;

    /** @var resource */
    private $out;

    /** @var resource */
    private $err;

    /**
     * @param  resource  $in
     * @param  resource  $out
     * @param  resource  $err
     */
    public function __construct($in, $out, $err)
    {
        $this->in = $in;
        $this->out = $out;
        $this->err = $err;
    }

    public static function standard(): self
    {
        return new self(STDIN, STDOUT, STDERR);
    }

    /** In-memory streams, for tests. */
    public static function inMemory(string $stdin = ''): self
    {
        $make = static function (string $contents = '') {
            $handle = fopen('php://memory', 'r+');

            if ($handle === false) {
                throw new \RuntimeException('Could not open an in-memory stream.');
            }

            if ($contents !== '') {
                fwrite($handle, $contents);
                rewind($handle);
            }

            return $handle;
        };

        return new self($make($stdin), $make(), $make());
    }

    /** @return resource */
    public function stdin()
    {
        return $this->in;
    }

    /** @return resource */
    public function stdout()
    {
        return $this->out;
    }

    /** Write to the artifact stream. */
    public function line(string $text): void
    {
        $this->write($this->out, $text);
    }

    /** Write narration: progress, warnings, failures, summaries. */
    public function error(string $text): void
    {
        $this->write($this->err, $text);
    }

    /**
     * Whether a human is watching.
     *
     * Used to suppress headers and progress when output is redirected, so a
     * script never has to parse around decoration it did not ask for.
     */
    public function isInteractive(): bool
    {
        if (! function_exists('posix_isatty')) {
            return false;
        }

        // posix_isatty() raises a warning for anything that is not a real
        // STDIO stream -- php://memory included -- so check the type first
        // rather than suppressing after the fact. Under a custom error handler
        // the @ operator does not help, and a warning here would pollute the
        // very stream this method exists to keep clean.
        return stream_get_meta_data($this->out)['stream_type'] === 'STDIO'
            && posix_isatty($this->out);
    }

    /**
     * Read back what was written -- tests only.
     *
     * @return array{out:string,err:string}
     */
    public function captured(): array
    {
        return ['out' => $this->contents($this->out), 'err' => $this->contents($this->err)];
    }

    /** @param resource $handle */
    private function write($handle, string $text): void
    {
        $written = fwrite($handle, $text);

        // A short write means a full disk. Silently truncating a migration
        // artifact is the worst outcome this tool can produce, so it is fatal.
        if ($written === false || $written !== strlen($text)) {
            throw new \RuntimeException('Could not write to output stream (disk full?).');
        }
    }

    /** @param resource $handle */
    private function contents($handle): string
    {
        $position = ftell($handle);
        rewind($handle);
        $contents = stream_get_contents($handle);

        if ($position !== false) {
            fseek($handle, $position);
        }

        return $contents === false ? '' : $contents;
    }
}
