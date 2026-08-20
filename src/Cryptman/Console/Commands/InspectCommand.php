<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console\Commands;

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Console\Command;
use Davmixcool\Cryptman\Console\ExitCode;
use Davmixcool\Cryptman\Console\Input;
use Davmixcool\Cryptman\Console\Streams;
use Davmixcool\Cryptman\Drivers\LegacyDriver;
use Davmixcool\Cryptman\Exceptions\InvalidPayloadException;
use Davmixcool\Cryptman\Exceptions\UnsupportedDriverException;
use Davmixcool\Cryptman\Exceptions\UnsupportedVersionException;

/**
 * Describe payloads without decrypting them.
 *
 *     cryptman inspect "cman2...."        one payload
 *     cryptman inspect < payloads.txt     one per line
 *
 * Reads NO environment and needs no key -- which is the point. This is the
 * command an operator reaches for on a host where nothing is configured, so
 * requiring configuration to run it would defeat its purpose. That is only
 * possible because Cryptman::describe() is static; constructing a Cryptman
 * resolves the default driver and would fail outright without ext-sodium.
 */
final class InspectCommand implements Command
{
    public function run(Input $input, Streams $streams): int
    {
        $input->rejectSecretOptions();
        $input->validate(flags: [], options: []);

        // The header is decoration, so it goes to STDERR and only when a human
        // is watching. A script piping this never has to skip a line.
        if ($streams->isInteractive()) {
            $streams->error("version\tdriver\tkey_id\tneeds_upgrade\tstatus\n");
        }

        $clean = true;

        foreach ($this->payloads($input, $streams) as $payload) {
            if (trim($payload) === '') {
                continue;
            }

            $clean = $this->describe($payload, $streams) && $clean;
        }

        return $clean ? ExitCode::OK : ExitCode::FAILURE;
    }

    private function describe(string $payload, Streams $streams): bool
    {
        try {
            $described = Cryptman::describe($payload);

            // describe() reports "version 1" for anything without the cman2.
            // prefix, because that is what needsUpgrade() means. For a library
            // caller reading a known column that is right. For a human who has
            // pasted the wrong string it is dangerous: "version 1, needs
            // upgrade" invites them to run `upgrade` on something that was
            // never a payload. So check the shape too.
            if ($described['version'] === 1 && ! (new LegacyDriver())->looksLikeLegacy($payload)) {
                return $this->problem(
                    $streams,
                    'unrecognised',
                    'Not a Cryptman payload: no cman2. prefix, and no hexadecimal IV prefix '
                    .'of the shape Cryptman v1 wrote. Check you pasted a stored ciphertext '
                    .'rather than a key or a plaintext.'
                );
            }

            $streams->line(sprintf(
                "%d\t%s\t%s\t%s\tok\n",
                $described['version'],
                $described['driver'] ?? '-',
                $described['key_id'] ?? '-',
                $described['version'] === 1 ? 'yes' : 'no'
            ));

            return true;
        } catch (InvalidPayloadException $e) {
            // Structurally broken: truncated column, double-encoded value.
            return $this->problem($streams, 'malformed', $e->getMessage());
        } catch (UnsupportedVersionException|UnsupportedDriverException $e) {
            // Well-formed but from a newer Cryptman. Conflating this with
            // "malformed" would send an operator hunting for data corruption
            // when the answer is "upgrade the library".
            return $this->problem($streams, 'unsupported', $e->getMessage());
        }
    }

    private function problem(Streams $streams, string $status, string $why): bool
    {
        $streams->line(sprintf("-\t-\t-\t-\t%s\n", $status));
        $streams->error($why."\n");

        return false;
    }

    /** @return iterable<string> */
    private function payloads(Input $input, Streams $streams): iterable
    {
        $arguments = $input->arguments();

        if ($arguments !== []) {
            yield from $arguments;

            return;
        }

        while (($line = fgets($streams->stdin())) !== false) {
            yield rtrim($line, "\r\n");
        }
    }
}
