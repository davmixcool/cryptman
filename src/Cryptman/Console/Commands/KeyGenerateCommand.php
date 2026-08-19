<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console\Commands;

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Console\Command;
use Davmixcool\Cryptman\Console\ExitCode;
use Davmixcool\Cryptman\Console\Input;
use Davmixcool\Cryptman\Console\Streams;

/**
 * Print a new encryption key.
 *
 * PRD §44's "primary useful command". Reads no environment and needs no
 * configuration, so it works on a bare host.
 *
 * The key goes to STDOUT and NOTHING else does, so this composes:
 *
 *     export CRYPTMAN_KEY="$(php vendor/bin/cryptman key:generate)"
 *
 * Any human guidance goes to STDERR, and only when someone is watching.
 */
final class KeyGenerateCommand implements Command
{
    public function run(Input $input, Streams $streams): int
    {
        $input->rejectSecretOptions();
        $input->validate(flags: [], options: []);

        $streams->line(Cryptman::generateKey()."\n");

        if ($streams->isInteractive()) {
            $streams->error(
                "\nStore this in your environment as CRYPTMAN_KEY. It cannot be recovered, "
                ."and anything encrypted with it becomes unreadable if it is lost.\n"
            );
        }

        return ExitCode::OK;
    }
}
