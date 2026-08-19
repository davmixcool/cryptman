<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console;

/**
 * One command.
 *
 * Returns an int; never calls exit(). bin/cryptman owns the only exit() in the
 * package, which is what makes every command testable inside a PHPUnit process.
 */
interface Command
{
    public function run(Input $input, Streams $streams): int;
}
