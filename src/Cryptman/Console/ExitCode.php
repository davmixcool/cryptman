<?php

declare(strict_types=1);

namespace Davmixcool\Cryptman\Console;

/**
 * Process exit codes.
 *
 * Three, not two. tools/generate-v1-corpus.php uses 0/1 only, but it has no
 * argument surface -- a command a CI pipeline drives over a production column
 * needs to distinguish "your invocation is wrong" from "your data is wrong",
 * because only one of those is worth retrying.
 */
final class ExitCode
{
    public const OK = 0;

    /** Completed, but rows failed -- or a runtime/IO error. */
    public const FAILURE = 1;

    /** The invocation itself is wrong: unknown flag, missing env, bad path. */
    public const USAGE = 2;
}
