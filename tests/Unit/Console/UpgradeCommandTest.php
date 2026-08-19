<?php

declare(strict_types=1);

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Console\ExitCode;

/** @param list<string> $lines */
function fixtureFile(array $lines): string
{
    $path = tempnam(sys_get_temp_dir(), 'cryptman-cli-');

    if ($path === false) {
        throw new RuntimeException('Could not create a temp file.');
    }

    file_put_contents($path, implode("\n", $lines)."\n");

    return $path;
}

function mixedFixture(int $legacy = 5, int $v2 = 3): string
{
    $cryptman = new Cryptman(['key' => LEGACY_KEY]);
    $lines = [];

    for ($i = 0; $i < $legacy; $i++) {
        $lines[] = v1Token("legacy {$i}");
    }
    for ($i = 0; $i < $v2; $i++) {
        $lines[] = $cryptman->encrypt("v2 {$i}");
    }

    $lines[] = '';

    return fixtureFile($lines);
}

afterEach(function () {
    foreach (glob(sys_get_temp_dir().'/cryptman-cli-*') ?: [] as $leftover) {
        @unlink($leftover);
    }
});

describe('configuration', function () {
    it('demands CRYPTMAN_KEY and names it', function () {
        $r = cli(['upgrade', '--dry-run'], []);

        expect($r['code'])->toBe(ExitCode::USAGE)
            ->and($r['err'])->toContain('CRYPTMAN_KEY')
            // Must not suggest generating one: a fresh key makes every v2 row
            // in the file unreadable.
            ->and($r['err'])->not->toContain('key:generate');
    });

    it('rejects a v1 cipher in --method and points at the right flag', function () {
        $r = cli(['upgrade', '--dry-run', '--method=aes-256-cbc'], ['CRYPTMAN_KEY' => 'k']);

        expect($r['code'])->toBe(ExitCode::USAGE)
            ->and($r['err'])->toContain('--legacy-method');
    });

    it('converts --legacy-strict from a string, and rejects nonsense', function () {
        $file = mixedFixture();

        expect(cli(['upgrade', '--dry-run', "--in={$file}", '--legacy-strict=false'],
            ['CRYPTMAN_KEY' => LEGACY_KEY])['code'])->toBe(ExitCode::OK)
            ->and(cli(['upgrade', '--dry-run', "--in={$file}", '--legacy-strict=maybe'],
                ['CRYPTMAN_KEY' => LEGACY_KEY])['code'])->toBe(ExitCode::USAGE);
    });
});

describe('dry run', function () {
    it('reports counts on stdout and writes nothing', function () {
        $file = mixedFixture(legacy: 5, v2: 3);
        $before = file_get_contents($file);

        $r = cli(['upgrade', '--dry-run', "--in={$file}"], ['CRYPTMAN_KEY' => LEGACY_KEY]);

        expect($r['code'])->toBe(ExitCode::OK)
            ->and($r['out'])->toContain('legacy         5')
            ->and($r['out'])->toContain('already v2     3')
            ->and($r['out'])->toContain('empty          1')
            ->and($r['out'])->toContain('failed         0')
            // Nothing but the report on stdout, and the input untouched.
            ->and($r['out'])->not->toContain('cman2.')
            ->and(file_get_contents($file))->toBe($before);
    });

    it('surveys the whole file rather than stopping at the first failure', function () {
        // A dry run writes nothing and cannot cause damage; stopping early
        // would report "1 failure" on a file where every row is broken.
        $file = mixedFixture(legacy: 6, v2: 0);

        $r = cli(['upgrade', '--dry-run', "--in={$file}", '--legacy-method=aes-256-cbc'],
            ['CRYPTMAN_KEY' => LEGACY_KEY]);

        expect($r['code'])->toBe(ExitCode::FAILURE)->and($r['out'])->toContain('failed         6');
    });

    it('explains unreadable v2 rows', function () {
        $file = mixedFixture(legacy: 0, v2: 4);

        $r = cli(['upgrade', '--dry-run', "--in={$file}"], ['CRYPTMAN_KEY' => 'a-different-key']);

        expect($r['code'])->toBe(ExitCode::FAILURE)
            ->and($r['out'])->toContain('v2 unreadable  4')
            ->and($r['err'])->toContain('--skip-v2-check');
    });

    it('skips the v2 check on request, for associated-data columns', function () {
        $file = mixedFixture(legacy: 0, v2: 4);

        $r = cli(['upgrade', '--dry-run', "--in={$file}", '--skip-v2-check'],
            ['CRYPTMAN_KEY' => 'a-different-key']);

        expect($r['code'])->toBe(ExitCode::OK)->and($r['out'])->toContain('v2 unreadable  0');
    });
});

describe('line alignment', function () {
    it('writes exactly one output line per input line', function () {
        $file = mixedFixture(legacy: 7, v2: 4);
        $out = tempnam(sys_get_temp_dir(), 'cryptman-cli-out-');
        unlink($out);

        $r = cli(['upgrade', "--in={$file}", "--out={$out}"], ['CRYPTMAN_KEY' => LEGACY_KEY]);

        expect($r['code'])->toBe(ExitCode::OK)
            ->and(substr_count((string) file_get_contents($out), "\n"))
            ->toBe(substr_count((string) file_get_contents($file), "\n"));
    });

    it('writes a failed row back UNCHANGED, so a write-back is a no-op', function () {
        // The safety property: callers zip output to primary keys by index, so
        // a failure must still occupy its line -- and it must carry the
        // original ciphertext, or a misapplied zip would destroy the row.
        $file = mixedFixture(legacy: 6, v2: 0);
        $out = tempnam(sys_get_temp_dir(), 'cryptman-cli-out-');
        unlink($out);

        $r = cli(['upgrade', "--in={$file}", "--out={$out}",
            '--legacy-method=aes-256-cbc', '--continue-on-error'], ['CRYPTMAN_KEY' => LEGACY_KEY]);

        expect($r['code'])->toBe(ExitCode::FAILURE)
            ->and(file_get_contents($out))->toBe(file_get_contents($file));
    });
});

describe('file safety', function () {
    it('refuses to overwrite without --force', function () {
        $file = mixedFixture();
        $out = fixtureFile(['existing']);

        expect(cli(['upgrade', "--in={$file}", "--out={$out}"],
            ['CRYPTMAN_KEY' => LEGACY_KEY])['code'])->toBe(ExitCode::USAGE);

        expect(cli(['upgrade', "--in={$file}", "--out={$out}", '--force'],
            ['CRYPTMAN_KEY' => LEGACY_KEY])['code'])->toBe(ExitCode::OK);
    });

    it('refuses --out == --in even with --force', function () {
        // A typo here would destroy the input while reading it. There is no
        // version of this the user meant.
        $file = mixedFixture();

        expect(cli(['upgrade', "--in={$file}", "--out={$file}", '--force'],
            ['CRYPTMAN_KEY' => LEGACY_KEY])['code'])->toBe(ExitCode::USAGE);
    });

    it('leaves no partial file behind when a run aborts', function () {
        $file = mixedFixture(legacy: 4, v2: 0);
        $out = tempnam(sys_get_temp_dir(), 'cryptman-cli-out-');
        unlink($out);

        cli(['upgrade', "--in={$file}", "--out={$out}", '--legacy-method=aes-256-cbc'],
            ['CRYPTMAN_KEY' => LEGACY_KEY]);

        expect(is_file($out.'.cryptman-partial'))->toBeFalse()
            ->and(is_file($out))->toBeFalse();
    });

    it('rejects an unreadable --in', function () {
        expect(cli(['upgrade', '--in=/nonexistent/path'],
            ['CRYPTMAN_KEY' => 'k'])['code'])->toBe(ExitCode::USAGE);
    });
});

describe('reporting', function () {
    it('suppresses failures after the first 20', function () {
        $file = mixedFixture(legacy: 30, v2: 0);

        $r = cli(['upgrade', '--dry-run', "--in={$file}", '--legacy-method=aes-256-cbc'],
            ['CRYPTMAN_KEY' => LEGACY_KEY]);

        expect(substr_count($r['err'], 'LegacyDecryptionException:'))->toBe(20)
            ->and($r['err'])->toContain('further failures suppressed')
            ->and($r['err'])->toContain('LegacyDecryptionException  ');
    });

    it('never leaks plaintext onto any stream', function () {
        // The assertion that stops a future "helpful" error message from
        // regressing PRD 44.1.
        $sentinel = 'SENTINEL-PLAINTEXT-'.bin2hex(random_bytes(8));
        $file = fixtureFile([v1Token($sentinel)]);

        $r = cli(['upgrade', '--dry-run', "--in={$file}"], ['CRYPTMAN_KEY' => LEGACY_KEY]);

        expect($r['out'])->not->toContain($sentinel)
            ->and($r['err'])->not->toContain($sentinel);
    });

    it('never leaks the key onto any stream', function () {
        $file = mixedFixture(legacy: 2, v2: 0);

        $r = cli(['upgrade', '--dry-run', "--in={$file}", '--legacy-method=aes-256-cbc'],
            ['CRYPTMAN_KEY' => LEGACY_KEY]);

        expect($r['out'])->not->toContain(LEGACY_KEY)->and($r['err'])->not->toContain(LEGACY_KEY);
    });
});

it('round-trips through stdin and stdout', function () {
    $cryptman = new Cryptman(['key' => LEGACY_KEY]);
    $stdin = v1Token('via stdin')."\n";

    $r = cli(['upgrade'], ['CRYPTMAN_KEY' => LEGACY_KEY], $stdin);

    expect($r['code'])->toBe(ExitCode::OK)
        ->and($cryptman->decrypt(trim($r['out'])))->toBe('via stdin');
});
