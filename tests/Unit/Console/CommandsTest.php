<?php

declare(strict_types=1);

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Console\Application;
use Davmixcool\Cryptman\Console\Environment;
use Davmixcool\Cryptman\Console\ExitCode;
use Davmixcool\Cryptman\Console\Streams;
use Davmixcool\Cryptman\Keys\Key;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

/**
 * Runs the CLI entirely in-process.
 *
 * Possible because exit() lives only in bin/cryptman and streams are injected;
 * Environment takes an override array so nothing here calls putenv(), which
 * would mutate process state for the whole suite.
 *
 * @param  array<string,string>  $env
 * @return array{code:int,out:string,err:string}
 */
function cli(array $argv, array $env = [], string $stdin = ''): array
{
    $streams = Streams::inMemory($stdin);
    $code = (new Application($streams, new Environment($env)))->run(['bin/cryptman', ...$argv]);

    return ['code' => $code] + $streams->captured();
}

const LEGACY_KEY = 'correct horse battery staple';

function v1Token(string $plaintext, string $method = 'aes-128-ctr'): string
{
    $iv = random_bytes((int) openssl_cipher_iv_length($method));

    return bin2hex($iv).openssl_encrypt(
        $plaintext, $method, (string) openssl_digest(LEGACY_KEY, 'SHA256', true), 0, $iv
    );
}

describe('application', function () {
    it('prints usage for --help on stdout, exit 0', function () {
        $r = cli(['--help']);

        expect($r['code'])->toBe(ExitCode::OK)
            ->and($r['out'])->toContain('key:generate')
            ->and($r['err'])->toBe('');
    });

    it('prints usage to stderr and exits 2 with no command', function () {
        $r = cli([]);

        expect($r['code'])->toBe(ExitCode::USAGE)->and($r['err'])->toContain('USAGE');
    });

    it('names an unknown command', function () {
        $r = cli(['frobnicate']);

        expect($r['code'])->toBe(ExitCode::USAGE)
            ->and($r['err'])->toContain('frobnicate')
            ->and($r['err'])->toContain('key:generate');
    });

    it('never prints a stack trace', function () {
        // Library messages are contractually free of key material; traces are
        // not, because arguments appear in them.
        $r = cli(['upgrade', '--in=/nonexistent/path']);

        expect($r['err'])->toContain('FAILED: ')
            ->and($r['err'])->not->toContain('#0 ')
            ->and($r['err'])->not->toContain('.php(');
    });
});

describe('key:generate', function () {
    it('prints a usable key on stdout and nothing else', function () {
        $r = cli(['key:generate']);

        expect($r['code'])->toBe(ExitCode::OK)
            ->and($r['err'])->toBe('')
            ->and($r['out'])->toMatch('/^cman_key_[A-Za-z0-9_-]+\n$/');

        // Tie the output to the library's own acceptance rule rather than to a
        // regex that could drift away from it.
        expect(fn () => Key::fromUserInput(trim($r['out'])))->not->toThrow(Exception::class);
    });

    it('reads no environment at all', function () {
        expect(cli(['key:generate'], [])['code'])->toBe(ExitCode::OK);
    });

    it('differs every time', function () {
        expect(cli(['key:generate'])['out'])->not->toBe(cli(['key:generate'])['out']);
    });

    it('prints a key id instead of a key with --id', function () {
        $r = cli(['key:generate', '--id']);

        expect($r['code'])->toBe(ExitCode::OK)
            ->and($r['err'])->toBe('')
            // "Instead of", not "as well as": one value on stdout is what keeps
            // this safe inside a shell substitution.
            ->and($r['out'])->not->toContain('cman_key_')
            ->and(EncryptedPayload::isValidKeyId(trim($r['out'])))->toBeTrue();
    });

    it('generates a distinct id every time', function () {
        expect(cli(['key:generate', '--id'])['out'])
            ->not->toBe(cli(['key:generate', '--id'])['out']);
    });
});

describe('inspect', function () {
    it('describes a v2 payload with no key configured', function () {
        $payload = (new Cryptman(['key' => 'k']))->encrypt('x');
        $r = cli(['inspect', $payload]);

        expect($r['code'])->toBe(ExitCode::OK)
            ->and($r['out'])->toBe("2\txchacha20-poly1305\t-\tno\tok\n");
    });

    it('reports the key id of a keyed payload', function () {
        // The operator-facing half of key ids: answering "which key wrote
        // this?" without holding any key material.
        $payload = (new Cryptman(['key' => 'k', 'key_id' => 'ck_alpha']))->encrypt('x');
        $r = cli(['inspect', $payload]);

        expect($r['code'])->toBe(ExitCode::OK)
            ->and($r['out'])->toBe("2\txchacha20-poly1305\tck_alpha\tno\tok\n");
    });

    it('describes a v1 token', function () {
        $r = cli(['inspect', v1Token('legacy')]);

        expect($r['code'])->toBe(ExitCode::OK)->and($r['out'])->toBe("1\t-\t-\tyes\tok\n");
    });

    it('reads payloads from stdin, one per line', function () {
        $c = new Cryptman(['key' => 'k']);
        $r = cli(['inspect'], [], $c->encrypt('a')."\n".v1Token('b')."\n");

        expect($r['code'])->toBe(ExitCode::OK)
            ->and(substr_count($r['out'], "\n"))->toBe(2);
    });

    it('does not call a key a v1 payload', function () {
        // describe() reports "version 1" for anything without the cman2.
        // prefix. For a human who pasted the wrong string that reads as
        // "needs upgrading" and invites running upgrade on it.
        $r = cli(['inspect', Cryptman::generateKey()]);

        expect($r['code'])->toBe(ExitCode::FAILURE)
            ->and($r['out'])->toContain('unrecognised');
    });

    it('separates malformed from unsupported', function () {
        $malformed = cli(['inspect', 'cman2.!!!']);
        // A well-formed frame declaring a future format version.
        $future = 'cman2.'.rtrim(strtr(base64_encode("\x63\x01".random_bytes(40)), '+/', '-_'), '=');
        $unsupported = cli(['inspect', $future]);

        expect($malformed['out'])->toContain('malformed')
            ->and($unsupported['out'])->toContain('unsupported');
    });
});
