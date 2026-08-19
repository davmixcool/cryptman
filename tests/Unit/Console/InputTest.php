<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Console\Exceptions\UsageException;
use Davmixcool\Cryptman\Console\Input;

function parse(string ...$tokens): Input
{
    return Input::fromArgv(['bin/cryptman', ...$tokens]);
}

it('reads the command', function () {
    expect(parse('upgrade')->command())->toBe('upgrade')
        ->and(parse()->command())->toBeNull();
});

it('reads flags and options', function () {
    $input = parse('upgrade', '--dry-run', '--in=payloads.txt');

    expect($input->flag('dry-run'))->toBeTrue()
        ->and($input->flag('force'))->toBeFalse()
        ->and($input->option('in'))->toBe('payloads.txt')
        ->and($input->option('out'))->toBeNull();
});

it('treats - as a value, never a flag', function () {
    // '-' means stdin/stdout. Parsing it as a malformed short option would
    // break `cryptman upgrade --in=- < file`.
    expect(parse('upgrade', '--in=-')->option('in'))->toBe('-')
        ->and(parse('inspect', '-')->arguments())->toBe(['-']);
});

it('stops parsing at --', function () {
    expect(parse('inspect', '--', '--not-a-flag')->arguments())->toBe(['--not-a-flag']);
});

it('keeps an = sign inside a value', function () {
    expect(parse('upgrade', '--in=a=b.txt')->option('in'))->toBe('a=b.txt');
});

it('rejects short options', function () {
    expect(fn () => parse('upgrade', '-x'))->toThrow(UsageException::class);
});

it('rejects a repeated option', function () {
    expect(fn () => parse('upgrade', '--in=a', '--in=b'))->toThrow(UsageException::class);
});

describe('validate()', function () {
    it('rejects an unknown flag', function () {
        expect(fn () => parse('upgrade', '--nonsense')->validate(flags: ['dry-run'], options: []))
            ->toThrow(UsageException::class);
    });

    it('rejects an unknown option', function () {
        expect(fn () => parse('upgrade', '--nope=1')->validate(flags: [], options: ['in']))
            ->toThrow(UsageException::class);
    });

    it('says a value-bearing option needs a value, rather than "unknown"', function () {
        // --in written without '=' would otherwise be reported as an unknown
        // flag, sending the user hunting for a typo that is not there.
        try {
            parse('upgrade', '--in')->validate(flags: [], options: ['in']);
            $this->fail('expected UsageException');
        } catch (UsageException $e) {
            expect($e->getMessage())->toContain('needs a value');
        }
    });

    it('says a flag takes no value', function () {
        try {
            parse('upgrade', '--dry-run=1')->validate(flags: ['dry-run'], options: []);
            $this->fail('expected UsageException');
        } catch (UsageException $e) {
            expect($e->getMessage())->toContain('takes no value');
        }
    });

    it('always allows --help', function () {
        expect(fn () => parse('upgrade', '--help')->validate(flags: [], options: []))->not->toThrow(UsageException::class);
    });
});

describe('secrets are refused by name', function () {
    it('rejects --key, --legacy-key and --previous-keys', function (string $option) {
        expect(fn () => parse('upgrade', "--{$option}=secret")->rejectSecretOptions())
            ->toThrow(UsageException::class);
    })->with(['key', 'legacy-key', 'previous-keys']);

    it('names the environment variable to use instead', function () {
        try {
            parse('upgrade', '--key=secret')->rejectSecretOptions();
            $this->fail('expected UsageException');
        } catch (UsageException $e) {
            expect($e->getMessage())->toContain('CRYPTMAN_KEY')
                ->and($e->getMessage())->toContain('ps');
        }
    });

    it('never echoes the secret it rejected', function () {
        try {
            parse('upgrade', '--key=super-secret-value')->rejectSecretOptions();
            $this->fail('expected UsageException');
        } catch (UsageException $e) {
            expect($e->getMessage())->not->toContain('super-secret-value');
        }
    });
});

it('survives a non-string argv element', function () {
    expect(Input::fromArgv(['bin/cryptman', 'inspect', 123])->command())->toBe('inspect');
});
