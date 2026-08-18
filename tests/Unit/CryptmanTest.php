<?php

declare(strict_types=1);

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Exceptions\DecryptionException;
use Davmixcool\Cryptman\Exceptions\InvalidConfigurationException;
use Davmixcool\Cryptman\Exceptions\InvalidKeyException;
use Davmixcool\Cryptman\Exceptions\InvalidPayloadException;
use Davmixcool\Cryptman\Exceptions\UnsupportedVersionException;

function cryptman(array $options = []): Cryptman
{
    return new Cryptman(array_merge(['key' => 'correct horse battery staple'], $options));
}

/**
 * Run something that is expected to emit a deprecation, capturing it so the
 * notice does not escape into the test runner. Returns the notices raised.
 *
 * @return list<string>
 */
function capturingDeprecations(callable $callback): array
{
    $notices = [];

    set_error_handler(function (int $no, string $message) use (&$notices): bool {
        $notices[] = $message;

        return true;
    }, E_USER_DEPRECATED);

    try {
        $callback();
    } finally {
        restore_error_handler();
    }

    return $notices;
}

it('encrypts and decrypts with one required option', function () {
    // The 90% case from the README.
    $cryptman = new Cryptman(['key' => Cryptman::generateKey()]);

    expect($cryptman->decrypt($cryptman->encrypt('Loose lips sink ships')))
        ->toBe('Loose lips sink ships');
});

it('defaults to xchacha20-poly1305', function () {
    expect(cryptman()->method())->toBe('xchacha20-poly1305');
});

it('produces different ciphertext for identical plaintext', function () {
    $cryptman = cryptman();

    expect($cryptman->encrypt('hello'))->not->toBe($cryptman->encrypt('hello'));
});

it('round-trips every plaintext shape', function () {
    $cryptman = cryptman();

    foreach ([
        '',
        'Loose lips sink ships',
        "h\u{e9}llo w\u{f6}rld \u{65e5}\u{672c}\u{8a9e} \u{1f389}",
        "\x00\x01\xff\xfe binary",
        str_repeat('x', 50_000),
    ] as $plaintext) {
        expect($cryptman->decrypt($cryptman->encrypt($plaintext)))->toBe($plaintext);
    }
});

describe('the fluent API from v1', function () {
    it('still works', function () {
        $cryptman = cryptman();
        $encrypted = $cryptman->cipher('Loose lips sink ships')->encrypt();

        expect($cryptman->cipher($encrypted)->decrypt())->toBe('Loose lips sink ships');
    });

    it('interoperates with the direct API', function () {
        $cryptman = cryptman();

        expect($cryptman->decrypt($cryptman->cipher('mixed')->encrypt()))->toBe('mixed');
        expect($cryptman->cipher($cryptman->encrypt('mixed'))->decrypt())->toBe('mixed');
    });

    it('clears pending state after each operation', function () {
        // Otherwise a stale value could silently leak into a later call.
        $cryptman = cryptman();
        $cryptman->cipher('first')->encrypt();

        expect(fn () => $cryptman->encrypt())->toThrow(InvalidPayloadException::class);
    });

    it('prefers an explicit argument over pending state', function () {
        $cryptman = cryptman();
        $encrypted = $cryptman->cipher('ignored')->encrypt('used');

        expect($cryptman->decrypt($encrypted))->toBe('used');
    });

    it('throws when no value is available at all', function () {
        expect(fn () => cryptman()->encrypt())->toThrow(InvalidPayloadException::class);
    });
});

describe('configuration', function () {
    it('requires a key - there is no default', function () {
        expect(fn () => new Cryptman())->toThrow(InvalidKeyException::class)
            ->and(fn () => new Cryptman(['key' => '']))->toThrow(InvalidKeyException::class);
    });

    it('accepts aes-256-gcm explicitly', function () {
        $cryptman = cryptman(['method' => 'aes-256-gcm']);

        expect($cryptman->method())->toBe('aes-256-gcm')
            ->and($cryptman->decrypt($cryptman->encrypt('hello')))->toBe('hello');
    });

    it('rejects an unknown method', function () {
        expect(fn () => cryptman(['method' => 'rot13']))
            ->toThrow(InvalidConfigurationException::class);
    });

    it('rejects non-string options', function () {
        expect(fn () => cryptman(['method' => 42]))->toThrow(InvalidConfigurationException::class);
    });

    it('reads payloads written by the other method', function () {
        // The algorithm travels in the payload, so a config change does not
        // strand existing data.
        $written = cryptman(['method' => 'aes-256-gcm'])->encrypt('hello');

        expect(cryptman()->decrypt($written))->toBe('hello');
    });
});

describe('v1 method inference', function () {
    it('reads a v1 method as legacy configuration and warns', function () {
        // An unchanged v1 config must keep working: old data readable, new
        // writes authenticated, one deprecation notice.
        $cryptman = null;
        $notices = capturingDeprecations(function () use (&$cryptman) {
            $cryptman = cryptman(['method' => 'aes-256-cbc']);
        });

        expect($notices)->toHaveCount(1)
            ->and($notices[0])->toContain('legacy')
            // New data is NOT written with the unauthenticated cipher.
            ->and($cryptman->method())->toBe('xchacha20-poly1305');
    });

    it('reads v1 data written under the inferred method', function () {
        $key = 'correct horse battery staple';
        $iv = random_bytes(16);
        $token = bin2hex($iv).openssl_encrypt(
            'legacy value', 'aes-256-cbc', openssl_digest($key, 'SHA256', true), 0, $iv
        );

        $cryptman = null;
        capturingDeprecations(function () use (&$cryptman) {
            $cryptman = cryptman(['method' => 'aes-256-cbc']);
        });

        expect($cryptman->decrypt($token))->toBe('legacy value');
    });

    it('rejects a v1 method that contradicts an explicit legacy.method', function () {
        $thrown = null;

        capturingDeprecations(function () use (&$thrown) {
            try {
                cryptman([
                    'method' => 'aes-256-cbc',
                    'legacy' => ['method' => 'aes-128-ctr'],
                ]);
            } catch (InvalidConfigurationException $e) {
                $thrown = $e;
            }
        });

        expect($thrown)->toBeInstanceOf(InvalidConfigurationException::class);
    });

    it('accepts ANY cipher v1 accepted, not just the four the corpus covers', function () {
        // REGRESSION: an earlier implementation hardcoded the four methods the
        // test corpus covers. But v1 accepted anything in
        // openssl_get_cipher_methods() - 100+ ciphers - so a user on, say,
        // aes-192-cbc got InvalidConfigurationException from the CONSTRUCTOR
        // and their app died at boot with their data unreachable.
        $key = 'correct horse battery staple';

        $candidates = array_values(array_filter(
            ['aes-192-cbc', 'aes-192-ctr', 'aes-256-cfb', 'camellia-256-cbc', 'des-ede3-cbc'],
            fn (string $m): bool => in_array($m, openssl_get_cipher_methods(), true)
        ));

        expect($candidates)->not->toBeEmpty('expected some non-corpus v1 ciphers to be available');

        foreach ($candidates as $method) {
            $iv = random_bytes((int) openssl_cipher_iv_length($method));
            $token = bin2hex($iv).openssl_encrypt(
                'old secret', $method, openssl_digest($key, 'SHA256', true), 0, $iv
            );

            $cryptman = null;
            capturingDeprecations(function () use (&$cryptman, $key, $method) {
                $cryptman = new Cryptman(['key' => $key, 'method' => $method]);
            });

            expect($cryptman->decrypt($token))->toBe('old secret', "failed for {$method}")
                // ...and new writes are still authenticated, not written with it.
                ->and($cryptman->method())->toBe('xchacha20-poly1305');
        }
    });

    it('keeps aes-256-gcm as a v2 method even though OpenSSL also lists it', function () {
        // Ordering matters: aes-256-gcm is in openssl_get_cipher_methods() AND
        // is a v2 driver. It must not be mistaken for legacy configuration.
        $notices = [];
        $cryptman = null;

        $notices = capturingDeprecations(function () use (&$cryptman) {
            $cryptman = cryptman(['method' => 'aes-256-gcm']);
        });

        expect($notices)->toBeEmpty()
            ->and($cryptman->method())->toBe('aes-256-gcm');
    });

    it('reports a retired cipher as an environment problem, not a config mistake', function () {
        // OpenSSL 3 moved Blowfish, RC4 and friends to its legacy provider.
        // v1 data encrypted with them exists; the remedy is at the OpenSSL
        // level, so saying "unknown method" would send the user the wrong way.
        $retired = array_values(array_filter(
            ['bf-cbc', 'rc4', 'cast5-cbc'],
            fn (string $m): bool => ! in_array($m, openssl_get_cipher_methods(), true)
        ));

        if ($retired === []) {
            expect(true)->toBeTrue();   // build still ships them

            return;
        }

        foreach ($retired as $method) {
            expect(fn () => cryptman(['method' => $method]))
                ->toThrow(\Davmixcool\Cryptman\Exceptions\EnvironmentException::class);
        }
    });

    it('reads v1 default-method data with no configuration at all', function () {
        // The no-config upgrade path: v1 users who never set 'method'.
        $key = 'correct horse battery staple';
        $iv = random_bytes(16);
        $token = bin2hex($iv).openssl_encrypt(
            'legacy value', 'aes-128-ctr', openssl_digest($key, 'SHA256', true), 0, $iv
        );

        expect(cryptman()->decrypt($token))->toBe('legacy value');
    });
});

describe('key rotation', function () {
    it('decrypts payloads written under a previous key', function () {
        $old = cryptman(['key' => 'old-key']);
        $written = $old->encrypt('rotated value');

        $rotated = cryptman(['key' => 'new-key', 'previous_keys' => ['old-key']]);

        expect($rotated->decrypt($written))->toBe('rotated value');
    });

    it('always encrypts with the current key', function () {
        $rotated = cryptman(['key' => 'new-key', 'previous_keys' => ['old-key']]);
        $written = $rotated->encrypt('fresh');

        expect(cryptman(['key' => 'new-key'])->decrypt($written))->toBe('fresh')
            ->and(fn () => cryptman(['key' => 'old-key'])->decrypt($written))
            ->toThrow(DecryptionException::class);
    });

    it('fails once every key is exhausted', function () {
        $written = cryptman(['key' => 'unrelated'])->encrypt('value');

        expect(fn () => cryptman(['key' => 'a', 'previous_keys' => ['b', 'c']])->decrypt($written))
            ->toThrow(DecryptionException::class);
    });
});

describe('migration helpers', function () {
    it('reports the payload version', function () {
        $cryptman = cryptman();

        expect($cryptman->version($cryptman->encrypt('x')))->toBe(2)
            ->and($cryptman->version('1f73df23a0e10e72df8d0123abcd4567body'))->toBe(1);
    });

    it('flags only legacy payloads for upgrade', function () {
        $cryptman = cryptman();

        expect($cryptman->needsUpgrade($cryptman->encrypt('x')))->toBeFalse()
            ->and($cryptman->needsUpgrade('1f73df23a0e10e72df8d0123abcd4567body'))->toBeTrue();
    });

    it('inspects without revealing plaintext', function () {
        $cryptman = cryptman();
        $encrypted = $cryptman->encrypt('super-secret-plaintext');

        $inspected = $cryptman->inspect($encrypted);

        expect($inspected)->toMatchArray(['version' => 2, 'driver' => 'xchacha20-poly1305'])
            ->and(implode('', array_map(strval(...), array_filter($inspected))))
            ->not->toContain('super-secret-plaintext');
    });

    it('leaves v2 payloads untouched when upgrading', function () {
        $cryptman = cryptman();
        $encrypted = $cryptman->encrypt('x');

        expect($cryptman->upgrade($encrypted))->toBe($encrypted);
    });
});

describe('json helpers', function () {
    it('round-trips structures', function () {
        $cryptman = cryptman();
        $data = ['api_key' => 'abc', 'account_id' => 123, 'nested' => ['a' => true, 'b' => null]];

        expect($cryptman->decryptJson($cryptman->encryptJson($data)))->toBe($data);
    });

    it('throws on invalid json rather than returning null', function () {
        $cryptman = cryptman();

        expect(fn () => $cryptman->decryptJson($cryptman->encrypt('not json')))
            ->toThrow(JsonException::class);
    });
});

describe('associated data', function () {
    it('binds a payload to its context', function () {
        $cryptman = cryptman();
        $encrypted = $cryptman->encrypt('api-token', 'user:123');

        expect($cryptman->decrypt($encrypted, 'user:123'))->toBe('api-token')
            ->and(fn () => $cryptman->decrypt($encrypted, 'user:456'))
            ->toThrow(DecryptionException::class)
            ->and(fn () => $cryptman->decrypt($encrypted))
            ->toThrow(DecryptionException::class);
    });

    it('works through the fluent API too', function () {
        $cryptman = cryptman();
        $encrypted = $cryptman->cipher('api-token')->encrypt(associatedData: 'tenant:42');

        expect($cryptman->cipher($encrypted)->decrypt(associatedData: 'tenant:42'))
            ->toBe('api-token');
    });
});

describe('malformed payloads', function () {
    it('rejects a corrupted v2 payload', function () {
        $cryptman = cryptman();
        $encrypted = $cryptman->encrypt('Loose lips sink ships');
        $tampered = substr($encrypted, 0, -4).'AAAA';

        expect(fn () => $cryptman->decrypt($tampered))
            ->toThrow(DecryptionException::class);
    });

    it('reports a future format version distinctly', function () {
        expect(fn () => cryptman()->decrypt('cman2.'.rtrim(strtr(base64_encode(
            "\x63\x01".random_bytes(40)
        ), '+/', '-_'), '=')))->toThrow(UnsupportedVersionException::class);
    });

    it('rejects an empty payload as malformed, not as a failed legacy read', function () {
        expect(fn () => cryptman()->decrypt(''))->toThrow(InvalidPayloadException::class);
    });

    it('never returns false', function () {
        // PRD 28 - the defect this whole release exists to remove. Every
        // failure path raises; none returns a value a caller could mistake
        // for plaintext.
        foreach (['', 'garbage', 'cman2.!!!', '1f73df23a0e10e72df8d0123abcd4567x'] as $bad) {
            $threw = false;

            try {
                cryptman()->decrypt($bad);
            } catch (\Davmixcool\Cryptman\Exceptions\CryptmanException) {
                $threw = true;
            }

            expect($threw)->toBeTrue("decrypt('{$bad}') should have thrown");
        }
    });
});

it('generates keys through the facade', function () {
    $key = Cryptman::generateKey();
    $cryptman = new Cryptman(['key' => $key]);

    expect($key)->toStartWith('cman_key_')
        ->and($cryptman->decrypt($cryptman->encrypt('hello')))->toBe('hello');
});
