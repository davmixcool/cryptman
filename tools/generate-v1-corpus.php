<?php

/**
 * One-shot generator for the frozen Cryptman v1 compatibility corpus.
 *
 * Read tests/Fixtures/README.md before running this. The corpus is FROZEN:
 * regenerating it is a breaking change to the compatibility contract, and this
 * script refuses to overwrite an existing corpus without an explicit flag.
 *
 *   php tools/generate-v1-corpus.php                 # generate (refuses if corpus exists)
 *   php tools/generate-v1-corpus.php --verify-only   # re-derive, diff, write nothing
 *
 * v1 source is extracted from the v1.0.0 tag, never from the working tree —
 * master becomes v2, so reading src/ would silently start producing v2 output.
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
// IV shadow.
//
// v1's Encrypt::token() calls openssl_random_pseudo_bytes() unqualified from
// inside namespace Davmixcool\Cipher. PHP resolves unqualified function calls
// to the current namespace before the global one, so declaring it here shadows
// the real function WITHOUT modifying v1 source.
// ---------------------------------------------------------------------------

namespace Davmixcool\Cipher {
    use Corpus\Iv;

    function openssl_random_pseudo_bytes(int $length): string
    {
        return Iv::next($length);
    }
}

namespace Corpus {
    /**
     * Deterministic IV source, keyed by fixture id.
     *
     * Determinism is what makes the frozen corpus re-derivable: `--verify-only`
     * can regenerate and diff, giving an integrity axis independent of the
     * sha256 file. See tests/Fixtures/README.md for the full rationale.
     */
    final class Iv
    {
        public const HMAC_KEY = 'cryptman/v1-corpus/iv/v1';

        public static string $fixtureId = '';

        /** 'deterministic' | 'wild' */
        public static string $mode = 'deterministic';

        public static function next(int $length): string
        {
            if (self::$mode === 'wild') {
                return \openssl_random_pseudo_bytes($length);
            }

            if (self::$fixtureId === '') {
                throw new \RuntimeException('IV requested outside a fixture scope');
            }

            return substr(
                hash_hmac('sha256', self::$fixtureId, self::HMAC_KEY, true),
                0,
                $length
            );
        }
    }

    /**
     * Loads Cryptman v1 from the released tag and proves it is the released code.
     */
    final class V1Source
    {
        public const TAG = 'v1.0.0';

        public const COMMIT = '44ee2023ef5d1b26c64da8317ae93738ebea410d';

        /** Git blob hashes of the four v1 source files at TAG. */
        public const BLOBS = [
            'src/Cipher/Bytes.php' => '688eacb9b999fc472f101941470f8f5fc555ea19',
            'src/Cipher/Encrypt.php' => '1f72aec6dabd44b41dcdd5052d6973b41eec39bc',
            'src/Cipher/Decrypt.php' => '7f84becb0a12c7d1186eb6beead2149884ef9eb0',
            'src/Cryptman.php' => 'bbc94d904fa37801ec6dc1d6d94bcc7dce6cd6a9',
        ];

        public static function load(string $repoRoot): void
        {
            // (a) the tag still resolves to the commit we froze against
            $resolved = trim((string) shell_exec(
                'git -C '.escapeshellarg($repoRoot).' rev-parse '.escapeshellarg(self::TAG.'^{}').' 2>/dev/null'
            ));

            if (! hash_equals(self::COMMIT, $resolved)) {
                throw new \RuntimeException(sprintf(
                    'Tag %s resolves to "%s", expected %s',
                    self::TAG,
                    $resolved,
                    self::COMMIT
                ));
            }

            // (b) read each file out of the tag's tree, never the working tree,
            // and (c) prove every byte matches the release
            foreach (self::BLOBS as $path => $expectedBlob) {
                $contents = shell_exec(
                    'git -C '.escapeshellarg($repoRoot).' show '.escapeshellarg(self::TAG.':'.$path)
                );

                if (! is_string($contents) || $contents === '') {
                    throw new \RuntimeException("Could not read {$path} from tag ".self::TAG);
                }

                $actualBlob = self::gitBlobHash($contents);

                if (! hash_equals($expectedBlob, $actualBlob)) {
                    throw new \RuntimeException(
                        "Blob mismatch for {$path}: got {$actualBlob}, expected {$expectedBlob}"
                    );
                }

                $tmp = tempnam(sys_get_temp_dir(), 'cryptman-v1-');
                file_put_contents($tmp, $contents);
                require $tmp;
                unlink($tmp);
            }
        }

        /** Reproduces `git hash-object` in pure PHP. */
        public static function gitBlobHash(string $contents): string
        {
            return sha1('blob '.strlen($contents)."\0".$contents);
        }
    }
}

namespace {

    use Corpus\Iv;
    use Corpus\V1Source;
    use Davmixcool\Cryptman;

    const CORPUS_PATH = __DIR__.'/../tests/Fixtures/v1-corpus.json';
    const SHA_PATH = __DIR__.'/../tests/Fixtures/v1-corpus.sha256';
    const OVERRIDE_FLAG = '--i-am-regenerating-a-frozen-corpus';

    const JSON_FLAGS = JSON_PRETTY_PRINT
        | JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
        | JSON_THROW_ON_ERROR;

    // -- fixture inputs -----------------------------------------------------

    /** Deterministic binary keys — never random_bytes(), which would break re-derivation. */
    function binKey(string $label, int $length): string
    {
        return substr(hash('sha256', 'cryptman/v1-corpus/key/'.$label, true), 0, $length);
    }

    /** @return array<string,string> */
    function keyShapes(): array
    {
        return [
            // printable ASCII -> ctype_print() true -> SHA-256 digest branch
            'key-ascii-printable' => 'correct horse battery staple',
            'key-ascii-1char' => 'x',
            // non-printable -> raw passthrough branch
            'key-utf8-cafe' => "caf\xc3\xa9",       // "café" — ctype_print() is FALSE
            'key-nul' => "abc\x00def",
            'key-bin16' => binKey('bin16', 16),
            'key-bin32' => binKey('bin32', 32),
            'key-empty' => '',
        ];
    }

    /** @return array<string,string> */
    function plaintextShapes(): array
    {
        return [
            'pt-empty' => '',
            'pt-short-ascii' => 'Loose lips sink ships',
            'pt-utf8' => "h\u{e9}llo w\u{f6}rld \u{2014} \u{65e5}\u{672c}\u{8a9e} \u{1f389}",
            'pt-binary' => "\x00\x01\x02\xfd\xfe\xff".binKey('pt-binary', 26),
            'pt-block-boundary' => '0123456789abcdef',            // exactly one AES block
            'pt-multiblock' => str_repeat('The quick brown fox. ', 10), // 210 bytes
        ];
    }

    /** @return array<string,string> family+bits => openssl method */
    function methods(): array
    {
        return [
            'ctr128' => 'aes-128-ctr',
            'ctr256' => 'aes-256-ctr',
            'cbc128' => 'aes-128-cbc',
            'cbc256' => 'aes-256-cbc',
        ];
    }

    // -- fixture construction ----------------------------------------------

    /**
     * Encrypts under $encryptWith, decrypts under $decryptWith, records what v1 did.
     *
     * A "negative" fixture is simply one where $decryptWith differs from
     * $encryptWith — positives and negatives share one shape so the test has a
     * single code path.
     *
     * @param  array{key:string,method:?string}  $encryptWith
     * @param  array{key:string,method:?string}  $decryptWith
     * @param  (callable(string): string)|null  $mutate  optional token corruption
     */
    function makeFixture(
        string $id,
        array $encryptWith,
        string $plaintext,
        array $decryptWith,
        ?callable $mutate = null,
        string $notes = '',
        bool $wild = false
    ): array {
        Iv::$fixtureId = $id;
        Iv::$mode = $wild ? 'wild' : 'deterministic';

        $expectedIv = $wild ? null : Iv::next(16);

        $token = (new Cryptman(buildOptions($encryptWith)))
            ->cipher($plaintext)
            ->encrypt();

        // The shadow must actually have taken effect. OPcache can in principle
        // inline internal functions, so assert rather than assume.
        if (! $wild && ! str_starts_with($token, bin2hex((string) $expectedIv))) {
            throw new RuntimeException(
                "IV shadow did not take effect for {$id}; aborting generation"
            );
        }

        if ($mutate !== null) {
            $token = $mutate($token);
        }

        $result = (new Cryptman(buildOptions($decryptWith)))
            ->cipher($token)
            ->decrypt();

        $fixture = [
            'id' => $id,
            'encrypt_with' => [
                'key_b64' => base64_encode($encryptWith['key']),
                'method' => $encryptWith['method'],
            ],
            'plaintext_b64' => base64_encode($plaintext),
            'token' => $token,
            'decrypt_with' => [
                'key_b64' => base64_encode($decryptWith['key']),
                'method' => $decryptWith['method'],
            ],
            'key_branch' => ctype_print($decryptWith['key']) ? 'digest' : 'raw',
            'iv' => $wild ? 'wild' : 'derived',
            'v1_result' => $result === false
                ? ['type' => 'false']
                : ['type' => 'string', 'value_b64' => base64_encode($result)],
            'v1_result_is_utf8' => $result === false
                ? null
                : mb_check_encoding($result, 'UTF-8'),
            'notes' => $notes,
        ];

        Iv::$fixtureId = '';
        Iv::$mode = 'deterministic';

        return $fixture;
    }

    /**
     * A null method means the option was OMITTED, exercising v1's aes-128-ctr default.
     *
     * @param  array{key:string,method:?string}  $spec
     */
    function buildOptions(array $spec): array
    {
        $options = ['key' => $spec['key']];

        if ($spec['method'] !== null) {
            $options['method'] = $spec['method'];
        }

        return $options;
    }

    // -- the matrix ---------------------------------------------------------

    function buildFixtures(): array
    {
        $fixtures = [];
        $keys = keyShapes();
        $plaintexts = plaintextShapes();
        $methods = methods();

        // Tier A — every method against every plaintext shape, printable key.
        foreach ($methods as $slug => $method) {
            foreach ($plaintexts as $ptShape => $plaintext) {
                $id = "{$slug}/key-ascii-printable/{$ptShape}";
                $notes = '';

                if ($ptShape === 'pt-empty' && str_starts_with($slug, 'ctr')) {
                    $notes = 'v1 QUIRK: CTR encryption of empty plaintext yields the bare '
                        .'32-char hex IV. Decrypt requires >=1 body char, so decrypt() '
                        ."returns FALSE. Compare cbc*/key-ascii-printable/pt-empty, which returns ''.";
                }

                $fixtures[] = makeFixture(
                    $id,
                    ['key' => $keys['key-ascii-printable'], 'method' => $method],
                    $plaintext,
                    ['key' => $keys['key-ascii-printable'], 'method' => $method],
                    null,
                    $notes
                );
            }
        }

        // Tier B — key shapes across one CTR and one CBC method.
        // key-ascii-printable is excluded: Tier A already covers it.
        foreach (['ctr128' => 'aes-128-ctr', 'cbc128' => 'aes-128-cbc'] as $slug => $method) {
            foreach ($keys as $keyShape => $key) {
                if ($keyShape === 'key-ascii-printable') {
                    continue;
                }

                $notes = match ($keyShape) {
                    'key-utf8-cafe' => 'ctype_print("café") is FALSE, so an accented passphrase '
                        .'silently takes the RAW key branch (5 bytes) instead of the SHA-256 '
                        .'branch. PRD 17.1.',
                    'key-ascii-1char' => 'Proves key LENGTH is irrelevant on the digest branch: '
                        .'a 1-char key becomes the same 32 bytes as any other printable key.',
                    'key-empty' => 'ctype_print("") is FALSE, so an empty key takes the RAW '
                        .'branch at 0 bytes and OpenSSL zero-pads it. v2 rejects this (PRD 19.1).',
                    default => '',
                };

                $fixtures[] = makeFixture(
                    "{$slug}/{$keyShape}/pt-short-ascii",
                    ['key' => $key, 'method' => $method],
                    $plaintexts['pt-short-ascii'],
                    ['key' => $key, 'method' => $method],
                    null,
                    $notes
                );
            }
        }

        // Tier C — widen the two most interesting raw-branch keys to AES-256.
        foreach ([
            'ctr256/key-utf8-cafe/pt-short-ascii' => ['key-utf8-cafe', 'aes-256-ctr'],
            'cbc256/key-utf8-cafe/pt-short-ascii' => ['key-utf8-cafe', 'aes-256-cbc'],
            'ctr256/key-empty/pt-short-ascii' => ['key-empty', 'aes-256-ctr'],
        ] as $id => [$keyShape, $method]) {
            $fixtures[] = makeFixture(
                $id,
                ['key' => $keys[$keyShape], 'method' => $method],
                $plaintexts['pt-short-ascii'],
                ['key' => $keys[$keyShape], 'method' => $method],
                null,
                'Raw key branch against AES-256.'
            );
        }

        $printable = $keys['key-ascii-printable'];

        // Tier D — negatives. decrypt_with deliberately differs from encrypt_with.

        // The PRD 22.1 headline: a CBC token misread under v1's default CTR does
        // not fail. CTR is a stream cipher; it returns garbage, not false.
        $fixtures[] = makeFixture(
            'neg/cbc-token-read-as-default-ctr/long',
            ['key' => $printable, 'method' => 'aes-256-cbc'],
            $plaintexts['pt-short-ascii'],
            ['key' => $printable, 'method' => null],
            null,
            'PRD 22.1/22.2: CBC token read under the omitted-method default (aes-128-ctr) '
                .'returns a garbage STRING, not false. The only signal is that the garbage is '
                .'not valid UTF-8.'
        );

        $fixtures[] = makeFixture(
            'neg/cbc-token-read-as-default-ctr/short',
            ['key' => $printable, 'method' => 'aes-256-cbc'],
            'A',
            ['key' => $printable, 'method' => null],
            null,
            'The weak spot, recorded deliberately: with only 16 bytes of garbage the UTF-8 '
                .'guard has a measured ~0.02% chance of a false negative. The guard REDUCES '
                .'misread probability; it does not detect misreads.'
        );

        $fixtures[] = makeFixture(
            'neg/ctr-token-read-as-cbc/basic',
            ['key' => $printable, 'method' => 'aes-128-ctr'],
            $plaintexts['pt-short-ascii'],
            ['key' => $printable, 'method' => 'aes-128-cbc'],
            null,
            'The reverse direction DOES fail: CBC checks PKCS#7 padding, so a CTR token '
                .'read as CBC returns false. Failure detection is asymmetric between families.'
        );

        // Key-ring behaviour, split by family. This is the load-bearing evidence
        // for PRD 20.1: rotation by trial decryption is unsound for v1 payloads.
        foreach ([1, 2, 3] as $n) {
            $fixtures[] = makeFixture(
                "neg/wrong-key-ctr/{$n}",
                ['key' => $printable, 'method' => 'aes-128-ctr'],
                $plaintexts['pt-short-ascii'],
                ['key' => "wrong-key-{$n}", 'method' => 'aes-128-ctr'],
                null,
                'PRD 20.1: a wrong key under CTR returns a garbage STRING, never false. A key '
                    .'ring cannot tell right from wrong, so trial decryption over previous_keys '
                    .'is unsound for v1 payloads.'
            );

            $fixtures[] = makeFixture(
                "neg/wrong-key-cbc/{$n}",
                ['key' => $printable, 'method' => 'aes-128-cbc'],
                $plaintexts['pt-short-ascii'],
                ['key' => "wrong-key-{$n}", 'method' => 'aes-128-cbc'],
                null,
                'Under CBC a wrong key fails the padding check and returns false — but this is '
                    .'luck, not integrity: ~1 in 256 wrong keys produce valid padding.'
            );
        }

        $fixtures[] = makeFixture(
            'neg/truncated-token/basic',
            ['key' => $printable, 'method' => 'aes-128-ctr'],
            $plaintexts['pt-short-ascii'],
            ['key' => $printable, 'method' => 'aes-128-ctr'],
            static fn (string $token): string => substr($token, 0, 20),
            'Token truncated below the 32-char IV prefix: the /^(.{32})(.+)$/ match fails '
                .'and decrypt() returns false.'
        );

        $fixtures[] = makeFixture(
            'neg/non-hex-iv/basic',
            ['key' => $printable, 'method' => 'aes-128-ctr'],
            $plaintexts['pt-short-ascii'],
            ['key' => $printable, 'method' => 'aes-128-ctr'],
            static fn (string $token): string => str_repeat('z', 32).substr($token, 32),
            'IV prefix replaced with non-hex characters: ctype_xdigit() fails and decrypt() '
                .'returns false.'
        );

        // Tier E — wild. Real openssl_random_pseudo_bytes IVs, proving genuine
        // production tokens decode. Not re-derivable; --verify-only skips these.
        foreach ($methods as $slug => $method) {
            $fixtures[] = makeFixture(
                "wild/{$slug}/pt-short-ascii",
                ['key' => $printable, 'method' => $method],
                $plaintexts['pt-short-ascii'],
                ['key' => $printable, 'method' => $method],
                null,
                'Generated with a REAL random IV from unmodified v1, not the derived-IV '
                    .'scheme. Proves production tokens decode. Skipped by --verify-only.',
                true
            );
        }

        usort($fixtures, static fn (array $a, array $b): int => strcmp($a['id'], $b['id']));

        return $fixtures;
    }

    function buildDocument(array $fixtures, string $generatedAt): array
    {
        return [
            '$schema_version' => 1,
            '_policy' => 'FROZEN, APPEND-ONLY. Never modify or remove an existing fixture. '
                .'New fixtures may be appended with new ids. Regenerating this file is a '
                .'breaking change to the compatibility contract. See tests/Fixtures/README.md.',
            'generated_at' => $generatedAt,
            'generated_by' => 'tools/generate-v1-corpus.php',
            'source' => [
                'package' => 'davmixcool/cryptman',
                'tag' => V1Source::TAG,
                'tag_type' => 'lightweight',
                'commit' => V1Source::COMMIT,
                'blobs' => V1Source::BLOBS,
            ],
            'encoding' => [
                'rule' => 'Every field whose name ends in _b64 is standard base64 (RFC 4648) '
                    .'of raw bytes.',
                'token' => 'Literal string. v1 guarantees printable ASCII: a lowercase hex IV '
                    .'followed by base64 ciphertext.',
                'method_null' => "A null 'method' means the option was OMITTED from the "
                    ."constructor, exercising v1's default of aes-128-ctr.",
                'v1_result' => 'Tagged union: {"type":"false"} or {"type":"string",'
                    .'"value_b64":...}. v1 returns strict false on some inputs and an empty '
                    .'string on others; these are NOT interchangeable.',
            ],
            'iv_derivation' => [
                'scheme' => "substr(hash_hmac('sha256', <fixture id>, '"
                    .Iv::HMAC_KEY."', true), 0, iv_len)",
                'why' => 'Deterministic so the corpus can be re-derived and audited '
                    .'(--verify-only). v1 in production uses openssl_random_pseudo_bytes; '
                    .'the wild/* fixtures cover that path.',
                'note' => 'Fixture ids are the HMAC input and are therefore load-bearing. '
                    .'Renaming an id changes its IV and invalidates its token.',
            ],
            'fixtures' => $fixtures,
        ];
    }

    function encodeDocument(array $document): string
    {
        return json_encode($document, JSON_FLAGS)."\n";
    }

    // -- entry point --------------------------------------------------------

    $argv = $_SERVER['argv'];
    $verifyOnly = in_array('--verify-only', $argv, true);
    $override = in_array(OVERRIDE_FLAG, $argv, true);
    $repoRoot = dirname(__DIR__);

    try {
        V1Source::load($repoRoot);

        if ($verifyOnly) {
            if (! is_file(CORPUS_PATH)) {
                fwrite(STDERR, 'No corpus at '.CORPUS_PATH." to verify against.\n");
                exit(1);
            }

            $committed = json_decode((string) file_get_contents(CORPUS_PATH), true, 512, JSON_THROW_ON_ERROR);

            // Re-derive, then compare only what is re-derivable: wild/* fixtures
            // use real random IVs and can never match.
            $regenerated = buildFixtures();

            $strip = static fn (array $list): array => array_values(array_filter(
                $list,
                static fn (array $f): bool => ($f['iv'] ?? 'derived') !== 'wild'
            ));

            $a = $strip($committed['fixtures']);
            $b = $strip($regenerated);

            $skipped = count($committed['fixtures']) - count($a);

            if (json_encode($a, JSON_FLAGS) === json_encode($b, JSON_FLAGS)) {
                printf(
                    "identical — %d derived fixtures re-derived exactly (%d wild fixtures skipped)\n",
                    count($a),
                    $skipped
                );
                exit(0);
            }

            fwrite(STDERR, "MISMATCH — the committed corpus does not match a fresh derivation.\n");

            $byId = static function (array $list): array {
                $out = [];
                foreach ($list as $f) {
                    $out[$f['id']] = $f;
                }

                return $out;
            };

            $committedById = $byId($a);
            $regeneratedById = $byId($b);

            foreach (array_diff(array_keys($committedById), array_keys($regeneratedById)) as $id) {
                fwrite(STDERR, "  only in committed:    {$id}\n");
            }

            foreach (array_diff(array_keys($regeneratedById), array_keys($committedById)) as $id) {
                fwrite(STDERR, "  only in regenerated:  {$id}\n");
            }

            foreach ($committedById as $id => $fixture) {
                if (isset($regeneratedById[$id]) && $regeneratedById[$id] !== $fixture) {
                    fwrite(STDERR, "  differs:              {$id}\n");
                }
            }

            exit(1);
        }

        if (is_file(CORPUS_PATH) && ! $override) {
            fwrite(STDERR, sprintf(
                "REFUSING to overwrite a frozen corpus.\n\n"
                ."  %s already exists.\n\n"
                ."The corpus is a frozen compatibility contract: regenerating it invalidates\n"
                ."every guarantee that depends on it. Read tests/Fixtures/README.md.\n\n"
                ."To verify it is unchanged:  php tools/generate-v1-corpus.php --verify-only\n"
                ."If you truly mean it:       php tools/generate-v1-corpus.php %s\n",
                CORPUS_PATH,
                OVERRIDE_FLAG
            ));
            exit(1);
        }

        $document = buildDocument(buildFixtures(), gmdate('Y-m-d\TH:i:s\Z'));
        $json = encodeDocument($document);

        if (! is_dir(dirname(CORPUS_PATH))) {
            mkdir(dirname(CORPUS_PATH), 0755, true);
        }

        file_put_contents(CORPUS_PATH, $json);
        // Path is relative to the package root so that
        // `shasum -a 256 -c tests/Fixtures/v1-corpus.sha256` works from there.
        file_put_contents(
            SHA_PATH,
            hash('sha256', $json).'  tests/Fixtures/v1-corpus.json'."\n"
        );

        printf(
            "wrote %d fixtures to %s\nsha256 %s\n",
            count($document['fixtures']),
            CORPUS_PATH,
            hash('sha256', $json)
        );
        exit(0);
    } catch (Throwable $e) {
        fwrite(STDERR, 'FAILED: '.$e->getMessage()."\n");
        exit(1);
    }
}
