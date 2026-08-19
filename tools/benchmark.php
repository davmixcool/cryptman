<?php

declare(strict_types=1);

/**
 * Throughput benchmark across every supported method and a range of sizes.
 *
 *   php tools/benchmark.php              # default: 1K, 10K, 100K, 1M
 *   php tools/benchmark.php --quick      # fewer iterations, for a sanity check
 *
 * Deliberately NOT a test. It measures wall-clock time, so it would be flaky
 * under CI and would slow the suite for no correctness gain. Performance is
 * secondary to correctness here; the point of this script is to make
 * regressions measurable, not to gate anything.
 *
 * What it is actually for: the three OpenSSL methods derive a per-message
 * subkey via HKDF on every operation, which the default does not. That cost is
 * fixed per message, so it dominates at small payloads and disappears at large
 * ones -- and small payloads are what this library is mostly used for. This
 * script shows where the crossover is.
 */

require __DIR__.'/../vendor/autoload.php';

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Keys\KeyGenerator;
use Davmixcool\Cryptman\Payload\EncryptedPayload;

$quick = in_array('--quick', $_SERVER['argv'], true);

/** @var array<string,int> label => bytes */
$sizes = ['1 KB' => 1024, '10 KB' => 10240, '100 KB' => 102400, '1 MB' => 1048576];

// Enough iterations that timer granularity is irrelevant, scaled down for the
// large payloads where each operation already takes real time.
$iterations = static function (int $bytes) use ($quick): int {
    $n = match (true) {
        $bytes <= 1024 => 5000,
        $bytes <= 10240 => 2000,
        $bytes <= 102400 => 400,
        default => 60,
    };

    return $quick ? max(20, intdiv($n, 10)) : $n;
};

$key = Cryptman::generateKey();
$methods = Cryptman::supportedMethods();

/** Median is used rather than mean: one GC pause should not move the number. */
$median = static function (array $samples): float {
    sort($samples);
    $n = count($samples);

    return $n % 2 ? $samples[intdiv($n, 2)]
        : ($samples[$n / 2 - 1] + $samples[$n / 2]) / 2;
};

$time = static function (callable $op, int $n) use ($median): float {
    // Warm up: first calls pay for autoloading and opcache.
    for ($i = 0; $i < min(50, $n); $i++) {
        $op();
    }

    $samples = [];
    for ($i = 0; $i < $n; $i++) {
        $t = hrtime(true);
        $op();
        $samples[] = (float) (hrtime(true) - $t);
    }

    return $median($samples) / 1000.0;   // nanoseconds -> microseconds
};

printf("PHP %s   sodium %s   %s\n\n",
    PHP_VERSION,
    extension_loaded('sodium') ? 'yes' : 'no',
    OPENSSL_VERSION_TEXT
);

printf("%-20s %10s %12s %12s %11s %8s %8s\n",
    'method', 'size', 'encrypt', 'decrypt', 'MB/s enc', 'frame', 'stored');
echo str_repeat('-', 88), "\n";

$fixedCost = [];

foreach ($methods as $method) {
    $cryptman = new Cryptman(['key' => $key, 'method' => $method]);

    foreach ($sizes as $label => $bytes) {
        $plaintext = random_bytes($bytes);
        $payload = $cryptman->encrypt($plaintext);
        $n = $iterations($bytes);

        $enc = $time(static fn () => $cryptman->encrypt($plaintext), $n);
        $dec = $time(static fn () => $cryptman->decrypt($payload), $n);

        if ($bytes === 1024) {
            $fixedCost[$method] = $enc;
        }

        // Two different overheads, and conflating them is misleading. The
        // frame overhead is fixed (42 or 62 bytes) and is what the docs quote.
        // The stored overhead is what a database column actually pays, and it
        // grows with the payload because base64url expands by 4/3.
        $frame = strlen((string) KeyGenerator::base64UrlDecode(
            substr($payload, strlen(EncryptedPayload::PREFIX))
        )) - $bytes;

        printf("%-20s %10s %10.1f µs %10.1f µs %11.1f %6d B %7.0f%%\n",
            $method,
            $label,
            $enc,
            $dec,
            $bytes / $enc,                       // bytes/µs == MB/s
            $frame,
            100 * (strlen($payload) / $bytes - 1)
        );
    }

    echo "\n";
}

// The question this script exists to answer.
$default = $fixedCost[Cryptman::supportedMethods()[0]] ?? 0.0;
$hkdf = (static function () use ($key): float {
    $material = KeyDeriver::deriveEncryptionKey($key);
    $salt = KeyDeriver::generateMessageSalt();
    $t = hrtime(true);
    for ($i = 0; $i < 20000; $i++) {
        KeyDeriver::deriveMessageKey($material, $salt);
    }

    return (hrtime(true) - $t) / 20000 / 1000.0;
})();

printf("per-message subkey derivation: %.1f µs, paid once per operation by the\n", $hkdf);
printf("three 96-bit-nonce methods. At 1 KB that is ~%.0f%% of an encrypt; by 1 MB\n",
    $default > 0 ? 100 * $hkdf / $default : 0);
echo "it is lost in the noise. It buys the removal of the ~2^32 message bound.\n";
