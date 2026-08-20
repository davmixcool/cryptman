<?php

declare(strict_types=1);

/**
 * Generate the test vectors published in SPEC.md.
 *
 * Cryptman's own encrypt() draws a random nonce and salt, so it cannot produce
 * a reproducible vector. This script performs the same steps with those values
 * FIXED, then verifies each result through the real public decrypt() path.
 *
 * That verification is the point. It means the vectors are not a
 * hand-maintained description of the format that could drift from the code --
 * they are output the shipping implementation agrees with, or this script
 * fails.
 *
 *     php tools/generate-spec-vectors.php            # print as markdown
 *     php tools/generate-spec-vectors.php --json     # machine-readable
 */

require __DIR__.'/../vendor/autoload.php';

use Davmixcool\Cryptman;
use Davmixcool\Cryptman\Keys\KeyDeriver;
use Davmixcool\Cryptman\Keys\KeyGenerator;
use Davmixcool\Cryptman\Payload\EncryptedPayload;
use Davmixcool\Cryptman\Payload\PayloadEncoder;

/** Fixed, non-secret, committed test key. Never use it for anything. */
const VECTOR_KEY = 'cman_key_KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio';

/** Fixed nonce and salt bytes, chosen to be visibly patterned in a hex dump. */
function fixedBytes(int $length): string
{
    return substr(str_repeat("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 4), 0, $length);
}

/**
 * @return array<string,mixed>
 */
function vector(string $method, string $plaintext, ?string $aad, ?string $keyId): array
{
    $algorithmId = match ($method) {
        'xchacha20-poly1305' => EncryptedPayload::ALG_XCHACHA20_POLY1305,
        'aes-256-gcm' => EncryptedPayload::ALG_AES_256_GCM,
        'aes-128-gcm' => EncryptedPayload::ALG_AES_128_GCM,
        'chacha20-poly1305' => EncryptedPayload::ALG_CHACHA20_POLY1305,
    };

    $ikm = KeyGenerator::toInputKeyMaterial(VECTOR_KEY);
    $encryptionKey = KeyDeriver::deriveEncryptionKey($ikm);

    $saltBytes = EncryptedPayload::saltBytes($algorithmId);
    $nonceBytes = EncryptedPayload::nonceBytes($algorithmId);

    $salt = $saltBytes > 0 ? fixedBytes($saltBytes) : '';
    $nonce = fixedBytes($nonceBytes);

    // The frame whose header supplies the associated data.
    $frame = new EncryptedPayload(
        algorithmId: $algorithmId,
        nonce: $nonce,
        ciphertext: '',
        salt: $salt,
        keyId: $keyId,
    );

    $associatedData = $frame->associatedData($aad);

    if ($algorithmId === EncryptedPayload::ALG_XCHACHA20_POLY1305) {
        $messageKey = $encryptionKey;   // no per-message derivation
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext, $associatedData, $nonce, $encryptionKey
        );
    } else {
        [$info, $length, $cipher] = match ($algorithmId) {
            EncryptedPayload::ALG_AES_256_GCM => [KeyDeriver::INFO_AES_MESSAGE, 32, 'aes-256-gcm'],
            EncryptedPayload::ALG_AES_128_GCM => [KeyDeriver::INFO_AES_128_MESSAGE, 16, 'aes-128-gcm'],
            EncryptedPayload::ALG_CHACHA20_POLY1305 => [KeyDeriver::INFO_CHACHA20_MESSAGE, 32, 'chacha20-poly1305'],
        };

        $messageKey = KeyDeriver::deriveMessageKey($encryptionKey, $salt, $info, $length);

        $tag = '';
        $body = openssl_encrypt(
            $plaintext, $cipher, $messageKey, OPENSSL_RAW_DATA, $nonce, $tag,
            $associatedData, EncryptedPayload::TAG_BYTES
        );

        if ($body === false) {
            throw new RuntimeException("openssl_encrypt failed for {$method}");
        }

        $ciphertext = $body.$tag;
    }

    $payload = (new PayloadEncoder())->encode(new EncryptedPayload(
        algorithmId: $algorithmId,
        nonce: $nonce,
        ciphertext: $ciphertext,
        salt: $salt,
        keyId: $keyId,
    ));

    // ---- the check that makes these vectors authoritative --------------
    // Round-trip through the real public API. If the steps above ever drift
    // from what the library does, this throws and no vector is published.
    $options = ['key' => VECTOR_KEY, 'method' => $method];

    if ($keyId !== null) {
        $options['key_id'] = $keyId;
    }

    $recovered = (new Cryptman($options))->decrypt($payload, $aad);

    if ($recovered !== $plaintext) {
        throw new RuntimeException("vector for {$method} does not round-trip");
    }

    return [
        'method' => $method,
        'algorithm_id' => sprintf('0x%02X', $algorithmId),
        'key_id' => $keyId,
        'plaintext' => $plaintext,
        'associated_data' => $aad,
        'salt_hex' => bin2hex($salt),
        'nonce_hex' => bin2hex($nonce),
        'encryption_key_hex' => bin2hex($encryptionKey),
        'message_key_hex' => bin2hex($messageKey),
        'aad_hex' => bin2hex($associatedData),
        'payload' => $payload,
    ];
}

$cases = [];

foreach (['xchacha20-poly1305', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305'] as $method) {
    $cases[] = vector($method, 'Loose lips sink ships', null, null);
}

$cases[] = vector('xchacha20-poly1305', 'Loose lips sink ships', 'tenant:42', null);
$cases[] = vector('xchacha20-poly1305', 'Loose lips sink ships', null, 'ck_example');
$cases[] = vector('xchacha20-poly1305', 'Loose lips sink ships', 'tenant:42', 'ck_example');
$cases[] = vector('xchacha20-poly1305', '', null, null);

if (in_array('--json', $argv, true)) {
    echo json_encode($cases, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit(0);
}

foreach ($cases as $case) {
    printf("### %s%s%s\n\n", $case['method'],
        $case['key_id'] !== null ? ', with key id' : '',
        $case['associated_data'] !== null ? ', with associated data' : ''
    );
    printf("```text\n");
    printf("algorithm id        %s\n", $case['algorithm_id']);
    printf("plaintext           %s\n", var_export($case['plaintext'], true));
    printf("associated data     %s\n", var_export($case['associated_data'], true));
    printf("key id              %s\n", var_export($case['key_id'], true));
    printf("salt                %s\n", $case['salt_hex'] === '' ? '(none)' : $case['salt_hex']);
    printf("nonce               %s\n", $case['nonce_hex']);
    printf("encryption key      %s\n", $case['encryption_key_hex']);
    printf("message key         %s\n", $case['message_key_hex']);
    printf("AAD (hex)           %s\n", $case['aad_hex']);
    printf("payload             %s\n", $case['payload']);
    printf("```\n\n");
}
