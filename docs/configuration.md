# Configuration

[← README](../README.md)

Everything here is optional. `new Cryptman(['key' => $key])` is a complete,
secure configuration.

```php
new Davmixcool\Cryptman([
    'key'    => $key,             // required
    'method' => 'aes-256-gcm',    // optional, see below

    'previous_keys' => [$old],    // optional, key rotation

    'legacy' => [                 // optional, v1 migration only
        'key'    => $oldV1Key,    // see docs/upgrading.md
        'method' => 'aes-256-cbc',
        'strict' => true,
    ],
]);
```

## Contents

- [Keys](#keys)
- [Choosing an encryption method](#choosing-an-encryption-method)
- [Associated data](#associated-data)
- [Key rotation](#key-rotation)
- [JSON helpers](#json-helpers)
- [Exceptions](#exceptions)
- [Framework integration](#framework-integration)

## Keys

```php
$key = Davmixcool\Cryptman::generateKey();
// cman_key_xO7q...
```

Store it as an environment variable:

```
CRYPTMAN_KEY=cman_key_xO7q...
```

The `cman_key_` prefix makes the value recognisable in a config file or log,
and lets Cryptman reject a truncated or corrupted key instead of silently
treating it as a passphrase.

A plain passphrase works too — it is stretched with HKDF-SHA256 — but a
generated key carries 32 bytes of real entropy and a passphrase usually does
not.

**There is no default key.** Constructing without one throws
`InvalidKeyException`.

## Choosing an encryption method

**If you have no specific reason, do not set `method` at all.**

| method | nonce | overhead | needs | choose when |
|---|---|---|---|---|
| `xchacha20-poly1305` *(default)* | 192-bit | 42 B | ext-sodium | always, unless a row below applies |
| `aes-256-gcm` | 96-bit | 62 B | OpenSSL | policy or compliance mandates AES |
| `aes-128-gcm` | 96-bit | 62 B | OpenSSL | an external profile mandates AES at 128 bits |
| `chacha20-poly1305` | 96-bit | 62 B | OpenSSL | ChaCha20 without ext-sodium, no AES-NI, or RFC 8439 interop |

```php
Davmixcool\Cryptman::supportedMethods();
```

### `chacha20-poly1305` is not `xchacha20-poly1305`

They differ by one letter and are **different algorithms**:

| | library | nonce | algorithm id |
|---|---|---|---|
| `xchacha20-poly1305` | libsodium | 192-bit | `0x01` |
| `chacha20-poly1305` | OpenSSL (RFC 8439) | 96-bit | `0x04` |

Not interchangeable — a payload written by one cannot be read by the other.

### All four are equally safe

Every method is authenticated, and none has a usage ceiling you need to track.
The three with 96-bit nonces derive a fresh key per message, which removes the
message-count limit those nonces would otherwise impose. That derivation is
what the extra 20 bytes pays for, and why the default — whose 192-bit nonce
needs none of it — is the smallest.

### Changing `method` is safe

The algorithm travels inside the payload. Changing `method` affects new writes
only; existing payloads keep their own algorithm and stay readable forever.

```php
$old = (new Cryptman(['key' => $k, 'method' => 'aes-256-gcm']))->encrypt('x');

(new Cryptman(['key' => $k]))->decrypt($old);   // still reads
```

### Why not other ciphers?

Every method is a permanent commitment — once a payload exists using it, it
must be supported forever. New **authenticated** methods can be added on
request if they are universally available. Unauthenticated ciphers (CBC, CTR,
ECB and friends) never will be: they keep data confidential but cannot detect
tampering, which is the defect v2 exists to remove.

## Associated data

Binds ciphertext to its context, so a value copied elsewhere fails to decrypt:

```php
$token = $cryptman->encrypt($apiKey, "user:{$user->id}");

$cryptman->decrypt($token, "user:{$user->id}");   // ok
$cryptman->decrypt($token, 'user:999');           // DecryptionException
$cryptman->decrypt($token);                       // DecryptionException
```

Useful when an attacker might copy one row's ciphertext into another. The
associated data is not stored — supply the same value to decrypt. An empty
string counts as none.

## Key rotation

```php
new Cryptman([
    'key'           => $currentKey,
    'previous_keys' => [$lastYearsKey, $theOneBeforeThat],
]);
```

Encryption always uses the current key. Decryption tries the current key first,
then each previous key in order.

**Rotation covers v2 payloads only.** v1 is unauthenticated: a wrong key
returns plausible-looking garbage rather than failing, so trying several keys
cannot tell success from corruption. Legacy reads use a single designated key —
see [upgrading](upgrading.md).

## JSON helpers

```php
$encrypted = $cryptman->encryptJson(['api_key' => 'abc', 'account_id' => 123]);
$data      = $cryptman->decryptJson($encrypted);
```

Uses JSON, never `serialize()` — decrypting an untrusted serialized payload is
an object-injection surface.

## Exceptions

```php
use Davmixcool\Cryptman\Exceptions\CryptmanException;
use Davmixcool\Cryptman\Exceptions\DecryptionException;

try {
    $plain = $cryptman->decrypt($payload);
} catch (DecryptionException $e) {
    // tampered, wrong key, or wrong associated data
} catch (CryptmanException $e) {
    // anything else this library throws
}
```

**Decryption never returns `false`.** Every failure raises. v1 returned
`false`, which callers routinely mistook for an empty value.

| exception | meaning |
|---|---|
| `CryptmanException` | interface implemented by all of the below |
| `EncryptionException` | encryption failed |
| `DecryptionException` | tampered, wrong key, or wrong associated data |
| `LegacyDecryptionException` | a v1 read failed — usually a wrong `legacy.method` |
| `InvalidKeyException` | key missing, empty, or malformed |
| `InvalidPayloadException` | payload empty, truncated, or not valid base64url |
| `InvalidConfigurationException` | contradictory or unrecognised options |
| `UnsupportedDriverException` | method unavailable, or payload from a newer Cryptman |
| `UnsupportedVersionException` | payload format from a newer Cryptman |
| `EnvironmentException` | required extension or cipher missing from this build |

`LegacyDecryptionException` extends `DecryptionException`, so catching the
parent covers both. Catch the child specifically during migration — it means
stop and fix configuration, not retry.

Exception messages never contain key material or plaintext.

## Framework integration

Cryptman is framework-agnostic. A first-party Laravel integration is planned
but **not yet shipped**; bind it yourself:

```php
// AppServiceProvider::register()
$this->app->singleton(Cryptman::class, fn () => new Cryptman([
    'key' => env('CRYPTMAN_KEY'),
]));
```
