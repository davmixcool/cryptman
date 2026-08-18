# Upgrading from Cryptman v1

[← README](../README.md)

**Your existing code keeps working.** The constructor, `cipher()`, `encrypt()`
and `decrypt()` are unchanged, and v2 still reads everything v1 wrote.

Two things to check before you deploy, both of which are silent in v1
configuration.

## Pre-upgrade checklist

```
Did your v1 config set 'key'?
    no  → your data is at risk — read "The php_uname default" below

Did your v1 config set 'method'?
    yes → carry it over as legacy.method
    no  → nothing to do

Are you rotating keys?
    yes → rotation does not cover v1 payloads

Does anything ELSE read this column?
    yes → upgrade every reader first — see "Mixed deployments"
```

## The `php_uname()` default

If v1 was constructed without a `key`, it fell back to `php_uname()` — a
publicly guessable description of the host operating system. Anyone who can
guess your platform can derive the key, so that data offers no real protection.

v2 throws `InvalidKeyException` rather than continuing. To recover the data,
pass the original value explicitly:

```php
// only works on the SAME host — php_uname() differs per machine
$old   = new Cryptman(['key' => php_uname()]);
$plain = $old->cipher($ciphertext)->decrypt();

$new = new Cryptman(['key' => $realKey]);
$ciphertext = $new->encrypt($plain);
```

Treat anything encrypted this way as compromised.

## Reading v1 data

Nothing is required if v1 used the default cipher:

```php
new Cryptman(['key' => $key]);   // reads v1 default-method data already
```

If v1 was configured with a `method`, carry that value over:

```php
new Cryptman([
    'key'    => $key,
    'legacy' => [
        'key'    => $oldV1Key,   // defaults to 'key'
        'method' => 'aes-256-cbc',
        'strict' => true,        // defaults to true
    ],
]);
```

Your existing v1 configuration also keeps working untouched — a v1 cipher name
in `method` is recognised as legacy configuration, with a deprecation notice
showing the explicit form.

The cipher method **cannot be detected from the ciphertext**. All v1 methods
used a 16-byte IV, so the payload looks identical. A wrong value returns
garbage rather than an error.

### `legacy.strict`

v1 ciphertext is unauthenticated, so a wrong legacy method cannot fail cleanly —
a stream cipher returns garbage instead of an error. As a backstop Cryptman
rejects legacy plaintext that is not valid UTF-8.

This is a usability guard, **not** authentication. It catches the common
misconfiguration and misses roughly 0.02% of short values. Set
`'strict' => false` only if your v1 plaintext is genuinely binary.

**If a legacy read fails, do not re-encrypt that value.** Fix the configuration
first. Rewriting on a failed legacy decrypt is how recoverable data becomes
unrecoverable.

## What changed deliberately

| v1 | v2 | why |
|---|---|---|
| `decrypt()` returned `false` on failure | throws | `false` is mistakable for plaintext |
| missing key defaulted to `php_uname()` | `InvalidKeyException` | the default was publicly guessable |
| unknown cipher called `die()` | `InvalidConfigurationException` | a library must not kill the process |
| any OpenSSL cipher could encrypt | authenticated only | unauthenticated ciphertext is malleable |

**Reading is fully compatible** — every cipher v1 accepted. **Writing is not:**
v2 has no way to produce v1 format, because that is the defect it exists to
remove.

## Mixed deployments

If two applications share an encrypted column and only one is upgraded, the one
still on v1 **cannot read** what v2 writes — and v1 returns `false` on every
failure, so it will quietly treat a live secret as an empty value.

**Upgrade every reader of a shared column before any writer.** There is no
option to keep writing v1 format.

## Bulk re-encryption

Lazy migration only upgrades records that are read. Cold rows stay v1
indefinitely — and those are the ones most likely to be exfiltrated wholesale
and least likely to be noticed.

`upgrade()` decrypts and re-encrypts in one call, and returns v2 payloads
unchanged, so it is safe to run repeatedly:

```php
$model->encrypted_value = $cryptman->upgrade($model->encrypted_value);
```

In a read path, handle failures explicitly:

```php
try {
    $plain = $cryptman->decrypt($value);
} catch (LegacyDecryptionException $e) {
    // legacy.method is probably wrong — do NOT rewrite this row
    report($e);
    return null;
} catch (DecryptionException $e) {
    report($e);
    return null;
}

if ($cryptman->needsUpgrade($value)) {
    $model->encrypted_value = $cryptman->encrypt($plain);
    $model->save();
}
```

Recommended sequence:

1. Deploy v2 with `legacy` configured
2. Verify a sample of legacy values decrypt as expected
3. Re-encrypt in batches
4. Confirm no `needsUpgrade()` values remain
5. **Remove the `legacy` block** — the migration is finished at this point

### Inspecting without decrypting

```php
$cryptman->version($payload);       // 1 or 2
$cryptman->needsUpgrade($payload);  // bool
$cryptman->inspect($payload);       // ['version' => 2, 'driver' => '...', 'key_id' => null]
```

## FAQ

**Do I need to re-encrypt everything after upgrading?**
No. v1 data stays readable. Re-encrypt when convenient.

**Can I still encrypt with `aes-256-cbc`?**
You can read it; you cannot write it. CBC is unauthenticated.

**Why does my v1 `'method' => 'aes-256-cbc'` config now warn?**
It is being read as legacy configuration. Old data stays readable and new data
is authenticated. Move it to `legacy.method` to silence the notice.

**Does changing `method` break existing data?**
No — the algorithm travels in the payload. See
[configuration](configuration.md#changing-method-is-safe).
