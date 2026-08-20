# Changelog

Notable changes to `davmixcool/cryptman`.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — 2.1.0

Key ids: an optional label recording *which* key encrypted a value.

**Nothing about 2.0.0 changes.** Existing payloads decrypt unchanged, and with
no `key_id` configured this version writes byte-identical output — so 2.0.0 and
2.1 interoperate freely until you opt in.

### Added

- **Key ids.** Set `key_id` and payloads become `cman2.<key_id>.<body>`,
  recording which key wrote each value:

  ```php
  new Cryptman([
      'key'    => $current,
      'key_id' => 'ck_01J6ABCDEF',
      'previous_keys' => ['ck_01J5ZYXWVU' => $old],
  ]);
  ```

  This exists so you can answer *"which rows still need this key?"* with a
  grouped count over a column — no keys held, no plaintext produced — instead of
  trial-decrypting every row. That is what makes retiring a key provable rather
  than assumed. See [docs/configuration.md](docs/configuration.md#key-ids).

- **`previous_keys` accepts an `id => key` map**, alongside the existing plain
  list. A mixed array is rejected rather than half-honoured.

- **`Cryptman::generateKeyId()`** and **`cryptman key:generate --id`**, producing
  opaque ids. Opaque on purpose: an id like `ck_prod_2026_08` travels in
  cleartext beside every value and tells anyone reading the column which
  environment they found and how old the key is.

- **`inspect` gained a `key_id` column**, so an operator can see which key wrote
  a payload without holding any key material.

- **[SPEC.md](SPEC.md)** — a language-neutral specification of the `cman2`
  payload format, with test vectors, so Cryptman can be implemented in other
  languages. The vectors are generated from the shipping code and verified
  through its public API, and a test decrypts the ones published in the document
  so it cannot drift. Regenerate with `composer spec:vectors`.

### Changed

- **`describe()` and `inspect()` now return a `key_id`.** It is read from the
  *payload*. `inspect()` previously reported the currently-configured key's id,
  which described the caller rather than the payload; it read as `null` in every
  real call, so nothing depended on it.

- **`DriverInterface::encrypt()` takes a fourth `?string $keyId` argument.**
  Only relevant if you implemented the interface yourself — the four bundled
  drivers are unaffected.

### Security

- **The key id is authenticated.** It is not secret, but it is covered by the
  AEAD associated data, so it cannot be rewritten to misdirect migration
  accounting without failing authentication. It is length-prefixed rather than
  separator-delimited so caller-supplied associated data cannot forge its
  framing.

### Compatibility

- Payloads written by 2.0.0 decrypt unchanged — verified against the published
  2.0.0 release across all four algorithms, with and without associated data.
- With no `key_id` set, output is byte-identical to 2.0.0.
- **A reader on 2.0.0 cannot read a payload carrying a key id.** It fails loudly
  with `InvalidPayloadException`, never silently. If several applications share
  an encrypted column, upgrade all of them before setting `key_id` on any writer.

---

## [2.0.0] — 2026-08-19

Cryptman v2 replaces the encryption underneath and keeps the API. **Data
written by v1 is still readable.** Start with [docs/upgrading.md](docs/upgrading.md);
there are two things to check before deploying.

### Breaking

- **PHP 8.2 is now the minimum**, up from 5.5. Composer will not offer 2.x to
  older runtimes — they stay on 1.x and nothing breaks.
- **There is no default key.** v1 fell back to `php_uname()`, a publicly
  guessable value that left data effectively unencrypted. Constructing without
  a key now throws `InvalidKeyException`. If you have data encrypted that way,
  treat it as compromised and re-encrypt it.
- **`decrypt()` throws instead of returning `false`.** A falsy return is
  silently mistakable for plaintext, which is the defect this release exists to
  remove. See the exception table in [docs/configuration.md](docs/configuration.md).
- **An unrecognised cipher throws instead of calling `die()`.** A library must
  not terminate the host process.
- **v1 ciphers can no longer encrypt.** Reading is fully compatible — every
  cipher v1 accepted, which is anything `openssl_get_cipher_methods()` returns.
  Writing is authenticated-only. A v1 cipher name in `method` is read as legacy
  configuration, with a deprecation notice.
- **`legacy.strict` must be a real boolean.** A string is rejected rather than
  cast, because `(bool) 'false'` is `true` in PHP — silently the opposite of
  what was written.

### Added

- **Four authenticated methods**, all interchangeable at the API level:
  `xchacha20-poly1305` (default, libsodium), `aes-256-gcm`, `aes-128-gcm` and
  `chacha20-poly1305` (OpenSSL). See
  [Choosing an encryption method](docs/configuration.md#choosing-an-encryption-method).
- **A command line tool** — `vendor/bin/cryptman` with `key:generate`,
  `inspect` and `upgrade --dry-run`. Keys are read from the environment, never
  from arguments. See [docs/cli.md](docs/cli.md).
- **Associated data**, binding a payload to its context so a value copied
  elsewhere fails to decrypt.
- **Key rotation** via `previous_keys`. v2 payloads only — v1 is
  unauthenticated, so trial decryption cannot tell a wrong key from corruption.
- **Migration helpers** — `needsUpgrade()`, `upgrade()`, `version()`,
  `inspect()`, and the static `describe()`, which needs no key or instance.
- `generateKey()`, `supportedMethods()`, `encryptJson()`, `decryptJson()`.
- **A typed exception hierarchy** rooted at the `CryptmanException` interface,
  so each exception also extends the SPL type that describes it.
- **Documentation** — configuration, upgrading, security and CLI references,
  including a threat model stating what Cryptman does *not* defend against.

### Security

- **Encryption is now authenticated.** v1's ciphers kept data confidential but
  could not detect modification; an attacker could alter ciphertext and the
  application would receive altered plaintext with no error.
- **Per-message subkeys** for the three methods with 96-bit nonces, removing
  the ~2³² message bound those nonces would otherwise impose.
- **Key material is kept out of `var_dump()`, `print_r()`, string
  interpolation, exception messages and stack traces**, and serialization is
  refused outright.
- **The CLI never accepts a key as an argument** — process arguments are
  visible to other users via `ps`. Error messages print option names, never
  values.

### Performance

- `isAvailable()` no longer rebuilds the OpenSSL cipher list on every call,
  which had made decryption roughly ten times slower than encryption for the
  OpenSSL methods. Run `composer benchmark` to measure on your own hardware.

---

## [1.1.0] — 2026-08-18

Final 1.x release. Security warning only; no behaviour changed.

### Security

- Constructing without a `key` now raises `E_USER_WARNING`. The fallback to
  `php_uname()` still works — removing it would break anyone relying on it, and
  a maintenance release on a legacy branch must not do that. **The fix is to
  pass an explicit key**, which works on 1.x today and needs no upgrade.

### Changed

- An unrecognised cipher method throws `InvalidArgumentException` instead of
  calling `die()`.

### Deprecated

- 1.x is maintenance-only and receives security fixes only.

---

## [1.0.0] — 2019-03-13

Initial release. Two-way encryption via OpenSSL, with a configurable cipher
method.

[Unreleased]: https://github.com/davmixcool/cryptman/compare/v2.0.0...master
[2.0.0]: https://github.com/davmixcool/cryptman/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/davmixcool/cryptman/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/davmixcool/cryptman/releases/tag/v1.0.0
