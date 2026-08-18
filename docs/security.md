# Security

[← README](../README.md)

## Do not use Cryptman for passwords

```php
password_hash($password, PASSWORD_DEFAULT);   // ✅ passwords
password_verify($password, $hash);
```

Passwords must be hashed, not encrypted — encryption is reversible, and that is
exactly what you do not want.

**Appropriate uses:** API keys, OAuth secrets, access credentials, private
configuration, sensitive database fields, integration secrets.

## Threat model

### Defended against

An attacker who obtains ciphertext but not the key — the
database-exfiltration case this package exists for:

- **Confidentiality** — ciphertext reveals nothing about plaintext beyond its
  approximate length
- **Integrity** — any modification causes decryption to fail rather than return
  altered plaintext
- **Relocation** — with [associated data](configuration.md#associated-data), a
  value valid in one context fails in another
- **Malformed input** — arbitrary, truncated or mutated payloads fail cleanly
  without crashing the process
- **Wrong key** — including every key in a rotation ring

### Not defended against

Stated explicitly so the documentation does not imply protection Cryptman
cannot provide:

- **Key compromise.** Anyone with the key reads everything. Cryptman does not
  manage key storage; that is the application's responsibility.
- **Length leakage.** Both constructions are length-preserving, so ciphertext
  length reveals plaintext length. For low-entropy values — a boolean, a short
  enum, a national ID — that can be enough to infer content. There is no
  padding.
- **Traffic and access-pattern analysis.** Which record was read, and when.
- **Host compromise.** Memory disclosure, core dumps, a hostile PHP extension,
  or a compromised interpreter.
- **Side channels.** Cryptman relies on the constant-time properties of
  libsodium and OpenSSL and adds no timing defences of its own.
- **Plaintext equality.** Random nonces mean identical plaintexts produce
  distinct ciphertexts, so equality is not directly observable — but Cryptman
  offers no searchable or deterministic mode, and applications must not attempt
  to build one by fixing a nonce.

### Legacy caveat

None of the integrity guarantees apply to v1 payloads. Legacy decryption is
unauthenticated by construction, and the UTF-8 guard described in
[upgrading](upgrading.md#legacystrict) is a usability backstop, not a security
control.

This is the central argument for completing migration rather than leaving
legacy data in place indefinitely.

## What v2 changed, and why

v1 used unauthenticated OpenSSL ciphers. Those keep data confidential but
cannot tell you whether ciphertext was modified in storage — an attacker could
alter it and the application would receive altered plaintext with no error.

v2 uses authenticated encryption throughout, so tampering fails loudly. It also
removes v1's `php_uname()` default key, which was publicly guessable. See
[upgrading](upgrading.md).

## Reporting a vulnerability

Please report security issues privately to the maintainer rather than opening a
public issue.
