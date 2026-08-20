# Cryptman Payload Format Specification

**Format version 2** · This document describes `cman2` payloads precisely enough
to implement Cryptman in any language.

The reference implementation is [`davmixcool/cryptman`](https://github.com/davmixcool/cryptman)
(PHP). Where this document and that implementation disagree, **this document is
wrong** and should be reported as a bug — the test vectors in
[Test vectors](#test-vectors) are generated from the shipping code and verified
through its public API, so they cannot drift.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Contents

- [Scope](#scope)
- [Notation](#notation)
- [Wire format](#wire-format)
- [Algorithms](#algorithms)
- [Key derivation](#key-derivation)
- [Associated data](#associated-data)
- [Encryption](#encryption)
- [Decryption](#decryption)
- [Key ids](#key-ids)
- [Error handling](#error-handling)
- [What is frozen](#what-is-frozen)
- [Test vectors](#test-vectors)

## Scope

This specifies the `cman2` payload format: how a plaintext becomes a string safe
to store in a database column, and how to reverse that.

**Out of scope:** key storage, key distribution, and the Cryptman v1 format.
v1 payloads are unauthenticated and are detected only by the *absence* of the
`cman2.` prefix; an implementation MAY decline to support them entirely.

## Notation

- `||` denotes concatenation.
- `x[a..b]` denotes bytes `a` inclusive to `b` exclusive, zero-indexed.
- Byte values are written `0x` hexadecimal.
- "Random" means a cryptographically secure random source. An implementation
  MUST NOT use a non-cryptographic PRNG for nonces, salts, or keys.

## Wire format

A payload is ASCII text in one of two shapes:

```text
cman2.<body>                    unkeyed
cman2.<key_id>.<body>           keyed
```

- `cman2.` is a literal, case-sensitive prefix.
- `<key_id>` is an optional identifier — see [Key ids](#key-ids).
- `<body>` is base64url of the binary frame below.

Because base64url never emits `.`, counting separators is sufficient to
distinguish the two shapes. An implementation MUST reject a payload containing
more than two separators.

### base64url

Base64 using the URL-safe alphabet (`-` and `_` replacing `+` and `/`), **with
padding removed**. Encoders MUST NOT emit `=`. Decoders MUST reject any
character outside `[A-Za-z0-9_-]`, and MUST reject an empty body.

### The binary frame

```text
header (2 bytes) || salt (0 or 32 bytes) || nonce (12 or 24 bytes) || ciphertext_with_tag
```

| offset | length | field |
|---|---|---|
| 0 | 1 | format version — MUST be `0x02` |
| 1 | 1 | algorithm id |
| 2 | 0 or 32 | salt, present only where the algorithm requires it |
| 2 + salt | 12 or 24 | nonce |
| 2 + salt + nonce | rest | ciphertext with the 16-byte authentication tag appended |

**No field is length-prefixed.** Every length is implied by the algorithm id,
which removes any possibility of an attacker-supplied length disagreeing with
the actual data.

The authentication tag is 16 bytes for every algorithm and is appended to the
ciphertext, matching libsodium's combined-mode output. Implementations built on
APIs that return the tag separately MUST append it.

The ciphertext MAY be empty: encrypting an empty plaintext is valid and produces
a frame consisting of header, salt, nonce and tag alone.

## Algorithms

| id | name | nonce | salt | subkey | frame overhead |
|---|---|---|---|---|---|
| `0x01` | `xchacha20-poly1305` | 24 | 0 | no | 42 B |
| `0x02` | `aes-256-gcm` | 12 | 32 | yes | 62 B |
| `0x03` | `aes-128-gcm` | 12 | 32 | yes | 62 B |
| `0x04` | `chacha20-poly1305` | 12 | 32 | yes | 62 B |

`0x01` and `0x04` are **different algorithms** despite similar names. `0x01` is
XChaCha20-Poly1305 (192-bit nonce, libsodium). `0x04` is ChaCha20-Poly1305 as
specified in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) (96-bit nonce).
They are not interchangeable.

### Implementing XChaCha20-Poly1305 without libsodium

Implementations with libsodium (or an equivalent binding) SHOULD use its
`crypto_aead_xchacha20poly1305_ietf` functions directly and can skip this.

XChaCha20-Poly1305 is not an independent primitive: it is RFC 8439
ChaCha20-Poly1305 preceded by a nonce-extension step, specified in
[draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03).
Given the 32-byte key and the 24-byte nonce from the frame:

1. `subkey = HChaCha20(key, nonce[0..16])` — the ChaCha20 core over the key and
   the first 16 nonce bytes, 20 rounds, emitting words 0–3 and 12–15 of the
   final state **without** the customary feed-forward addition.
2. `ietf_nonce = 0x00000000 || nonce[16..24]` — four zero bytes followed by the
   remaining 8 nonce bytes.
3. Run standard ChaCha20-Poly1305 with `subkey` and `ietf_nonce`.

The omitted feed-forward in step 1 is the detail most independent
implementations get wrong; HChaCha20 is not ChaCha20 with a truncated output.

An implementation MUST reject an unknown algorithm id rather than guess, and
SHOULD report it distinctly from a malformed payload — a well-formed frame
carrying an unknown id usually means the reader is older than the writer.

**Algorithm ids are append-only.** An id, once published, names one algorithm
forever, because payloads carrying it exist and must stay readable.

## Key derivation

All derivation is HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)).

### Input key material

Configuration supplies either a generated key or an arbitrary passphrase.

A **generated key** has the form `cman_key_<base64url>` and MUST decode to
exactly 32 bytes; those 32 bytes are the input key material. A value carrying
the prefix that fails either check MUST be rejected rather than silently treated
as a passphrase.

Anything else is a **passphrase**, used as its raw bytes. HKDF handles the
non-uniformity.

Empty input key material MUST be rejected.

### Encryption key

```text
encryption_key = HKDF-SHA256(
    ikm    = input_key_material,
    salt   = ""                        (empty)
    info   = "cryptman-v2-encryption",
    length = 32
)
```

The salt is deliberately empty so the key is reproducible from configuration
alone, with no per-payload state. Domain separation is carried entirely by
`info`.

### Message key

Algorithms with a 96-bit nonce (`0x02`, `0x03`, `0x04`) derive a fresh key per
message. Random 96-bit nonces carry a birthday bound around 2³² messages, and a
collision under GCM or Poly1305 is catastrophic rather than graceful — it can
expose the authentication subkey. A per-message key removes the bound.

```text
message_key = HKDF-SHA256(
    ikm    = encryption_key,
    salt   = <the 32-byte salt from the frame>,
    info   = <per-algorithm string, below>,
    length = <16 for 0x03, otherwise 32>
)
```

| id | info | length |
|---|---|---|
| `0x02` | `cryptman-v2-aesgcm-message` | 32 |
| `0x03` | `cryptman-v2-aes128gcm-message` | 16 |
| `0x04` | `cryptman-v2-chacha20poly1305-message` | 32 |

`0x01` performs **no** per-message derivation. Its 192-bit nonce makes random
selection safe indefinitely, so it uses `encryption_key` directly.

> **Why each algorithm has its own `info` string.** HKDF output at length 16 is
> a byte-for-byte prefix of output at length 32 for identical
> `(ikm, salt, info)`. A shared string would therefore give `aes-128-gcm` a
> prefix of `aes-256-gcm`'s key, and `chacha20-poly1305` an identical one — the
> same bytes serving as two different algorithms' keys. Implementations MUST use
> the exact strings above.

## Associated data

Every payload authenticates its own header, so version and algorithm cannot be
altered independently of the ciphertext. The AEAD associated data is:

```text
AAD = header
      || ( key_id  present ? len(key_id) || key_id : "" )
      || ( caller_data non-empty ? 0x00 || caller_data : "" )
```

where `len(key_id)` is a single byte holding the id's length in bytes.

Three consequences an implementation MUST preserve:

1. **With no key id and no caller data, the AAD is exactly the 2-byte header.**
2. **The key id is length-prefixed, not separator-delimited.** A length byte is
   always `>= 0x01` because empty ids are invalid, while the caller-data
   separator is exactly `0x00`. This makes the two unambiguous with no
   lookahead, and prevents caller data such as `"ck_live\x00..."` from forging
   the framing of a keyed payload.
3. **Empty caller data is identical to absent caller data.** Distinguishing them
   would make `encrypt(d)` and `encrypt(d, "")` produce mutually undecryptable
   payloads.

Caller-supplied associated data is **not stored** in the payload. The same value
must be supplied to decrypt.

## Encryption

1. Reject empty input key material; derive `encryption_key`.
2. Select the algorithm; look up its nonce and salt lengths.
3. If the algorithm uses a salt, generate 32 random bytes; otherwise the salt is
   empty.
4. Generate a random nonce of the algorithm's nonce length. A nonce MUST NOT be
   reused with the same key.
5. Derive `message_key` if the algorithm requires one; otherwise use
   `encryption_key`.
6. Build the header and compute the AAD.
7. Perform the AEAD encryption, producing ciphertext with a 16-byte tag
   appended.
8. Assemble the frame and encode: `cman2.` `[key_id .]` base64url(frame).

## Decryption

Decryption operates on untrusted input. Every step below MUST fail with a typed
error rather than crash, read out of bounds, or return a partially decoded
result.

1. Reject an empty payload.
2. Verify the `cman2.` prefix. Absence means the value is not a v2 payload.
3. Split the remainder on `.`. Two parts means a key id is present; validate it
   before use. More than two separators MUST be rejected.
4. base64url-decode the body; reject invalid characters or an empty body.
5. Require at least 2 bytes; read the version byte and reject anything but
   `0x02`. **Version MUST be checked before algorithm**, because a future format
   may reuse algorithm ids with different meanings.
6. Read the algorithm id and reject unknown values.
7. Require at least `2 + salt + nonce + 16` bytes.
8. Slice salt, nonce and ciphertext by the algorithm's fixed lengths.
9. Derive the message key if required.
10. Recompute the AAD and perform the AEAD decryption. Authentication failure
    MUST be reported as a failure, never as empty or partial plaintext.

**Failure MUST NOT be signalled by a falsy return value.** Returning something
indistinguishable from valid plaintext is the defect this format exists to
remove.

Where a key ring is available:

- If the payload names a key the ring holds, that key MUST be used and failure
  under it reported as failure. Falling through to other keys would make the id
  advisory rather than authoritative and would mask misconfiguration.
- If the payload names an unknown key, or names none, an implementation MAY try
  each available key in turn. This is safe only because AEAD failure is
  unambiguous.

## Key ids

A key id records which key encrypted a value. It is optional, **not secret**, and
travels in cleartext.

- MUST match `[A-Za-z0-9_-]`, 1 to 64 characters.
- MUST NOT contain `.`.
- MUST be unique within a key ring.
- MUST NOT contain, encode, or be derived from the key.
- MUST be validated on decode, before use — it is attacker-controlled text.

Implementations SHOULD generate opaque ids. A descriptive id such as
`ck_prod_2026_08` sits beside every value it encrypted and reveals the
environment and the key's approximate age to anyone who can read the column.
The reference implementation emits `ck_` followed by base64url of 16 random
bytes.

Omitting the key id produces byte-identical output to a Cryptman 2.0.0 writer,
which is what allows keyed and unkeyed readers to share a column during a
rollout. Note that a reader predating key id support will **reject** a keyed
payload as malformed.

## Error handling

An implementation MUST distinguish at least:

| condition | why it is distinct |
|---|---|
| malformed payload | structurally broken — truncation, bad base64, bad key id |
| unsupported version | well-formed but written by a newer implementation |
| unknown algorithm | well-formed but the reader does not know the algorithm |
| authentication failure | tampering, wrong key, or wrong associated data |

Conflating "written by something newer" with "corrupt" sends operators hunting
for data loss when the answer is to upgrade the reader.

Error messages MUST NOT include key material, plaintext, or derived keys.

## What is frozen

Changing any of the following makes existing payloads permanently unreadable.
None may change within format version 2:

- the `cman2.` prefix and the `0x02` version byte
- the algorithm id table, including each id's nonce and salt geometry
- the three `info` strings and `cryptman-v2-encryption`
- the empty HKDF salt for the encryption key
- HKDF-SHA256 as the derivation function, and 32 bytes as the encryption key
  length
- the AAD construction, including the `0x00` separator and the key id length
  prefix
- base64url without padding

New algorithms MAY be added by allocating a new id. A change to anything above
requires a new format version and a new prefix.

## Test vectors

Generated by `tools/generate-spec-vectors.php` and verified through the
reference implementation's public `decrypt()` on every run, so they cannot drift
from the shipping code.

All vectors use this fixed, non-secret, committed key:

```text
cman_key_KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio
```

which decodes to 32 bytes of `0x2a`. **Never use it for anything real.**

Nonce and salt are fixed to the repeating pattern `00 01 02 ... 0f` so a vector
is reproducible; a real implementation MUST generate both randomly.

A conforming implementation given the key, plaintext, associated data, key id,
salt and nonce below MUST produce the stated payload byte-for-byte. The
intermediate values are published so a mismatch can be localised rather than
merely observed.

### xchacha20-poly1305

```text
algorithm id        0x01
plaintext           'Loose lips sink ships'
associated data     NULL
key id              NULL
salt                (none)
nonce               000102030405060708090a0b0c0d0e0f0001020304050607
encryption key      3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
message key         3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
AAD (hex)           0201
payload             cman2.AgEAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgdL6n76IgnSqDOJDR6vuOokftrzoJiboPULybyGlh3FFuhLQ9mK
```

### aes-256-gcm

```text
algorithm id        0x02
plaintext           'Loose lips sink ships'
associated data     NULL
key id              NULL
salt                000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
nonce               000102030405060708090a0b
encryption key      3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
message key         af1bea3ca43bd94e4af5cb2324979d374c85606e537f7ed66622055034ad8ca5
AAD (hex)           0202
payload             cman2.AgIAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCxNpyAgKnvGjmPYJMz5PAazzwZoV9aPVAPXs8f_A3Df-RhlxKGQ
```

### aes-128-gcm

```text
algorithm id        0x03
plaintext           'Loose lips sink ships'
associated data     NULL
key id              NULL
salt                000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
nonce               000102030405060708090a0b
encryption key      3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
message key         f1df65da76d8c27941e9a93eabe39fef
AAD (hex)           0203
payload             cman2.AgMAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKC-X9_KmqUgiosuOihbcjgOuBBSdEWmTYdlzekDjSBfW6NFsylws
```

### chacha20-poly1305

```text
algorithm id        0x04
plaintext           'Loose lips sink ships'
associated data     NULL
key id              NULL
salt                000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
nonce               000102030405060708090a0b
encryption key      3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
message key         4ef7c369762a38c1c5ff9f53525e30afc548d2730cf21fa575f86eadad477490
AAD (hex)           0204
payload             cman2.AgQAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKC6oIWEOSsHMn9zf-LIccYA535rBoquL7QzH1nqAD0x99SzmmzRI
```

### xchacha20-poly1305, with associated data

```text
algorithm id        0x01
plaintext           'Loose lips sink ships'
associated data     'tenant:42'
key id              NULL
salt                (none)
nonce               000102030405060708090a0b0c0d0e0f0001020304050607
encryption key      3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
message key         3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
AAD (hex)           02010074656e616e743a3432
payload             cman2.AgEAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgdL6n76IgnSqDOJDR6vuOokftrzoJhJWvMuBFYC0DI0QGJjENCm
```

### xchacha20-poly1305, with key id

```text
algorithm id        0x01
plaintext           'Loose lips sink ships'
associated data     NULL
key id              'ck_example'
salt                (none)
nonce               000102030405060708090a0b0c0d0e0f0001020304050607
encryption key      3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
message key         3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
AAD (hex)           02010a636b5f6578616d706c65
payload             cman2.ck_example.AgEAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgdL6n76IgnSqDOJDR6vuOokftrzoJioNgW_ZX_ysMLqdgr4yqkv
```

### xchacha20-poly1305, with key id, with associated data

```text
algorithm id        0x01
plaintext           'Loose lips sink ships'
associated data     'tenant:42'
key id              'ck_example'
salt                (none)
nonce               000102030405060708090a0b0c0d0e0f0001020304050607
encryption key      3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
message key         3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
AAD (hex)           02010a636b5f6578616d706c650074656e616e743a3432
payload             cman2.ck_example.AgEAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgdL6n76IgnSqDOJDR6vuOokftrzoJjbmfxRSsiWbZKNSFj6uAKU
```

### xchacha20-poly1305

```text
algorithm id        0x01
plaintext           ''
associated data     NULL
key id              NULL
salt                (none)
nonce               000102030405060708090a0b0c0d0e0f0001020304050607
encryption key      3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
message key         3a023fbe9d24e7a8550c3dee0f8f027f908a1b19b1db69fb94e8159b6ab094bd
AAD (hex)           0201
payload             cman2.AgEAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgeTSeSAHk5wqg8o76CvW272
```

