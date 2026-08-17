# v1 Compatibility Corpus — FROZEN

`v1-corpus.json` is a frozen record of exactly what Cryptman **v1.0.0** does.
It is the evidence behind v2's headline promise: existing v1 ciphertext stays
decryptable after upgrade.

## The rule

**Never modify or remove an existing fixture.** New fixtures may be appended
with new ids. That is the only permitted change.

Regenerating this file is a **breaking change to the compatibility contract**,
not a refresh. If a fixture starts failing, the correct response is to fix the
code — the fixture is the specification, and it is right by definition.

`tools/generate-v1-corpus.php` refuses to overwrite an existing corpus. That
guard is deliberate. Do not route around it.

## Provenance

Generated from tag `v1.0.0` = commit `44ee2023ef5d1b26c64da8317ae93738ebea410d`,
which at the time of freezing was also `master` and the only published version
of the package. The generator reads v1 source **out of the tag**, never the
working tree, because `master` becomes v2 — a generator reading `src/` would
silently start producing v2 output.

Three independent provenance checks run on every generation:

1. the tag resolves to the expected commit;
2. source is read from the tag's tree, not the index or working tree;
3. every file's git blob hash matches a pinned constant.

The envelope records all three in `source.{tag,commit,blobs}`.

## Why the IVs are derived, not random

v1 uses `openssl_random_pseudo_bytes()` for IVs, so its output is
non-deterministic. The generator shadows that function — via a namespaced
function declaration, with **no modification to v1 source** — and derives each
IV as:

```
substr(hash_hmac('sha256', <fixture id>, 'cryptman/v1-corpus/iv/v1', true), 0, 16)
```

"Frozen forever" and "reproducible" are complements, not opposites. A
deterministic corpus can be **re-derived**:

```bash
php tools/generate-v1-corpus.php --verify-only
```

That converts "trust this file" into "verify this file", giving an integrity
axis independent of `v1-corpus.sha256`. With random IVs the corpus could only
ever be re-validated (does it still decrypt?), never re-derived — so a fixture
edited to weaken a case would be undetectable by any mechanism other than the
checksum.

The second reason is concrete. The `neg/cbc-token-read-as-default-ctr/short`
fixture has a measured **~0.02% chance** of producing valid-UTF-8 garbage.
Frozen, that is a fact verified once. Random, it is a 1-in-5000 CI flake that
fires months later and gets "fixed" by someone who does not understand it.

**Fixture ids are load-bearing.** They are the HMAC input, so renaming an id
changes its IV and invalidates its token. Ids are append-only too.

### The `wild/*` tier

Four fixtures use real `openssl_random_pseudo_bytes` IVs from unmodified v1,
proving genuine production tokens decode. They are marked `"iv": "wild"` and
are the one part of the corpus that is not re-derivable, so `--verify-only`
skips them.

## Schema notes

- Any field whose name ends `_b64` is standard base64 of raw bytes. No
  exceptions, no "raw if printable" shortcuts.
- `token` is stored literally — v1 guarantees it is printable ASCII by
  construction (hex IV + base64 body), and double-encoding the most-inspected
  field would destroy its readability.
- `method: null` means the option was **omitted** from the constructor,
  exercising v1's `aes-128-ctr` default.
- `v1_result` is a **tagged union**: `{"type":"false"}` or
  `{"type":"string","value_b64":…}`. v1 returns strict `false` on some inputs
  and `''` on others, and these are not interchangeable — see the empty-plaintext
  quirk below.
- A negative fixture is simply one where `decrypt_with` differs from
  `encrypt_with`. Positives and negatives share one shape so the test has a
  single code path.

## v1 behaviours this corpus pins

- **Empty plaintext does not round-trip under CTR.** Encryption yields a bare
  32-char hex IV; `Decrypt`'s `/^(.{32})(.+)$/` needs at least one body
  character, so it returns strict `false`. Under CBC, padding produces a block
  and it returns `''`. Two different truths per cipher family.
- **A printable key always becomes a 32-byte SHA-256**, regardless of length.
  Key length is only a variable on the raw branch.
- **`ctype_print("café")` is false** — accented passphrases silently take the
  raw branch. So does an empty key.
- **A wrong key cannot be detected under CTR.** It returns a garbage string,
  never `false`. Under CBC the padding check catches it roughly 255 times in
  256. This asymmetry is why key rotation by trial decryption is unsound for v1
  payloads, and it is the structural argument for AEAD in v2.
- **The cipher method is not recoverable from a token.** All four methods use a
  16-byte IV, so the hex prefix does not discriminate.

## Regeneration, if it is ever genuinely necessary

Requires a full clone with tags — `git show v1.0.0:…` will not work against a
shallow `fetch-depth: 1` checkout. Since regeneration is banned, this is
documentation rather than a constraint.

JSON is emitted with `JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES |
JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR`, fixtures sorted by id, trailing
newline. Changing those flags breaks `--verify-only` for no reason.
