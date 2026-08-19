# Command line

[← README](../README.md)

```shell
php vendor/bin/cryptman key:generate
php vendor/bin/cryptman inspect "cman2...."
php vendor/bin/cryptman upgrade --dry-run --in=payloads.txt
```

Three commands. `key:generate` and `inspect` need no configuration at all and
run on a bare host.

## Contents

- [Keys come from the environment](#keys-come-from-the-environment)
- [`key:generate`](#keygenerate)
- [`inspect`](#inspect)
- [`upgrade`](#upgrade)
- [Exit codes](#exit-codes)
- [What the CLI cannot do](#what-the-cli-cannot-do)

## Keys come from the environment

**Cryptman never accepts a key as a command-line argument.** Process arguments
are visible to every user on the host via `ps` and `/proc`, so `--key=` is
rejected outright rather than merely undocumented.

| variable | used by | notes |
|---|---|---|
| `CRYPTMAN_KEY` | `upgrade` | required |
| `CRYPTMAN_PREVIOUS_KEYS` | `upgrade` | comma-separated, for rotation |
| `CRYPTMAN_LEGACY_KEY` | `upgrade` | defaults to `CRYPTMAN_KEY` |
| `CRYPTMAN_METHOD` | `upgrade` | overridden by `--method` |
| `CRYPTMAN_LEGACY_METHOD` | `upgrade` | overridden by `--legacy-method` |
| `CRYPTMAN_LEGACY_STRICT` | `upgrade` | `true` or `false` |

An empty value counts as unset.

## `key:generate`

```shell
export CRYPTMAN_KEY="$(php vendor/bin/cryptman key:generate)"
```

Prints a key to STDOUT and nothing else, so it composes. Any human guidance
goes to STDERR and only when you are watching, so a pipe stays clean.

## `inspect`

```shell
php vendor/bin/cryptman inspect "cman2...."      # one payload
php vendor/bin/cryptman inspect < payloads.txt   # one per line
```

Needs **no key and no configuration** — it never decrypts. One tab-separated
record per payload:

```
2	xchacha20-poly1305	no	ok
1	-	yes	ok
-	-	-	unrecognised
```

Columns: version, method, whether it needs upgrading, status.

| status | meaning |
|---|---|
| `ok` | recognised |
| `malformed` | truncated, double-encoded, or otherwise structurally broken |
| `unsupported` | written by a newer Cryptman than this build |
| `unrecognised` | not a Cryptman payload at all — a key or a plaintext, perhaps |

The header line goes to STDERR and only when interactive, so scripts never see
it. Exit 1 if any record is not `ok`.

## `upgrade`

Re-encrypts Cryptman v1 payloads as v2. One payload per line, output in input
order.

```shell
export CRYPTMAN_KEY='cman_key_...'

# 1. survey first — writes nothing
php vendor/bin/cryptman upgrade --dry-run --in=payloads.txt

# 2. then do it
php vendor/bin/cryptman upgrade --in=payloads.txt --out=upgraded.txt
```

`--in` and `--out` default to STDIN and STDOUT, so this works too:

```shell
psql -At -c 'select token from secrets order by id' \
  | php vendor/bin/cryptman upgrade > upgraded.txt
```

| flag | |
|---|---|
| `--dry-run` | decrypt and report, write nothing |
| `--continue-on-error` | process the whole file instead of stopping at the first failure |
| `--force` | allow overwriting an existing `--out` |
| `--skip-v2-check` | do not test-decrypt rows that are already v2 |
| `--method=` `--legacy-method=` `--legacy-strict=` | override the environment |

### Output is always line-aligned with input

**Every input line produces exactly one output line, including failures.**

You will zip the output back to primary keys by line number, so a row that
fails to decrypt is written back as its **original ciphertext** — not omitted,
not a placeholder. Writing that row back to your database is a no-op.

This is deliberate. It means a botched migration cannot destroy data even if
you write the results back without checking, and re-running after fixing the
configuration is safe because `upgrade()` is idempotent.

### What the dry run tells you

```
total          124312
already v2      98110
legacy          26200
empty               2
failed              0
v2 unreadable       0
```

A dry run **decrypts** — that is the point. Counting which rows *look* legacy
would report `26200 legacy / 0 failed` even when every one of them fails,
which is exactly the misconfiguration you are checking for. It writes nothing,
and it always processes the whole file.

`v2 unreadable` counts rows already in v2 format that would not decrypt under
your key. **A real run never reports these**, because it passes v2 payloads
through untouched without reading them. Finding them is the reason to dry-run
first: it means either `CRYPTMAN_KEY` is wrong for this data, or the column
uses associated data (see below).

Failures print with a line number and exception class — never the payload, and
never the plaintext. After 20, they are suppressed and summarised by class,
because a wrong `--legacy-method` produces the same message on every row.

### File safety

`--out` will not overwrite an existing file without `--force`, and will never
accept the same path as `--in` even with it. Output is written to a
`.cryptman-partial` file and renamed on success, so an interrupted run cannot
leave a truncated file that looks complete.

## Exit codes

| code | meaning |
|---|---|
| `0` | success |
| `1` | rows failed, or a runtime error |
| `2` | usage error — unknown flag, missing key, unreadable path |

`--continue-on-error` controls whether the run *continues*, not whether it
*reports failure*. A completed run with failed rows still exits 1, so CI can
tell a clean migration from a broken one.

## What the CLI cannot do

**Columns encrypted with associated data.** The CLI has no way to supply the
per-row context, so `upgrade` cannot re-encrypt them and `--dry-run` would
report every such row as `v2 unreadable`. Pass `--skip-v2-check` to silence
that, and use the PHP loop in
[upgrading](upgrading.md#bulk-re-encryption) for the re-encryption itself.

**Lazy upgrade on read.** If you want to migrate rows as they are accessed
rather than in a batch, that is application code — see the same section.

**Reading your database.** By design. Cryptman has no database dependency and
never will; you supply the payloads and write back the results.
