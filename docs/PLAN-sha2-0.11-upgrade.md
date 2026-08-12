# Plan: Upgrade to `sha2` 0.11 (digest 0.11 ecosystem)

**Status:** Planned (future release, likely v0.5.0 or a dedicated v0.4.x)
**Motivation:** benchmark finding in v0.4.2 — SHA-256 runs the software backend
(~234 MiB/s on a Comet Lake i5-10400, which lacks SHA-NI). `sha2` 0.11 adds an
`x86-avx2` backend that accelerates the *software* path **without** the external
assembly that breaks Windows MSVC (the reason the `sha2` 0.10 `asm` feature was
rejected).

## Why this is a separate release

It is **not** a one-line bump. `sha2` 0.11 depends on `digest` 0.11, which is a
breaking change across the whole RustCrypto hashing/MAC/KDF ecosystem. Every
crate that shares `digest` traits must move together.

## Scope

### 1. Dependency bumps (workspace)

| Crate | From | To | Reason |
|-------|------|----|--------|
| `sha2` | 0.10 | 0.11 | the `x86-avx2` software backend |
| `hmac` | 0.12 | 0.13 | digest 0.11 compatibility |
| `hkdf` | 0.12 | 0.13 | digest 0.11 compatibility |
| `digest` (transitive) | 0.10 | 0.11 | the trait update itself |

Verify exact published versions at implementation time — `digest` 0.11 / `hkdf`
0.13 may still be in release-candidate state; do not adopt until stable unless
we accept an RC.

### 2. Code changes (the real work)

`digest` 0.11 drops `generic-array` in favor of plain arrays / `hybrid-array`.
Our code that touches the digest output types needs updating:

- **`sc-sha256`** — `finalize()` return type changes (`GenericArray<u8, U32>` →
  `Array<u8, U32>` / `[u8; 32]`). Our wrappers already return `[u8; 32]`, so the
  conversion at the boundary is what changes.
- **`sc-hmac`** — the `Mac`/`Update`/`FixedOutput` trait surface changed; the
  `Hmac<Sha256>` usage and `finalize().into_bytes()` calls need review.
- **`sc-hkdf`** — `Hkdf<Sha256>` from `hkdf` 0.13; the `expand`/`extract` API is
  stable in shape but the underlying types shift with digest 0.11.

Everything is internal — the **public NAPI / TS API does not change**. This is a
dependency-and-internals migration, not an API break for consumers.

### 3. The dalek duplicate-`sha2` question

`ed25519-dalek` 2.1 and `curve25519-dalek` 4.1 depend on `sha2` 0.10 internally.
If we move our crates to `sha2` 0.11 while dalek stays on 0.10, the tree will
contain **both** `sha2` 0.10 and 0.11 (cargo allows this; it's binary bloat, not
a correctness bug). Options:

- **Accept the duplicate** short-term (simplest; our SHA-256 wrapper uses 0.11,
  dalek keeps its own 0.10 internally).
- **Wait for dalek** to publish a release depending on `sha2` 0.11, then align.

Recommended: accept the duplicate initially; the acceleration we want is in our
own `sc-sha256`, which is what the benchmark measured.

## Verification plan (before merge)

1. `cargo build --workspace` on all four CI targets — **especially
   `x86_64-pc-windows-msvc`**, to confirm the `x86-avx2` backend compiles where
   the old `asm` feature did not.
2. `cargo test --workspace --exclude sc-node` — all existing crypto vectors must
   still pass (the migration must not change any output).
3. Re-run `cargo bench -p sc-benches --bench hashing` on a non-SHA-NI CPU and
   confirm the SHA-256 throughput improves over the ~234 MiB/s baseline.
4. Re-run the NAPI test suite (`npm test`) to confirm the binding is unaffected.

## Explicitly out of scope

- No change to AES-GCM / ChaCha20-Poly1305 / Curve25519 / Ed25519 code paths.
- No public API changes.
- Not adopting the `asm` feature (rejected — breaks Windows MSVC).

## Rollback

The change is confined to the workspace dependency versions plus
`sc-sha256` / `sc-hmac` / `sc-hkdf` internals. If any platform build fails,
revert those crates and the four dependency lines; nothing else depends on it.
