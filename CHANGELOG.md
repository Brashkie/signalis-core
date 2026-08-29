# Changelog

All notable changes to `@brashkie/signalis-core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] — 2026-08-26

### 🧰 Changed — expanded benchmarks & internal dependency hygiene (no API changes)

A maintenance/robustness release. No new primitives, no API changes, no crypto
math touched.

- **Expanded Criterion benchmarks** (`crates/sc-benches`) to cover every
  primitive added since v0.4.2: SHA-3 (256/512) and BLAKE3 in the `hashing`
  bench; HKDF-SHA512, HMAC (SHA-256/512) and BLAKE3 keyed/derive in the `kdf`
  bench; and a new `password_kdf` bench for PBKDF2 and Argon2id (with modest
  parameters so it stays runnable). Run with `cargo bench -p sc-benches`.
- **Internal workspace dependencies switched to path-only.** The `sc-*` crates
  are workspace-internal and not published to crates.io, so their inter-crate
  dependencies no longer pin a `version` (only `path`). This removes the version
  requirement that broke the build at the `0.4.x → 0.5.0` boundary and prevents
  it from recurring on any future version bump.



### 🎉 Milestone — Phase 4 (modern primitives) complete

This release adds **BLAKE3** and, with it, completes Phase 4 of the roadmap
(9/9 modern primitives). The `0.5.0` version marks that milestone.

### ✨ Added — BLAKE3 (hash, keyed hash, key derivation)

A new `BLAKE3` namespace exposing the three core BLAKE3 modes, built on the
official `blake3` reference crate:

- **`BLAKE3.hash(data)`** — fast general-purpose hashing (32-byte output).
- **`BLAKE3.keyedHash(key, data)`** — a MAC with a 32-byte key (an alternative to
  HMAC), plus **`BLAKE3.keyedHashVerify(...)`** for constant-time verification.
- **`BLAKE3.deriveKey(context, keyMaterial)`** — context-separated key derivation
  (an alternative to HKDF). The context string provides domain separation.

Verified against the official BLAKE3 test vectors (hash / keyed_hash / derive_key
across empty, 1-byte, and 1024-byte inputs). The XOF (extendable-output) mode is
intentionally not exposed in this release.

**Why not 1.0?** The API surface is broad and stable, but a `1.0` implies a
long-term compatibility commitment; the project continues through the remaining
roadmap phases (hardening, platform coverage) before that.

### 📋 Phase status

- Phase 1 (foundation): ✅ complete + hardened
- Phase 3 (utilities): ✅ complete
- **Phase 4 (modern primitives): ✅ complete (ChaCha20 family, PBKDF2, Argon2id,
  SHA-512 variants, SHA-3, BLAKE3)**



### ✨ Added — SHA-3 (SHA3-256 & SHA3-512)

A new `SHA3` namespace implementing SHA-3 (FIPS 202), the Keccak-based NIST
standard. Structurally different from the SHA-2 family — useful when a protocol
requires SHA-3 specifically, or for algorithmic diversity from SHA-2.

- `SHA3.hash256(data)` → 32-byte digest; `SHA3.hash512(data)` → 64-byte digest.
- `SHA3.hash256All(buffers)` convenience for hashing concatenated buffers.
- New `sc-sha3` crate over the audited RustCrypto `sha3` crate.
- **Verified against NIST FIPS 202 known-answer tests** (empty string and "abc"
  for both variants), cross-checked with Node's `crypto` SHA-3.

### 📋 Notes

- Advances Phase 4 (modern primitives) to 8/9. Only **BLAKE3** remains —
  completing it will close Phase 4 and be the milestone for **0.5.0**.



### ✨ Added — SHA-512 variants: HMAC-SHA512 & HKDF-SHA512

Two new SHA-512-based primitives, added to the existing `HMAC` and `HKDF`
namespaces (no new namespaces, no new dependencies — `sha2` already provides
`Sha512`, and `hmac`/`hkdf` are generic over the hash):

- **`HMAC.sha512(key, data)`** → 64-byte tag, plus **`HMAC.verifySha512(...)`**
  (constant-time). Verified against RFC 4231 known-answer tests.
- **`HKDF.deriveSha512(salt, ikm, info, length)`** → one-shot HKDF-SHA512
  (64-byte PRK internally, up to 16320 bytes output). Verified against reference
  KATs (`cryptography` + Node's `crypto.hkdfSync`).

Use these when a 512-bit hash is required for domain consistency with the rest of
a protocol. The SHA-256 variants are unchanged.

### 📋 Notes

- Advances Phase 4 (modern primitives) to 7/9. Remaining: SHA-3 and BLAKE3 —
  completing those will be the milestone for **0.5.0**.



### 🛡️ Hardening — supply chain, fuzzing, and property tests (no API changes)

A robustness-only release: no new primitives, no cryptographic math touched. It
strengthens the `.rs` around the audited primitives.

- **`cargo-deny`** — new `deny.toml` supply-chain policy (allowed licenses,
  trusted sources, banned crates — OpenSSL is explicitly denied so a stray
  transitive dependency can't sneak in). Enforced as a CI gate (bans/licenses/
  sources block; advisories are non-blocking, complementing the existing
  `cargo-audit` gate).
- **`cargo-fuzz`** — a `fuzz/` crate with libFuzzer targets on the untrusted-input
  surfaces: Ed25519 verification, X25519 Diffie-Hellman, and base64/hex decoding.
  Each asserts the invariant *"never panic on arbitrary input."* Runs via a
  weekly `fuzz.yml` workflow (kept out of the blocking CI since it needs nightly
  and is long-running).
- **Property-based tests (`proptest`)** — mathematical invariants checked across
  thousands of generated inputs, added to the existing crates:
  - X25519: Diffie-Hellman commutativity, shared-secret length.
  - Ed25519: sign→verify round-trip, tampered-message rejection, signature length.
  - HKDF: determinism and output-length correctness.
  - Encoding: base64 / base64url / hex encode→decode round-trips.

These target the wrapper's behaviour and invariants — the primitive math remains
entirely RustCrypto's audited implementations.



### 🔒 Security — Ed25519 now uses strict verification (behavior change)

`Ed25519.verify` / `verifyBool` now use ed25519-dalek's **`verify_strict`**
instead of the permissive `verify`. This rejects:

- **Signature malleability** — a valid signature `(R, S)` could previously be
  transformed into a *different* still-valid signature `(R, S + L)` for the same
  message. Systems that assume signatures are unique (dedup, replay protection,
  signature-derived IDs) were at risk. Strict verification rejects non-canonical
  `S`.
- **Non-canonical point encodings** and **small-order public keys**.

**Impact:** all legitimate, canonically-encoded signatures continue to verify
exactly as before — there is no impact on normal use. Only malleable /
non-canonical / weak-key inputs (which should never be accepted) are now
rejected. This uses the audited crate's stricter function; no cryptographic math
was modified.

### 🔒 Added — Wycheproof adversarial vectors for the asymmetric primitives

Extends the AEAD Wycheproof suite (v0.4.5) to the elliptic-curve primitives —
where the most dangerous edge cases live.

- **X25519 (ECDH)**: 518 vectors (low-order points, twist points, non-canonical
  and special public keys). `diffieHellman(private, public)` must equal the
  expected shared secret for every case (curve25519-dalek's clamped scalar
  multiplication is permissive and produces the all-zero secret for low-order
  points, matching the vectors).
- **Ed25519 (verification)**: 151 vectors (signature malleability, invalid
  encodings, small-order keys). With strict verification, the pass/fail
  classification now matches RFC 8032 / Wycheproof exactly.

Tests only for the vectors themselves; the fixtures under `__tests__/vectors/`
are not shipped in the npm package. Verified end-to-end against RFC 8032 strict
reference behaviour (669 vectors).



### ✨ Added — Argon2id (memory-hard password KDF)

A new `Argon2id` namespace implementing Argon2id (RFC 9106), the current
recommended password-hashing function. Unlike `PBKDF2` (iteration-only),
Argon2id is **memory-hard** — it forces an attacker to spend large amounts of
RAM per guess, defeating the cheap massive parallelism of GPUs/ASICs.

- `Argon2id.derive(password, salt, mCost, tCost, pCost, length)` → derived key.
  `mCost` is memory in KiB, `tCost` iterations, `pCost` parallelism.
- New `sc-argon2` crate over the audited RustCrypto `argon2` crate. Algorithm
  fixed to Argon2id, version 0x13 (v1.3, the RFC 9106 standard).
- **Verified against the Argon2 reference implementation** (argon2-cffi /
  libargon2) — four known-answer vectors across parameter sets (including
  parallelism = 2 and a 64-byte output) in both the Rust and TypeScript tests.
- Validation: non-empty salt (≥8 bytes enforced by the library), positive cost
  parameters and length; friendly errors for out-of-range params.

**PBKDF2 vs Argon2id:** both derive keys from passwords. Prefer Argon2id for new
code when you can afford the memory cost; PBKDF2 remains available for
constrained environments or FIPS-oriented requirements.



### 🔒 Added — Wycheproof adversarial test vectors (hardening)

Integrated Google's [Wycheproof](https://github.com/C2SP/wycheproof) test
vectors for the AEAD primitives. Unlike round-trip tests, Wycheproof
deliberately includes malformed and edge-case inputs — flipped authentication
tag bits, Poly1305 edge cases, boundary ciphertexts — that catch subtle bugs
plain tests miss.

- **AES-256-GCM**: 66 vectors (39 valid + 27 tampered-tag) filtered to this
  library's parameters (256-bit key, 96-bit nonce, 128-bit tag).
- **ChaCha20-Poly1305**: 316 vectors (256 valid + 60 adversarial, including
  Poly1305/ciphertext/tag edge cases).
- Every vector is checked both ways: `valid` → encryption reproduces `ct‖tag`
  and decryption round-trips; `invalid` → decryption must reject (auth failure).

No code or API changes — this release is purely additional test coverage. The
committed vector fixtures live under `__tests__/vectors/` and are **not** shipped
in the npm package. Wycheproof is Apache-2.0 licensed (same as this project).

### 📝 Notes

- Advances Phase 6 (security hardening) to 2/11. Next hardening steps: fuzzing
  (`cargo-fuzz`) and `cargo-deny`.

## [0.4.4] — 2026-08-12

### ✨ Added — PBKDF2-HMAC-SHA256 (password-based KDF)

A new `PBKDF2` namespace for deriving keys from **passwords** (RFC 8018). Where
`HKDF` expands a high-entropy secret, PBKDF2 is built for low-entropy passwords:
it applies HMAC-SHA256 a configurable number of iterations to make brute-forcing
expensive.

- `PBKDF2.derive(password, salt, iterations, length)` → derived key `Buffer`.
- New `sc-pbkdf2` crate over the audited RustCrypto `pbkdf2` crate (no crypto
  written by hand). Kept as its own crate so the core stays modular.
- Validation: non-empty salt, `iterations >= 1`, `length >= 1` (enforced in Rust;
  the JS layer additionally rejects non-numbers/negatives early).
- **Verified against known-answer tests** (the SHA-256 analogues of the RFC 6070
  vectors) in both the Rust unit tests and the TypeScript tests, cross-checked
  against Node's `crypto.pbkdf2` / OpenSSL.

### 📝 Notes — iOS / Apple binding (roadmap only)

Clarified Phase 2: **iOS is not an N-API `.node` target.** The Rust core already
compiles for Apple platforms; what's needed is a separate Apple binding
(`sc-apple` → XCFramework via UniFFI or FFI+cbindgen), documented as a future
design note rather than an N-API platform. No code change — planning only.

## [0.4.3] — 2026-08-12

### ✨ Added — XChaCha20-Poly1305 (extended-nonce AEAD)

The extended-nonce (24-byte) variant of ChaCha20-Poly1305, exposed as a new
`XChaCha20Poly1305` namespace with the same shape as `ChaCha20Poly1305`
(`encrypt` / `decrypt` / `encryptWithAad` / `decryptWithAad` + `KEY_SIZE` /
`NONCE_SIZE` / `TAG_SIZE`).

- **Why it matters:** the 192-bit nonce makes it safe to pick nonces at random
  per message — no counter or uniqueness tracking needed. Prefer it over
  `ChaCha20Poly1305` when you can't guarantee unique 12-byte nonces.
- Built on the same audited `chacha20poly1305` crate (no new dependency; the
  `xchacha20poly1305` feature is on by default).
- **Verified against a libsodium known-answer vector** (both the Rust unit tests
  and the TypeScript tests check the exact ciphertext against
  `crypto_aead_xchacha20poly1305_ietf`), proving interoperability with the
  reference implementation.
- Fully backwards compatible; no existing API changes.

### 📝 Notes

- Completes 3/9 of Phase 4 (modern primitives). Phase 1 remains complete; no
  changes to existing primitives.

## [0.4.2] — 2026-08-10

### ✨ Added — Criterion benchmark suite (starts Phase 5)

A dedicated, non-published benchmark crate (`crates/sc-benches`) that measures
the core primitives with [Criterion](https://github.com/bheisler/criterion.rs).
This establishes a performance baseline before any optimization work — measure
first, optimize with evidence.

- **`hashing`** — SHA-256 one-shot across input sizes (64 B → 256 KiB) plus the
  streaming (`Sha256Hasher`) path.
- **`aead`** — AES-256-GCM vs ChaCha20-Poly1305 side by side across sizes, so
  the faster cipher on a given machine is visible.
- **`curve`** — Curve25519 key generation and Diffie-Hellman (the asymmetric
  handshake cost).
- **`kdf`** — HKDF-SHA256 extract / expand / derive.

Run with `cargo bench -p sc-benches` (or `--bench hashing`, etc.).

### 📈 Baseline findings (first run, Comet Lake i5-10400)

- **AES-256-GCM** wins on small messages (AES-NI): ~375 MiB/s at 64 B, >1 GiB/s
  from 1 KiB up. **ChaCha20-Poly1305** overtakes it above ~16 KiB (1.3–1.4 GiB/s).
  For WhatsApp-style small messages, AES-GCM is the better default.
- **Curve25519**: keygen ~32.5 µs, Diffie-Hellman ~55 µs — normal for X25519.
- **HKDF-SHA256**: extract/expand/derive all in the 1–3 µs range.
- **SHA-256** tops out at ~234 MiB/s. This is the **software** backend: the
  i5-10400 (Comet Lake) has no SHA-NI. On CPUs that do (Intel 11th-gen+, all AMD
  Zen), `sha2` 0.10 auto-detects and uses hardware acceleration at runtime with
  the same binary. A future `sha2` 0.11 upgrade would speed up the software path
  too — see `docs/PLAN-sha2-0.11-upgrade.md`.

### 🔍 Performance audit (no code changes)

Audited the NAPI binding for wasteful copies/allocations. Finding: it's already
clean — inputs are borrowed (`&plaintext`), outputs are moved (`Buffer::from(ct)`),
with **zero `.clone()` and zero redundant `.to_vec()`** on variable-length data.
The remaining `.to_vec()` calls convert fixed-size arrays (hashes, keys,
signatures) to the heap, which is necessary. No optimization was manufactured
where the data didn't justify one; any future change will be driven by the
benchmark numbers.

## [0.4.1] — 2026-08-08

### ✨ Added — Buffer/byte-array utilities (completes Phase 3)

Small, pure-TypeScript helpers that round out the utility layer. No native or
API-breaking changes; fully backwards compatible with v0.4.0.

- **`split(buf, sizes)`** — the inverse of `concat`: divide a Buffer into
  consecutive segments. Trailing bytes come back as a final segment. Ideal for
  deserializing a `nonce ‖ ciphertext ‖ tag` blob.
- **`bytesEqual(a, b)`** — fast, **non**-constant-time equality for *public*
  data (headers, identifiers). For secrets, keep using `constantTimeEqual`.
- **`concatBytes(...arrays)`** — the `Uint8Array` counterpart of `concat`, for
  browser / WASM environments without Node's `Buffer`.
- **`splitBytes(bytes, sizes)`** — the `Uint8Array` counterpart of `split`
  (segments are zero-copy `subarray` views).

All new `split*` helpers validate their sizes and throw `RangeError` on
negative, non-integer, or oversized inputs.

### 📝 Docs

- Synced the roadmap with reality: several Phase 3 items (`randomIv`,
  `randomNonce`, validators, buffer utils) already shipped but were still marked
  pending. **Phase 3 is now 100%.**

## [0.4.0] — 2026-07-08

### ✨ Added — Encoding helpers + Android x86_64

v0.4.0 introduces native encoding helpers (Base64, Hex, UTF-8) and adds
Android x86_64 to the supported platform list. Fully backwards compatible
with v0.3.x.

#### 🆕 Encoding namespaces (Rust-side implementations)

Three new namespaces exported from the top level, backed by the new
`sc-encoding` crate. All operations are audited RustCrypto ecosystem
routines with strict validation (no lossy conversions).

- **`Base64`**
  - `encode(bytes) → string` — RFC 4648 standard (with `=` padding)
  - `decode(string) → Buffer` — throws on invalid input
  - `encodeUrlSafe(bytes) → string` — `-` and `_` alphabet, no padding
  - `decodeUrlSafe(string) → Buffer`

- **`Hex`**
  - `encode(bytes) → string` — lowercase output
  - `encodeUpper(bytes) → string` — uppercase output
  - `decode(string) → Buffer` — case-insensitive
  - `isValid(string) → boolean` — cheap format check

- **`Utf8`**
  - `encode(string) → Buffer` — UTF-8 bytes
  - `decode(bytes) → string` — **strict** validation, throws on invalid
    UTF-8 (unlike `Buffer.toString('utf-8')` which silently substitutes U+FFFD)
  - `isValid(bytes) → boolean`

Quick example:

```typescript
import { Base64, Hex, Utf8 } from '@brashkie/signalis-core';

const bytes = Utf8.encode('Hola 🦀');
const b64 = Base64.encode(bytes);          // 'SG9sYSDwn6aA'
const hex = Hex.encode(bytes);             // '486f6c6120f09fa680'
const back = Utf8.decode(Base64.decode(b64)); // 'Hola 🦀'
```

#### 🆕 New crate: `sc-encoding`

A dedicated Rust crate for encoding routines, separated from `sc-utils`
to keep encoding logic isolated from cryptographic utilities. This makes
the codebase easier to audit and lets adopters pull in just what they need.

Dependencies (all RustCrypto ecosystem):
- `base64` v0.22 — RFC 4648 encoder/decoder
- `hex` v0.4 — Base16 encoder/decoder
- Rust standard library for UTF-8 validation

#### 🆕 Android x86_64 support

New sub-package `@brashkie/signalis-core-android-x64` published to npm.
Primary use cases:
- **Android Emulator** — runs x86_64, so devs testing apps in Android
  Studio's emulator now get native binaries automatically
- **Termux on x86 tablets / Chromebooks** — install via
  `pkg install nodejs && npm install @brashkie/signalis-core`

Total platforms supported: **10** (was 9 in v0.3.1).

### 🔄 Changed
- `VERSION` bumped to `'0.4.0'`
- `Cargo.toml` workspace: version 0.3.x → 0.4.0
- `sc-node`: 10 new `#[napi]` exports for the encoding functions
- `optionalDependencies` in `package.json`: adds `android-x64` (10 sub-packages total)
- `napi.triples.additional`: adds `x86_64-linux-android`
- `.github/workflows/release.yml`: adds `x86_64-linux-android` build job
- `scripts/create-npm-dirs.js`: adds `android-x64` to `PLATFORMS` array

### ✅ Compatibility
**100% backwards compatible with v0.3.x.** No API changes. No breaking
behavior. Existing code continues to work; the encoding namespaces are
purely additive.

### 📋 What's next (v0.5.0 candidates)
- Buffer / ByteArray utility helpers (`sc-encoding` extension)
- XChaCha20-Poly1305 (extended-nonce AEAD)
- Argon2id password hashing
- PBKDF2-SHA256
- HKDF-SHA512

---

## [0.3.0] — 2026-06-17

### ✨ Added — Multi-Platform Expansion + New Primitives

**Focus: Android support + AEAD alternative for ARM-heavy deployments.**

#### 🆕 New crates
- **`sc-chacha20poly1305`** — RFC 8439 ChaCha20-Poly1305 AEAD
  - Encrypt/decrypt with optional AAD
  - Same API shape as `sc-aes`'s GCM helpers
  - 2-3× faster than AES-GCM on ARM without AES-NI hardware
  - Full RFC 8439 test vector compliance
- **`sc-utils`** — public utility helpers
  - `secure_random(buf)` / `random_bytes(size)` — OS-backed CSPRNG
  - `constant_time_eq(a, b)` — timing-safe comparison
  - `secure_zeroize(buf)` — guaranteed-not-elided buffer wipe
  - 16 MiB cap on single random allocation (DoS guard)

#### 🆕 New build targets
- ✅ `aarch64-linux-android` — Android arm64-v8a (React Native, Termux, modern phones)
- ✅ `armv7-linux-androideabi` — Android armv7 (older devices, IoT)

#### 🆕 Public JS API
- `ChaCha20Poly1305` namespace mirroring `AES_GCM`:
  - `.encrypt(key, nonce, plaintext)`
  - `.decrypt(key, nonce, ciphertext)`
  - `.encryptWithAad(key, nonce, plaintext, aad)`
  - `.decryptWithAad(key, nonce, ciphertext, aad)`
  - Constants: `KEY_SIZE`, `NONCE_SIZE`, `TAG_SIZE`
- `constantTimeEq(a, b)` — timing-safe Buffer comparison
- `nativeSecureRandom(size)` — OS-backed CSPRNG via the native side

#### 🆕 CI
- `cargo-audit` pre-merge gate (fails PRs introducing vulnerable transitive deps)
- Build matrix now includes both Android targets

### 🔄 Changed
- Workspace `Cargo.toml`: added `chacha20poly1305 = "0.10"` to shared deps
- `sc-node` re-exports new primitives + helpers from the new crates
- `package.json` lists `android-arm64` + `android-arm-eabi` as optional sub-packages

### ✅ Compatibility
**100% backwards compatible with v0.2.0.** All existing APIs (`Curve25519`,
`Ed25519`, `XEd25519`, `HKDF`, `AES_GCM`, `AES_CBC`, `HMAC`, `SHA256`) are
unchanged. `signalis@0.6.0` (the TypeScript Signal Protocol wrapper) continues
to work without modifications.

### 📦 New install footprint (Android)

```bash
npm i @brashkie/signalis-core
# On Android (Termux / React Native), npm/yarn will automatically pull:
#   @brashkie/signalis-core-android-arm64   (or)
#   @brashkie/signalis-core-android-arm-eabi
```

### 🔒 Security
- All new code follows the same audit-friendly patterns as v0.2.0
- ChaCha20-Poly1305 backed by RustCrypto's `chacha20poly1305@0.10`
- `secure_random` panics (not silently degrades) if OS RNG is unavailable
- `constant_time_eq` backed by `subtle@2.5`
- `secure_zeroize` backed by `zeroize@1.7`

### 📋 What's next (v0.4.0)
- iOS arm64 target
- WASM target (browsers, via `wasm-bindgen`)
- PBKDF2 + Argon2id (for the upcoming `signalis-vault` package)
- Benchmark suite (criterion)

---

## [0.2.0] — 2026-05-22

### ✨ Added

- **Ed25519 signatures** (RFC 8032) — new `Ed25519` namespace
  - `Ed25519.generateKeyPair()`
  - `Ed25519.keyPairFromSeed(seed)` — deterministic from 32-byte seed
  - `Ed25519.publicFromPrivate(privateKey)`
  - `Ed25519.sign(privateKey, message)` — deterministic
  - `Ed25519.verify(publicKey, message, signature)` — throws on failure
  - `Ed25519.verifyBool(publicKey, message, signature)` — returns boolean
  - Constants: `Ed25519.PRIVATE_KEY_SIZE`, `PUBLIC_KEY_SIZE`, `SIGNATURE_SIZE`, `SEED_SIZE`

- **XEd25519 signatures** (Signal Protocol style) — new `XEd25519` namespace
  - Sign with Curve25519 keys: ONE keypair for both ECDH and signing
  - `XEd25519.sign(privateKey, message)` — uses OS RNG, non-deterministic
  - `XEd25519.signWithRandom(privateKey, message, random)` — deterministic with 64-byte nonce
  - `XEd25519.verify(publicKey, message, signature)`
  - `XEd25519.verifyBool(publicKey, message, signature)`
  - Constants: `XEd25519.PRIVATE_KEY_SIZE`, `PUBLIC_KEY_SIZE`, `SIGNATURE_SIZE`, `RANDOM_SIZE`

- **AES-GCM with AAD** — Additional Authenticated Data support
  - `AES_GCM.encryptWithAad(key, nonce, plaintext, aad)`
  - `AES_GCM.decryptWithAad(key, nonce, ciphertext, aad)`
  - Bind metadata (headers) to ciphertext without encrypting them
  - Tampering with AAD fails decryption (just like tampering with ciphertext)

- **New error class:**
  - `SignatureError extends CryptoError` — thrown by `Ed25519.verify` / `XEd25519.verify`

- **New type:**
  - `Signature = Buffer & { __brand?: 'Signature' }` — branded type for signatures
  - Helper: `asSignature(buf): Signature`

- **New constants exported:**
  - `ED25519_PRIVATE_KEY_SIZE`, `ED25519_PUBLIC_KEY_SIZE`, `ED25519_SIGNATURE_SIZE`, `ED25519_SEED_SIZE`
  - `XED25519_PRIVATE_KEY_SIZE`, `XED25519_PUBLIC_KEY_SIZE`, `XED25519_SIGNATURE_SIZE`, `XED25519_RANDOM_SIZE`

- **New Rust crates:**
  - `sc-ed25519` — Ed25519 signing (built on `ed25519-dalek`)
  - `sc-xed25519` — XEd25519 with Curve25519 keys (built on `curve25519-dalek`)

- **New runnable examples** in `examples/`:
  - `basic.mjs` — ECDH + HKDF + AES-GCM
  - `signing.mjs` — Ed25519 + XEd25519
  - `aad.mjs` — AES-GCM with AAD
  - `e2e-channel.mjs` — Complete E2E channel

- **New documentation:**
  - `MIGRATION.md` — Upgrade guide v0.1 → v0.2
  - Updated `README.md`, `README.es.md`, `API.md`, `EXAMPLES.md`

### 🔄 Changed

- `VERSION` constant bumped to `'0.2.0'`
- `package.json` keywords expanded with `ed25519`, `xed25519`, `aead`
- `AesGcmParams` interface now includes optional `aad?: Buffer`

### 🔒 Security

- All new primitives use audited crates:
  - `ed25519-dalek 2.x` — RFC 8032 reference implementation
  - `curve25519-dalek 4.x` — Constant-time scalar operations
- XEd25519 implementation follows the [Signal spec](https://signal.org/docs/specifications/xeddsa/)
- All new Rust modules carry `#![deny(missing_docs)] #![deny(unsafe_code)] #![deny(clippy::unwrap_used)]`

### ✅ Compatibility

**100% backwards compatible with v0.1.0.** Every existing API works unchanged:

- All existing imports continue to work
- All existing function signatures unchanged
- All existing error classes preserved
- All existing constants preserved
- Drop-in upgrade: just bump the version

### 🧪 Testing

- **Total: ~269 tests passing**
- **Rust:** 48 tests (8 sc-aes incl. 3 AAD + 10 sc-ed25519 + 8 sc-xed25519 + existing)
- **Vitest:** 172 tests across 4 files
- **CJS:** 12 assertions
- **ESM:** 15 assertions

## [0.1.0] — 2026-05-18

### ✨ Initial release

- `Curve25519` — X25519 ECDH key agreement
- `HKDF` — RFC 5869 key derivation (extract, expand, derive, deriveMultiple)
- `AES_GCM` — AES-256-GCM authenticated encryption
- `AES_CBC` — AES-256-CBC block cipher (paired with HMAC)
- `HMAC` — HMAC-SHA256 with constant-time verification
- `SHA256` — SHA-256 hashing (hash, hashAll)
- Utility helpers: `secureRandom`, `randomNonce`, `randomIv`, `randomKey`, `toHex`, `fromHex`, `toBase64`, `fromBase64`, `toBase64Url`, `fromBase64Url`, `concat`, `zeroize`, `xor`, `constantTimeEqual`
- Validators: `assertBuffer`, `assertBufferLength`, `assertBufferOfSize`, `assertPositiveInteger`, `assertHkdfLength`
- Errors: `SignalisError`, `ValidationError`, `CryptoError`, `AuthenticationError`, `KeyDerivationError`, `LengthError`
- TypeScript types: `KeyPair`, `PublicKey`, `PrivateKey`, `SharedSecret`, `HkdfParams`, etc.
- Native bindings via napi-rs (7 platforms supported)
- 172 tests passing

[0.2.0]: https://github.com/Brashkie/signalis-core/releases/tag/v0.2.0
[0.1.0]: https://github.com/Brashkie/signalis-core/releases/tag/v0.1.0
