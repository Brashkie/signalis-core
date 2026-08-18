# 🗺️ Roadmap

Signalis Core is being built as a high-performance native cryptography engine for Node.js, providing modern, audited cryptographic primitives with a strong focus on performance, security, portability, and developer experience.

The goal is to become a production-grade cryptographic foundation suitable for secure messaging, authentication, key management, and other security-critical applications.

**Legend:**
- ✅ Complete
- 🟡 In progress / partial
- 🔴 Not started

**Current release:** `v0.4.0` (encoding helpers + Android x86_64).

---

## ✅ Phase 1 — Cryptographic foundation

Core primitives.

- [x] AES-256-GCM
- [x] AES-256-CBC
- [x] SHA-256
- [x] HMAC-SHA256
- [x] HKDF (RFC 5869)
- [x] Curve25519
- [x] Ed25519
- [x] XEd25519
- [x] RFC test vectors
- [x] NIST test vectors
- [x] Constant-time verification
- [x] Native Rust implementation
- [x] Node.js bindings (N-API)

---

## 🟡 Phase 2 — Multi-platform support

Native builds across major platforms.

- [x] Windows x64
- [x] Windows ARM64
- [x] Linux x64 (GNU)
- [x] Linux x64 (musl)
- [x] Linux ARM64
- [x] macOS Intel
- [x] macOS Apple Silicon
- [x] Android ARM64
- [x] Android ARMv7
- [x] Android x86_64 *(new in v0.4.0)*
- [ ] iOS — **not an N-API `.node` target.** iOS can't load arbitrary native
  addons the way Node does, so iOS is not "add `aarch64-apple-ios` to the build
  matrix". The Rust core already compiles for Apple targets; what's missing is an
  Apple-appropriate *binding* (a separate `sc-apple` crate → XCFramework),
  tracked as "Apple binding" below rather than as an N-API platform.
- [ ] WASM
- [ ] FreeBSD
- [ ] RISC-V

**Progress: 10 / 14 (71%)**

### 🍎 Apple binding — future (design note, not scheduled)

When `signalis-core` needs native iOS/macOS integration, the answer is a new
binding crate over the *same* crypto core — **not** an N-API `.node`. The core
crates (`sc-curve25519`, `sc-ed25519`, `sc-hkdf`, …) stay Node-agnostic; only a
sibling binding is added, exactly as `sc-node` is today:

```
crates/
├── [core crypto crates]        ← untouched, platform-agnostic
├── sc-node    → N-API   → Node.js
└── sc-apple   → (future) → Swift / iOS / macOS   [XCFramework, not .node]
```

Two options, to be decided **when we get there** (the choice depends on how
complex the public API is at that point — buffers, sessions, custom error/types):

- **Option 1 — UniFFI** (Mozilla): auto-generates Swift bindings from Rust. Less
  hand-written FFI; good for a high-level API; keeps Rust/Swift APIs in sync.
- **Option 2 — manual FFI + `cbindgen`**: Rust exposes a stable C ABI, `cbindgen`
  generates headers, Swift/Obj-C consumes it. More work, maximum control over
  ABI, memory, ownership, and layout.

Not started deliberately: stabilize the crypto core first; pick the binding
approach against the real API shape at that time, not now.

---

## 🟡 Phase 3 — Cryptographic utilities

Common helpers used by modern cryptographic software.

- [x] Secure random generation *(v0.3.0 — `nativeSecureRandom`)*
- [x] Constant-time comparison *(v0.3.0 — `constantTimeEq`)*
- [x] Secure memory zeroization *(v0.3.0 — `sc-utils`)*
- [x] Base64 helpers *(v0.4.0 — `Base64` namespace, standard + URL-safe)*
- [x] Hex helpers *(v0.4.0 — `Hex` namespace)*
- [x] UTF-8 helpers *(v0.4.0 — `Utf8` namespace, strict validation)*
- [x] Buffer utilities *(`concat`, `xor`, `zeroize`; `split` added v0.4.1)*
- [x] Byte array utilities *(v0.4.1 — `concatBytes`, `splitBytes` over `Uint8Array` for browser/WASM)*
- [x] Random IV generation *(`randomIv` — 16-byte AES-CBC IV)*
- [x] Random nonce generation *(`randomNonce` — 12-byte AEAD nonce)*
- [x] Secure validation helpers *(`validators.ts` — `assertBuffer`, `assertLength`, …)*

**Progress: 11 / 11 (100%) ✅**

---

## 🟡 Phase 4 — Modern cryptographic primitives

Expand the available primitive set.

- [x] ChaCha20 *(part of ChaCha20-Poly1305, v0.3.0)*
- [x] ChaCha20-Poly1305 *(v0.3.0)*
- [x] XChaCha20-Poly1305 *(v0.4.3 — 24-byte extended nonce; verified vs libsodium KAT)*
- [x] PBKDF2 *(v0.4.4 — PBKDF2-HMAC-SHA256, RFC 8018; verified vs RFC 6070-style KATs)*
- [x] Argon2id *(v0.4.6 — RFC 9106, memory-hard; verified vs argon2-cffi reference KATs)*
- [ ] SHA-3
- [ ] BLAKE3
- [ ] HKDF-SHA512
- [ ] HMAC-SHA512

**Progress: 5 / 9 (56%)**

---

## 🔴 Phase 5 — Performance

Optimize native execution.

- [ ] SIMD optimizations
- [ ] AES-NI acceleration *(implicit via RustCrypto — needs explicit `-C target-feature=+aes` flag in release profile to document)*
- [ ] ARM Crypto Extensions *(same — implicit today, needs explicit flag)*
- [ ] NEON optimizations
- [ ] Zero-copy buffers *(binding audited v0.4.2 — inputs borrowed, outputs moved, no redundant copies; no work needed)*
- [ ] Reduced allocations *(same audit — no wasteful allocations found in the binding)*
- [ ] Cache-friendly implementations
- [x] Criterion benchmarks *(v0.4.2 — `crates/sc-benches`: SHA256, AES-GCM, ChaCha20-Poly1305, Curve25519, HKDF)*
- [ ] SHA-256 software-path speedup *(planned — upgrade to `sha2` 0.11 for the `x86-avx2` backend; see `docs/PLAN-sha2-0.11-upgrade.md`. The `sha2` 0.10 `asm` feature was evaluated and rejected: it breaks Windows MSVC. Note: CPUs with SHA-NI already auto-accelerate today.)*
- [ ] Performance regression detection

**Progress: 1 / 10 (10%)**

---

## 🟡 Phase 6 — Security hardening

Production-grade security.

- [x] cargo-audit *(v0.3.0 — CI gate)*
- [x] cargo-deny *(v0.4.8 — bans/licenses/sources gate + `deny.toml`; OpenSSL explicitly banned)*
- [x] cargo-fuzz *(v0.4.8 — fuzz targets for Ed25519 verify, X25519 DH, base64/hex decode; weekly `fuzz.yml` workflow)*
- [ ] Miri
- [ ] AddressSanitizer
- [ ] UndefinedBehaviorSanitizer
- [ ] LeakSanitizer
- [x] Google Wycheproof vectors *(v0.4.5 AEAD: AES-GCM + ChaCha20-Poly1305, 382 vectors; v0.4.7 asymmetric: X25519 + Ed25519, 669 vectors — the latter prompted switching Ed25519 to strict verification, rejecting signature malleability & non-canonical encodings)*
- [x] Fuzz testing *(v0.4.8 — see cargo-fuzz; "never panic on arbitrary input" harnesses)*
- [ ] Side-channel review
- [ ] Secure default configuration

**Progress: 5 / 11 (45%)**

---

## 🟡 Phase 7 — Modular architecture

Maintainable internal design.

- [x] Modular workspace crates *(10 crates as of v0.4.0)*
- [x] Shared error system *(via `thiserror`)*
- [x] Shared crypto traits *(via RustCrypto ecosystem)*
- [x] Internal utility crate *(`sc-utils`)*
- [x] Dedicated encoding crate *(`sc-encoding` — new in v0.4.0)*
- [ ] Common testing framework
- [x] Unified public API *(`sc-node` re-exports everything)*
- [ ] Stable internal abstractions

**Progress: 6 / 8 (75%)**

---

## 🟡 Phase 8 — Developer experience

Better APIs and documentation.

- [x] Complete TypeScript declarations *(auto-generated by napi-rs)*
- [x] ESM / CommonJS parity *(handled by napi-rs)*
- [ ] Tree-shaking support *(requires pure ESM — napi-rs doesn't make this easy)*
- [x] Interactive examples *(README code samples)*
- [x] API documentation *(bilingual EN + ES)*
- [ ] Migration guides
- [ ] Better error messages
- [ ] Cookbook examples

**Progress: 4 / 8 (50%)**

---

## 🟡 Phase 9 — Testing & Quality

Reliability and correctness.

- [x] Cross-platform CI *(matrix Linux/macOS/Windows/Android)*
- [ ] Continuous benchmarking
- [x] Coverage reports *(100% TS-side, ~99% Rust-side)*
- [ ] Property-based testing *(proptest available in dev-deps, not yet used broadly)*
- [ ] Stress testing
- [ ] Large input testing
- [ ] Concurrency testing
- [ ] Memory leak detection
- [ ] Reproducible builds

**Progress: 2 / 9 (22%)**

---

## 🔴 Phase 10 — Enterprise readiness

Long-term production support.

- [ ] Stable API guarantees
- [ ] Semantic versioning policy
- [ ] Security policy
- [ ] CVE response process
- [ ] Software Bill of Materials (SBOM)
- [ ] Signed release artifacts
- [ ] Long-term support releases
- [ ] External security audit
- [ ] Published benchmark reports

**Progress: 0 / 9 (0%)**

---

## 🔴 Phase 11 — Advanced cryptography

Additional algorithms for advanced use cases.

- [ ] AES Key Wrap (RFC 3394)
- [ ] AES Key Wrap with Padding (RFC 5649)
- [ ] AES-CTR
- [ ] AES-XTS
- [ ] HKDF multi-key derivation
- [ ] Streaming encryption helpers
- [ ] Incremental hashing APIs
- [ ] Incremental HMAC APIs
- [ ] Secure key serialization
- [ ] Secure key import/export

**Progress: 0 / 10 (0%)**

---

## 🔴 Phase 12 — Future improvements

Long-term enhancements.

- [ ] Hardware-backed acceleration
- [ ] Pluggable cryptographic backends
- [ ] Runtime CPU feature detection
- [ ] Configurable secure allocators
- [ ] Memory protection APIs
- [ ] Advanced benchmark suite
- [ ] Performance telemetry hooks
- [ ] Long-term compatibility testing

**Progress: 0 / 8 (0%)**

---

## 📊 Overall Progress

| Phase | Progress |
|-------|----------|
| 1. Cryptographic foundation | ✅ 100% (13/13) |
| 2. Multi-platform support | 🟡 71% (10/14) |
| 3. Cryptographic utilities | ✅ 100% (11/11) |
| 4. Modern cryptographic primitives | 🟡 56% (5/9) |
| 5. Performance | 🟡 10% (1/10) |
| 6. Security hardening | 🟡 45% (5/11) |
| 7. Modular architecture | 🟡 75% (6/8) |
| 8. Developer experience | 🟡 50% (4/8) |
| 9. Testing & Quality | 🟡 22% (2/9) |
| 10. Enterprise readiness | 🔴 0% (0/9) |
| 11. Advanced cryptography | 🔴 0% (0/10) |
| 12. Future improvements | 🔴 0% (0/8) |

**Total: 57 / 120 (48%)**

---

## 🎯 Near-term Focus (v0.5.0 candidates)

Not committed — this is a menu of the next natural steps, in rough priority order:

1. ~~**Finish Phase 3 (Utilities)**~~ — ✅ done in v0.4.1 (`split`, `bytesEqual`, `concatBytes`, `splitBytes`; the roadmap was also synced with helpers that already shipped).
2. **XChaCha20-Poly1305** — extended-nonce AEAD (24-byte nonces), useful when you can't guarantee nonce uniqueness with 12 bytes.
3. **PBKDF2-SHA256** — password-based KDF, small addition, useful for key derivation from user passwords.
4. **Argon2id** — modern password hashing, replaces PBKDF2 for greenfield use cases.
5. **Criterion benchmarks** *(Phase 5)* — establish baseline before performance work begins.

---

## 💡 Notes on Deferred Items

**iOS ARM64:** Requires macOS host + Xcode + Apple Developer certificate (paid). Additionally, "Node.js on iOS" is essentially non-existent as a runtime (React Native uses JSI, not NAPI; NodeJS-Mobile is unmaintained). Deferred until WASM lands — which will cover React Native use cases via a bridge anyway.

**WASM:** Higher priority than iOS ARM64. Opens up React Native (via `react-native-wasm`), browsers, and Cloudflare Workers in one binary target.

**Post-quantum cryptography:** Not tracked in this roadmap — it's a separate long-term effort (probably v2.0.0).

---

🔐 + ❤️ Hepein Oficial — *Signalis Core is a passion project of [@Brashkie](https://github.com/Brashkie).*
