# 🗺️ Roadmap

Long-term plan for `@brashkie/signalis-core`.

This roadmap is **directional, not prescriptive**. Versions and timelines may shift based on community feedback, security research, and ecosystem changes.

---

## 🎯 Vision

> A complete, production-ready cryptographic foundation for end-to-end encrypted messaging in TypeScript — fast as native libraries, easy as a JS package.

**Principles:**

1. **Security first** — audited primitives, no rolling our own
2. **Performance** — match or beat native bindings of established libraries
3. **Type safety** — leverage TypeScript fully (branded types, strict mode)
4. **Cross-platform** — pre-built binaries for all major platforms
5. **Ecosystem alignment** — compatible with Signal Protocol specs

---

## 📅 Release Timeline

```
v0.1.0 ━━━━━ Released May 2026 ━━━━━ Core primitives (foundation)
v0.2.0 ━━━━━ Released May 2026 ━━━━━ Signatures (Ed25519 + XEd25519) + AAD  ← CURRENT
v0.3.0 ━━━━━ Q3 2026 ━━━━━━━━━━━━━━━ Modern AEAD + KDF + protocol helpers
v0.4.0 ━━━━━ Q4 2026 ━━━━━━━━━━━━━━━ Advanced primitives + side-channel hardening
v0.5.0 ━━━━━ Q1 2027 ━━━━━━━━━━━━━━━ Group crypto + sender keys helpers
v1.0.0 ━━━━━ Q2 2027 ━━━━━━━━━━━━━━━ Stable API, security audit
v2.0.0 ━━━━━ 2028 ━━━━━━━━━━━━━━━━━━ Post-quantum cryptography
```

---

## ✅ v0.1.0 — Foundation (Released)

The initial release establishing the core architecture.

- [x] Rust workspace setup
- [x] NAPI-RS bindings infrastructure
- [x] Multi-platform builds (7 platforms via GitHub Actions)
- [x] Curve25519 (X25519 ECDH)
- [x] HKDF-SHA256
- [x] AES-256-GCM (no AAD)
- [x] AES-256-CBC
- [x] HMAC-SHA256
- [x] SHA-256
- [x] Encoding utilities (hex, base64)
- [x] Constant-time helpers

---

## ✅ v0.2.0 — Signatures + AAD (Released)

Digital signatures and authenticated encryption with associated data.

- [x] Ed25519 (RFC 8032)
- [x] XEd25519 (Signal-style signatures with Curve25519 keys)
- [x] AES-GCM with AAD support
- [x] Constants exposed in namespace API (`Ed25519.SIGNATURE_SIZE`, etc.)
- [x] Comprehensive RFC test vectors
- [x] CHANGELOG, migration guide

---

## 🚧 v0.3.0 — Modern Crypto Suite (Q3 2026)

Modern AEAD, additional KDFs, and protocol-level helpers.

### Symmetric Crypto
- [ ] **ChaCha20-Poly1305** — Alternative AEAD (faster on CPUs without AES-NI)
- [ ] **XChaCha20-Poly1305** — Extended nonce variant (96 → 192 bits)
- [ ] **AEAD streaming API** — For large files

### Hashing
- [ ] **SHA-512** — For applications requiring 512-bit hashes
- [ ] **BLAKE3** — Modern hash (faster than SHA-256 on multi-core)
- [ ] **HMAC-SHA512** — For interop with systems requiring it

### Key Derivation
- [ ] **HKDF-Expand-Label** — TLS 1.3-style label-prefixed HKDF
- [ ] **Argon2id** — Password-based key derivation (for PIN/passphrase encryption)
- [ ] **PBKDF2-HMAC-SHA256** — Legacy interop

### Protocol Helpers
- [ ] **X3DH helper functions** — `x3dhInitiate()` / `x3dhRespond()` building blocks
- [ ] **Double Ratchet primitives** — `ratchetEncrypt()` / `ratchetDecrypt()` low-level
- [ ] **Safety number generation** — SHA-512-based fingerprints (like Signal app)

### Quality Improvements
- [ ] **Streaming AEAD** for files > memory
- [ ] Benchmarks suite (`npm run bench`)
- [ ] Memory profiling tools

---

## 🔒 v0.4.0 — Hardening & Side-Channels (Q4 2026)

Production-grade defenses and edge cases.

### Side-Channel Defenses
- [ ] **Constant-time scalar multiplication** verification tests
- [ ] **Cache-attack resistance** documentation
- [ ] **Timing attack** test suite
- [ ] **Power analysis** considerations doc

### Memory Safety
- [ ] **Locked memory** for private keys (mlock on Linux)
- [ ] **Secure key wiping** verification
- [ ] **Stack canaries** in Rust crates

### Hardware Integration
- [ ] **HSM support** documentation (PKCS#11 stub)
- [ ] **TPM 2.0** integration helpers (Linux)
- [ ] **Apple Secure Enclave** docs
- [ ] **Windows TBS** stub

### Auditing & Compliance
- [ ] Third-party audit preparation
- [ ] FIPS 140-3 compliance assessment
- [ ] CRYPTREC evaluation
- [ ] Common Criteria documentation

---

## 👥 v0.5.0 — Groups & Sender Keys (Q1 2027)

Group messaging primitives for protocols like Signal's Sender Keys.

- [ ] **Sender key generation** helpers
- [ ] **Group chain key** derivation
- [ ] **Skipped message keys** management
- [ ] **Group state serialization** format
- [ ] **MLS-style tree operations** (optional, exploratory)

---

## 🎯 v1.0.0 — Stable Release (Q2 2027)

Production-ready, stable API, audited.

### Pre-1.0 Checklist
- [ ] Security audit by recognized firm
- [ ] 95%+ code coverage (Rust + TS)
- [ ] Fuzz testing (cargo-fuzz, AFL)
- [ ] Performance benchmarks vs libsignal-protocol
- [ ] Real-world deployment (powering production app)
- [ ] Stable API commitment (semver guarantees)
- [ ] Full documentation site (mdbook-based)
- [ ] Migration guides from 0.x → 1.0

### v1.0 API Promises
- ✅ No breaking changes in 1.x.x
- ✅ Deprecation warnings 6 months ahead
- ✅ LTS support (security patches for 2 years)

---

## 🌌 v2.0.0+ — Post-Quantum (2028)

Preparing for the quantum era.

### Post-Quantum Primitives
- [ ] **Kyber768** (ML-KEM) — Key encapsulation
- [ ] **Dilithium3** (ML-DSA) — Digital signatures
- [ ] **SPHINCS+** — Hash-based signatures (conservative option)

### Hybrid Schemes
- [ ] **X25519 + Kyber768** hybrid key exchange
- [ ] **Ed25519 + Dilithium** hybrid signatures
- [ ] PQXDH (Signal's post-quantum X3DH)

### Migration Tools
- [ ] Hybrid → PQ-only migration utilities
- [ ] Compatibility shims for legacy peers

---

## 📊 Performance Targets

| Operation | v0.2 actual | v1.0 target |
|-----------|------------:|------------:|
| SHA-256 (1KB) | 142k ops/s | 200k ops/s |
| Curve25519 keygen | 24k ops/s | 30k ops/s |
| Ed25519 sign | 12k ops/s | 18k ops/s |
| AES-GCM (1KB) | 250k ops/s | 350k ops/s |

Optimization strategies:
- AVX2/SIMD intrinsics
- Multi-threaded operations (`napi-rs` ThreadsafeFunction)
- Hardware accelerated AES (already using AES-NI)
- Compile-time optimization tuning

---

## 🌐 Ecosystem Goals

### Tooling
- [ ] **CLI tool** (`npx signalis-core`) for debugging/testing
- [ ] **Browser build** (WASM) — possibly via separate package
- [ ] **Deno support** — once Deno's NAPI compatibility matures
- [ ] **Bun support** — verify and document

### Integrations
- [ ] Reference example: chat app skeleton
- [ ] Plugins for popular frameworks (Express, Fastify, Hono)
- [ ] Storage adapters reference (IndexedDB, SQLite, Redis)

### Documentation
- [ ] Full mdBook site at `signalis.dev` (TBD domain)
- [ ] Interactive playground (CodeSandbox-style)
- [ ] Video tutorials
- [ ] Spanish + Portuguese translations

---

## 🤝 Community Priorities

We are particularly interested in contributions for:

🟢 **High priority**
- Cross-platform testing (especially edge cases)
- Documentation improvements
- Performance benchmarks vs other libraries
- Security review

🟡 **Medium priority**
- Additional language bindings (Python, Go via FFI)
- Example applications
- Tutorials and blog posts

🟠 **Exploratory**
- WASM build for browsers
- React Native bridge
- Mobile-first features

---

## ❓ What's NOT in Scope

To keep `signalis-core` focused, the following are **out of scope**:

- ❌ Higher-level protocols (use `@brashkie/signalis` for X3DH/Double Ratchet)
- ❌ Network/transport layer (use a separate library)
- ❌ Persistent storage (interface, don't implement)
- ❌ UI components / safety number rendering
- ❌ Account management / device linking flows
- ❌ Federation / discovery protocols

These belong in higher-level packages.

---

## 🔄 Versioning Strategy

We follow [semver](https://semver.org/):

- **Patch** (0.x.Y): Bug fixes, performance improvements
- **Minor** (0.X.0): New features, no breaking changes
- **Major** (X.0.0): Breaking changes (rare, well-documented)

In pre-1.0 (0.x.x):
- Minor versions **may** include small breaking changes
- All breaking changes documented in CHANGELOG with migration guide

After 1.0:
- Strict semver, no breaking changes in minors
- Deprecation cycle of 2+ minor versions before removal

---

## 💬 Feedback

This roadmap is **community-driven**. To influence priorities:

- 💬 Open a [Discussion](https://github.com/Brashkie/signalis-core/discussions)
- 🐛 Report [Issues](https://github.com/Brashkie/signalis-core/issues)
- 🗳️ Vote with 👍 on existing proposals
- 📧 Email: brashkie@hepein.com (for sensitive feedback)

---

**Last updated:** May 2026
**Next review:** August 2026
