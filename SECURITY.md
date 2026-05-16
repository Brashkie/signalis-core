# 🛡️ Security Policy

## Reporting a Vulnerability

The Signalis Core team takes security seriously. We appreciate your efforts to responsibly disclose your findings.

### 🚨 Please DO NOT

- ❌ Open a public GitHub issue
- ❌ Discuss the vulnerability publicly before it's resolved
- ❌ Exploit the vulnerability beyond proof of concept

### ✅ Please DO

Report vulnerabilities using GitHub's [private vulnerability reporting](https://github.com/Brashkie/signalis-core/security/advisories/new).

Please include:

1. **Description** of the vulnerability
2. **Steps to reproduce** (minimal proof of concept)
3. **Impact assessment** (what an attacker could do)
4. **Suggested fix** (if you have one)
5. **Your name/handle** for credit (optional)

### Response Timeline

| Action | Timeline |
|--------|----------|
| Initial acknowledgment | Within **72 hours** |
| Severity assessment | Within **7 days** |
| Fix for critical issues | Within **30 days** |
| Fix for high issues | Within **60 days** |
| Fix for medium/low | Within **90 days** |
| Public disclosure | After fix is released |

---

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
|---------|--------------------|
| 0.x     | ✅ Active development |
| Pre-release | ✅ Best effort   |

Once we release **v1.0**, we'll maintain LTS branches for at least 12 months each.

---

## Security Practices

### Cryptographic Implementation

- **All primitives use audited Rust crates**:
  - `curve25519-dalek` (audited by NCC Group)
  - RustCrypto suite (`aes`, `hkdf`, `hmac`, `sha2`)
- **No `unsafe` Rust** in our wrapper code (enforced by `#![deny(unsafe_code)]`)
- **Constant-time** comparisons via the `subtle` crate
- **Automatic zeroization** of sensitive data via the `zeroize` crate
- **Test vectors from official RFCs/NIST** for every primitive

### CI/CD Security

- **`cargo audit`** runs on every PR (checks for known vulnerabilities)
- **`clippy`** with `-D warnings` flag (catches common Rust issues)
- **Multi-OS testing** (Linux, macOS, Windows)
- **Multi-Node version testing** (18, 20, 22)
- **Dependabot** monitors dependencies

### Dependencies

We follow a **minimal dependency** philosophy:

- No transitive dependencies older than 6 months
- All cryptographic deps from RustCrypto or dalek-cryptography
- No deps with known security advisories (verified weekly)
- All deps pinned to specific versions in `Cargo.lock`

---

## Known Limitations

Please be aware of the following:

### Side-Channel Resistance

While we use constant-time primitives where possible, **side-channel resistance ultimately depends on the underlying Rust crates**. We do not guarantee complete resistance to:

- Cache-timing attacks
- Power analysis attacks
- Speculative execution attacks (Spectre/Meltdown)

For applications requiring formal side-channel protection, consider hardware security modules.

### JavaScript Runtime Limitations

JavaScript runtimes (V8, JSCore) may keep copies of Buffer contents in:

- GC buffers
- Snapshot heaps
- String interning pools

This means our `zeroize` utility provides **best-effort cleanup**, not cryptographic erasure on the JS side. **All sensitive secrets are zeroized properly on the Rust side**, which is the primary security boundary.

### Threat Model

Signalis Core protects against:

- ✅ Passive eavesdroppers (encryption)
- ✅ Active man-in-the-middle (authenticated encryption)
- ✅ Tampering of ciphertext (AES-GCM tag verification)
- ✅ Timing attacks on MAC verification (constant-time compare)

Signalis Core does NOT protect against:

- ❌ Compromised endpoints (malware on user's machine)
- ❌ Compromised PRNG (we trust the OS CSPRNG)
- ❌ Side-channel attacks beyond timing
- ❌ Social engineering
- ❌ Compromised dependencies before our level (Node.js, OS, hardware)

---

## Past Advisories

No security advisories have been issued yet.

When vulnerabilities are fixed, advisories will be published at:
https://github.com/Brashkie/signalis-core/security/advisories

---

## Acknowledgments

We thank the following researchers for responsibly disclosing security issues:

*(None yet — be the first!)*

---

## Cryptographic Disclosure

This library implements cryptographic primitives. Export, import, and/or use of cryptographic software is restricted in some countries. Please check your local laws and regulations before using this library.

---

## Contact

- **Security issues**: [Private vulnerability reporting](https://github.com/Brashkie/signalis-core/security/advisories/new)
- **Bugs (non-security)**: [GitHub Issues](https://github.com/Brashkie/signalis-core/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Brashkie/signalis-core/discussions)
