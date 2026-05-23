# 🛡️ Security Policy

## Supported Versions

| Version | Supported | Status |
|---------|-----------|--------|
| 0.2.x | ✅ | Active development |
| 0.1.x | ⚠️ | Security fixes only (until 2026-08-01) |
| < 0.1 | ❌ | Not supported |

When a new minor version is released, the previous minor enters **3 months of security-only support**.

---

## 🚨 Reporting a Vulnerability

**Please do NOT open public GitHub issues for security bugs.**

### Reporting Channels

Use one of these private channels:

1. **GitHub Security Advisories** (preferred):
   - https://github.com/Brashkie/signalis-core/security/advisories/new

2. **Email**: brashkie@hepein.com
   - PGP key: [download from GitHub profile]
   - Subject: `[SECURITY] signalis-core: <brief description>`

### What to Include

To help us triage quickly, please provide:

- **Description** of the vulnerability
- **Affected versions** (if known)
- **Reproduction steps** (proof of concept welcome)
- **Impact assessment** (your view on severity)
- **Suggested fix** (if any)
- **Your contact info** (for follow-up)

### Response Timeline

| Severity | First response | Fix target |
|----------|---------------|------------|
| **Critical** (remote exploit, key recovery) | 24 hours | 7 days |
| **High** (timing leaks, DoS) | 3 days | 30 days |
| **Medium** (specific edge cases) | 7 days | Next minor release |
| **Low** (theoretical, hard to exploit) | 14 days | Best effort |

### Disclosure Process

1. We acknowledge receipt within the timeframes above
2. We investigate and confirm the issue
3. We develop a fix in a private branch
4. We prepare a security advisory
5. We coordinate a release (typically 7-30 days from confirmation)
6. **You are credited** in the advisory (unless you prefer anonymity)

### Bounty Program

We do **not** currently offer monetary bounties, but we:
- Publicly credit researchers (with permission)
- Provide signed acknowledgment letters
- Add you to the contributors hall of fame

If you're interested in funded research, please reach out.

---

## 🔒 Security Considerations

### Cryptographic Implementation

All primitives use **audited, widely-deployed Rust crates**:

| Primitive | Crate | Last audited |
|-----------|-------|--------------|
| Curve25519 | `curve25519-dalek` 4.x | 2023 (Cure53) |
| Ed25519 | `ed25519-dalek` 2.x | 2023 (Cure53) |
| AES-GCM | `aes-gcm` (RustCrypto) | 2022 |
| SHA-256/HMAC | `sha2`, `hmac` (RustCrypto) | 2022 |
| HKDF | `hkdf` (RustCrypto) | 2022 |

We do **not** implement primitives ourselves. Our work is:
- Glue code (NAPI bindings)
- Validation logic
- Type safety wrappers
- Test infrastructure

### Side-Channel Resistance

The underlying Rust crates provide:
- ✅ **Constant-time** scalar multiplication (Curve25519, Ed25519)
- ✅ **Constant-time** equality checks (HMAC verify, point equality)
- ✅ **AES-NI** hardware acceleration (when available)
- ✅ **Zeroization** of private key buffers on drop

### Known Limitations

#### XEd25519 (v0.2.0)

XEd25519 implementation follows the [Signal specification](https://signal.org/docs/specifications/xeddsa/). While Signal has deployed this in production for years, our implementation is **new** and has not been independently audited.

**Mitigation:** We use `curve25519-dalek`'s low-level primitives and `ed25519-dalek`'s `hazmat` API, both of which ARE audited. Only the high-level XEd25519 logic is ours.

If you require audited XEd25519, consider waiting for v1.0.0 (audited release).

#### Random Number Generation

We use `OsRng` from the `rand` crate, which sources entropy from:
- **Linux**: `getrandom()` syscall
- **macOS**: `SecRandomCopyBytes`
- **Windows**: `BCryptGenRandom`
- **iOS**: same as macOS

These are the standard, recommended sources. However:
- 🚨 **VMs with poor entropy** can produce weak keys
- 🚨 **Hibernation/snapshots** can reuse RNG state

Mitigation: Generate keys after the system has accumulated entropy, especially in VM contexts.

### Memory Safety

- **Rust side**: Compile-time memory safety, zeroization on drop
- **JS/Node side**: Buffers can be GC'd at any time

If you need guaranteed key wiping in JS:
```typescript
// Explicit overwrite (best effort)
function wipeKey(buf: Buffer) {
  buf.fill(0);
}
```

**Note:** Due to JS GC behavior, this is best-effort. For highest assurance, use HSM/TPM-backed keys.

### Network Security

This library provides **cryptographic primitives only**. It does NOT:
- ❌ Establish network connections
- ❌ Implement TLS/HTTPS
- ❌ Validate certificates
- ❌ Manage sessions

Your application is responsible for transport-layer security.

---

## 🚫 Out of Scope

The following are **not considered vulnerabilities**:

- 🔵 **Performance issues** (open as feature request)
- 🔵 **API ergonomics** (open as feature request)
- 🔵 **Documentation typos** (open as PR)
- 🔵 **Behavior on invalid inputs** that throws clear errors (working as intended)
- 🔵 **Side-channels in user code** (your code's responsibility)
- 🔵 **Issues in dependencies** (report upstream, but tell us too)
- 🔵 **Hypothetical attacks** without practical demonstration

---

## 🏆 Hall of Fame

We thank the following security researchers for responsible disclosure:

_(Empty for now — be the first!)_

---

## 📚 Security Resources

For learning about cryptographic security:

- 📘 [Cryptography Engineering](https://www.schneier.com/books/cryptography-engineering/) — Schneier, Ferguson, Kohno
- 📘 [Real-World Cryptography](https://www.manning.com/books/real-world-cryptography) — David Wong
- 📘 [Serious Cryptography](https://nostarch.com/seriouscrypto) — Jean-Philippe Aumasson
- 🌐 [Signal Protocol Documentation](https://signal.org/docs/)
- 🌐 [Cryptography Stack Exchange](https://crypto.stackexchange.com/)

---

## 🔄 Policy Updates

This policy may be updated. Significant changes will be:
1. Committed to the repo with a clear commit message
2. Announced in the next release notes
3. Posted in GitHub Discussions

**Last updated:** May 2026
**Next scheduled review:** November 2026
