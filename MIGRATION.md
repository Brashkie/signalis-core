# Migration Guide

## v0.1.0 → v0.2.0

**TL;DR:** It's a 100% drop-in replacement. Just bump the version.

```bash
npm install @brashkie/signalis-core@^0.2.0
```

No code changes needed. All v0.1.0 APIs continue to work identically.

---

## What's New

You now have access to:

- **`Ed25519`** namespace for standard digital signatures
- **`XEd25519`** namespace for Signal-style signatures with Curve25519 keys
- **`AES_GCM.encryptWithAad()` / `decryptWithAad()`** for authenticated encryption with associated data
- **`SignatureError`** class for signature verification failures
- **`Signature`** branded type and **`asSignature()`** helper
- New constants: `ED25519_*` and `XED25519_*`

---

## What's NOT Changed

These continue to work exactly as in v0.1.0:

| API | Status |
|-----|--------|
| `Curve25519.generateKeyPair()` | ✅ Unchanged — still returns `{ privateKey, publicKey }`, still frozen |
| `Curve25519.publicFromPrivate()` | ✅ Unchanged |
| `Curve25519.diffieHellman()` | ✅ Unchanged |
| `HKDF.extract()`, `expand()`, `derive()`, `deriveMultiple()`, `deriveFromParams()` | ✅ Unchanged |
| `AES_GCM.encrypt()`, `decrypt()` | ✅ Unchanged |
| `AES_CBC.encrypt()`, `decrypt()` | ✅ Unchanged |
| `HMAC.sha256()`, `verifySha256()` | ✅ Unchanged |
| `SHA256.hash()`, `hashAll()` | ✅ Unchanged |
| All utilities (`secureRandom`, `toHex`, etc.) | ✅ Unchanged |
| All errors (`SignalisError`, `ValidationError`, etc.) | ✅ Unchanged |
| All constants (`CURVE25519_*`, `AES_*`, `HKDF_*`, etc.) | ✅ Unchanged |
| Default export (`SignalisCore`) | ✅ Unchanged (now includes `Ed25519` and `XEd25519`) |

The only change you'll observe in your code base is that `VERSION === '0.2.0'`.

---

## Step-by-Step Migration

### 1. Update the package

```bash
npm install @brashkie/signalis-core@^0.2.0
```

### 2. Verify

```bash
node -e "console.log(require('@brashkie/signalis-core').VERSION)"
# Should print: 0.2.0
```

### 3. Run your tests

Your existing test suite should pass without modifications. If anything fails, [open an issue](https://github.com/Brashkie/signalis-core/issues) — that would be a bug in v0.2.0.

### 4. (Optional) Use new features

#### Adopt Ed25519 for separate signing keys

```typescript
import { Ed25519 } from '@brashkie/signalis-core';

const keys = Ed25519.generateKeyPair();
const sig = Ed25519.sign(keys.privateKey, message);
Ed25519.verify(keys.publicKey, message, sig);
```

#### Or adopt XEd25519 (Signal-style)

```typescript
import { Curve25519, XEd25519 } from '@brashkie/signalis-core';

const identity = Curve25519.generateKeyPair();

// Use the SAME key for both ECDH and signing:
const shared = Curve25519.diffieHellman(identity.privateKey, peer);
const sig = XEd25519.sign(identity.privateKey, message);
XEd25519.verify(identity.publicKey, message, sig);
```

#### Bind metadata to ciphertext with AAD

```typescript
import { AES_GCM } from '@brashkie/signalis-core';

const header = Buffer.from('msg_id=42|sender=alice');
const ct = AES_GCM.encryptWithAad(key, nonce, plaintext, header);

// Decrypt MUST pass same AAD or fails
const pt = AES_GCM.decryptWithAad(key, nonce, ct, header);
```

---

## Common Patterns

### Pattern: Replacing HMAC-based authentication with proper signatures

**Before (v0.1.0):**

```typescript
// Using HMAC over arbitrary data — symmetric, both parties share the key
const tag = HMAC.sha256(sharedKey, dataToAuthenticate);
const valid = HMAC.verifySha256(sharedKey, dataToAuthenticate, receivedTag);
```

**After (v0.2.0):**

```typescript
// Using Ed25519 — asymmetric, sender signs, anyone with public key verifies
const sig = Ed25519.sign(signerPrivateKey, dataToAuthenticate);
Ed25519.verify(signerPublicKey, dataToAuthenticate, sig);
```

**When to use which:**

- **HMAC** — When both parties already share a secret (e.g., session key)
- **Ed25519/XEd25519** — When sender's identity needs to be verified by parties who only have the sender's public key

### Pattern: Single identity key for ECDH + Signing

**Before (v0.1.0):**

```typescript
// Needed two separate keypairs
const ecdhKeys = Curve25519.generateKeyPair();
// (no native signing — would need to roll your own)
```

**After (v0.2.0):**

```typescript
// One keypair for both!
const identity = Curve25519.generateKeyPair();

// ECDH:
const shared = Curve25519.diffieHellman(identity.privateKey, peerPublic);

// Signing with the SAME key:
const sig = XEd25519.sign(identity.privateKey, message);
```

This is the Signal Protocol's design: one identity key, multiple uses.

### Pattern: Authenticated metadata in encrypted messages

**Before (v0.1.0):**

```typescript
// Had to manually MAC the header alongside ciphertext
const ciphertext = AES_GCM.encrypt(key, nonce, body);
const headerMac = HMAC.sha256(key, header);
const packet = Buffer.concat([header, headerMac, ciphertext]);
// Receiver: verify MAC, then decrypt
```

**After (v0.2.0):**

```typescript
// AES-GCM with AAD handles both at once
const ciphertext = AES_GCM.encryptWithAad(key, nonce, body, header);
const packet = Buffer.concat([header, ciphertext]);
// Receiver: decrypt with same header
const body = AES_GCM.decryptWithAad(key, nonce, ciphertext, header);
// Header tampering → AuthenticationError automatically
```

---

## Performance Notes

- **No regressions** — all v0.1.0 paths are unchanged
- **New primitives:**
  - Ed25519 signing: ~25,000 ops/sec
  - Ed25519 verification: ~10,000 ops/sec
  - XEd25519 signing: ~20,000 ops/sec
  - XEd25519 verification: ~10,000 ops/sec
  - AAD adds <5% overhead vs no AAD
- **Bundle size:** +~50 KB (Ed25519 + XEd25519 Rust bindings, compressed)

---

## Compatibility Matrix

| Node.js | Status |
|---------|--------|
| 18.x | ✅ Supported |
| 20.x | ✅ Supported |
| 22.x | ✅ Supported |
| 24.x | ✅ Supported |

| Platform | Status |
|----------|--------|
| Windows x64 (MSVC) | ✅ Prebuilt |
| macOS x64 | ✅ Prebuilt |
| macOS ARM64 | ✅ Prebuilt |
| Linux x64 (glibc) | ✅ Prebuilt |
| Linux x64 (musl) | ✅ Prebuilt |
| Linux ARM64 (glibc) | ✅ Prebuilt |
| Linux ARM64 (musl) | ✅ Prebuilt |

---

## FAQ

### Q: Do I have to change anything in my code?

**A:** No. v0.2.0 is 100% backwards compatible.

### Q: When should I use Ed25519 vs XEd25519?

**A:**
- **Ed25519** if you want clean separation between signing and ECDH keys, or you need deterministic signatures.
- **XEd25519** if you want to follow the Signal Protocol design (one identity key for both).

### Q: Is XEd25519 less secure than Ed25519?

**A:** No. Both provide the same 128-bit security level. XEd25519 is a clever construction that lets you reuse a Curve25519 key for signing without compromising security. It's been used by Signal in production for years.

### Q: Does AAD add overhead?

**A:** Negligible (<5%). AES-GCM natively supports AAD without performance penalty in the cryptographic operation; the small overhead is just the extra data passed across the NAPI boundary.

### Q: Will there be a v0.3.0?

**A:** Yes, but it will be handled by the higher-level `@brashkie/signalis` package, which builds X3DH and Double Ratchet on top of these primitives.

### Q: What if I find a bug?

**A:** [Open an issue](https://github.com/Brashkie/signalis-core/issues) on GitHub. For security issues, see [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## Resources

- [README.md](README.md) — Library overview
- [API.md](API.md) — Full API reference
- [EXAMPLES.md](EXAMPLES.md) — More usage examples
- [`examples/`](examples/) — Runnable code samples
- [CHANGELOG.md](CHANGELOG.md) — Full release history

🦀 + ❤️ Hepein Oficial
