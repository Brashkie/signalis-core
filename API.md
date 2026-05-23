# 📖 API Reference

Complete API documentation for `@brashkie/signalis-core`.

> 📚 For tutorials and examples, see the [README](./README.md).
> 🗺️ For future plans, see the [ROADMAP](./ROADMAP.md).

---

## 📑 Table of Contents

- [Imports](#imports)
- [Curve25519](#curve25519)
- [Ed25519](#ed25519)
- [XEd25519](#xed25519)
- [HKDF](#hkdf)
- [AES_GCM](#aes_gcm)
- [AES_CBC](#aes_cbc)
- [HMAC](#hmac)
- [SHA256](#sha256)
- [Utilities](#utilities)
- [Constants](#constants)
- [Errors](#errors)
- [Types](#types)

---

## Imports

### Named (recommended)

```typescript
import {
  Curve25519,
  Ed25519,
  XEd25519,
  HKDF,
  AES_GCM,
  AES_CBC,
  HMAC,
  SHA256,
  secureRandom,
  // utilities, constants, errors...
} from '@brashkie/signalis-core';
```

### Default

```typescript
import sc from '@brashkie/signalis-core';
sc.Curve25519.generateKeyPair();
```

### CommonJS

```javascript
const { Curve25519, Ed25519 } = require('@brashkie/signalis-core');
```

---

## Curve25519

ECDH (Elliptic Curve Diffie-Hellman) using Curve25519.

### Properties

```typescript
Curve25519.PUBLIC_KEY_SIZE: 32
Curve25519.PRIVATE_KEY_SIZE: 32
```

### `generateKeyPair()`

Generate a new Curve25519 keypair using OS RNG.

```typescript
Curve25519.generateKeyPair(): KeyPair
```

**Returns:** `{ publicKey: Buffer, privateKey: Buffer }`

**Example:**
```typescript
const kp = Curve25519.generateKeyPair();
console.log(kp.publicKey.length);  // 32
console.log(kp.privateKey.length); // 32
```

### `diffieHellman(privateKey, publicKey)`

Compute the shared secret between two parties.

```typescript
Curve25519.diffieHellman(privateKey: Buffer, publicKey: Buffer): Buffer
```

**Parameters:**
- `privateKey` (Buffer, 32 bytes): Your private key
- `publicKey` (Buffer, 32 bytes): Their public key

**Returns:** `Buffer` (32 bytes) — shared secret

**Throws:** `ValidationError` if either key has wrong size.

**Example:**
```typescript
const alice = Curve25519.generateKeyPair();
const bob = Curve25519.generateKeyPair();

const aliceSecret = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
const bobSecret = Curve25519.diffieHellman(bob.privateKey, alice.publicKey);

assert(aliceSecret.equals(bobSecret)); // ✓
```

---

## Ed25519

Standard Ed25519 digital signatures (RFC 8032). Deterministic.

### Properties

```typescript
Ed25519.PUBLIC_KEY_SIZE: 32
Ed25519.PRIVATE_KEY_SIZE: 32
Ed25519.SIGNATURE_SIZE: 64
Ed25519.SEED_SIZE: 32
```

### `generateKeyPair()`

Generate a fresh Ed25519 keypair.

```typescript
Ed25519.generateKeyPair(): KeyPair
```

### `keyPairFromSeed(seed)`

Derive a keypair deterministically from a 32-byte seed.

```typescript
Ed25519.keyPairFromSeed(seed: Buffer): KeyPair
```

**Parameters:**
- `seed` (Buffer, 32 bytes)

**Use case:** Reproducible key generation for testing or HD wallets.

```typescript
const seed = Buffer.alloc(32, 1);
const kp1 = Ed25519.keyPairFromSeed(seed);
const kp2 = Ed25519.keyPairFromSeed(seed);
assert(kp1.publicKey.equals(kp2.publicKey)); // ✓ deterministic
```

### `publicFromPrivate(privateKey)`

Derive the public key from a private key.

```typescript
Ed25519.publicFromPrivate(privateKey: Buffer): Buffer
```

### `sign(privateKey, message)`

Sign a message. Signatures are deterministic (RFC 8032).

```typescript
Ed25519.sign(privateKey: Buffer, message: Buffer): Buffer
```

**Returns:** `Buffer` (64 bytes)

**Note:** Same message + same key = same signature (always).

### `verify(publicKey, message, signature)`

Verify a signature. **Throws on failure.**

```typescript
Ed25519.verify(publicKey: Buffer, message: Buffer, signature: Buffer): void
```

**Throws:** `Error` if signature is invalid or inputs malformed.

### `verifyBool(publicKey, message, signature)`

Verify a signature. Returns `boolean` (no throws).

```typescript
Ed25519.verifyBool(publicKey: Buffer, message: Buffer, signature: Buffer): boolean
```

---

## XEd25519

Signal-style signatures using Curve25519 keys. **Non-deterministic** by default.

This lets you use **one keypair** for both ECDH (`Curve25519`) and signing.

### Properties

```typescript
XEd25519.PUBLIC_KEY_SIZE: 32   // same as Curve25519
XEd25519.PRIVATE_KEY_SIZE: 32  // same as Curve25519
XEd25519.SIGNATURE_SIZE: 64
XEd25519.RANDOM_SIZE: 64
```

### `sign(privateKey, message)`

Sign with OS-provided randomness.

```typescript
XEd25519.sign(privateKey: Buffer, message: Buffer): Buffer
```

**Note:** Calling `sign` twice on the same input produces **different** signatures (both valid). Use `signWithRandom` for reproducibility.

### `signWithRandom(privateKey, message, random)`

Sign with explicit 64-byte randomness.

```typescript
XEd25519.signWithRandom(
  privateKey: Buffer,
  message: Buffer,
  random: Buffer  // 64 bytes
): Buffer
```

**Use case:** Test vectors, reproducible signatures.

### `verify(publicKey, message, signature)`

Verify XEd25519 signature. Throws on failure.

### `verifyBool(publicKey, message, signature)`

Verify XEd25519 signature. Returns boolean.

---

## HKDF

HKDF-SHA256 key derivation (RFC 5869).

### `derive(salt, ikm, info, outputLength)`

Derive a key of any length.

```typescript
HKDF.derive(
  salt: Buffer,
  ikm: Buffer,
  info: Buffer,
  outputLength: number  // 1 to 8160
): Buffer
```

**Parameters:**
- `salt`: Optional salt (use `Buffer.alloc(0)` for none)
- `ikm`: Input keying material (e.g., DH shared secret)
- `info`: Context info (e.g., `Buffer.from('chat-session-v1')`)
- `outputLength`: Desired key size in bytes

**Throws:** `ValidationError` if `outputLength` is out of range.

### `deriveMultiple(salt, ikm, info, lengths)`

Derive multiple keys efficiently in one call.

```typescript
HKDF.deriveMultiple(
  salt: Buffer,
  ikm: Buffer,
  info: Buffer,
  lengths: number[]
): Buffer[]
```

**Example:**
```typescript
const [encKey, macKey, iv] = HKDF.deriveMultiple(
  salt,
  sharedSecret,
  Buffer.from('session-v1'),
  [32, 32, 16]
);
```

---

## AES_GCM

AES-256-GCM authenticated encryption.

### Properties

```typescript
AES_GCM.KEY_SIZE: 32
AES_GCM.NONCE_SIZE: 12
AES_GCM.TAG_SIZE: 16
```

### `encrypt(key, nonce, plaintext)`

Encrypt without AAD.

```typescript
AES_GCM.encrypt(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer
```

**Output format:** `ciphertext || tag` (tag appended).

### `decrypt(key, nonce, ciphertext)`

Decrypt. Throws on tag mismatch.

```typescript
AES_GCM.decrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer): Buffer
```

### `encryptWithAad(key, nonce, plaintext, aad)` (v0.2.0+)

Encrypt with Additional Authenticated Data.

```typescript
AES_GCM.encryptWithAad(
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
  aad: Buffer
): Buffer
```

**AAD is authenticated but NOT encrypted.** Useful for binding metadata.

### `decryptWithAad(key, nonce, ciphertext, aad)` (v0.2.0+)

Decrypt with AAD verification.

```typescript
AES_GCM.decryptWithAad(
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  aad: Buffer
): Buffer
```

**Throws** if AAD doesn't match what was used in encryption.

### Nonce Reuse Warning

⚠️ **NEVER reuse a nonce with the same key.** This catastrophically breaks AES-GCM security.

Recommended approaches:
- Random 12-byte nonce per encryption (use `secureRandom(12)`)
- Counter-based nonces (carefully managed)
- Derive nonces from message numbers (Double Ratchet style)

---

## AES_CBC

AES-256-CBC with PKCS7 padding. ⚠️ Requires separate authentication (HMAC).

> **Recommendation:** Use `AES_GCM` unless you specifically need CBC.

### Properties

```typescript
AES_CBC.KEY_SIZE: 32
AES_CBC.IV_SIZE: 16
```

### `encrypt(key, iv, plaintext)`

```typescript
AES_CBC.encrypt(key: Buffer, iv: Buffer, plaintext: Buffer): Buffer
```

### `decrypt(key, iv, ciphertext)`

```typescript
AES_CBC.decrypt(key: Buffer, iv: Buffer, ciphertext: Buffer): Buffer
```

---

## HMAC

HMAC-SHA256.

### Properties

```typescript
HMAC.TAG_SIZE: 32
```

### `sha256(key, data)`

```typescript
HMAC.sha256(key: Buffer, data: Buffer): Buffer
```

**Returns:** 32-byte tag.

### `verifySha256(key, data, tag)`

Constant-time verification.

```typescript
HMAC.verifySha256(key: Buffer, data: Buffer, tag: Buffer): boolean
```

---

## SHA256

### Properties

```typescript
SHA256.HASH_SIZE: 32
```

### `hash(data)`

```typescript
SHA256.hash(data: Buffer): Buffer
```

### `hashAll(buffers)`

Hash the concatenation of multiple buffers (efficient).

```typescript
SHA256.hashAll(buffers: Buffer[]): Buffer
```

**Equivalent to but faster than:**
```typescript
SHA256.hash(Buffer.concat(buffers))
```

---

## Utilities

### `secureRandom(size)`

Generate cryptographically secure random bytes.

```typescript
secureRandom(size: number): Buffer
```

**Sources:**
- Linux: `getrandom()` syscall
- macOS: `SecRandomCopyBytes`
- Windows: `BCryptGenRandom`

### `randomKey()`

Shorthand for `secureRandom(32)`. Returns 32 random bytes.

### `randomNonce()`

Shorthand for `secureRandom(12)`. Returns 12 random bytes.

### Encoding

```typescript
toHex(buffer: Buffer): string
fromHex(hex: string): Buffer
toBase64(buffer: Buffer): string
fromBase64(b64: string): Buffer
```

### `constantTimeEqual(a, b)`

Compare two buffers in constant time. Use for comparing MACs/tags.

```typescript
constantTimeEqual(a: Buffer, b: Buffer): boolean
```

**Note:** Returns `false` if lengths differ (without leaking timing).

---

## Constants

All sizes are exported as top-level constants:

```typescript
// Curve25519
PUBLIC_KEY_SIZE         // 32
PRIVATE_KEY_SIZE        // 32
SHARED_SECRET_SIZE      // 32

// Ed25519
ED25519_PUBLIC_KEY_SIZE     // 32
ED25519_PRIVATE_KEY_SIZE    // 32
ED25519_SIGNATURE_SIZE      // 64
ED25519_SEED_SIZE           // 32

// XEd25519
XED25519_PUBLIC_KEY_SIZE    // 32
XED25519_PRIVATE_KEY_SIZE   // 32
XED25519_SIGNATURE_SIZE     // 64
XED25519_RANDOM_SIZE        // 64

// AES
AES_KEY_SIZE                // 32
AES_NONCE_SIZE              // 12
AES_TAG_SIZE                // 16
AES_CBC_IV_SIZE             // 16

// SHA / HMAC
HASH_SIZE                   // 32
MAC_SIZE                    // 32

// Library
VERSION                     // '0.2.0'
nativeVersion: string       // native binding version
```

---

## Errors

All errors extend the base `SignalisCoreError`.

### Hierarchy

```
SignalisCoreError
├── ValidationError      (bad input size/type)
├── AuthenticationError  (HMAC/GCM tag mismatch)
├── EncryptionError      (encryption operation failed)
├── DecryptionError      (decryption operation failed)
└── SignatureError       (signature invalid)
```

### Example

```typescript
import { AES_GCM, AuthenticationError } from '@brashkie/signalis-core';

try {
  AES_GCM.decrypt(key, nonce, tamperedCiphertext);
} catch (e) {
  if (e instanceof AuthenticationError) {
    console.log('Ciphertext was tampered with!');
  }
}
```

---

## Types

```typescript
interface KeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}
```

All keys, nonces, ciphertexts, and signatures are `Buffer` (Node's `Buffer`, which extends `Uint8Array`).

---

## 📊 Performance Notes

- All operations release the JS thread during native execution (non-blocking).
- For very small operations (< 1KB), overhead may dominate.
- Batching (e.g., `hashAll`) is faster than multiple separate calls.
- AES-NI used automatically on supported CPUs.

---

## 🐛 Error Recovery

If a function throws, the library state is **not corrupted**. You can:

- Retry with different inputs
- Catch and continue your control flow
- Log and fail gracefully

No global state is mutated by any function.

---

## 📚 Further Reading

- [Examples in README](./README.md#-quick-start)
- [Migration Guide](./MIGRATION.md)
- [Security Policy](./SECURITY.md)
- [Contributing](./CONTRIBUTING.md)
- [Roadmap](./ROADMAP.md)

---

**API stable in 1.x.x.** Pre-1.0 may have breaking changes between minor versions (documented in CHANGELOG).
