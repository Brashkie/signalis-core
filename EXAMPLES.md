# Examples

Practical patterns and snippets for `@brashkie/signalis-core` v0.2.0.

## Table of Contents

1. [Generating Keys](#1-generating-keys)
2. [ECDH Key Agreement](#2-ecdh-key-agreement)
3. [Key Derivation with HKDF](#3-key-derivation-with-hkdf)
4. [AES-256-GCM Encryption](#4-aes-256-gcm-encryption)
5. [AES-GCM with AAD (NEW v0.2.0)](#5-aes-gcm-with-aad-new-v020)
6. [Ed25519 Signatures (NEW v0.2.0)](#6-ed25519-signatures-new-v020)
7. [XEd25519 Signatures (NEW v0.2.0)](#7-xed25519-signatures-new-v020)
8. [HMAC Authentication](#8-hmac-authentication)
9. [SHA-256 Hashing](#9-sha-256-hashing)
10. [Encoding Helpers](#10-encoding-helpers)
11. [Error Handling](#11-error-handling)
12. [Full E2E Channel](#12-full-e2e-channel)

---

## 1. Generating Keys

```typescript
import { Curve25519, Ed25519, secureRandom, randomKey, randomNonce } from '@brashkie/signalis-core';

// Curve25519 (for ECDH)
const ecdhKeys = Curve25519.generateKeyPair();
// → { privateKey: Buffer(32), publicKey: Buffer(32) }

// Ed25519 (for standard signing) — NEW v0.2.0
const signKeys = Ed25519.generateKeyPair();
// → { privateKey: Buffer(32), publicKey: Buffer(32) }

// Deterministic Ed25519 from a seed
const seed = Buffer.alloc(32, 0x42);
const deterministic = Ed25519.keyPairFromSeed(seed);

// Random symmetric key (AES, HMAC, etc.)
const key = randomKey();           // 32 bytes
const aesGcmNonce = randomNonce(); // 12 bytes
const customRandom = secureRandom(64); // any length
```

---

## 2. ECDH Key Agreement

```typescript
import { Curve25519, toHex } from '@brashkie/signalis-core';

const alice = Curve25519.generateKeyPair();
const bob = Curve25519.generateKeyPair();

// Each side computes the SAME shared secret using their private key
// and the OTHER party's public key
const aliceShared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
const bobShared = Curve25519.diffieHellman(bob.privateKey, alice.publicKey);

console.log(aliceShared.equals(bobShared)); // true

// ⚠️ NEVER use the shared secret directly as a key.
// Always derive via HKDF (see next section).
```

---

## 3. Key Derivation with HKDF

```typescript
import { HKDF } from '@brashkie/signalis-core';

const salt = Buffer.from('app-salt-v1');
const ikm = sharedSecret; // From ECDH, for example
const info = Buffer.from('encryption-key');

// One-shot (recommended)
const key = HKDF.derive(salt, ikm, info, 32);

// Two-step (advanced)
const prk = HKDF.extract(salt, ikm);
const okm = HKDF.expand(prk, info, 32);

// Derive multiple keys at once (for bidirectional channels)
const [sendKey, recvKey, sendIv, recvIv] = HKDF.deriveMultiple(
  salt,
  ikm,
  Buffer.from('bidirectional-channel'),
  [32, 32, 16, 16],
);

// Using a params object
const result = HKDF.deriveFromParams({
  salt,
  ikm,
  info: Buffer.from('my-context'),
  length: 64,
});
```

---

## 4. AES-256-GCM Encryption

```typescript
import { AES_GCM, randomKey, randomNonce, AuthenticationError } from '@brashkie/signalis-core';

const key = randomKey();
const nonce = randomNonce(); // ⚠️ MUST be unique per message with same key

const plaintext = Buffer.from('Secret message');

const ciphertext = AES_GCM.encrypt(key, nonce, plaintext);
const decrypted = AES_GCM.decrypt(key, nonce, ciphertext);

console.log(decrypted.toString()); // "Secret message"

// Tamper detection
const tampered = Buffer.from(ciphertext);
tampered[0] ^= 0xff;
try {
  AES_GCM.decrypt(key, nonce, tampered);
} catch (e) {
  if (e instanceof AuthenticationError) {
    console.error('Tampered!'); // ✅
  }
}
```

⚠️ **Critical:** Never reuse `(key, nonce)` pairs. Always generate a fresh nonce per message.

---

## 5. AES-GCM with AAD (NEW v0.2.0)

Use AAD to bind unencrypted metadata (like headers) to the ciphertext.

```typescript
import { AES_GCM, randomKey, randomNonce, AuthenticationError } from '@brashkie/signalis-core';

const key = randomKey();
const nonce = randomNonce();
const body = Buffer.from('Top secret body');
const header = Buffer.from('msg_id=42|sender=alice|timestamp=' + Date.now());

// Encrypt
const ciphertext = AES_GCM.encryptWithAad(key, nonce, body, header);

// Decrypt — must pass SAME aad or it fails
const decrypted = AES_GCM.decryptWithAad(key, nonce, ciphertext, header);

// Tampering with header (AAD) → fails
const tamperedHeader = Buffer.from(header);
tamperedHeader[5] ^= 0xff;
try {
  AES_GCM.decryptWithAad(key, nonce, ciphertext, tamperedHeader);
} catch (e) {
  if (e instanceof AuthenticationError) {
    console.error('Header tampering detected!');
  }
}
```

**Use cases:**

- Bind message headers to ciphertext (Signal Protocol's "associated data")
- Authenticate routing metadata without encrypting it
- Protect API request tokens alongside encrypted payloads

---

## 6. Ed25519 Signatures (NEW v0.2.0)

Standard Ed25519 — deterministic signatures (RFC 8032).

```typescript
import { Ed25519, SignatureError } from '@brashkie/signalis-core';

const keys = Ed25519.generateKeyPair();
const message = Buffer.from('Important contract');

// Sign
const signature = Ed25519.sign(keys.privateKey, message);
// → Buffer(64)

// Verify (throws on failure)
try {
  Ed25519.verify(keys.publicKey, message, signature);
  console.log('Valid!');
} catch (e) {
  if (e instanceof SignatureError) {
    console.error('Invalid:', e.message);
  }
}

// Verify (boolean, no throw)
if (Ed25519.verifyBool(keys.publicKey, message, signature)) {
  console.log('Valid!');
}

// Deterministic: same input → same output
const sig1 = Ed25519.sign(keys.privateKey, message);
const sig2 = Ed25519.sign(keys.privateKey, message);
console.log(sig1.equals(sig2)); // true

// Derive from a seed for reproducibility
const seed = Buffer.alloc(32, 0x42);
const fromSeed = Ed25519.keyPairFromSeed(seed);

// Get public key from private key
const pub = Ed25519.publicFromPrivate(keys.privateKey);
console.log(pub.equals(keys.publicKey)); // true
```

---

## 7. XEd25519 Signatures (NEW v0.2.0)

Sign with the SAME Curve25519 keypair used for ECDH (Signal Protocol style).

```typescript
import { Curve25519, XEd25519 } from '@brashkie/signalis-core';

// ONE keypair for everything
const identity = Curve25519.generateKeyPair();
const peer = Curve25519.generateKeyPair();

// Use for ECDH:
const shared = Curve25519.diffieHellman(identity.privateKey, peer.publicKey);

// Use the SAME key to sign messages:
const message = Buffer.from('I am alice and I authorize this');
const signature = XEd25519.sign(identity.privateKey, message);

// Verify using the SAME Curve25519 public key:
XEd25519.verify(identity.publicKey, message, signature);

// XEd25519 signatures are NOT deterministic
const sig1 = XEd25519.sign(identity.privateKey, message);
const sig2 = XEd25519.sign(identity.privateKey, message);
console.log(sig1.equals(sig2)); // false (different each time)

// For deterministic XEd25519 (testing), provide explicit random
const random = Buffer.alloc(64, 0x99);
const detSig1 = XEd25519.signWithRandom(identity.privateKey, message, random);
const detSig2 = XEd25519.signWithRandom(identity.privateKey, message, random);
console.log(detSig1.equals(detSig2)); // true (deterministic with same random)
```

**When to use XEd25519 vs Ed25519:**

| Need | Use |
|------|-----|
| Single identity key for ECDH + signing | **XEd25519** |
| Separate signing key, deterministic sigs | **Ed25519** |
| Compatibility with Signal Protocol | **XEd25519** |
| RFC 8032 compliance | **Ed25519** |
| Reproducible signatures from seed | **Ed25519** |

---

## 8. HMAC Authentication

```typescript
import { HMAC, randomKey } from '@brashkie/signalis-core';

const key = randomKey();
const data = Buffer.from('message to authenticate');

// Generate tag
const tag = HMAC.sha256(key, data);

// Verify (constant-time)
const valid = HMAC.verifySha256(key, data, tag);
console.log(valid); // true

// vs wrong tag
const wrongTag = Buffer.alloc(32, 0);
console.log(HMAC.verifySha256(key, data, wrongTag)); // false
```

⚠️ **Always** use `verifySha256` (constant-time) instead of `tag1.equals(tag2)`.

---

## 9. SHA-256 Hashing

```typescript
import { SHA256 } from '@brashkie/signalis-core';

// Single buffer
const hash = SHA256.hash(Buffer.from('hello'));
console.log(hash.length); // 32

// Multiple buffers (concatenated internally)
const hashAll = SHA256.hashAll([
  Buffer.from('alice|'),
  Buffer.from('bob|'),
  Buffer.from('shared'),
]);
```

---

## 10. Encoding Helpers

```typescript
import { toHex, fromHex, toBase64, fromBase64, toBase64Url, fromBase64Url } from '@brashkie/signalis-core';

const buf = Buffer.from([0x01, 0x02, 0xff]);

// Hex
const hex = toHex(buf);          // "0102ff"
const back = fromHex(hex);       // Buffer([0x01, 0x02, 0xff])

// Base64
const b64 = toBase64(buf);       // "AQL/"
const b64Url = toBase64Url(buf); // "AQL_" (URL-safe, no padding)
```

---

## 11. Error Handling

```typescript
import {
  AES_GCM,
  Ed25519,
  HKDF,
  Curve25519,
  SignalisError,
  ValidationError,
  AuthenticationError,
  SignatureError,
  CryptoError,
  LengthError,
} from '@brashkie/signalis-core';

try {
  // Various operations
  const sig = Ed25519.sign(privateKey, message);
  AES_GCM.decryptWithAad(key, nonce, ciphertext, aad);
} catch (e) {
  // All errors inherit from SignalisError
  if (e instanceof SignalisError) {
    console.error(`[${e.code}] ${e.name}: ${e.message}`);
  }

  // More specific handling
  if (e instanceof ValidationError) {
    console.error(`Bad input: ${e.parameter} (expected ${e.expected})`);
  } else if (e instanceof AuthenticationError) {
    console.error('Tampered or wrong key!');
  } else if (e instanceof SignatureError) {
    console.error('Invalid signature!');
  } else if (e instanceof LengthError) {
    console.error('Wrong length');
  } else if (e instanceof CryptoError) {
    console.error('Crypto operation failed');
  }
}
```

Error hierarchy:

```
SignalisError (base)
├── ValidationError
│   └── LengthError
└── CryptoError
    ├── AuthenticationError      (AES-GCM tag mismatch)
    ├── SignatureError            (Ed25519/XEd25519 verify fail) — NEW v0.2.0
    └── KeyDerivationError
```

---

## 12. Full E2E Channel

A complete example combining everything for an end-to-end secure messaging channel.

```typescript
import {
  Curve25519,
  XEd25519,
  HKDF,
  AES_GCM,
  secureRandom,
} from '@brashkie/signalis-core';

// ─── Identity setup ─────────────────────────────────────────────────────
const alice = { identity: Curve25519.generateKeyPair() };
const bob = { identity: Curve25519.generateKeyPair() };

// ─── Handshake: Alice signs her ephemeral with her identity ─────────────
const aliceEphemeral = Curve25519.generateKeyPair();
const authSig = XEd25519.sign(alice.identity.privateKey, aliceEphemeral.publicKey);

// Alice sends to Bob: { identity.pk, ephemeral.pk, authSig }

// ─── Bob verifies and derives session ───────────────────────────────────
XEd25519.verify(alice.identity.publicKey, aliceEphemeral.publicKey, authSig);

const shared = Curve25519.diffieHellman(bob.identity.privateKey, aliceEphemeral.publicKey);

const [sendKey, recvKey] = HKDF.deriveMultiple(
  Buffer.from('signalis-session-v1'),
  shared,
  Buffer.concat([alice.identity.publicKey, bob.identity.publicKey]),
  [32, 32],
);

// ─── Encrypted messages with header binding ─────────────────────────────
function send(senderKey, body, msgId) {
  const nonce = secureRandom(12);
  const header = Buffer.from(JSON.stringify({ msg_id: msgId, ts: Date.now() }));
  const ciphertext = AES_GCM.encryptWithAad(senderKey, nonce, body, header);
  return { header, nonce, ciphertext };
}

function receive(recipientKey, packet) {
  return AES_GCM.decryptWithAad(
    recipientKey,
    packet.nonce,
    packet.ciphertext,
    packet.header,
  );
}

// Alice → Bob
const msg = send(sendKey, Buffer.from('Hello Bob!'), 1);
const received = receive(sendKey, msg);
console.log(received.toString()); // "Hello Bob!"
```

For a runnable version with detailed comments, see [`examples/e2e-channel.mjs`](examples/e2e-channel.mjs).

---

## More Resources

- [`examples/`](examples/) — Runnable code samples (`node examples/basic.mjs`)
- [API.md](API.md) — Complete API reference
- [MIGRATION.md](MIGRATION.md) — Upgrade guide
- [Signal Protocol docs](https://signal.org/docs/) — The protocol this library is designed for

🦀 + ❤️ Hepein Oficial
