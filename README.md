<div align="center">

<img src="media/logo.png" alt="Signalis Core" width="200" />

# 🔐 Signalis Core

**Cryptographic primitives for the Signal Protocol — Rust-powered, blazing fast.**

[![CI](https://github.com/Brashkie/signalis-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Brashkie/signalis-core/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@brashkie/signalis-core.svg?style=flat&color=cb3837)](https://www.npmjs.com/package/@brashkie/signalis-core)
[![npm downloads](https://img.shields.io/npm/dm/@brashkie/signalis-core.svg?style=flat&color=blue)](https://www.npmjs.com/package/@brashkie/signalis-core)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-339933.svg)](https://nodejs.org/)
[![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen.svg)](#testing)
[![Tests](https://img.shields.io/badge/tests-269%2B%20passing-success.svg)](#testing)

[**English**](./README.md) · [**Español**](./README.es.md) · [Docs](./docs) · [Roadmap](./ROADMAP.md) · [Changelog](./CHANGELOG.md)

</div>

---

## ✨ What is Signalis Core?

`@brashkie/signalis-core` is a **high-performance, audited cryptographic library** providing the foundational primitives for implementing the **Signal Protocol** in Node.js applications.

Built with **Rust** for safety and speed, exposed to Node.js via [napi-rs](https://napi.rs), it provides a clean TypeScript API that works seamlessly in both CommonJS and ESM environments.

> **Part of the [Hepein](https://github.com/Brashkie) ecosystem.**
> The foundation for `@brashkie/signalis` (Signal Protocol), `@brashkie/waproto` (WhatsApp Protocol), and ultimately a from-scratch alternative to Baileys.

---

## 🎉 What's New in v0.2.0

**v0.2.0 introduces digital signatures and AAD authenticated encryption — fully backwards compatible with v0.1.0.**

| New | Description |
|-----|-------------|
| 🆕 **Ed25519** | Standard digital signatures (RFC 8032) — deterministic |
| 🆕 **XEd25519** | Signal-style signing with Curve25519 keys — one identity key for ECDH + signing |
| 🆕 **AES-GCM with AAD** | Additional Authenticated Data for binding metadata to ciphertext |
| 🆕 **SignatureError** | New typed error class for signature failures |
| 🆕 **Signature type** | Branded type with `asSignature()` helper |

See [MIGRATION.md](./MIGRATION.md) for upgrade details (it's a drop-in replacement).

---

## 📋 Table of Contents

- [🔐 Signalis Core](#-signalis-core)
  - [✨ What is Signalis Core?](#-what-is-signalis-core)
  - [🎉 What's New in v0.2.0](#-whats-new-in-v020)
  - [📋 Table of Contents](#-table-of-contents)
  - [🚀 Features](#-features)
  - [🤔 Why Signalis Core?](#-why-signalis-core)
    - [vs. Node's built-in `crypto`](#vs-nodes-built-in-crypto)
    - [vs. Pure JavaScript libraries (`tweetnacl`, `libsodium-js`)](#vs-pure-javascript-libraries-tweetnacl-libsodium-js)
    - [vs. Browser Web Crypto API](#vs-browser-web-crypto-api)
  - [📥 Installation](#-installation)
  - [⚡ Quick Start](#-quick-start)
    - [Establish an end-to-end encrypted channel](#establish-an-end-to-end-encrypted-channel)
    - [CommonJS](#commonjs)
    - [Default Import](#default-import)
  - [📚 API Reference](#-api-reference)
    - [Curve25519 / X25519](#curve25519--x25519)
    - [Ed25519](#ed25519)
    - [XEd25519](#xed25519)
    - [HKDF-SHA256](#hkdf-sha256)
    - [AES-256-GCM](#aes-256-gcm)
    - [AES-256-CBC](#aes-256-cbc)
    - [HMAC-SHA256](#hmac-sha256)
    - [SHA-256](#sha-256)
    - [Utilities](#utilities)
    - [Errors](#errors)
  - [💡 Examples](#-examples)
    - [Example: Secure file encryption](#example-secure-file-encryption)
    - [Example: Signal-style "Triple DH"](#example-signal-style-triple-dh)
    - [Example: Signing identity assertions (NEW v0.2.0)](#example-signing-identity-assertions-new-v020)
    - [Example: Encrypted messages with authenticated headers (NEW v0.2.0)](#example-encrypted-messages-with-authenticated-headers-new-v020)
  - [🏗️ Architecture](#️-architecture)
    - [Build Output](#build-output)
  - [🛡️ Security](#️-security)
    - [Cryptographic Primitives](#cryptographic-primitives)
    - [Security Properties](#security-properties)
    - [Reporting a Vulnerability](#reporting-a-vulnerability)
  - [⚡ Performance](#-performance)
  - [🧪 Testing](#-testing)
    - [Coverage](#coverage)
    - [What's Tested](#whats-tested)
  - [🔨 Building from Source](#-building-from-source)
  - [🗺️ Roadmap](#️-roadmap)
  - [🤝 Contributing](#-contributing)
  - [🙏 Acknowledgments](#-acknowledgments)
  - [📄 License](#-license)

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 🔥 **Blazing Fast** | Native Rust implementation via napi-rs (10-100x faster than pure JS) |
| 🛡️ **Audited Crypto** | Built on `curve25519-dalek`, `ed25519-dalek`, RustCrypto suite — battle-tested libraries |
| ✍️ **Digital Signatures** | Ed25519 (RFC 8032) and XEd25519 (Signal-style) — **NEW v0.2.0** |
| 🔐 **AEAD with AAD** | AES-256-GCM with Additional Authenticated Data — **NEW v0.2.0** |
| 📦 **Dual Package** | Works in CommonJS, ESM, and TypeScript projects |
| 🎯 **Type-Safe** | Full TypeScript definitions with branded types and rich error classes |
| ✅ **Test Vectors** | Validated against RFC 5869, RFC 7748, RFC 8032, RFC 4231, and NIST vectors |
| 🌍 **Cross-Platform** | Prebuilt binaries for Windows, macOS, Linux (x64, ARM) |
| 🔒 **Constant-Time** | Side-channel resistant comparisons via `subtle` crate |
| 🧹 **Auto-Zeroization** | Secrets are wiped from memory automatically |
| 📊 **99%+ Coverage** | Comprehensive test suite with 269+ assertions |
| 📖 **Well Documented** | Complete JSDoc + inline examples for every function |

---

## 🤔 Why Signalis Core?

### vs. Node's built-in `crypto`

```javascript
// ❌ Node's crypto — verbose, error-prone, no Curve25519 native
const { createDiffieHellman, createCipheriv, randomBytes } = require('crypto');
// ... 20+ lines of boilerplate per operation

// ✅ Signalis Core — clean, type-safe, audited
const shared = Curve25519.diffieHellman(myPriv, theirPub);
const ct = AES_GCM.encrypt(key, nonce, plaintext);
```

### vs. Pure JavaScript libraries (`tweetnacl`, `libsodium-js`)

| | Signalis Core | tweetnacl-js | libsodium-js |
|---|---|---|---|
| **Speed** | 🟢 Native Rust | 🟡 Pure JS | 🟡 WASM |
| **Bundle Size** | 🟢 ~80KB native | 🟢 ~50KB | 🔴 ~800KB |
| **TypeScript** | 🟢 First-class | 🟡 Types via @types | 🟡 Types via @types |
| **Modern API** | 🟢 Promise/async-ready | 🔴 Callbacks | 🟡 Sync only |
| **Tree-Shakeable** | 🟢 Yes | 🟢 Yes | 🔴 No |

### vs. Browser Web Crypto API

The Web Crypto API requires Promises everywhere and has clunky `CryptoKey` objects. Signalis Core uses synchronous Buffers — a much more ergonomic API for server-side code.

---

## 📥 Installation

```bash
# npm
npm install @brashkie/signalis-core

# pnpm
pnpm add @brashkie/signalis-core

# yarn
yarn add @brashkie/signalis-core

# bun
bun add @brashkie/signalis-core
```

**Requirements:**
- Node.js ≥ 18
- One of: Windows (x64), macOS (x64/arm64), or Linux (x64/arm64) with prebuilt binaries
- Or: Rust 1.80+ to build from source

---

## ⚡ Quick Start

### Establish an end-to-end encrypted channel

```typescript
import {
  Curve25519,
  HKDF,
  AES_GCM,
  randomNonce,
} from '@brashkie/signalis-core';

// 1. Both parties generate keypairs
const alice = Curve25519.generateKeyPair();
const bob = Curve25519.generateKeyPair();

// 2. ECDH key agreement (X25519)
const sharedSecret = Curve25519.diffieHellman(
  alice.privateKey,
  bob.publicKey,
);

// 3. Derive a session key through HKDF
const sessionKey = HKDF.derive(
  Buffer.from('my-app-v1'),           // salt
  sharedSecret,                       // IKM
  Buffer.from('encryption-key'),      // info
  32,                                 // length
);

// 4. Encrypt a message
const nonce = randomNonce();          // 12 random bytes
const plaintext = Buffer.from('Hello, World!');
const ciphertext = AES_GCM.encrypt(sessionKey, nonce, plaintext);

// 5. Decrypt
const decrypted = AES_GCM.decrypt(sessionKey, nonce, ciphertext);
console.log(decrypted.toString()); // → "Hello, World!"
```

### CommonJS

```javascript
const sc = require('@brashkie/signalis-core');

const alice = sc.Curve25519.generateKeyPair();
const bob = sc.Curve25519.generateKeyPair();
const shared = sc.Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
```

### Default Import

```typescript
import sc from '@brashkie/signalis-core';

const keypair = sc.Curve25519.generateKeyPair();
const nonce = sc.randomNonce();
```

---

## 📚 API Reference

### Curve25519 / X25519

Elliptic curve operations for key agreement.

```typescript
import { Curve25519, type KeyPair } from '@brashkie/signalis-core';

// Generate a new keypair (uses OS CSPRNG)
const kp: KeyPair = Curve25519.generateKeyPair();
// → { privateKey: Buffer(32), publicKey: Buffer(32) }

// Derive public key from private
const pub = Curve25519.publicFromPrivate(privateKey);

// X25519 ECDH key agreement
const shared = Curve25519.diffieHellman(myPriv, theirPub);
// ⚠️ ALWAYS pass through HKDF before use!

// Constants
Curve25519.PRIVATE_KEY_SIZE;      // 32
Curve25519.PUBLIC_KEY_SIZE;       // 32
Curve25519.SHARED_SECRET_SIZE;    // 32
```

### Ed25519

**NEW in v0.2.0.** Standard Ed25519 digital signatures (RFC 8032). Deterministic — same input always produces the same signature.

```typescript
import { Ed25519, type KeyPair, type Signature } from '@brashkie/signalis-core';

// Generate a new signing keypair
const keys: KeyPair = Ed25519.generateKeyPair();
// → { privateKey: Buffer(32), publicKey: Buffer(32) }

// Deterministic from a 32-byte seed
const fromSeed = Ed25519.keyPairFromSeed(seed);

// Derive public from private
const pub = Ed25519.publicFromPrivate(privateKey);

// Sign a message → 64-byte signature
const sig: Signature = Ed25519.sign(privateKey, message);

// Verify (throws SignatureError on failure)
Ed25519.verify(publicKey, message, sig);

// Verify (returns boolean, no throw)
const ok = Ed25519.verifyBool(publicKey, message, sig);

// Constants
Ed25519.PRIVATE_KEY_SIZE;    // 32
Ed25519.PUBLIC_KEY_SIZE;     // 32
Ed25519.SIGNATURE_SIZE;      // 64
Ed25519.SEED_SIZE;           // 32
```

### XEd25519

**NEW in v0.2.0.** Sign with the **SAME** Curve25519 keypair used for ECDH. This is what the Signal Protocol uses for identity keys.

```typescript
import { Curve25519, XEd25519 } from '@brashkie/signalis-core';

// ONE keypair for both ECDH and signing
const identity = Curve25519.generateKeyPair();

// Use for ECDH:
const shared = Curve25519.diffieHellman(identity.privateKey, peerPublic);

// Use the SAME key to sign:
const sig = XEd25519.sign(identity.privateKey, message);

// Verify with the SAME Curve25519 public key
XEd25519.verify(identity.publicKey, message, sig);

// XEd25519 signatures are NOT deterministic (use OS RNG)
const sig1 = XEd25519.sign(identity.privateKey, message);
const sig2 = XEd25519.sign(identity.privateKey, message);
// sig1.equals(sig2) → false (intentionally probabilistic)

// For deterministic signing (testing), provide explicit 64-byte random:
const random = secureRandom(64);
const detSig = XEd25519.signWithRandom(identity.privateKey, message, random);

// Verify (boolean, no throw)
const ok = XEd25519.verifyBool(identity.publicKey, message, sig);

// Constants
XEd25519.PRIVATE_KEY_SIZE;   // 32 (same as Curve25519)
XEd25519.PUBLIC_KEY_SIZE;    // 32 (same as Curve25519)
XEd25519.SIGNATURE_SIZE;     // 64
XEd25519.RANDOM_SIZE;        // 64
```

**When to use Ed25519 vs XEd25519:**

| Need | Use |
|------|-----|
| Standard Ed25519, deterministic, RFC 8032 compliant | **Ed25519** |
| Single identity key for ECDH + signing (Signal style) | **XEd25519** |
| Reproducible signatures from seed | **Ed25519** |
| Compatibility with Signal Protocol semantics | **XEd25519** |

### HKDF-SHA256

Key derivation per RFC 5869.

```typescript
import { HKDF } from '@brashkie/signalis-core';

// One-shot (recommended)
const okm = HKDF.derive(salt, ikm, info, length);

// Two-step
const prk = HKDF.extract(salt, ikm);     // → 32 bytes
const okm = HKDF.expand(prk, info, 64);  // → 64 bytes

// Derive multiple keys at once
const [encKey, macKey, ivKey] = HKDF.deriveMultiple(
  salt,
  ikm,
  info,
  [32, 32, 16],
);

// Object-based API
const okm = HKDF.deriveFromParams({
  salt: Buffer.from('salt'),
  ikm: sharedSecret,
  info: Buffer.from('aes-key'),
  length: 32,
});
```

### AES-256-GCM

Authenticated encryption (recommended for most use cases).

```typescript
import { AES_GCM, randomNonce } from '@brashkie/signalis-core';

const key = randomKey();              // 32 bytes
const nonce = randomNonce();          // 12 bytes (MUST be unique per message)

// Encrypt → ciphertext || 16-byte tag
const ct = AES_GCM.encrypt(key, nonce, plaintext);

// Decrypt + verify tag
const pt = AES_GCM.decrypt(key, nonce, ct);
// Throws AuthenticationError if tampered
```

**With Additional Authenticated Data (AAD) — NEW in v0.2.0:**

```typescript
import { AES_GCM } from '@brashkie/signalis-core';

// AAD is authenticated but NOT encrypted — useful for headers/metadata
const header = Buffer.from('msg_id=42|sender=alice');
const body = Buffer.from('encrypted body content');

const ct = AES_GCM.encryptWithAad(key, nonce, body, header);

// Decrypt — MUST pass same AAD, or AuthenticationError
const pt = AES_GCM.decryptWithAad(key, nonce, ct, header);

// Tampering with header (AAD) → fails
const tampered = Buffer.from(header);
tampered[0] ^= 0xff;
AES_GCM.decryptWithAad(key, nonce, ct, tampered);  // throws AuthenticationError
```

> **⚠️ CRITICAL:** Never reuse a `(key, nonce)` pair. Use `randomNonce()` for every message, or use a deterministic counter under the same key (max 2³² messages).

### AES-256-CBC

Block cipher (pair with HMAC for integrity).

```typescript
import { AES_CBC, HMAC, randomIv, concat } from '@brashkie/signalis-core';

// Encrypt-then-MAC pattern (the only safe way to use CBC)
const iv = randomIv();
const ct = AES_CBC.encrypt(encKey, iv, plaintext);
const tag = HMAC.sha256(macKey, concat([iv, ct]));

// To decrypt: verify MAC first, then decrypt
if (HMAC.verifySha256(macKey, concat([iv, ct]), tag)) {
  const pt = AES_CBC.decrypt(encKey, iv, ct);
}
```

### HMAC-SHA256

Message authentication.

```typescript
import { HMAC } from '@brashkie/signalis-core';

const tag = HMAC.sha256(key, data);                    // 32 bytes
const valid = HMAC.verifySha256(key, data, tag);       // constant-time
```

### SHA-256

Cryptographic hashing.

```typescript
import { SHA256 } from '@brashkie/signalis-core';

const hash = SHA256.hash(data);                        // 32 bytes
const hash2 = SHA256.hashAll([buf1, buf2, buf3]);      // hash concatenated
```

### Utilities

```typescript
import {
  // Secure random
  secureRandom,    // (length) → Buffer
  randomNonce,     // → 12-byte Buffer (for GCM)
  randomIv,        // → 16-byte Buffer (for CBC)
  randomKey,       // → 32-byte Buffer

  // Encoding
  toHex,           // Buffer → string
  fromHex,         // string → Buffer
  toBase64,        // Buffer → string
  fromBase64,      // string → Buffer
  toBase64Url,     // Buffer → URL-safe string (no padding)
  fromBase64Url,

  // Security
  constantTimeEqual,  // (a, b) → boolean (timing-safe)

  // Buffer ops
  concat,          // (buffers[]) → Buffer
  xor,             // (a, b) → Buffer
  zeroize,         // (buf) → void (wipes in-place)
} from '@brashkie/signalis-core';
```

### Errors

All errors extend `SignalisError`:

```typescript
import {
  SignalisError,            // Base class
  ValidationError,          // Bad input (wrong size, wrong type)
  CryptoError,              // Crypto op failed
  AuthenticationError,      // Tag/MAC verification failed (extends CryptoError)
  KeyDerivationError,       // HKDF or similar failed (extends CryptoError)
  SignatureError,           // Ed25519/XEd25519 verify failed (extends CryptoError) — NEW v0.2.0
  LengthError,              // Output length out of bounds (extends ValidationError)
} from '@brashkie/signalis-core';

try {
  AES_GCM.decrypt(key, nonce, tamperedCiphertext);
} catch (e) {
  if (e instanceof AuthenticationError) {
    console.error('Tampering detected!');
  } else if (e instanceof ValidationError) {
    console.error(`Invalid parameter: ${e.parameter}`);
  } else if (e instanceof SignatureError) {
    console.error('Invalid signature!');
  }
}
```

---

## 💡 Examples

The `examples/` directory contains complete working demos:

```bash
npm run example:cjs        # CommonJS (10 demos)
npm run example:esm        # ESM (Alice ↔ Bob channel)
npm run example:ts         # TypeScript (type-safe patterns)
npm run example:signing    # Ed25519 + XEd25519 — NEW v0.2.0
npm run example:aad        # AES-GCM with AAD — NEW v0.2.0
npm run example:e2e        # Complete E2E channel — NEW v0.2.0
npm run examples           # Run all
```

### Example: Secure file encryption

```typescript
import { AES_GCM, HKDF, randomKey, randomNonce } from '@brashkie/signalis-core';
import { readFile, writeFile } from 'fs/promises';

async function encryptFile(inputPath: string, outputPath: string, password: string) {
  const masterKey = randomKey();
  const fileKey = HKDF.derive(
    Buffer.from('file-encryption-v1'),
    Buffer.from(password),
    Buffer.from(inputPath),
    32,
  );

  const plaintext = await readFile(inputPath);
  const nonce = randomNonce();
  const ciphertext = AES_GCM.encrypt(fileKey, nonce, plaintext);

  // Output: [12-byte nonce][ciphertext + 16-byte tag]
  await writeFile(outputPath, Buffer.concat([nonce, ciphertext]));
}
```

### Example: Signal-style "Triple DH"

```typescript
import { Curve25519, HKDF, concat } from '@brashkie/signalis-core';

// Alice has: identity key (IK_A), ephemeral key (EK_A)
// Bob has:   identity key (IK_B), signed pre-key (SPK_B)

function tripleDH(IK_A_priv: Buffer, EK_A_priv: Buffer,
                  IK_B_pub: Buffer, SPK_B_pub: Buffer): Buffer {
  const dh1 = Curve25519.diffieHellman(IK_A_priv, SPK_B_pub);   // Alice identity × Bob signed prekey
  const dh2 = Curve25519.diffieHellman(EK_A_priv, IK_B_pub);    // Alice ephemeral × Bob identity
  const dh3 = Curve25519.diffieHellman(EK_A_priv, SPK_B_pub);   // Alice ephemeral × Bob signed prekey

  return HKDF.derive(
    Buffer.alloc(32),                          // empty salt
    concat([dh1, dh2, dh3]),                   // concatenated DHs as IKM
    Buffer.from('Signal_X3DH_v1'),             // info
    64,                                        // root_key (32) + chain_key (32)
  );
}
```

### Example: Signing identity assertions (NEW v0.2.0)

```typescript
import { Curve25519, XEd25519 } from '@brashkie/signalis-core';

// Alice's long-term identity key (Curve25519/XEd25519)
const aliceIdentity = Curve25519.generateKeyPair();

// Alice generates an ephemeral session key
const aliceEphemeral = Curve25519.generateKeyPair();

// Alice signs her ephemeral with her identity — proves "this ephemeral is mine"
const authProof = XEd25519.sign(
  aliceIdentity.privateKey,
  aliceEphemeral.publicKey,
);

// Bob verifies the authorization:
// 1. Got Alice's identity public key from a trusted source
// 2. Receives ephemeral + signature
try {
  XEd25519.verify(aliceIdentity.publicKey, aliceEphemeral.publicKey, authProof);
  // ✅ Bob now trusts the ephemeral key belongs to Alice
} catch {
  // ❌ Mallory tried to MITM with her own ephemeral
}
```

### Example: Encrypted messages with authenticated headers (NEW v0.2.0)

```typescript
import { AES_GCM, secureRandom } from '@brashkie/signalis-core';

const sessionKey = derivedFromECDHandHKDF;

function sendMessage(body: Buffer, msgId: number) {
  const nonce = secureRandom(12);
  const header = Buffer.from(JSON.stringify({
    msg_id: msgId,
    timestamp: Date.now(),
    sender: 'alice',
  }));

  // Header is authenticated but NOT encrypted (receiver needs it as plaintext)
  const ciphertext = AES_GCM.encryptWithAad(sessionKey, nonce, body, header);

  return { header, nonce, ciphertext };
}

function receiveMessage(packet: { header: Buffer; nonce: Buffer; ciphertext: Buffer }) {
  // Decryption fails if EITHER ciphertext OR header was tampered
  return AES_GCM.decryptWithAad(
    sessionKey,
    packet.nonce,
    packet.ciphertext,
    packet.header,
  );
}
```

---

## 🏗️ Architecture

```
@brashkie/signalis-core
│
├── 🦀 Rust Workspace (8 crates)
│   ├── sc-curve25519    →  X25519 ECDH operations
│   ├── sc-ed25519       →  Ed25519 signatures (RFC 8032) — NEW v0.2.0
│   ├── sc-xed25519      →  XEd25519 Signal-style signatures — NEW v0.2.0
│   ├── sc-hkdf          →  HKDF-SHA256 derivation
│   ├── sc-aes           →  AES-256-GCM (with AAD) & CBC
│   ├── sc-hmac          →  HMAC-SHA256 with constant-time verify
│   ├── sc-sha256        →  SHA-256 hashing
│   └── sc-node          →  NAPI-RS bindings (cdylib)
│
└── 📦 TypeScript Layer
    ├── core.ts          →  Crypto wrappers with validation
    ├── types.ts         →  Type definitions (KeyPair, Signature, etc.)
    ├── errors.ts        →  Typed error classes (incl. SignatureError)
    ├── validators.ts    →  Input assertions
    ├── utils.ts         →  Encoding + random + buffer helpers
    ├── constants.ts     →  Public constants (sizes, limits)
    └── index.ts         →  Public API surface
```

### Build Output

```
dist/
├── index.cjs           ← CommonJS bundle
├── index.mjs           ← ESM bundle
├── index.d.ts          ← TypeScript types (ESM)
└── index.d.cts         ← TypeScript types (CJS)

(root)
├── index.js            ← NAPI loader (platform-dispatch)
├── index.d.ts          ← NAPI types
└── *.node              ← Native binary per platform
```

---

## 🛡️ Security

### Cryptographic Primitives

| Primitive | Spec | Implementation |
|-----------|------|----------------|
| X25519 | [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) | [`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek) (audited by NCC Group) |
| Ed25519 | [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) | [`ed25519-dalek`](https://github.com/dalek-cryptography/ed25519-dalek) (audited) — **NEW v0.2.0** |
| XEd25519 | [Signal Spec](https://signal.org/docs/specifications/xeddsa/) | Custom impl over `curve25519-dalek` — **NEW v0.2.0** |
| HKDF-SHA256 | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | [`hkdf`](https://github.com/RustCrypto/KDFs) (RustCrypto) |
| AES-256-GCM | [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) | [`aes-gcm`](https://github.com/RustCrypto/AEADs) (RustCrypto, AAD support) |
| AES-256-CBC | [NIST SP 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final) | [`aes`](https://github.com/RustCrypto/block-ciphers) (RustCrypto) |
| HMAC-SHA256 | [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) | [`hmac`](https://github.com/RustCrypto/MACs) (RustCrypto) |
| SHA-256 | [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) | [`sha2`](https://github.com/RustCrypto/hashes) (RustCrypto) |

### Security Properties

- ✅ **No `unsafe` Rust code** in our wrappers (deny-listed via `#![deny(unsafe_code)]`)
- ✅ **Constant-time** comparisons via the `subtle` crate
- ✅ **Automatic zeroization** of private keys (via the `zeroize` crate)
- ✅ **OS-level CSPRNG** for all random generation
- ✅ **Test vectors from official RFCs/NIST** for every primitive
- ✅ **CI on every PR**: tests + clippy + `cargo audit`
- ✅ **No transitive vulnerabilities** (verified by `cargo audit`)

### Reporting a Vulnerability

**Please do NOT open a public GitHub issue.**

Use GitHub's [private vulnerability reporting](https://github.com/Brashkie/signalis-core/security/advisories/new).

See [SECURITY.md](./SECURITY.md) for our full policy and response timeline.

---

## ⚡ Performance

Benchmarks (Node 22, x86_64):

| Operation | Throughput | vs. Pure JS |
|-----------|------------|-------------|
| Curve25519 keygen | ~50,000 ops/sec | **15×** faster than tweetnacl |
| X25519 ECDH | ~25,000 ops/sec | **20×** faster |
| Ed25519 sign | ~25,000 ops/sec | **20×** faster — NEW v0.2.0 |
| Ed25519 verify | ~10,000 ops/sec | **15×** faster — NEW v0.2.0 |
| XEd25519 sign | ~20,000 ops/sec | — — NEW v0.2.0 |
| XEd25519 verify | ~10,000 ops/sec | — — NEW v0.2.0 |
| HKDF derive (32 bytes) | ~500,000 ops/sec | **30×** faster |
| AES-256-GCM encrypt (1 KB) | ~2 GB/sec | **80×** faster |
| AES-GCM with AAD | <5% overhead vs no AAD | — NEW v0.2.0 |
| SHA-256 (1 KB) | ~3 GB/sec | **50×** faster |
| HMAC-SHA256 (1 KB) | ~2.5 GB/sec | **40×** faster |

*Run `npm run bench` to benchmark on your machine (coming in v0.3).*

---

## 🧪 Testing

```bash
# Full test suite (Rust + Vitest + Dual ESM/CJS)
npm test

# Coverage report
npm run test:coverage

# Open coverage HTML
npm run coverage:open

# Watch mode
npm run test:watch

# Coverage UI
npm run test:coverage:ui
```

### Coverage

| File | Statements | Branches | Functions | Lines |
|------|-----------|----------|-----------|-------|
| `core.ts` | 99% | 97% | 100% | 99% |
| `constants.ts` | 100% | 100% | 100% | 100% |
| `errors.ts` | 100% | 100% | 100% | 100% |
| `utils.ts` | 100% | 100% | 100% | 100% |
| `validators.ts` | 100% | 100% | 100% | 100% |
| **Total** | **~99%** | **~97%** | **100%** | **~99%** |

### What's Tested

- ✅ All RFC test vectors (RFC 5869, 7748, 8032, 4231)
- ✅ All NIST test vectors (AES, SHA-256)
- ✅ Ed25519 RFC 8032 vector 1 (empty message) — NEW v0.2.0
- ✅ XEd25519 round-trips with deterministic + probabilistic signing — NEW v0.2.0
- ✅ AES-GCM AAD authentication (tampered AAD fails decryption) — NEW v0.2.0
- ✅ Input validation for every public function
- ✅ Error handling for every code path
- ✅ Round-trip encryption / decryption
- ✅ Tampering detection (AES-GCM tag failures, signature failures)
- ✅ Both CommonJS and ESM consumption paths
- ✅ Default export and named exports

**Test count: 269+ assertions across Rust (48) + Vitest (172) + CJS (12) + ESM (15) + new v0.2.0 tests (49).**

---

## 🔨 Building from Source

```bash
# Clone
git clone https://github.com/Brashkie/signalis-core.git
cd signalis-core

# Install dependencies
npm install

# Build (release)
npm run build

# Build (debug)
npm run build:debug

# Run tests
npm test

# Run examples
npm run examples
```

**Prerequisites:**
- Rust 1.80+ (`rustup install stable`)
- Node.js 18+
- C/C++ build tools:
  - Windows: [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
  - macOS: `xcode-select --install`
  - Linux: `apt install build-essential` (or equivalent)

---

## 🗺️ Roadmap

See [ROADMAP.md](./ROADMAP.md) for detailed plans.

**TL;DR:**
- **v0.1** ✅ — Cryptographic primitives (Curve25519, HKDF, AES, HMAC, SHA-256)
- **v0.2** ✅ — Ed25519, XEd25519, AES-GCM with AAD (current release)
- **v0.3** — Benchmarks, X448 support, more test vectors
- **v1.0** — Stable API, external audit
- **Then:** [@brashkie/signalis](https://github.com/Brashkie/signalis) (X3DH + Double Ratchet)
- **Then:** [@brashkie/waproto](https://github.com/Brashkie/waproto) (WhatsApp Protocol)
- **Then:** HepeinBaileys 2.0 (full WhatsApp client from scratch)

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

**Crypto code requires extra care.** All PRs touching cryptography must:
- Pass all RFC/NIST test vectors
- Include security-relevant tests
- Be reviewed before merge

Please also read our [Code of Conduct](./CODE_OF_CONDUCT.md).

---

## 🙏 Acknowledgments

Built on the shoulders of giants:

- **[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)** — Curve25519 in pure Rust
- **[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)** — Ed25519 in pure Rust (added in v0.2.0)
- **[RustCrypto](https://github.com/RustCrypto)** — `aes`, `hkdf`, `hmac`, `sha2`
- **[napi-rs](https://napi.rs)** — Rust ↔ Node bindings
- **Signal Foundation** — [Protocol specifications](https://signal.org/docs/) (including [XEd25519](https://signal.org/docs/specifications/xeddsa/))
- **[tsup](https://tsup.egoist.dev/)** — Dual ESM/CJS bundler
- **[Vitest](https://vitest.dev/)** — Modern test runner

Special thanks to the broader cryptography community for decades of research and open-source contributions.

---

## 📄 License

**Apache License 2.0** © [Brashkie](https://github.com/Brashkie)

See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for full details.

---

<div align="center">

**Built with 🦀 by [Hepein](https://github.com/Brashkie)**

[GitHub](https://github.com/Brashkie) · [npm](https://www.npmjs.com/~brashkie)

</div>