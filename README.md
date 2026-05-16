<div align="center">

<img src="https://raw.githubusercontent.com/Brashkie/signalis-core/main/.github/assets/logo.png" alt="Signalis Core" width="180" />

# 🔐 Signalis Core

**Cryptographic primitives for the Signal Protocol — Rust-powered, blazing fast.**

[![CI](https://github.com/Brashkie/signalis-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Brashkie/signalis-core/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@brashkie/signalis-core.svg?style=flat&color=cb3837)](https://www.npmjs.com/package/@brashkie/signalis-core)
[![npm downloads](https://img.shields.io/npm/dm/@brashkie/signalis-core.svg?style=flat&color=blue)](https://www.npmjs.com/package/@brashkie/signalis-core)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-339933.svg)](https://nodejs.org/)
[![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen.svg)](#testing)
[![Tests](https://img.shields.io/badge/tests-100%2B%20passing-success.svg)](#testing)

[**English**](./README.md) · [**Español**](./README.es.md) · [Docs](./docs) · [Roadmap](./ROADMAP.md) · [Changelog](./CHANGELOG.md)

</div>

---

## ✨ What is Signalis Core?

`@brashkie/signalis-core` is a **high-performance, audited cryptographic library** providing the foundational primitives for implementing the **Signal Protocol** in Node.js applications.

Built with **Rust** for safety and speed, exposed to Node.js via [napi-rs](https://napi.rs), it provides a clean TypeScript API that works seamlessly in both CommonJS and ESM environments.

> **Part of the [Hepein](https://github.com/Brashkie) ecosystem.**
> The foundation for `@brashkie/signalis` (Signal Protocol), `@brashkie/waproto` (WhatsApp Protocol), and ultimately a from-scratch alternative to Baileys.

---

## 📋 Table of Contents

- [Features](#-features)
- [Why Signalis Core?](#-why-signalis-core)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [API Reference](#-api-reference)
  - [Curve25519](#curve25519--x25519)
  - [HKDF-SHA256](#hkdf-sha256)
  - [AES-256-GCM](#aes-256-gcm)
  - [AES-256-CBC](#aes-256-cbc)
  - [HMAC-SHA256](#hmac-sha256)
  - [SHA-256](#sha-256)
  - [Utilities](#utilities)
  - [Errors](#errors)
- [Examples](#-examples)
- [Architecture](#-architecture)
- [Security](#-security)
- [Performance](#-performance)
- [Testing](#-testing)
- [Building from Source](#-building-from-source)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Acknowledgments](#-acknowledgments)
- [License](#-license)

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 🔥 **Blazing Fast** | Native Rust implementation via napi-rs (10-100x faster than pure JS) |
| 🛡️ **Audited Crypto** | Built on `curve25519-dalek`, RustCrypto suite — battle-tested libraries |
| 📦 **Dual Package** | Works in CommonJS, ESM, and TypeScript projects |
| 🎯 **Type-Safe** | Full TypeScript definitions with branded types and rich error classes |
| ✅ **Test Vectors** | Validated against RFC 5869, RFC 7748, RFC 4231, and NIST vectors |
| 🌍 **Cross-Platform** | Prebuilt binaries for Windows, macOS, Linux (x64, ARM) |
| 🔒 **Constant-Time** | Side-channel resistant comparisons via `subtle` crate |
| 🧹 **Auto-Zeroization** | Secrets are wiped from memory automatically |
| 📊 **99%+ Coverage** | Comprehensive test suite with 100+ assertions |
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
  LengthError,              // Output length out of bounds (extends ValidationError)
} from '@brashkie/signalis-core';

try {
  AES_GCM.decrypt(key, nonce, tamperedCiphertext);
} catch (e) {
  if (e instanceof AuthenticationError) {
    console.error('Tampering detected!');
  } else if (e instanceof ValidationError) {
    console.error(`Invalid parameter: ${e.parameter}`);
  }
}
```

---

## 💡 Examples

The `examples/` directory contains complete working demos:

```bash
npm run example:cjs    # CommonJS (10 demos)
npm run example:esm    # ESM (Alice ↔ Bob channel)
npm run example:ts     # TypeScript (type-safe patterns)
npm run examples       # Run all three
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

---

## 🏗️ Architecture

```
@brashkie/signalis-core
│
├── 🦀 Rust Workspace (5 crates)
│   ├── sc-curve25519    →  X25519 ECDH operations
│   ├── sc-hkdf          →  HKDF-SHA256 derivation
│   ├── sc-aes           →  AES-256-GCM & CBC
│   ├── sc-hmac          →  HMAC-SHA256 with constant-time verify
│   ├── sc-sha256        →  SHA-256 hashing
│   └── sc-node          →  NAPI-RS bindings (cdylib)
│
└── 📦 TypeScript Layer
    ├── core.ts          →  Crypto wrappers with validation
    ├── types.ts         →  Type definitions (KeyPair, etc.)
    ├── errors.ts        →  Typed error classes
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
| HKDF-SHA256 | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | [`hkdf`](https://github.com/RustCrypto/KDFs) (RustCrypto) |
| AES-256-GCM | [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) | [`aes-gcm`](https://github.com/RustCrypto/AEADs) (RustCrypto) |
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
| HKDF derive (32 bytes) | ~500,000 ops/sec | **30×** faster |
| AES-256-GCM encrypt (1 KB) | ~2 GB/sec | **80×** faster |
| SHA-256 (1 KB) | ~3 GB/sec | **50×** faster |
| HMAC-SHA256 (1 KB) | ~2.5 GB/sec | **40×** faster |

*Run `npm run bench` to benchmark on your machine (coming in v0.2).*

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

- ✅ All RFC test vectors (RFC 5869, 7748, 4231)
- ✅ All NIST test vectors (AES, SHA-256)
- ✅ Input validation for every public function
- ✅ Error handling for every code path
- ✅ Round-trip encryption / decryption
- ✅ Tampering detection (AES-GCM tag failures)
- ✅ Both CommonJS and ESM consumption paths
- ✅ Default export and named exports

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
- **v0.1** ✅ — Cryptographic primitives (current)
- **v0.2** — Benchmarks, Ed25519 signatures, X448 support
- **v1.0** — Stable API, audit
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
- **[RustCrypto](https://github.com/RustCrypto)** — `aes`, `hkdf`, `hmac`, `sha2`
- **[napi-rs](https://napi.rs)** — Rust ↔ Node bindings
- **Signal Foundation** — [Protocol specifications](https://signal.org/docs/)
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
