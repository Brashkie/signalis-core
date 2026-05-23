# Changelog

All notable changes to `@brashkie/signalis-core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
