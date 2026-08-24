/**
 * # @brashkie/signalis-core
 *
 * **Cryptographic primitives for the Signal Protocol — Rust-powered.**
 *
 * High-performance, audited crypto for Node.js with full TypeScript support.
 * Works seamlessly in both CommonJS and ESM environments.
 *
 * ## Quick start
 *
 * ```typescript
 * import { Curve25519, HKDF, AES_GCM, secureRandom } from '@brashkie/signalis-core';
 *
 * // 1. Generate keypairs
 * const alice = Curve25519.generateKeyPair();
 * const bob = Curve25519.generateKeyPair();
 *
 * // 2. ECDH key agreement
 * const shared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
 *
 * // 3. Derive a session key via HKDF
 * const key = HKDF.derive(
 *   Buffer.from('app-salt'),
 *   shared,
 *   Buffer.from('encryption'),
 *   32,
 * );
 *
 * // 4. Encrypt with AES-256-GCM
 * const nonce = secureRandom(12);
 * const ciphertext = AES_GCM.encrypt(key, nonce, Buffer.from('Secret!'));
 *
 * // 5. Decrypt
 * const plaintext = AES_GCM.decrypt(key, nonce, ciphertext);
 * ```
 *
 * ## Security
 *
 * - All primitives use audited Rust crates from RustCrypto / curve25519-dalek
 * - Constant-time operations where applicable
 * - Automatic zeroization of secrets on the Rust side
 * - Test vectors from RFC 5869, RFC 7748, RFC 4231, NIST
 *
 * @packageDocumentation
 */

// ═══════════════════════════════════════════════════════════════════════════
// Core crypto primitives
// ═══════════════════════════════════════════════════════════════════════════

export {
  Curve25519,
  Ed25519,
  XEd25519,
  HKDF,
  PBKDF2,
  Argon2id,
  AES_GCM,
  AES_CBC,
  HMAC,
  SHA256,
  SHA3,
  // NEW in v0.3.0
  ChaCha20Poly1305,
  // NEW in v0.4.3
  XChaCha20Poly1305,
  constantTimeEq,
  nativeSecureRandom,
  CHACHA20_POLY1305_KEY_SIZE,
  CHACHA20_POLY1305_NONCE_SIZE,
  CHACHA20_POLY1305_TAG_SIZE,
  XCHACHA20_POLY1305_NONCE_SIZE,
  // NEW in v0.4.0
  Base64,
  Hex,
  Utf8,
  // ────────────────
  nativeVersion,
} from './core';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

export type {
  KeyPair,
  PublicKey,
  PrivateKey,
  SharedSecret,
  Signature,
  PseudoRandomKey,
  HkdfParams,
  AesGcmParams,
  AesCbcParams,
  Encoding,
} from './types';

export {
  asPublicKey,
  asPrivateKey,
  asSharedSecret,
  asSignature,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════

export {
  SignalisError,
  ValidationError,
  CryptoError,
  AuthenticationError,
  KeyDerivationError,
  SignatureError,
  LengthError,
} from './errors';

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════

export {
  // Secure random
  secureRandom,
  randomNonce,
  randomIv,
  randomKey,
  // Encoding
  toHex,
  fromHex,
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
  bufferToString,
  stringToBuffer,
  // Constant-time
  constantTimeEqual,
  // Buffer manipulation
  concat,
  zeroize,
  xor,
  split,
  bytesEqual,
  // Byte-array (Uint8Array) helpers — for browser / WASM environments
  concatBytes,
  splitBytes,
} from './utils';

// ═══════════════════════════════════════════════════════════════════════════
// Validators (for advanced users building higher-level protocols)
// ═══════════════════════════════════════════════════════════════════════════

export {
  assertBuffer,
  assertBufferLength,
  assertBufferOfSize,
  assertPositiveInteger,
  assertHkdfLength,
  buffersSameLength,
} from './validators';

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

export {
  // Curve25519
  CURVE25519_PRIVATE_KEY_SIZE,
  CURVE25519_PUBLIC_KEY_SIZE,
  CURVE25519_SHARED_SECRET_SIZE,
  // Ed25519 (NEW v0.2.0)
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  ED25519_SEED_SIZE,
  // XEd25519 (NEW v0.2.0)
  XED25519_PRIVATE_KEY_SIZE,
  XED25519_PUBLIC_KEY_SIZE,
  XED25519_SIGNATURE_SIZE,
  XED25519_RANDOM_SIZE,
  // HKDF
  HKDF_PRK_SIZE,
  HKDF_MAX_OUTPUT_SIZE,
  // AES
  AES_256_KEY_SIZE,
  AES_256_GCM_NONCE_SIZE,
  AES_256_GCM_TAG_SIZE,
  AES_256_CBC_IV_SIZE,
  AES_BLOCK_SIZE,
  AES_GCM_MAX_PLAINTEXT_SIZE,
  AES_GCM_RECOMMENDED_MESSAGES_PER_KEY,
  // SHA-256 / HMAC
  SHA256_OUTPUT_SIZE,
  HMAC_SHA256_TAG_SIZE,
  SHA256_BLOCK_SIZE,
} from './constants';

// ═══════════════════════════════════════════════════════════════════════════
// Library version
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The version of `@brashkie/signalis-core` (matches `package.json`).
 *
 * Bumped on every release.
 */
export const VERSION = '0.4.10' as const;

// ═══════════════════════════════════════════════════════════════════════════
// Default export — Convenience namespace
// ═══════════════════════════════════════════════════════════════════════════

import {
  Curve25519,
  Ed25519,
  XEd25519,
  HKDF,
  PBKDF2,
  Argon2id,
  AES_GCM,
  AES_CBC,
  HMAC,
  SHA256,
  SHA3,
  ChaCha20Poly1305,
  XChaCha20Poly1305,
  Base64,
  Hex,
  Utf8,
  constantTimeEq,
  nativeSecureRandom,
  nativeVersion,
} from './core';
import {
  secureRandom,
  randomNonce,
  randomIv,
  randomKey,
  toHex,
  fromHex,
  toBase64,
  fromBase64,
  constantTimeEqual,
} from './utils';

/**
 * Default export — provides all primitives and helpers under one namespace.
 *
 * @example
 * ```ts
 * import sc from '@brashkie/signalis-core';
 *
 * const kp = sc.Curve25519.generateKeyPair();
 * const nonce = sc.secureRandom(12);
 * const b64 = sc.Base64.encode(nonce);
 * ```
 */
const SignalisCore = Object.freeze({
  // Crypto primitives
  Curve25519,
  Ed25519,
  XEd25519,
  HKDF,
  PBKDF2,
  Argon2id,
  AES_GCM,
  AES_CBC,
  ChaCha20Poly1305,
  XChaCha20Poly1305,
  HMAC,
  SHA256,
  SHA3,
  // Random
  secureRandom,
  nativeSecureRandom,
  randomNonce,
  randomIv,
  randomKey,
  // Encoding (JS-side legacy helpers — use Base64/Hex/Utf8 for native)
  toHex,
  fromHex,
  toBase64,
  fromBase64,
  // Encoding (NEW v0.4.0 — native, RFC-compliant)
  Base64,
  Hex,
  Utf8,
  // Security
  constantTimeEqual,
  constantTimeEq,
  // Version
  VERSION,
  nativeVersion,
});

export default SignalisCore;
