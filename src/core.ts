/**
 * Core cryptographic wrappers for signalis-core.
 *
 * Provides robust, validated, and well-documented APIs over the native Rust
 * crypto primitives.
 *
 * @packageDocumentation
 */

import * as native from '../index.js';

import {
  CURVE25519_PRIVATE_KEY_SIZE,
  CURVE25519_PUBLIC_KEY_SIZE,
  CURVE25519_SHARED_SECRET_SIZE,
  HKDF_PRK_SIZE,
  AES_256_KEY_SIZE,
  AES_256_GCM_NONCE_SIZE,
  AES_256_GCM_TAG_SIZE,
  AES_256_CBC_IV_SIZE,
  HMAC_SHA256_TAG_SIZE,
  SHA256_OUTPUT_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  ED25519_SEED_SIZE,
  XED25519_PRIVATE_KEY_SIZE,
  XED25519_PUBLIC_KEY_SIZE,
  XED25519_SIGNATURE_SIZE,
  XED25519_RANDOM_SIZE,
} from './constants';

import {
  CryptoError,
  AuthenticationError,
  SignatureError,
  LengthError,
} from './errors';

import {
  assertBufferOfSize,
  assertBuffer,
  assertHkdfLength,
  assertPositiveInteger,
} from './validators';

import type {
  KeyPair,
  HkdfParams,
  Signature,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// Curve25519 / X25519
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Curve25519 / X25519 elliptic curve operations.
 *
 * Provides:
 * - Keypair generation
 * - Public key derivation
 * - ECDH key agreement
 *
 * @example
 * ```ts
 * import { Curve25519 } from '@brashkie/signalis-core';
 *
 * const alice = Curve25519.generateKeyPair();
 * const bob = Curve25519.generateKeyPair();
 *
 * const shared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
 * // ⚠️ Always derive via HKDF before use as a key!
 * ```
 */
export const Curve25519 = Object.freeze({
  /**
   * Generate a new random Curve25519 keypair.
   *
   * Uses the OS's cryptographically secure RNG (via Rust's `OsRng`).
   *
   * @returns A {@link KeyPair} with private and public keys (32 bytes each)
   */
  generateKeyPair(): KeyPair {
    const kp = native.curve25519GenerateKeypair() as {
      private: Buffer;
      public: Buffer;
    };
    return Object.freeze({
      privateKey: kp.private,
      publicKey: kp.public,
    });
  },

  /**
   * Derive the public key corresponding to a given private key.
   *
   * @param privateKey - 32-byte private key
   * @returns The corresponding 32-byte public key
   * @throws {ValidationError} If `privateKey` is not a 32-byte Buffer.
   */
  publicFromPrivate(privateKey: Buffer): Buffer {
    assertBufferOfSize(privateKey, CURVE25519_PRIVATE_KEY_SIZE, 'privateKey');
    // X25519 base scalar mult cannot fail with a 32-byte (clamped) scalar
    return native.curve25519PublicFromPrivate(privateKey) as Buffer;
  },

  /**
   * Perform X25519 Diffie-Hellman key agreement.
   *
   * Both parties run this with swapped (private, peer-public) arguments
   * and obtain the same 32-byte shared secret.
   *
   * **⚠️ CRITICAL:** Do NOT use the returned secret directly as an
   * encryption key. Always derive an actual key through HKDF:
   *
   * @example
   * ```ts
   * const shared = Curve25519.diffieHellman(myPriv, theirPub);
   * const key = HKDF.derive(salt, shared, Buffer.from('aes-key'), 32);
   * ```
   *
   * @param privateKey - Your 32-byte private key
   * @param peerPublicKey - Peer's 32-byte public key
   * @returns 32-byte shared secret
   * @throws {ValidationError} If keys are not 32 bytes.
   * @throws {CryptoError} If the operation fails.
   */
  diffieHellman(privateKey: Buffer, peerPublicKey: Buffer): Buffer {
    assertBufferOfSize(privateKey, CURVE25519_PRIVATE_KEY_SIZE, 'privateKey');
    assertBufferOfSize(peerPublicKey, CURVE25519_PUBLIC_KEY_SIZE, 'peerPublicKey');
    // X25519 ECDH cannot fail with valid 32-byte inputs
    return native.curve25519DiffieHellman(privateKey, peerPublicKey) as Buffer;
  },

  /**
   * The size of a Curve25519 private key in bytes (32).
   */
  PRIVATE_KEY_SIZE: CURVE25519_PRIVATE_KEY_SIZE,

  /**
   * The size of a Curve25519 public key in bytes (32).
   */
  PUBLIC_KEY_SIZE: CURVE25519_PUBLIC_KEY_SIZE,

  /**
   * The size of an X25519 shared secret in bytes (32).
   */
  SHARED_SECRET_SIZE: CURVE25519_SHARED_SECRET_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// HKDF-SHA256
// ═══════════════════════════════════════════════════════════════════════════

/**
 * HKDF-SHA256 (RFC 5869) — HMAC-based Key Derivation Function.
 *
 * Provides cryptographic key derivation from high-entropy inputs (e.g., ECDH
 * shared secrets) into arbitrary-length output keying material (OKM).
 *
 * @example
 * ```ts
 * // One-shot (recommended)
 * const key = HKDF.derive(salt, sharedSecret, Buffer.from('aes-key'), 32);
 *
 * // Two-step (advanced)
 * const prk = HKDF.extract(salt, ikm);
 * const okm = HKDF.expand(prk, info, 64);
 * ```
 */
export const HKDF = Object.freeze({
  /**
   * HKDF-Extract: produces a 32-byte pseudorandom key (PRK).
   *
   * @param salt - Optional salt (pass `Buffer.alloc(0)` if not available)
   * @param ikm - Input keying material
   * @returns 32-byte PRK
   * @throws {ValidationError} If inputs are not Buffers.
   */
  extract(salt: Buffer, ikm: Buffer): Buffer {
    assertBuffer(salt, 'salt');
    assertBuffer(ikm, 'ikm');
    return native.hkdfExtract(salt, ikm) as Buffer;
  },

  /**
   * HKDF-Expand: produces `length` bytes of output keying material.
   *
   * @param prk - 32-byte pseudorandom key from {@link extract}
   * @param info - Context-specific information (binds output to a usage)
   * @param length - Desired output length (1 to 8160 bytes)
   * @returns OKM of requested length
   * @throws {ValidationError} If PRK is not 32 bytes or length is out of bounds.
   */
  expand(prk: Buffer, info: Buffer, length: number): Buffer {
    assertBufferOfSize(prk, HKDF_PRK_SIZE, 'prk');
    assertBuffer(info, 'info');
    assertHkdfLength(length);
    // Length already validated; native cannot fail with valid PRK + length <= 8160
    return native.hkdfExpand(prk, info, length) as Buffer;
  },

  /**
   * HKDF one-shot: extract + expand in a single call.
   *
   * Use this whenever possible — it's the standard HKDF API.
   *
   * @param salt - Optional salt
   * @param ikm - Input keying material
   * @param info - Context info
   * @param length - Desired output length
   * @returns OKM of requested length
   */
  derive(salt: Buffer, ikm: Buffer, info: Buffer, length: number): Buffer {
    assertBuffer(salt, 'salt');
    assertBuffer(ikm, 'ikm');
    assertBuffer(info, 'info');
    assertHkdfLength(length);
    // Length already validated; native cannot fail with valid inputs
    return native.hkdfDerive(salt, ikm, info, length) as Buffer;
  },

  /**
   * Derive multiple keys from the same shared secret in a single call.
   *
   * Useful for deriving e.g., a send key AND a receive key simultaneously.
   *
   * @example
   * ```ts
   * const [sendKey, recvKey] = HKDF.deriveMultiple(
   *   salt,
   *   sharedSecret,
   *   Buffer.from('signalis-channel-v1'),
   *   [32, 32],
   * );
   * ```
   *
   * @param salt - Optional salt
   * @param ikm - Input keying material
   * @param info - Context info
   * @param lengths - Array of output lengths
   * @returns Array of derived keys, one per requested length
   */
  deriveMultiple(
    salt: Buffer,
    ikm: Buffer,
    info: Buffer,
    lengths: number[],
  ): Buffer[] {
    assertBuffer(salt, 'salt');
    assertBuffer(ikm, 'ikm');
    assertBuffer(info, 'info');
    if (!Array.isArray(lengths) || lengths.length === 0) {
      throw new TypeError('lengths must be a non-empty array of integers');
    }

    const total = lengths.reduce((sum, len) => sum + len, 0);
    assertHkdfLength(total);

    const okm = this.derive(salt, ikm, info, total);
    const results: Buffer[] = [];
    let offset = 0;
    for (const len of lengths) {
      results.push(okm.subarray(offset, offset + len));
      offset += len;
    }
    return results;
  },

  /**
   * Derive a key using an {@link HkdfParams} object (alternative API).
   */
  deriveFromParams(params: HkdfParams): Buffer {
    return this.derive(params.salt, params.ikm, params.info, params.length);
  },

  /**
   * One-shot HKDF-**SHA512** (extract + expand). Uses a 64-byte PRK internally
   * and supports up to 16320 bytes of output. Prefer this over the SHA-256
   * variant when a 512-bit hash is required for domain consistency.
   *
   * @param salt - Optional salt (`Buffer.alloc(0)` if not available)
   * @param ikm - Input keying material
   * @param info - Context-specific information
   * @param length - Desired output length in bytes (1..=16320)
   * @throws {ValidationError} If inputs are not Buffers or length is not positive.
   */
  deriveSha512(salt: Buffer, ikm: Buffer, info: Buffer, length: number): Buffer {
    assertBuffer(salt, 'salt');
    assertBuffer(ikm, 'ikm');
    assertBuffer(info, 'info');
    assertPositiveInteger(length, 'length');
    if (length === 0) {
      throw new LengthError('HKDF output length must be greater than 0', {
        expected: '> 0',
        actual: 0,
      });
    }
    // The native layer enforces the SHA-512 upper bound (255 * 64 = 16320).
    return native.hkdfSha512Derive(salt, ikm, info, length) as Buffer;
  },

  /**
   * The size of an HKDF PRK in bytes (32).
   */
  PRK_SIZE: HKDF_PRK_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// PBKDF2-HMAC-SHA256 (password-based KDF, NEW in v0.4.4)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * PBKDF2-HMAC-SHA256 (RFC 8018) — derive a key from a password.
 *
 * Unlike {@link HKDF} (which expands a high-entropy secret), PBKDF2 is built for
 * *low-entropy* passwords: it applies HMAC-SHA256 `iterations` times to make
 * brute-forcing expensive. Use it to turn a user password into an encryption
 * key, or to store password verifiers.
 *
 * @example
 * import { PBKDF2, secureRandom } from '@brashkie/signalis-core';
 *
 * const salt = secureRandom(16);                 // unique, random, per password
 * const key = PBKDF2.derive(Buffer.from(password), salt, 600_000, 32);
 */
export const PBKDF2 = Object.freeze({
  /**
   * Derive a `length`-byte key from `password` + `salt`.
   *
   * @param password - the password bytes
   * @param salt - a unique, random salt (≥16 bytes recommended); must be non-empty
   * @param iterations - work factor (≥1; use hundreds of thousands in production)
   * @param length - desired key length in bytes (≥1)
   * @throws {ValidationError} If inputs are not Buffers or numbers are not positive.
   */
  derive(password: Buffer, salt: Buffer, iterations: number, length: number): Buffer {
    assertBuffer(password, 'password');
    assertBuffer(salt, 'salt');
    assertPositiveInteger(iterations, 'iterations');
    assertPositiveInteger(length, 'length');
    return native.pbkdf2Derive(password, salt, iterations, length) as Buffer;
  },
});

// ═══════════════════════════════════════════════════════════════════════════
// Argon2id (memory-hard password KDF, NEW in v0.4.6)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Argon2id (RFC 9106) — the current recommended password-hashing function.
 *
 * Unlike {@link PBKDF2} (iteration-only), Argon2id is **memory-hard**: it forces
 * an attacker to spend large amounts of RAM per guess, which defeats the cheap
 * massive parallelism of GPUs/ASICs. Prefer Argon2id over PBKDF2 for new
 * password-to-key derivation when you can afford the memory.
 *
 * @example
 * import { Argon2id, secureRandom } from '@brashkie/signalis-core';
 *
 * const salt = secureRandom(16);
 * // OWASP starting point for interactive logins: 19 MiB, 2 passes, 1 lane
 * const key = Argon2id.derive(Buffer.from(password), salt, 19456, 2, 1, 32);
 */
export const Argon2id = Object.freeze({
  /**
   * Derive a `length`-byte key from `password` + `salt` using Argon2id.
   *
   * @param password - the password bytes
   * @param salt - a unique, random salt (≥8 bytes required, ≥16 recommended)
   * @param mCost - memory cost in **KiB** (e.g. 19456 = 19 MiB)
   * @param tCost - iterations / time cost (≥1)
   * @param pCost - parallelism / lanes (≥1)
   * @param length - desired key length in bytes (≥1)
   * @throws {ValidationError} If inputs are not Buffers or numbers are not positive.
   */
  derive(
    password: Buffer,
    salt: Buffer,
    mCost: number,
    tCost: number,
    pCost: number,
    length: number,
  ): Buffer {
    assertBuffer(password, 'password');
    assertBuffer(salt, 'salt');
    assertPositiveInteger(mCost, 'mCost');
    assertPositiveInteger(tCost, 'tCost');
    assertPositiveInteger(pCost, 'pCost');
    assertPositiveInteger(length, 'length');
    return native.argon2IdDerive(password, salt, mCost, tCost, pCost, length) as Buffer;
  },
});

// ═══════════════════════════════════════════════════════════════════════════
// AES-256-GCM (Authenticated Encryption)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * AES-256-GCM authenticated encryption (AEAD).
 *
 * Combines confidentiality + authenticity in a single primitive.
 *
 * **⚠️ CRITICAL SECURITY RULES:**
 * 1. Never reuse a (key, nonce) pair. Catastrophic failure.
 * 2. Generate nonces with `secureRandom(12)` for each message.
 * 3. After 2^32 messages with random nonces, rotate the key.
 *
 * @example
 * ```ts
 * import { AES_GCM, secureRandom } from '@brashkie/signalis-core';
 *
 * const key = secureRandom(32);
 * const nonce = secureRandom(12);
 * const plaintext = Buffer.from('Hello!');
 *
 * const ciphertext = AES_GCM.encrypt(key, nonce, plaintext);
 * const decrypted = AES_GCM.decrypt(key, nonce, ciphertext);
 * ```
 */
export const AES_GCM = Object.freeze({
  /**
   * Encrypt plaintext.
   *
   * Returns: ciphertext || 16-byte authentication tag (concatenated).
   *
   * @param key - 32-byte symmetric key
   * @param nonce - 12-byte unique nonce (NEVER reuse with same key)
   * @param plaintext - Data to encrypt
   * @returns Ciphertext + auth tag (output is `plaintext.length + 16` bytes)
   * @throws {ValidationError} On invalid sizes.
   * @throws {CryptoError} If the operation fails.
   */
  encrypt(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
    assertBufferOfSize(key, AES_256_KEY_SIZE, 'key');
    assertBufferOfSize(nonce, AES_256_GCM_NONCE_SIZE, 'nonce');
    assertBuffer(plaintext, 'plaintext');
    // GCM encryption cannot fail with valid-sized inputs
    return native.aes256GcmEncrypt(key, nonce, plaintext) as Buffer;
  },

  /**
   * Decrypt ciphertext and verify authentication tag.
   *
   * @param key - 32-byte symmetric key (same as encryption)
   * @param nonce - 12-byte nonce (same as encryption)
   * @param ciphertext - Ciphertext || auth tag
   * @returns Original plaintext
   * @throws {ValidationError} On invalid sizes.
   * @throws {AuthenticationError} If the tag is invalid (tampered or wrong key).
   */
  decrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer): Buffer {
    assertBufferOfSize(key, AES_256_KEY_SIZE, 'key');
    assertBufferOfSize(nonce, AES_256_GCM_NONCE_SIZE, 'nonce');
    assertBuffer(ciphertext, 'ciphertext');

    if (ciphertext.length < AES_256_GCM_TAG_SIZE) {
      throw new CryptoError(
        `Ciphertext too short: must be at least ${AES_256_GCM_TAG_SIZE} bytes (tag size)`,
        'aes_gcm_decrypt',
      );
    }

    try {
      return native.aes256GcmDecrypt(key, nonce, ciphertext) as Buffer;
    } catch (e) {
      throw new AuthenticationError(
        `AES-256-GCM authentication failed: ${(e as Error).message}`,
      );
    }
  },

  /** Key size in bytes (32). */
  KEY_SIZE: AES_256_KEY_SIZE,
  /** Nonce size in bytes (12). */
  NONCE_SIZE: AES_256_GCM_NONCE_SIZE,
  /** Tag size in bytes (16). */
  TAG_SIZE: AES_256_GCM_TAG_SIZE,

  /**
   * Encrypt with AES-256-GCM and Additional Authenticated Data (NEW in v0.2.0).
   *
   * AAD is authenticated but NOT encrypted. Useful for binding metadata
   * (like message headers) to the ciphertext.
   *
   * @param key - 32-byte symmetric key
   * @param nonce - 12-byte unique nonce
   * @param plaintext - Data to encrypt
   * @param aad - Additional authenticated data (any length, can be empty)
   * @returns Ciphertext + auth tag
   * @throws {ValidationError} On invalid sizes.
   */
  encryptWithAad(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
    assertBufferOfSize(key, AES_256_KEY_SIZE, 'key');
    assertBufferOfSize(nonce, AES_256_GCM_NONCE_SIZE, 'nonce');
    assertBuffer(plaintext, 'plaintext');
    assertBuffer(aad, 'aad');
    return native.aes256GcmEncryptWithAad(key, nonce, plaintext, aad) as Buffer;
  },

  /**
   * Decrypt with AES-256-GCM and AAD (NEW in v0.2.0).
   *
   * The same AAD used during encryption must be provided. Mismatch = failure.
   *
   * @throws {AuthenticationError} If tag verification fails (incl. AAD mismatch).
   */
  decryptWithAad(key: Buffer, nonce: Buffer, ciphertext: Buffer, aad: Buffer): Buffer {
    assertBufferOfSize(key, AES_256_KEY_SIZE, 'key');
    assertBufferOfSize(nonce, AES_256_GCM_NONCE_SIZE, 'nonce');
    assertBuffer(ciphertext, 'ciphertext');
    assertBuffer(aad, 'aad');

    if (ciphertext.length < AES_256_GCM_TAG_SIZE) {
      throw new CryptoError(
        `Ciphertext too short: must be at least ${AES_256_GCM_TAG_SIZE} bytes (tag size)`,
        'aes_gcm_decrypt_with_aad',
      );
    }

    try {
      return native.aes256GcmDecryptWithAad(key, nonce, ciphertext, aad) as Buffer;
    } catch (e) {
      throw new AuthenticationError(
        `AES-256-GCM authentication failed: ${(e as Error).message}`,
      );
    }
  },
});

// ═══════════════════════════════════════════════════════════════════════════
// AES-256-CBC (Encryption only — pair with HMAC!)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * AES-256-CBC block cipher (NOT authenticated by itself).
 *
 * **⚠️ MUST be paired with HMAC** for integrity protection (encrypt-then-MAC).
 *
 * Prefer {@link AES_GCM} unless you need:
 * - Legacy Signal Protocol media compatibility
 * - Hardware that lacks GCM acceleration
 */
export const AES_CBC = Object.freeze({
  /**
   * Encrypt with PKCS#7 padding.
   *
   * @param key - 32-byte symmetric key
   * @param iv - 16-byte initialization vector
   * @param plaintext - Data to encrypt
   * @returns Ciphertext (padded to nearest 16-byte block)
   */
  encrypt(key: Buffer, iv: Buffer, plaintext: Buffer): Buffer {
    assertBufferOfSize(key, AES_256_KEY_SIZE, 'key');
    assertBufferOfSize(iv, AES_256_CBC_IV_SIZE, 'iv');
    assertBuffer(plaintext, 'plaintext');
    // CBC encryption with PKCS#7 padding cannot fail given valid-sized inputs
    return native.aes256CbcEncrypt(key, iv, plaintext) as Buffer;
  },

  /**
   * Decrypt with PKCS#7 padding (no authentication).
   *
   * @param key - 32-byte symmetric key
   * @param iv - 16-byte IV (same as encryption)
   * @param ciphertext - Ciphertext
   * @returns Original plaintext
   * @throws {CryptoError} On padding errors.
   */
  decrypt(key: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
    assertBufferOfSize(key, AES_256_KEY_SIZE, 'key');
    assertBufferOfSize(iv, AES_256_CBC_IV_SIZE, 'iv');
    assertBuffer(ciphertext, 'ciphertext');
    try {
      return native.aes256CbcDecrypt(key, iv, ciphertext) as Buffer;
    } catch (e) {
      throw new CryptoError(
        `AES-256-CBC decryption failed: ${(e as Error).message}`,
        'aes_cbc_decrypt',
      );
    }
  },

  /** Key size in bytes (32). */
  KEY_SIZE: AES_256_KEY_SIZE,
  /** IV size in bytes (16). */
  IV_SIZE: AES_256_CBC_IV_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// HMAC-SHA256
// ═══════════════════════════════════════════════════════════════════════════

/**
 * HMAC-SHA256 message authentication code.
 *
 * Provides cryptographic authentication of arbitrary data with a shared key.
 *
 * @example
 * ```ts
 * const tag = HMAC.sha256(key, message);
 * const valid = HMAC.verifySha256(key, message, tag);  // constant-time
 * ```
 */
export const HMAC = Object.freeze({
  /**
   * Compute HMAC-SHA256 of `data` using `key`.
   *
   * @param key - Authentication key (any length)
   * @param data - Data to authenticate
   * @returns 32-byte HMAC tag
   */
  sha256(key: Buffer, data: Buffer): Buffer {
    assertBuffer(key, 'key');
    assertBuffer(data, 'data');
    return native.hmacSha256(key, data) as Buffer;
  },

  /**
   * Verify an HMAC-SHA256 tag in **constant time**.
   *
   * Always use this instead of `===` to prevent timing attacks.
   *
   * @param key - Authentication key
   * @param data - Original data
   * @param expectedTag - Tag to verify
   * @returns `true` if tag matches, `false` otherwise
   */
  verifySha256(key: Buffer, data: Buffer, expectedTag: Buffer): boolean {
    assertBuffer(key, 'key');
    assertBuffer(data, 'data');
    assertBuffer(expectedTag, 'expectedTag');
    return native.hmacSha256Verify(key, data, expectedTag) as boolean;
  },

  /**
   * Compute HMAC-SHA512 of `data` using `key`.
   *
   * @param key - Authentication key (any length)
   * @param data - Data to authenticate
   * @returns 64-byte HMAC tag
   */
  sha512(key: Buffer, data: Buffer): Buffer {
    assertBuffer(key, 'key');
    assertBuffer(data, 'data');
    return native.hmacSha512(key, data) as Buffer;
  },

  /**
   * Verify an HMAC-SHA512 tag in **constant time**.
   *
   * @param key - Authentication key
   * @param data - Original data
   * @param expectedTag - Tag to verify
   * @returns `true` if tag matches, `false` otherwise
   */
  verifySha512(key: Buffer, data: Buffer, expectedTag: Buffer): boolean {
    assertBuffer(key, 'key');
    assertBuffer(data, 'data');
    assertBuffer(expectedTag, 'expectedTag');
    return native.hmacSha512Verify(key, data, expectedTag) as boolean;
  },

  /** Tag size in bytes (32). */
  TAG_SIZE: HMAC_SHA256_TAG_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// SHA-256
// ═══════════════════════════════════════════════════════════════════════════

/**
 * SHA-256 cryptographic hash function.
 *
 * @example
 * ```ts
 * const digest = SHA256.hash(Buffer.from('hello'));
 * ```
 */
export const SHA256 = Object.freeze({
  /**
   * Compute SHA-256 hash of `data`.
   *
   * @param data - Data to hash
   * @returns 32-byte digest
   */
  hash(data: Buffer): Buffer {
    assertBuffer(data, 'data');
    return native.sha256(data) as Buffer;
  },

  /**
   * Hash multiple Buffers concatenated together.
   *
   * Equivalent to `SHA256.hash(Buffer.concat([...]))` but slightly more
   * efficient (avoids the intermediate concat).
   */
  hashAll(buffers: Buffer[]): Buffer {
    if (!Array.isArray(buffers)) {
      throw new TypeError('buffers must be an array');
    }
    for (let i = 0; i < buffers.length; i++) {
      assertBuffer(buffers[i]!, `buffers[${i}]`);
    }
    return this.hash(Buffer.concat(buffers));
  },

  /** Output size in bytes (32). */
  OUTPUT_SIZE: SHA256_OUTPUT_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// SHA-3 (Keccak, FIPS 202) — NEW in v0.4.10
// ═══════════════════════════════════════════════════════════════════════════

/**
 * SHA-3 hashing (FIPS 202). Structurally different from the SHA-2 family
 * (Keccak sponge construction) — use it when a protocol requires SHA-3
 * specifically, or for algorithmic diversity from SHA-2.
 *
 * @example
 * import { SHA3 } from '@brashkie/signalis-core';
 * const digest = SHA3.hash256(Buffer.from('hello')); // 32 bytes
 * const long = SHA3.hash512(Buffer.from('hello'));    // 64 bytes
 */
export const SHA3 = Object.freeze({
  /**
   * Compute SHA3-256 of `data`.
   *
   * @param data - Data to hash
   * @returns 32-byte digest
   */
  hash256(data: Buffer): Buffer {
    assertBuffer(data, 'data');
    return native.sha3256(data) as Buffer;
  },

  /**
   * Compute SHA3-512 of `data`.
   *
   * @param data - Data to hash
   * @returns 64-byte digest
   */
  hash512(data: Buffer): Buffer {
    assertBuffer(data, 'data');
    return native.sha3512(data) as Buffer;
  },

  /**
   * Hash multiple Buffers concatenated together with SHA3-256.
   */
  hash256All(buffers: Buffer[]): Buffer {
    if (!Array.isArray(buffers)) {
      throw new TypeError('buffers must be an array');
    }
    for (let i = 0; i < buffers.length; i++) {
      assertBuffer(buffers[i]!, `buffers[${i}]`);
    }
    return this.hash256(Buffer.concat(buffers));
  },

  /** SHA3-256 output size in bytes (32). */
  OUTPUT_SIZE_256: 32,
  /** SHA3-512 output size in bytes (64). */
  OUTPUT_SIZE_512: 64,
});

// ═══════════════════════════════════════════════════════════════════════════
// Ed25519 (Standard Digital Signatures) — NEW in v0.2.0
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Ed25519 digital signatures (RFC 8032).
 *
 * Standard Ed25519 with deterministic signatures. Use when you want clean
 * separation between signing and ECDH keys.
 *
 * @example
 * ```ts
 * import { Ed25519 } from '@brashkie/signalis-core';
 *
 * const keys = Ed25519.generateKeyPair();
 * const sig = Ed25519.sign(keys.privateKey, Buffer.from('Hello'));
 * Ed25519.verify(keys.publicKey, Buffer.from('Hello'), sig);
 * ```
 */
export const Ed25519 = Object.freeze({
  /**
   * Generate a new random Ed25519 keypair.
   */
  generateKeyPair(): KeyPair {
    const kp = native.ed25519GenerateKeypair() as {
      private: Buffer;
      public: Buffer;
    };
    return Object.freeze({
      privateKey: kp.private,
      publicKey: kp.public,
    });
  },

  /**
   * Derive a deterministic Ed25519 keypair from a 32-byte seed.
   */
  keyPairFromSeed(seed: Buffer): KeyPair {
    assertBufferOfSize(seed, ED25519_SEED_SIZE, 'seed');
    const kp = native.ed25519KeypairFromSeed(seed) as {
      private: Buffer;
      public: Buffer;
    };
    return Object.freeze({
      privateKey: kp.private,
      publicKey: kp.public,
    });
  },

  /**
   * Derive the public key from a private key.
   */
  publicFromPrivate(privateKey: Buffer): Buffer {
    assertBufferOfSize(privateKey, ED25519_PRIVATE_KEY_SIZE, 'privateKey');
    return native.ed25519PublicFromPrivate(privateKey) as Buffer;
  },

  /**
   * Sign a message. Ed25519 signatures are deterministic (RFC 8032).
   */
  sign(privateKey: Buffer, message: Buffer): Signature {
    assertBufferOfSize(privateKey, ED25519_PRIVATE_KEY_SIZE, 'privateKey');
    assertBuffer(message, 'message');
    return native.ed25519Sign(privateKey, message) as Signature;
  },

  /**
   * Verify a signature. Throws on failure.
   *
   * @throws {SignatureError} If signature is invalid.
   */
  verify(publicKey: Buffer, message: Buffer, signature: Buffer): void {
    assertBufferOfSize(publicKey, ED25519_PUBLIC_KEY_SIZE, 'publicKey');
    assertBuffer(message, 'message');
    assertBufferOfSize(signature, ED25519_SIGNATURE_SIZE, 'signature');
    try {
      native.ed25519Verify(publicKey, message, signature);
    } catch (e) {
      throw new SignatureError((e as Error).message);
    }
  },

  /**
   * Verify a signature. Returns boolean (does not throw).
   */
  verifyBool(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
    if (!Buffer.isBuffer(publicKey) || publicKey.length !== ED25519_PUBLIC_KEY_SIZE) return false;
    if (!Buffer.isBuffer(message)) return false;
    if (!Buffer.isBuffer(signature) || signature.length !== ED25519_SIGNATURE_SIZE) return false;
    return native.ed25519VerifyBool(publicKey, message, signature) as boolean;
  },

  /** Private key size in bytes (32). */
  PRIVATE_KEY_SIZE: ED25519_PRIVATE_KEY_SIZE,
  /** Public key size in bytes (32). */
  PUBLIC_KEY_SIZE: ED25519_PUBLIC_KEY_SIZE,
  /** Signature size in bytes (64). */
  SIGNATURE_SIZE: ED25519_SIGNATURE_SIZE,
  /** Seed size for deterministic keypair derivation (32). */
  SEED_SIZE: ED25519_SEED_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// XEd25519 (Signal-style signatures with Curve25519 keys) — NEW in v0.2.0
// ═══════════════════════════════════════════════════════════════════════════

/**
 * XEd25519 — sign messages using the SAME Curve25519 keypair used for ECDH.
 *
 * This is what Signal Protocol uses to maintain a single identity key.
 * Signatures are non-deterministic (each call gives a different valid sig).
 *
 * @example
 * ```ts
 * import { Curve25519, XEd25519 } from '@brashkie/signalis-core';
 *
 * const identity = Curve25519.generateKeyPair();
 *
 * // Use for ECDH:
 * const shared = Curve25519.diffieHellman(identity.privateKey, peerPublic);
 *
 * // SAME key used to sign:
 * const sig = XEd25519.sign(identity.privateKey, message);
 * XEd25519.verify(identity.publicKey, message, sig);
 * ```
 */
export const XEd25519 = Object.freeze({
  /**
   * Sign a message using a Curve25519 private key. Uses OS RNG.
   * Signatures are NOT deterministic (different each call).
   */
  sign(privateKey: Buffer, message: Buffer): Signature {
    assertBufferOfSize(privateKey, XED25519_PRIVATE_KEY_SIZE, 'privateKey');
    assertBuffer(message, 'message');
    return native.xed25519Sign(privateKey, message) as Signature;
  },

  /**
   * Sign with explicit 64-byte random nonce (for testing/reproducibility).
   */
  signWithRandom(privateKey: Buffer, message: Buffer, random: Buffer): Signature {
    assertBufferOfSize(privateKey, XED25519_PRIVATE_KEY_SIZE, 'privateKey');
    assertBuffer(message, 'message');
    assertBufferOfSize(random, XED25519_RANDOM_SIZE, 'random');
    return native.xed25519SignWithRandom(privateKey, message, random) as Signature;
  },

  /**
   * Verify a XEd25519 signature. Throws on failure.
   *
   * @throws {SignatureError} If signature is invalid.
   */
  verify(publicKey: Buffer, message: Buffer, signature: Buffer): void {
    assertBufferOfSize(publicKey, XED25519_PUBLIC_KEY_SIZE, 'publicKey');
    assertBuffer(message, 'message');
    assertBufferOfSize(signature, XED25519_SIGNATURE_SIZE, 'signature');
    try {
      native.xed25519Verify(publicKey, message, signature);
    } catch (e) {
      throw new SignatureError((e as Error).message);
    }
  },

  /**
   * Verify a XEd25519 signature. Returns boolean (does not throw).
   */
  verifyBool(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
    if (!Buffer.isBuffer(publicKey) || publicKey.length !== XED25519_PUBLIC_KEY_SIZE) return false;
    if (!Buffer.isBuffer(message)) return false;
    if (!Buffer.isBuffer(signature) || signature.length !== XED25519_SIGNATURE_SIZE) return false;
    return native.xed25519VerifyBool(publicKey, message, signature) as boolean;
  },

  /** Private key size in bytes (32, same as Curve25519). */
  PRIVATE_KEY_SIZE: XED25519_PRIVATE_KEY_SIZE,
  /** Public key size in bytes (32, same as Curve25519). */
  PUBLIC_KEY_SIZE: XED25519_PUBLIC_KEY_SIZE,
  /** Signature size in bytes (64). */
  SIGNATURE_SIZE: XED25519_SIGNATURE_SIZE,
  /** Random nonce size for signing (64). */
  RANDOM_SIZE: XED25519_RANDOM_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// Library version
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The version of the underlying Rust crate (from `Cargo.toml`).
 */
export const nativeVersion: string = (native.version as () => string)();

// ═══════════════════════════════════════════════════════════════════════════
// ChaCha20-Poly1305 (NEW in v0.3.0)
// ═══════════════════════════════════════════════════════════════════════════

/** ChaCha20-Poly1305 key size (bytes). */
export const CHACHA20_POLY1305_KEY_SIZE = 32;
/** ChaCha20-Poly1305 nonce size (bytes). */
export const CHACHA20_POLY1305_NONCE_SIZE = 12;
/** Poly1305 authentication tag size (bytes), appended to ciphertext. */
export const CHACHA20_POLY1305_TAG_SIZE = 16;
/** XChaCha20-Poly1305 extended nonce size (bytes). */
export const XCHACHA20_POLY1305_NONCE_SIZE = 24;

/**
 * ChaCha20-Poly1305 authenticated encryption with associated data (AEAD).
 *
 * RFC 8439-compliant alternative to AES-GCM. Same security guarantees,
 * but typically 2-3x faster on platforms without AES-NI hardware
 * (Android arm64-v8a without crypto extensions, IoT, older embedded).
 *
 * On servers and modern desktops with AES-NI, AES-GCM is usually faster
 * — pick the cipher based on your deployment target.
 *
 * @example
 * ```ts
 * import { ChaCha20Poly1305, secureRandom } from '@brashkie/signalis-core';
 *
 * const key = secureRandom(32);
 * const nonce = secureRandom(12);
 * const ct = ChaCha20Poly1305.encrypt(key, nonce, Buffer.from('secret'));
 * const pt = ChaCha20Poly1305.decrypt(key, nonce, ct);
 * ```
 */
export const ChaCha20Poly1305 = Object.freeze({
  /**
   * Encrypt + authenticate `plaintext`.
   *
   * @param key 32-byte key
   * @param nonce 12-byte nonce — MUST be unique per (key, plaintext)
   * @param plaintext data to encrypt
   * @returns ciphertext || tag (16 bytes appended)
   */
  encrypt(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
    if (!Buffer.isBuffer(key) || key.length !== CHACHA20_POLY1305_KEY_SIZE) {
      throw new RangeError(`key must be ${CHACHA20_POLY1305_KEY_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(nonce) || nonce.length !== CHACHA20_POLY1305_NONCE_SIZE) {
      throw new RangeError(`nonce must be ${CHACHA20_POLY1305_NONCE_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(plaintext)) {
      throw new TypeError('plaintext must be a Buffer');
    }
    return native.chacha20Poly1305Encrypt(key, nonce, plaintext) as Buffer;
  },

  /**
   * Verify-then-decrypt. Returns plaintext on success, throws on auth failure.
   */
  decrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer): Buffer {
    if (!Buffer.isBuffer(key) || key.length !== CHACHA20_POLY1305_KEY_SIZE) {
      throw new RangeError(`key must be ${CHACHA20_POLY1305_KEY_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(nonce) || nonce.length !== CHACHA20_POLY1305_NONCE_SIZE) {
      throw new RangeError(`nonce must be ${CHACHA20_POLY1305_NONCE_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(ciphertext)) {
      throw new TypeError('ciphertext must be a Buffer');
    }
    return native.chacha20Poly1305Decrypt(key, nonce, ciphertext) as Buffer;
  },

  /**
   * Encrypt + authenticate with Additional Authenticated Data.
   *
   * AAD is NOT encrypted but IS authenticated. Use for plaintext metadata
   * (e.g., message headers) that must not be tampered with.
   */
  encryptWithAad(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
    aad: Buffer,
  ): Buffer {
    if (!Buffer.isBuffer(key) || key.length !== CHACHA20_POLY1305_KEY_SIZE) {
      throw new RangeError(`key must be ${CHACHA20_POLY1305_KEY_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(nonce) || nonce.length !== CHACHA20_POLY1305_NONCE_SIZE) {
      throw new RangeError(`nonce must be ${CHACHA20_POLY1305_NONCE_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(plaintext) || !Buffer.isBuffer(aad)) {
      throw new TypeError('plaintext and aad must be Buffers');
    }
    return native.chacha20Poly1305EncryptWithAad(key, nonce, plaintext, aad) as Buffer;
  },

  /**
   * Verify (key + nonce + ciphertext + AAD) and decrypt.
   */
  decryptWithAad(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
    aad: Buffer,
  ): Buffer {
    if (!Buffer.isBuffer(key) || key.length !== CHACHA20_POLY1305_KEY_SIZE) {
      throw new RangeError(`key must be ${CHACHA20_POLY1305_KEY_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(nonce) || nonce.length !== CHACHA20_POLY1305_NONCE_SIZE) {
      throw new RangeError(`nonce must be ${CHACHA20_POLY1305_NONCE_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(ciphertext) || !Buffer.isBuffer(aad)) {
      throw new TypeError('ciphertext and aad must be Buffers');
    }
    return native.chacha20Poly1305DecryptWithAad(key, nonce, ciphertext, aad) as Buffer;
  },

  /** Key size in bytes (32). */
  KEY_SIZE: CHACHA20_POLY1305_KEY_SIZE,
  /** Nonce size in bytes (12). */
  NONCE_SIZE: CHACHA20_POLY1305_NONCE_SIZE,
  /** Authentication tag size in bytes (16), appended to ciphertext. */
  TAG_SIZE: CHACHA20_POLY1305_TAG_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// XChaCha20-Poly1305 — extended-nonce AEAD (NEW in v0.4.3)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * XChaCha20-Poly1305: the extended-nonce (24-byte) variant of
 * ChaCha20-Poly1305. Same key size and security; the larger nonce makes it
 * safe to pick nonces at random per message without tracking uniqueness.
 * Prefer this over {@link ChaCha20Poly1305} when you can't guarantee unique
 * 12-byte nonces.
 *
 * @example
 * import { XChaCha20Poly1305, secureRandom } from '@brashkie/signalis-core';
 *
 * const key = secureRandom(32);
 * const nonce = secureRandom(24);           // random is safe with 24 bytes
 * const ct = XChaCha20Poly1305.encrypt(key, nonce, Buffer.from('secret'));
 * const pt = XChaCha20Poly1305.decrypt(key, nonce, ct);
 */
export const XChaCha20Poly1305 = Object.freeze({
  /**
   * Encrypt + authenticate `plaintext`.
   *
   * @param key 32-byte key
   * @param nonce 24-byte nonce (safe to generate randomly per message)
   * @param plaintext data to encrypt
   * @returns ciphertext || tag (16 bytes appended)
   */
  encrypt(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
    if (!Buffer.isBuffer(key) || key.length !== CHACHA20_POLY1305_KEY_SIZE) {
      throw new RangeError(`key must be ${CHACHA20_POLY1305_KEY_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(nonce) || nonce.length !== XCHACHA20_POLY1305_NONCE_SIZE) {
      throw new RangeError(`nonce must be ${XCHACHA20_POLY1305_NONCE_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(plaintext)) {
      throw new TypeError('plaintext must be a Buffer');
    }
    return native.xchacha20Poly1305Encrypt(key, nonce, plaintext) as Buffer;
  },

  /**
   * Verify-then-decrypt. Returns plaintext on success, throws on auth failure.
   */
  decrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer): Buffer {
    if (!Buffer.isBuffer(key) || key.length !== CHACHA20_POLY1305_KEY_SIZE) {
      throw new RangeError(`key must be ${CHACHA20_POLY1305_KEY_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(nonce) || nonce.length !== XCHACHA20_POLY1305_NONCE_SIZE) {
      throw new RangeError(`nonce must be ${XCHACHA20_POLY1305_NONCE_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(ciphertext)) {
      throw new TypeError('ciphertext must be a Buffer');
    }
    return native.xchacha20Poly1305Decrypt(key, nonce, ciphertext) as Buffer;
  },

  /**
   * Encrypt + authenticate with Additional Authenticated Data.
   *
   * AAD is NOT encrypted but IS authenticated. Use for plaintext metadata
   * (e.g., message headers) that must not be tampered with.
   */
  encryptWithAad(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
    if (!Buffer.isBuffer(key) || key.length !== CHACHA20_POLY1305_KEY_SIZE) {
      throw new RangeError(`key must be ${CHACHA20_POLY1305_KEY_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(nonce) || nonce.length !== XCHACHA20_POLY1305_NONCE_SIZE) {
      throw new RangeError(`nonce must be ${XCHACHA20_POLY1305_NONCE_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(plaintext) || !Buffer.isBuffer(aad)) {
      throw new TypeError('plaintext and aad must be Buffers');
    }
    return native.xchacha20Poly1305EncryptWithAad(key, nonce, plaintext, aad) as Buffer;
  },

  /**
   * Verify (key + nonce + ciphertext + AAD) and decrypt.
   */
  decryptWithAad(key: Buffer, nonce: Buffer, ciphertext: Buffer, aad: Buffer): Buffer {
    if (!Buffer.isBuffer(key) || key.length !== CHACHA20_POLY1305_KEY_SIZE) {
      throw new RangeError(`key must be ${CHACHA20_POLY1305_KEY_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(nonce) || nonce.length !== XCHACHA20_POLY1305_NONCE_SIZE) {
      throw new RangeError(`nonce must be ${XCHACHA20_POLY1305_NONCE_SIZE} bytes`);
    }
    if (!Buffer.isBuffer(ciphertext) || !Buffer.isBuffer(aad)) {
      throw new TypeError('ciphertext and aad must be Buffers');
    }
    return native.xchacha20Poly1305DecryptWithAad(key, nonce, ciphertext, aad) as Buffer;
  },

  /** Key size in bytes (32). */
  KEY_SIZE: CHACHA20_POLY1305_KEY_SIZE,
  /** Extended nonce size in bytes (24). */
  NONCE_SIZE: XCHACHA20_POLY1305_NONCE_SIZE,
  /** Authentication tag size in bytes (16), appended to ciphertext. */
  TAG_SIZE: CHACHA20_POLY1305_TAG_SIZE,
});

// ═══════════════════════════════════════════════════════════════════════════
// Constant-time comparison (NEW in v0.3.0)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compare two buffers in constant time.
 *
 * Returns `true` only if both buffers have identical length AND contents.
 *
 * Use this for any secret comparison (MAC tags, signatures, tokens) where
 * a fast-fail comparison could leak information via timing side-channels.
 *
 * **Wrong:**
 * ```ts
 * if (expectedMac.equals(receivedMac)) { ... }  // ← timing-vulnerable
 * ```
 *
 * **Right:**
 * ```ts
 * if (constantTimeEq(expectedMac, receivedMac)) { ... }
 * ```
 */
export function constantTimeEq(a: Buffer, b: Buffer): boolean {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('constantTimeEq: both arguments must be Buffers');
  }
  return native.constantTimeEq(a, b) as boolean;
}

/**
 * Generate `size` cryptographically secure random bytes via the OS RNG
 * (Rust side). Equivalent to {@link secureRandom} but routed through the
 * native bindings — useful when you want to ensure entropy comes from the
 * same source that the rest of the library uses internally.
 *
 * For most code, plain {@link secureRandom} (which uses `node:crypto`)
 * is fine and avoids a NAPI hop.
 */
export function nativeSecureRandom(size: number): Buffer {
  if (!Number.isInteger(size) || size <= 0) {
    throw new RangeError(`size must be a positive integer, got ${size}`);
  }
  return native.secureRandom(size) as Buffer;
}

// ═══════════════════════════════════════════════════════════════════════════
// Encoding helpers (NEW in v0.4.0)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Base64 encoding (RFC 4648).
 *
 * Two variants are available:
 * - **Standard** (`encode`/`decode`) — uses `A-Z a-z 0-9 + /` with `=` padding.
 *   Suitable for MIME, email, and general payloads.
 * - **URL-safe** (`encodeUrlSafe`/`decodeUrlSafe`) — uses `-` and `_` instead
 *   of `+` and `/`, and omits padding. Safe for URLs, filenames, HTTP headers.
 *
 * @example
 * ```ts
 * const encoded = Base64.encode(Buffer.from('hello'));      // "aGVsbG8="
 * const decoded = Base64.decode(encoded);                    // <Buffer 68 65 6c 6c 6f>
 * const url = Base64.encodeUrlSafe(Buffer.from('hello'));    // "aGVsbG8" (no padding)
 * ```
 */
export const Base64 = Object.freeze({
  /**
   * Encode bytes to standard Base64 (with `=` padding).
   */
  encode(input: Buffer): string {
    if (!Buffer.isBuffer(input)) {
      throw new TypeError('Base64.encode: input must be a Buffer');
    }
    return native.base64Encode(input) as string;
  },

  /**
   * Decode a standard Base64 string back to bytes.
   *
   * @throws {RangeError} on invalid characters, wrong length, or invalid padding.
   */
  decode(input: string): Buffer {
    if (typeof input !== 'string') {
      throw new TypeError('Base64.decode: input must be a string');
    }
    return native.base64Decode(input) as Buffer;
  },

  /**
   * Encode bytes to URL-safe Base64 without padding.
   * Uses `-` and `_` instead of `+` and `/`.
   */
  encodeUrlSafe(input: Buffer): string {
    if (!Buffer.isBuffer(input)) {
      throw new TypeError('Base64.encodeUrlSafe: input must be a Buffer');
    }
    return native.base64EncodeUrlSafe(input) as string;
  },

  /**
   * Decode a URL-safe Base64 string (no padding) back to bytes.
   *
   * @throws {RangeError} on invalid characters or wrong length.
   */
  decodeUrlSafe(input: string): Buffer {
    if (typeof input !== 'string') {
      throw new TypeError('Base64.decodeUrlSafe: input must be a string');
    }
    return native.base64DecodeUrlSafe(input) as Buffer;
  },
});

/**
 * Hex (Base16) encoding.
 *
 * - Encoding produces lowercase output by default.
 * - Decoding is case-insensitive.
 *
 * @example
 * ```ts
 * const encoded = Hex.encode(Buffer.from([0xde, 0xad, 0xbe, 0xef]));  // "deadbeef"
 * const decoded = Hex.decode('DEADBEEF');                              // <Buffer de ad be ef>
 * Hex.isValid('deadbeef');   // true
 * Hex.isValid('nope!');      // false
 * ```
 */
export const Hex = Object.freeze({
  /**
   * Encode bytes to a lowercase hex string.
   */
  encode(input: Buffer): string {
    if (!Buffer.isBuffer(input)) {
      throw new TypeError('Hex.encode: input must be a Buffer');
    }
    return native.hexEncode(input) as string;
  },

  /**
   * Encode bytes to an uppercase hex string.
   * (Rare, but included for legacy protocols.)
   */
  encodeUpper(input: Buffer): string {
    if (!Buffer.isBuffer(input)) {
      throw new TypeError('Hex.encodeUpper: input must be a Buffer');
    }
    return native.hexEncodeUpper(input) as string;
  },

  /**
   * Decode a hex string to bytes. Case-insensitive.
   *
   * @throws {RangeError} on odd-length input or non-hex characters.
   */
  decode(input: string): Buffer {
    if (typeof input !== 'string') {
      throw new TypeError('Hex.decode: input must be a string');
    }
    return native.hexDecode(input) as Buffer;
  },

  /**
   * Cheap validation: is this a well-formed hex string?
   */
  isValid(input: string): boolean {
    if (typeof input !== 'string') {
      throw new TypeError('Hex.isValid: input must be a string');
    }
    return native.hexIsValid(input) as boolean;
  },
});

/**
 * UTF-8 encoding with strict validation.
 *
 * - `encode` converts a string to its UTF-8 byte representation.
 * - `decode` validates strictly — invalid UTF-8 throws (does NOT silently
 *   replace with U+FFFD like `Buffer.toString('utf-8')` does).
 * - `isValid` is a cheap check without allocation.
 *
 * @example
 * ```ts
 * const bytes = Utf8.encode('Hola 🦀');     // <Buffer 48 6f 6c 61 20 f0 9f a6 80>
 * const text = Utf8.decode(bytes);           // "Hola 🦀"
 * Utf8.isValid(Buffer.from([0xff]));         // false
 * ```
 */
export const Utf8 = Object.freeze({
  /**
   * Encode a string to its UTF-8 byte representation.
   */
  encode(input: string): Buffer {
    if (typeof input !== 'string') {
      throw new TypeError('Utf8.encode: input must be a string');
    }
    return native.utf8Encode(input) as Buffer;
  },

  /**
   * Decode UTF-8 bytes to a string.
   *
   * @throws {RangeError} on invalid UTF-8 (truncated multi-byte, lone surrogate,
   *   invalid start byte, etc.). Unlike `Buffer.toString('utf-8')`, this does
   *   NOT silently substitute U+FFFD.
   */
  decode(input: Buffer): string {
    if (!Buffer.isBuffer(input)) {
      throw new TypeError('Utf8.decode: input must be a Buffer');
    }
    return native.utf8Decode(input) as string;
  },

  /**
   * Check whether the given bytes are valid UTF-8.
   */
  isValid(input: Buffer): boolean {
    if (!Buffer.isBuffer(input)) {
      throw new TypeError('Utf8.isValid: input must be a Buffer');
    }
    return native.utf8IsValid(input) as boolean;
  },
});
