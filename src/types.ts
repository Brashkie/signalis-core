/**
 * Shared TypeScript types for signalis-core.
 *
 * @packageDocumentation
 */

// ═══════════════════════════════════════════════════════════════════════════
// Curve25519
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A Curve25519 keypair (private + public key).
 *
 * Both keys are 32-byte Buffers.
 */
export interface KeyPair {
  /**
   * Private key (32 bytes).
   *
   * **⚠️ KEEP THIS SECRET.** Never log, transmit, or store in plaintext.
   */
  readonly privateKey: Buffer;

  /**
   * Public key (32 bytes).
   *
   * Safe to share publicly.
   */
  readonly publicKey: Buffer;
}

/**
 * A Curve25519 public key — type-tag for stronger typing.
 *
 * Use {@link asPublicKey} to brand a Buffer.
 */
export type PublicKey = Buffer & { readonly __brand?: 'PublicKey' };

/**
 * A Curve25519 private key — type-tag for stronger typing.
 *
 * Use {@link asPrivateKey} to brand a Buffer.
 */
export type PrivateKey = Buffer & { readonly __brand?: 'PrivateKey' };

/**
 * An X25519 ECDH shared secret (32 bytes).
 *
 * **⚠️ DO NOT USE DIRECTLY AS A KEY.** Always derive through HKDF.
 */
export type SharedSecret = Buffer & { readonly __brand?: 'SharedSecret' };

// ═══════════════════════════════════════════════════════════════════════════
// HKDF
// ═══════════════════════════════════════════════════════════════════════════

/**
 * HKDF pseudorandom key (32 bytes), output of the Extract step.
 */
export type PseudoRandomKey = Buffer & { readonly __brand?: 'PRK' };

/**
 * HKDF parameters object — useful for organizing key derivation calls.
 */
export interface HkdfParams {
  /** Optional salt (use `Buffer.alloc(0)` if absent). */
  salt: Buffer;
  /** Input keying material (e.g., ECDH shared secret). */
  ikm: Buffer;
  /** Context-specific information (binds the output to a usage). */
  info: Buffer;
  /** Desired output length in bytes (1 to 8160). */
  length: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// AES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * AES-256-GCM parameters.
 */
export interface AesGcmParams {
  /** 32-byte symmetric key. */
  key: Buffer;
  /** 12-byte nonce (MUST be unique per message). */
  nonce: Buffer;
  /** Plaintext or ciphertext. */
  data: Buffer;
}

/**
 * AES-256-CBC parameters.
 */
export interface AesCbcParams {
  /** 32-byte symmetric key. */
  key: Buffer;
  /** 16-byte initialization vector. */
  iv: Buffer;
  /** Plaintext or ciphertext. */
  data: Buffer;
}

// ═══════════════════════════════════════════════════════════════════════════
// Encoding
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Supported encodings for converting Buffers to/from strings.
 */
export type Encoding = 'hex' | 'base64' | 'base64url' | 'utf8' | 'binary';

// ═══════════════════════════════════════════════════════════════════════════
// Branding helpers (zero-cost casts with documentation)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Brand a Buffer as a {@link PublicKey}.
 *
 * Does NOT validate length — use validators separately.
 */
export function asPublicKey(buf: Buffer): PublicKey {
  return buf as PublicKey;
}

/**
 * Brand a Buffer as a {@link PrivateKey}.
 *
 * Does NOT validate length — use validators separately.
 */
export function asPrivateKey(buf: Buffer): PrivateKey {
  return buf as PrivateKey;
}

/**
 * Brand a Buffer as a {@link SharedSecret}.
 */
export function asSharedSecret(buf: Buffer): SharedSecret {
  return buf as SharedSecret;
}
