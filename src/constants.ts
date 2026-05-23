/**
 * Public constants used throughout signalis-core.
 *
 * @packageDocumentation
 */

// ═══════════════════════════════════════════════════════════════════════════
// Curve25519 / X25519
// ═══════════════════════════════════════════════════════════════════════════

/** Size of a Curve25519 private key in bytes. */
export const CURVE25519_PRIVATE_KEY_SIZE = 32;

/** Size of a Curve25519 public key in bytes. */
export const CURVE25519_PUBLIC_KEY_SIZE = 32;

/** Size of an X25519 ECDH shared secret in bytes. */
export const CURVE25519_SHARED_SECRET_SIZE = 32;

// ═══════════════════════════════════════════════════════════════════════════
// Ed25519 (NEW in v0.2.0) — Standard digital signatures
// ═══════════════════════════════════════════════════════════════════════════

/** Size of an Ed25519 private key in bytes. */
export const ED25519_PRIVATE_KEY_SIZE = 32;

/** Size of an Ed25519 public key in bytes. */
export const ED25519_PUBLIC_KEY_SIZE = 32;

/** Size of an Ed25519 signature in bytes. */
export const ED25519_SIGNATURE_SIZE = 64;

/** Size of an Ed25519 seed for deterministic key derivation. */
export const ED25519_SEED_SIZE = 32;

// ═══════════════════════════════════════════════════════════════════════════
// XEd25519 (NEW in v0.2.0) — Signatures using Curve25519 keys (Signal style)
// ═══════════════════════════════════════════════════════════════════════════

/** Size of an XEd25519 private key in bytes (same as Curve25519). */
export const XED25519_PRIVATE_KEY_SIZE = 32;

/** Size of an XEd25519 public key in bytes (same as Curve25519). */
export const XED25519_PUBLIC_KEY_SIZE = 32;

/** Size of an XEd25519 signature in bytes. */
export const XED25519_SIGNATURE_SIZE = 64;

/** Size of XEd25519 random nonce for signing (in bytes). */
export const XED25519_RANDOM_SIZE = 64;

// ═══════════════════════════════════════════════════════════════════════════
// HKDF-SHA256
// ═══════════════════════════════════════════════════════════════════════════

/** Size of HKDF-SHA256 PRK (pseudorandom key) in bytes. */
export const HKDF_PRK_SIZE = 32;

/** Maximum HKDF-SHA256 output length: 255 * HashLen = 255 * 32 = 8160 bytes. */
export const HKDF_MAX_OUTPUT_SIZE = 8160;

// ═══════════════════════════════════════════════════════════════════════════
// AES-256
// ═══════════════════════════════════════════════════════════════════════════

/** Size of an AES-256 key in bytes. */
export const AES_256_KEY_SIZE = 32;

/** Size of an AES-256-GCM nonce in bytes (recommended size per NIST SP 800-38D). */
export const AES_256_GCM_NONCE_SIZE = 12;

/** Size of an AES-256-GCM authentication tag in bytes. */
export const AES_256_GCM_TAG_SIZE = 16;

/** Size of an AES-256-CBC IV in bytes (one AES block). */
export const AES_256_CBC_IV_SIZE = 16;

/** AES block size in bytes. */
export const AES_BLOCK_SIZE = 16;

// ═══════════════════════════════════════════════════════════════════════════
// SHA-256 / HMAC
// ═══════════════════════════════════════════════════════════════════════════

/** Size of a SHA-256 hash output in bytes. */
export const SHA256_OUTPUT_SIZE = 32;

/** Size of an HMAC-SHA256 tag in bytes. */
export const HMAC_SHA256_TAG_SIZE = 32;

/** SHA-256 block size (used internally by HMAC). */
export const SHA256_BLOCK_SIZE = 64;

// ═══════════════════════════════════════════════════════════════════════════
// Limits & Recommendations
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Maximum recommended plaintext size for AES-GCM (~64 GiB).
 *
 * AES-GCM has a hard limit of 2^39 - 256 bits ≈ 64 GiB per single encryption
 * under the same key+nonce. We recommend much smaller messages and key rotation.
 */
export const AES_GCM_MAX_PLAINTEXT_SIZE = 64 * 1024 * 1024 * 1024;

/**
 * Recommended maximum number of messages encrypted under the same AES-GCM key
 * with random 96-bit nonces before key rotation: 2^32.
 */
export const AES_GCM_RECOMMENDED_MESSAGES_PER_KEY = 4294967296;
