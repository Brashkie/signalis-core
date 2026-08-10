/**
 * Utility functions for signalis-core.
 *
 * Encoding helpers, secure random generation, and constant-time comparisons.
 *
 * @packageDocumentation
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { Encoding } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// Secure Random
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate cryptographically secure random bytes.
 *
 * Uses Node's `crypto.randomBytes` which delegates to the OS CSPRNG:
 * - Linux/macOS: `getrandom()` / `/dev/urandom`
 * - Windows: `BCryptGenRandom`
 *
 * @param length - Number of bytes to generate
 * @returns A Buffer of `length` random bytes
 *
 * @example
 * ```ts
 * const nonce = secureRandom(12);  // 12-byte nonce for AES-GCM
 * const key = secureRandom(32);    // 32-byte AES key
 * ```
 */
export function secureRandom(length: number): Buffer {
  if (!Number.isInteger(length) || length < 0) {
    throw new RangeError(`length must be a non-negative integer, got ${length}`);
  }
  return randomBytes(length);
}

/**
 * Generate a cryptographically secure random 12-byte nonce (for AES-GCM).
 */
export function randomNonce(): Buffer {
  return randomBytes(12);
}

/**
 * Generate a cryptographically secure random 16-byte IV (for AES-CBC).
 */
export function randomIv(): Buffer {
  return randomBytes(16);
}

/**
 * Generate a cryptographically secure random 32-byte key.
 */
export function randomKey(): Buffer {
  return randomBytes(32);
}

// ═══════════════════════════════════════════════════════════════════════════
// Encoding helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert a Buffer to its hexadecimal string representation.
 *
 * @example
 * ```ts
 * toHex(Buffer.from([0xff, 0x00])); // "ff00"
 * ```
 */
export function toHex(buf: Buffer): string {
  return buf.toString('hex');
}

/**
 * Parse a hexadecimal string into a Buffer.
 *
 * @throws {Error} If `hex` contains non-hex characters or has odd length.
 */
export function fromHex(hex: string): Buffer {
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Invalid hex string: contains non-hex characters');
  }
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd number of characters');
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Convert a Buffer to a standard base64 string.
 */
export function toBase64(buf: Buffer): string {
  return buf.toString('base64');
}

/**
 * Parse a base64 string into a Buffer.
 */
export function fromBase64(b64: string): Buffer {
  return Buffer.from(b64, 'base64');
}

/**
 * Convert a Buffer to a URL-safe base64 string (no padding).
 *
 * Useful for URLs, query strings, JWT headers, etc.
 */
export function toBase64Url(buf: Buffer): string {
  return buf.toString('base64url');
}

/**
 * Parse a base64url string into a Buffer.
 */
export function fromBase64Url(b64url: string): Buffer {
  return Buffer.from(b64url, 'base64url');
}

/**
 * Convert a Buffer to a string using the specified encoding.
 */
export function bufferToString(buf: Buffer, encoding: Encoding = 'hex'): string {
  return buf.toString(encoding);
}

/**
 * Parse a string into a Buffer using the specified encoding.
 */
export function stringToBuffer(str: string, encoding: Encoding = 'hex'): Buffer {
  return Buffer.from(str, encoding);
}

// ═══════════════════════════════════════════════════════════════════════════
// Constant-time comparison
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compare two Buffers in constant time (resistant to timing attacks).
 *
 * **Always** use this instead of `===` or `Buffer.equals` when comparing
 * MACs, signatures, or any other security-sensitive bytes.
 *
 * Returns `false` if lengths differ (without revealing the difference).
 *
 * @example
 * ```ts
 * const valid = constantTimeEqual(receivedTag, expectedTag);
 * if (!valid) throw new Error('MAC verification failed');
 * ```
 */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    // Compare against itself to keep some constant work
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

// ═══════════════════════════════════════════════════════════════════════════
// Buffer manipulation
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Concatenate multiple Buffers into one.
 *
 * Thin wrapper over `Buffer.concat` with cleaner naming.
 */
export function concat(buffers: Buffer[]): Buffer {
  return Buffer.concat(buffers);
}

/**
 * Zero out a Buffer in-place.
 *
 * Useful for clearing sensitive data after use.
 *
 * **Note:** JavaScript runtimes may keep copies in GC buffers, so this is
 * NOT a guaranteed wipe. For real security, use Rust-side zeroization.
 */
export function zeroize(buf: Buffer): void {
  buf.fill(0);
}

/**
 * XOR two equal-length Buffers and return the result.
 *
 * @throws {Error} If buffers have different lengths.
 */
export function xor(a: Buffer, b: Buffer): Buffer {
  if (a.length !== b.length) {
    throw new Error(`XOR operands must have equal length: ${a.length} vs ${b.length}`);
  }
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i]! ^ b[i]!;
  }
  return result;
}

/**
 * Split a Buffer into consecutive segments of the given sizes.
 *
 * The inverse of {@link concat}: useful for deserializing a blob that packs
 * several fixed-size fields, e.g. splitting `nonce ‖ ciphertext ‖ tag`.
 *
 * If the segment sizes sum to less than the buffer length, the trailing bytes
 * are returned as one final segment. Pass sizes that sum to exactly the buffer
 * length to avoid the remainder.
 *
 * @throws {RangeError} If any size is not a non-negative integer, or if the
 *   sizes sum to more than the buffer length.
 *
 * @example
 * const [nonce, rest] = split(blob, [12]);
 * const [nonce, ct, tag] = split(blob, [12, blob.length - 28, 16]);
 */
export function split(buf: Buffer, sizes: number[]): Buffer[] {
  let total = 0;
  for (const size of sizes) {
    if (!Number.isInteger(size) || size < 0) {
      throw new RangeError(`each size must be a non-negative integer, got ${size}`);
    }
    total += size;
  }
  if (total > buf.length) {
    throw new RangeError(
      `sizes sum to ${total} but buffer is only ${buf.length} byte(s) long`,
    );
  }

  const segments: Buffer[] = [];
  let offset = 0;
  for (const size of sizes) {
    segments.push(buf.subarray(offset, offset + size));
    offset += size;
  }
  if (offset < buf.length) {
    segments.push(buf.subarray(offset));
  }
  return segments;
}

/**
 * Compare two Buffers for equality (NON constant-time).
 *
 * Use this for **public** data (headers, identifiers, non-secret metadata)
 * where timing side channels don't matter and speed does. For anything secret
 * (MAC tags, key material), use {@link constantTimeEqual} instead.
 */
export function bytesEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && a.equals(b);
}

/**
 * Concatenate several `Uint8Array`s into one.
 *
 * The `Uint8Array` counterpart of {@link concat}, for environments without
 * Node's `Buffer` (browsers, WASM). Accepts `Buffer`s too, since they are
 * `Uint8Array`s.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const arr of arrays) {
    total += arr.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

/**
 * Split a `Uint8Array` into consecutive segments of the given sizes.
 *
 * The `Uint8Array` counterpart of {@link split}. Segments are views into the
 * same underlying memory (`subarray`), not copies.
 *
 * @throws {RangeError} If any size is not a non-negative integer, or if the
 *   sizes sum to more than the array length.
 */
export function splitBytes(bytes: Uint8Array, sizes: number[]): Uint8Array[] {
  let total = 0;
  for (const size of sizes) {
    if (!Number.isInteger(size) || size < 0) {
      throw new RangeError(`each size must be a non-negative integer, got ${size}`);
    }
    total += size;
  }
  if (total > bytes.length) {
    throw new RangeError(
      `sizes sum to ${total} but array is only ${bytes.length} byte(s) long`,
    );
  }

  const segments: Uint8Array[] = [];
  let offset = 0;
  for (const size of sizes) {
    segments.push(bytes.subarray(offset, offset + size));
    offset += size;
  }
  if (offset < bytes.length) {
    segments.push(bytes.subarray(offset));
  }
  return segments;
}
