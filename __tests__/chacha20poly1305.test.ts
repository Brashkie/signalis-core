import { describe, it, expect } from 'vitest';

import {
  ChaCha20Poly1305,
  constantTimeEq,
  nativeSecureRandom,
  secureRandom,
  CHACHA20_POLY1305_KEY_SIZE,
  CHACHA20_POLY1305_NONCE_SIZE,
  CHACHA20_POLY1305_TAG_SIZE,
} from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// ChaCha20Poly1305
// ═══════════════════════════════════════════════════════════════════════════

describe('ChaCha20Poly1305', () => {
  const freshKey = () => secureRandom(CHACHA20_POLY1305_KEY_SIZE);
  const freshNonce = () => secureRandom(CHACHA20_POLY1305_NONCE_SIZE);

  it('exposes correct constants', () => {
    expect(ChaCha20Poly1305.KEY_SIZE).toBe(32);
    expect(ChaCha20Poly1305.NONCE_SIZE).toBe(12);
    expect(ChaCha20Poly1305.TAG_SIZE).toBe(16);
  });

  it('round-trips a short message', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const pt = Buffer.from('Hello ChaCha!');

    const ct = ChaCha20Poly1305.encrypt(key, nonce, pt);
    expect(ct.length).toBe(pt.length + CHACHA20_POLY1305_TAG_SIZE);

    const recovered = ChaCha20Poly1305.decrypt(key, nonce, ct);
    expect(recovered.equals(pt)).toBe(true);
  });

  it('round-trips empty plaintext', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const ct = ChaCha20Poly1305.encrypt(key, nonce, Buffer.alloc(0));
    expect(ct.length).toBe(CHACHA20_POLY1305_TAG_SIZE);

    const recovered = ChaCha20Poly1305.decrypt(key, nonce, ct);
    expect(recovered.length).toBe(0);
  });

  it('round-trips large plaintext (10 KB)', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const pt = Buffer.alloc(10_000, 0xab);

    const ct = ChaCha20Poly1305.encrypt(key, nonce, pt);
    const recovered = ChaCha20Poly1305.decrypt(key, nonce, ct);
    expect(recovered.equals(pt)).toBe(true);
  });

  it('round-trips with AAD', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const pt = Buffer.from('secret');
    const aad = Buffer.from('public header');

    const ct = ChaCha20Poly1305.encryptWithAad(key, nonce, pt, aad);
    const recovered = ChaCha20Poly1305.decryptWithAad(key, nonce, ct, aad);
    expect(recovered.equals(pt)).toBe(true);
  });

  it('rejects tampered ciphertext', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const ct = ChaCha20Poly1305.encrypt(key, nonce, Buffer.from('data'));

    const tampered = Buffer.from(ct);
    tampered[0] ^= 0xff;

    expect(() => ChaCha20Poly1305.decrypt(key, nonce, tampered)).toThrow();
  });

  it('rejects tampered AAD', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const ct = ChaCha20Poly1305.encryptWithAad(
      key,
      nonce,
      Buffer.from('data'),
      Buffer.from('aad-1'),
    );

    expect(() =>
      ChaCha20Poly1305.decryptWithAad(key, nonce, ct, Buffer.from('aad-2')),
    ).toThrow();
  });

  it('rejects wrong key size', () => {
    expect(() =>
      ChaCha20Poly1305.encrypt(Buffer.alloc(16), freshNonce(), Buffer.from('x')),
    ).toThrow(RangeError);
  });

  it('rejects wrong nonce size', () => {
    expect(() =>
      ChaCha20Poly1305.encrypt(freshKey(), Buffer.alloc(8), Buffer.from('x')),
    ).toThrow(RangeError);
  });

  it('rejects non-Buffer plaintext', () => {
    expect(() =>
      ChaCha20Poly1305.encrypt(freshKey(), freshNonce(), 'string' as never),
    ).toThrow(TypeError);
  });

  it('decryptWithAad rejects wrong key size', () => {
    expect(() =>
      ChaCha20Poly1305.decryptWithAad(
        Buffer.alloc(16),
        freshNonce(),
        Buffer.alloc(32),
        Buffer.alloc(0),
      ),
    ).toThrow(RangeError);
  });

  it('decryptWithAad rejects wrong nonce size', () => {
    expect(() =>
      ChaCha20Poly1305.decryptWithAad(
        freshKey(),
        Buffer.alloc(8),
        Buffer.alloc(32),
        Buffer.alloc(0),
      ),
    ).toThrow(RangeError);
  });

  it('encryptWithAad rejects non-Buffer AAD', () => {
    expect(() =>
      ChaCha20Poly1305.encryptWithAad(
        freshKey(),
        freshNonce(),
        Buffer.from('x'),
        'aad' as never,
      ),
    ).toThrow(TypeError);
  });

  // ─── Coverage completion: decrypt + encryptWithAad + decryptWithAad ──
  // Hits every remaining unchecked branch in core.ts ChaCha20Poly1305 namespace.

  it('decrypt rejects wrong key size', () => {
    expect(() =>
      ChaCha20Poly1305.decrypt(Buffer.alloc(16), freshNonce(), Buffer.alloc(32)),
    ).toThrow(RangeError);
  });

  it('decrypt rejects wrong nonce size', () => {
    expect(() =>
      ChaCha20Poly1305.decrypt(freshKey(), Buffer.alloc(8), Buffer.alloc(32)),
    ).toThrow(RangeError);
  });

  it('decrypt rejects non-Buffer ciphertext', () => {
    expect(() =>
      ChaCha20Poly1305.decrypt(freshKey(), freshNonce(), 'string' as never),
    ).toThrow(TypeError);
  });

  it('encryptWithAad rejects wrong key size', () => {
    expect(() =>
      ChaCha20Poly1305.encryptWithAad(
        Buffer.alloc(16),
        freshNonce(),
        Buffer.from('x'),
        Buffer.from('aad'),
      ),
    ).toThrow(RangeError);
  });

  it('encryptWithAad rejects wrong nonce size', () => {
    expect(() =>
      ChaCha20Poly1305.encryptWithAad(
        freshKey(),
        Buffer.alloc(8),
        Buffer.from('x'),
        Buffer.from('aad'),
      ),
    ).toThrow(RangeError);
  });

  it('encryptWithAad rejects non-Buffer plaintext', () => {
    expect(() =>
      ChaCha20Poly1305.encryptWithAad(
        freshKey(),
        freshNonce(),
        'string' as never,
        Buffer.from('aad'),
      ),
    ).toThrow(TypeError);
  });

  it('decryptWithAad rejects non-Buffer ciphertext', () => {
    expect(() =>
      ChaCha20Poly1305.decryptWithAad(
        freshKey(),
        freshNonce(),
        'string' as never,
        Buffer.from('aad'),
      ),
    ).toThrow(TypeError);
  });

  it('decryptWithAad rejects non-Buffer AAD', () => {
    expect(() =>
      ChaCha20Poly1305.decryptWithAad(
        freshKey(),
        freshNonce(),
        Buffer.alloc(32),
        'aad' as never,
      ),
    ).toThrow(TypeError);
  });

  it('different nonces produce different ciphertexts (same key, same plaintext)', () => {
    const key = freshKey();
    const pt = Buffer.from('same data');

    const ct1 = ChaCha20Poly1305.encrypt(key, freshNonce(), pt);
    const ct2 = ChaCha20Poly1305.encrypt(key, freshNonce(), pt);

    expect(ct1.equals(ct2)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// constantTimeEq
// ═══════════════════════════════════════════════════════════════════════════

describe('constantTimeEq', () => {
  it('returns true for identical buffers', () => {
    const a = Buffer.from([1, 2, 3, 4]);
    const b = Buffer.from([1, 2, 3, 4]);
    expect(constantTimeEq(a, b)).toBe(true);
  });

  it('returns false for different buffers (same length)', () => {
    const a = Buffer.from([1, 2, 3, 4]);
    const b = Buffer.from([1, 2, 3, 5]);
    expect(constantTimeEq(a, b)).toBe(false);
  });

  it('returns false for different lengths', () => {
    expect(constantTimeEq(Buffer.from([1, 2]), Buffer.from([1, 2, 3]))).toBe(false);
    expect(constantTimeEq(Buffer.from([1, 2, 3]), Buffer.from([1, 2]))).toBe(false);
  });

  it('returns true for two empty buffers', () => {
    expect(constantTimeEq(Buffer.alloc(0), Buffer.alloc(0))).toBe(true);
  });

  it('throws TypeError on non-Buffer input', () => {
    expect(() => constantTimeEq('string' as never, Buffer.from([]))).toThrow(TypeError);
    expect(() => constantTimeEq(Buffer.from([]), 'string' as never)).toThrow(TypeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// nativeSecureRandom
// ═══════════════════════════════════════════════════════════════════════════

describe('nativeSecureRandom', () => {
  it('returns Buffer of requested size', () => {
    const buf = nativeSecureRandom(32);
    expect(buf).toBeInstanceOf(Buffer);
    expect(buf.length).toBe(32);
  });

  it('two calls produce different output', () => {
    const a = nativeSecureRandom(32);
    const b = nativeSecureRandom(32);
    expect(a.equals(b)).toBe(false);
  });

  it('rejects non-integer size', () => {
    expect(() => nativeSecureRandom(1.5)).toThrow(RangeError);
  });

  it('rejects zero size', () => {
    expect(() => nativeSecureRandom(0)).toThrow(RangeError);
  });

  it('rejects negative size', () => {
    expect(() => nativeSecureRandom(-1)).toThrow(RangeError);
  });

  it('throws via NAPI when size exceeds Rust cap (16 MiB)', () => {
    expect(() => nativeSecureRandom(16 * 1024 * 1024 + 1)).toThrow();
  });
});
