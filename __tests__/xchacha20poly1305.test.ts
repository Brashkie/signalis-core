import { describe, it, expect } from 'vitest';

import {
  XChaCha20Poly1305,
  ChaCha20Poly1305,
  secureRandom,
  XCHACHA20_POLY1305_NONCE_SIZE,
  CHACHA20_POLY1305_KEY_SIZE,
  CHACHA20_POLY1305_TAG_SIZE,
} from '../src';

describe('XChaCha20Poly1305', () => {
  const freshKey = () => secureRandom(CHACHA20_POLY1305_KEY_SIZE);
  const freshNonce = () => secureRandom(XCHACHA20_POLY1305_NONCE_SIZE);

  it('exposes correct constants', () => {
    expect(XChaCha20Poly1305.KEY_SIZE).toBe(32);
    expect(XChaCha20Poly1305.NONCE_SIZE).toBe(24);
    expect(XChaCha20Poly1305.TAG_SIZE).toBe(16);
    expect(XCHACHA20_POLY1305_NONCE_SIZE).toBe(24);
  });

  it('round-trips a short message', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const pt = Buffer.from('hello xchacha');
    const ct = XChaCha20Poly1305.encrypt(key, nonce, pt);
    expect(ct.length).toBe(pt.length + CHACHA20_POLY1305_TAG_SIZE);
    const recovered = XChaCha20Poly1305.decrypt(key, nonce, ct);
    expect(recovered.equals(pt)).toBe(true);
  });

  it('round-trips empty plaintext', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const ct = XChaCha20Poly1305.encrypt(key, nonce, Buffer.alloc(0));
    const recovered = XChaCha20Poly1305.decrypt(key, nonce, ct);
    expect(recovered.length).toBe(0);
  });

  it('round-trips large plaintext (10 KB)', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const pt = secureRandom(10 * 1024);
    const ct = XChaCha20Poly1305.encrypt(key, nonce, pt);
    const recovered = XChaCha20Poly1305.decrypt(key, nonce, ct);
    expect(recovered.equals(pt)).toBe(true);
  });

  it('round-trips with AAD', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const pt = Buffer.from('secret');
    const aad = Buffer.from('header-v1');
    const ct = XChaCha20Poly1305.encryptWithAad(key, nonce, pt, aad);
    const recovered = XChaCha20Poly1305.decryptWithAad(key, nonce, ct, aad);
    expect(recovered.equals(pt)).toBe(true);
  });

  it('rejects tampered ciphertext', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const ct = XChaCha20Poly1305.encrypt(key, nonce, Buffer.from('data'));
    const tampered = Buffer.from(ct);
    tampered[0] ^= 0x01;
    expect(() => XChaCha20Poly1305.decrypt(key, nonce, tampered)).toThrow();
  });

  it('rejects wrong AAD', () => {
    const key = freshKey();
    const nonce = freshNonce();
    const ct = XChaCha20Poly1305.encryptWithAad(key, nonce, Buffer.from('x'), Buffer.from('a'));
    expect(() => XChaCha20Poly1305.decryptWithAad(key, nonce, ct, Buffer.from('b'))).toThrow();
  });

  it('rejects a 12-byte nonce (must be 24)', () => {
    const key = freshKey();
    const shortNonce = secureRandom(12);
    expect(() => XChaCha20Poly1305.encrypt(key, shortNonce, Buffer.from('x'))).toThrow(RangeError);
  });

  it('rejects a wrong-size key', () => {
    const nonce = freshNonce();
    expect(() => XChaCha20Poly1305.encrypt(secureRandom(16), nonce, Buffer.from('x'))).toThrow(
      RangeError,
    );
  });

  // ─── Full validation coverage (each guard on each method) ────────────────

  it('encrypt rejects non-Buffer plaintext', () => {
    const key = freshKey();
    const nonce = freshNonce();
    expect(() => XChaCha20Poly1305.encrypt(key, nonce, 'nope' as never)).toThrow(TypeError);
  });

  it('decrypt rejects wrong key size', () => {
    const nonce = freshNonce();
    expect(() => XChaCha20Poly1305.decrypt(secureRandom(16), nonce, Buffer.alloc(32))).toThrow(
      RangeError,
    );
  });

  it('decrypt rejects wrong nonce size', () => {
    const key = freshKey();
    expect(() => XChaCha20Poly1305.decrypt(key, secureRandom(12), Buffer.alloc(32))).toThrow(
      RangeError,
    );
  });

  it('decrypt rejects non-Buffer ciphertext', () => {
    const key = freshKey();
    const nonce = freshNonce();
    expect(() => XChaCha20Poly1305.decrypt(key, nonce, 'nope' as never)).toThrow(TypeError);
  });

  it('encryptWithAad rejects wrong key size', () => {
    const nonce = freshNonce();
    expect(() =>
      XChaCha20Poly1305.encryptWithAad(secureRandom(16), nonce, Buffer.from('x'), Buffer.alloc(0)),
    ).toThrow(RangeError);
  });

  it('encryptWithAad rejects wrong nonce size', () => {
    const key = freshKey();
    expect(() =>
      XChaCha20Poly1305.encryptWithAad(key, secureRandom(12), Buffer.from('x'), Buffer.alloc(0)),
    ).toThrow(RangeError);
  });

  it('encryptWithAad rejects non-Buffer plaintext/aad', () => {
    const key = freshKey();
    const nonce = freshNonce();
    expect(() => XChaCha20Poly1305.encryptWithAad(key, nonce, 'x' as never, Buffer.alloc(0))).toThrow(
      TypeError,
    );
  });

  it('decryptWithAad rejects wrong key size', () => {
    const nonce = freshNonce();
    expect(() =>
      XChaCha20Poly1305.decryptWithAad(secureRandom(16), nonce, Buffer.alloc(32), Buffer.alloc(0)),
    ).toThrow(RangeError);
  });

  it('decryptWithAad rejects wrong nonce size', () => {
    const key = freshKey();
    expect(() =>
      XChaCha20Poly1305.decryptWithAad(key, secureRandom(12), Buffer.alloc(32), Buffer.alloc(0)),
    ).toThrow(RangeError);
  });

  it('decryptWithAad rejects non-Buffer ciphertext/aad', () => {
    const key = freshKey();
    const nonce = freshNonce();
    expect(() => XChaCha20Poly1305.decryptWithAad(key, nonce, 'x' as never, Buffer.alloc(0))).toThrow(
      TypeError,
    );
  });

  it('produces different ciphertext than ChaCha20Poly1305 (distinct construction)', () => {
    // Same key + 24-byte nonce truncated to 12 for the classic variant — the
    // outputs must differ (XChaCha derives a subkey via HChaCha20).
    const key = freshKey();
    const xnonce = freshNonce();
    const ctX = XChaCha20Poly1305.encrypt(key, xnonce, Buffer.from('data'));
    const ct12 = ChaCha20Poly1305.encrypt(key, xnonce.subarray(0, 12), Buffer.from('data'));
    expect(ctX.equals(ct12)).toBe(false);
  });

  it('matches the libsodium known-answer vector', () => {
    // KAT generated with libsodium (crypto_aead_xchacha20poly1305_ietf).
    // Proves interoperability with the reference XChaCha20-Poly1305.
    const key = Buffer.from(
      '00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567b',
      'hex',
    );
    const nonce = Buffer.from('404142434445464748494a4b4c4d4e4f5051525354555657', 'hex');
    const pt = Buffer.from('Signalis XChaCha KAT');

    const ctWithAad = XChaCha20Poly1305.encryptWithAad(key, nonce, pt, Buffer.from('header-v1'));
    expect(ctWithAad.toString('hex')).toBe(
      '20df03f87c3b34d02b52cf608be5cabd670faa5acc8b9aa8bc1e53cae2b273d0a3d28e02',
    );

    const ctNoAad = XChaCha20Poly1305.encrypt(key, nonce, pt);
    expect(ctNoAad.toString('hex')).toBe(
      '20df03f87c3b34d02b52cf608be5cabd670faa5a19defa41298eceeaa9398789d9888d17',
    );
  });
});
