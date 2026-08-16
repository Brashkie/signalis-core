/**
 * Wycheproof adversarial test vectors for the asymmetric primitives.
 *
 * Complements the AEAD Wycheproof suite (v0.4.5) with the elliptic-curve
 * primitives, where the most dangerous edge cases live: low-order points and
 * twist points for X25519, and signature malleability / non-canonical encodings
 * for Ed25519.
 *
 * Ed25519 here relies on strict verification (`verify_strict` in the Rust
 * layer, v0.4.7) — signalis-core rejects malleable and non-canonically encoded
 * signatures, matching RFC 8032 strict behaviour and Wycheproof's classification.
 *
 * Fixtures under ./vectors are curated from C2SP/wycheproof (Apache-2.0) and are
 * NOT shipped in the npm package.
 */

import { describe, it, expect } from 'vitest';

import { Curve25519, Ed25519 } from '../src';
import x25519Vectors from './vectors/x25519_wycheproof.json';
import ed25519Vectors from './vectors/ed25519_wycheproof.json';

const hex = (s: string) => Buffer.from(s, 'hex');

// ─── X25519 (ECDH) ──────────────────────────────────────────────────────────

interface X25519Test {
  tcId: number;
  comment: string;
  public: string;
  private: string;
  shared: string;
  result: 'valid' | 'acceptable' | 'invalid';
  flags: string[];
}

describe('Wycheproof: X25519 (ECDH)', () => {
  const fixture = x25519Vectors as { count: number; tests: X25519Test[] };

  it(`has the expected number of vectors (${fixture.count})`, () => {
    expect(fixture.tests.length).toBe(fixture.count);
  });

  for (const t of fixture.tests) {
    const label = `#${t.tcId} [${t.result}] ${t.comment}`.slice(0, 90);
    it(label, () => {
      // curve25519-dalek's clamped scalar mult is permissive: it computes the
      // shared secret for every 32-byte input, including low-order and twist
      // points (producing the all-zero secret where Wycheproof marks
      // ZeroSharedSecret). So DH(private, public) must equal the listed shared
      // secret for both `valid` and `acceptable` vectors.
      const out = Curve25519.diffieHellman(hex(t.private), hex(t.public));
      expect(out.toString('hex')).toBe(t.shared);
    });
  }
});

// ─── Ed25519 (signature verification) ────────────────────────────────────────

interface Ed25519Test {
  tcId: number;
  comment: string;
  pk: string;
  msg: string;
  sig: string;
  result: 'valid' | 'invalid';
  flags: string[];
}

describe('Wycheproof: Ed25519 (verify_strict)', () => {
  const fixture = ed25519Vectors as { count: number; tests: Ed25519Test[] };

  it(`has the expected number of vectors (${fixture.count})`, () => {
    expect(fixture.tests.length).toBe(fixture.count);
  });

  for (const t of fixture.tests) {
    const label = `#${t.tcId} [${t.result}] ${t.comment}`.slice(0, 90);
    it(label, () => {
      // verifyBool never throws — it returns false on any invalid input
      // (wrong length, bad encoding, malleable S, failed verification).
      const ok = Ed25519.verifyBool(hex(t.pk), hex(t.msg), hex(t.sig));
      expect(ok).toBe(t.result === 'valid');
    });
  }
});
