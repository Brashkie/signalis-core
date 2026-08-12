import { describe, it, expect } from 'vitest';

import { PBKDF2, secureRandom } from '../src';

describe('PBKDF2-HMAC-SHA256', () => {
  // Known-answer tests (SHA-256 analogues of the RFC 6070 vectors,
  // cross-checked against Node's crypto.pbkdf2 / OpenSSL).

  it('matches KAT: password/salt, 1 iteration, 32 bytes', () => {
    const out = PBKDF2.derive(Buffer.from('password'), Buffer.from('salt'), 1, 32);
    expect(out.toString('hex')).toBe(
      '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
    );
  });

  it('matches KAT: 2 iterations', () => {
    const out = PBKDF2.derive(Buffer.from('password'), Buffer.from('salt'), 2, 32);
    expect(out.toString('hex')).toBe(
      'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43',
    );
  });

  it('matches KAT: 4096 iterations', () => {
    const out = PBKDF2.derive(Buffer.from('password'), Buffer.from('salt'), 4096, 32);
    expect(out.toString('hex')).toBe(
      'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a',
    );
  });

  it('matches KAT: long password + salt, dkLen 40', () => {
    const out = PBKDF2.derive(
      Buffer.from('passwordPASSWORDpassword'),
      Buffer.from('saltSALTsaltSALTsaltSALTsaltSALTsalt'),
      4096,
      40,
    );
    expect(out.toString('hex')).toBe(
      '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9',
    );
  });

  it('respects the requested output length', () => {
    expect(PBKDF2.derive(Buffer.from('pw'), Buffer.from('salt'), 10, 16).length).toBe(16);
    expect(PBKDF2.derive(Buffer.from('pw'), Buffer.from('salt'), 10, 64).length).toBe(64);
  });

  it('is deterministic', () => {
    const a = PBKDF2.derive(Buffer.from('pw'), Buffer.from('salt'), 1000, 32);
    const b = PBKDF2.derive(Buffer.from('pw'), Buffer.from('salt'), 1000, 32);
    expect(a.equals(b)).toBe(true);
  });

  it('different salt → different output', () => {
    const a = PBKDF2.derive(Buffer.from('pw'), secureRandom(16), 1000, 32);
    const b = PBKDF2.derive(Buffer.from('pw'), secureRandom(16), 1000, 32);
    expect(a.equals(b)).toBe(false);
  });

  // ─── Validation ──────────────────────────────────────────────────────────

  it('rejects zero iterations', () => {
    expect(() => PBKDF2.derive(Buffer.from('pw'), Buffer.from('salt'), 0, 32)).toThrow();
  });

  it('rejects zero length', () => {
    expect(() => PBKDF2.derive(Buffer.from('pw'), Buffer.from('salt'), 1000, 0)).toThrow();
  });

  it('rejects negative / non-integer iterations', () => {
    expect(() => PBKDF2.derive(Buffer.from('pw'), Buffer.from('salt'), -1, 32)).toThrow();
    expect(() => PBKDF2.derive(Buffer.from('pw'), Buffer.from('salt'), 1.5, 32)).toThrow();
  });

  it('rejects non-Buffer password', () => {
    expect(() => PBKDF2.derive('pw' as never, Buffer.from('salt'), 1000, 32)).toThrow();
  });

  it('rejects non-Buffer salt', () => {
    expect(() => PBKDF2.derive(Buffer.from('pw'), 'salt' as never, 1000, 32)).toThrow();
  });
});
