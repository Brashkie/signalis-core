import { describe, it, expect } from 'vitest';

import { Argon2id, secureRandom } from '../src';

describe('Argon2id', () => {
  // Known-answer tests generated with the Argon2 reference implementation
  // (argon2-cffi / libargon2), Argon2id, version 0x13, no secret/associated data.
  const SALT = Buffer.from('somesalt12345678'); // 16 bytes

  it('matches KAT: t=1 m=32 p=1 len=32', () => {
    const out = Argon2id.derive(Buffer.from('password'), SALT, 32, 1, 1, 32);
    expect(out.toString('hex')).toBe(
      'd9bc939174cecff705ca7bd6e2a66c00defa130d8f978d92a3fe0ce9bbc8dc03',
    );
  });

  it('matches KAT: t=3 m=256 p=1 len=32', () => {
    const out = Argon2id.derive(Buffer.from('password'), SALT, 256, 3, 1, 32);
    expect(out.toString('hex')).toBe(
      '11d2bf6764de12ca6e31c394416c87b2d60fc9676acb35ed2b92c15ce3c6842c',
    );
  });

  it('matches KAT: t=1 m=32 p=1 len=64', () => {
    const out = Argon2id.derive(Buffer.from('password'), SALT, 32, 1, 1, 64);
    expect(out.toString('hex')).toBe(
      '07f872346434ed9713385ee2737d533ba5a8475f0e45ec2410fd7829f645224b' +
        'ef805cd9522ea9ed6bb28d907abcb41a816381a2204802beb0482dcf4918e145',
    );
  });

  it('matches KAT: t=2 m=64 p=2 len=32 (parallelism)', () => {
    const out = Argon2id.derive(Buffer.from('password'), SALT, 64, 2, 2, 32);
    expect(out.toString('hex')).toBe(
      'bc418ea5103abc2ba7105df54a95022fd755ef3cef33bbc8c0f7a4666acaddbc',
    );
  });

  it('respects the requested output length', () => {
    expect(Argon2id.derive(Buffer.from('pw'), SALT, 32, 1, 1, 16).length).toBe(16);
    expect(Argon2id.derive(Buffer.from('pw'), SALT, 32, 1, 1, 48).length).toBe(48);
  });

  it('is deterministic', () => {
    const a = Argon2id.derive(Buffer.from('pw'), SALT, 64, 2, 1, 32);
    const b = Argon2id.derive(Buffer.from('pw'), SALT, 64, 2, 1, 32);
    expect(a.equals(b)).toBe(true);
  });

  it('different salt → different output', () => {
    const a = Argon2id.derive(Buffer.from('pw'), secureRandom(16), 32, 1, 1, 32);
    const b = Argon2id.derive(Buffer.from('pw'), secureRandom(16), 32, 1, 1, 32);
    expect(a.equals(b)).toBe(false);
  });

  // ─── Validation ──────────────────────────────────────────────────────────

  it('rejects zero length', () => {
    expect(() => Argon2id.derive(Buffer.from('pw'), SALT, 32, 1, 1, 0)).toThrow();
  });

  it('rejects bad cost params (m_cost < 8*p_cost)', () => {
    expect(() => Argon2id.derive(Buffer.from('pw'), SALT, 4, 1, 4, 32)).toThrow();
  });

  it('rejects zero / non-integer mCost', () => {
    expect(() => Argon2id.derive(Buffer.from('pw'), SALT, -1, 1, 1, 32)).toThrow();
    expect(() => Argon2id.derive(Buffer.from('pw'), SALT, 1.5, 1, 1, 32)).toThrow();
  });

  it('rejects short salt (< 8 bytes)', () => {
    expect(() => Argon2id.derive(Buffer.from('pw'), Buffer.from('short'), 32, 1, 1, 32)).toThrow();
  });

  it('rejects non-Buffer password', () => {
    expect(() => Argon2id.derive('pw' as never, SALT, 32, 1, 1, 32)).toThrow();
  });

  it('rejects non-Buffer salt', () => {
    expect(() => Argon2id.derive(Buffer.from('pw'), 'salt' as never, 32, 1, 1, 32)).toThrow();
  });
});
