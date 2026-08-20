import { describe, it, expect } from 'vitest';

import { HMAC, HKDF } from '../src';

describe('HMAC-SHA512', () => {
  // Known-answer tests from RFC 4231.
  it('matches RFC 4231 test case 1', () => {
    const key = Buffer.from('0b'.repeat(20), 'hex');
    const data = Buffer.from('Hi There');
    const tag = HMAC.sha512(key, data);
    expect(tag.length).toBe(64);
    expect(tag.toString('hex')).toBe(
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
        'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    );
  });

  it('matches RFC 4231 test case 2', () => {
    const key = Buffer.from('Jefe');
    const data = Buffer.from('what do ya want for nothing?');
    expect(HMAC.sha512(key, data).toString('hex')).toBe(
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554' +
        '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    );
  });

  it('verifies its own tag in constant time', () => {
    const key = Buffer.from('secret');
    const data = Buffer.from('message');
    const tag = HMAC.sha512(key, data);
    expect(HMAC.verifySha512(key, data, tag)).toBe(true);
  });

  it('rejects a wrong tag', () => {
    const key = Buffer.from('secret');
    const data = Buffer.from('message');
    expect(HMAC.verifySha512(key, data, Buffer.alloc(64))).toBe(false);
  });

  it('rejects non-Buffer inputs', () => {
    expect(() => HMAC.sha512('nope' as never, Buffer.from('x'))).toThrow();
  });
});

describe('HKDF-SHA512', () => {
  // KAT generated with the `cryptography` reference (HKDF-SHA512),
  // RFC 5869 A.1-style inputs adapted to SHA-512.
  const ikm = Buffer.from('0b'.repeat(22), 'hex');
  const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
  const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');

  it('matches the reference KAT (42 bytes)', () => {
    const okm = HKDF.deriveSha512(salt, ikm, info, 42);
    expect(okm.toString('hex')).toBe(
      '832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb',
    );
  });

  it('respects requested output length', () => {
    expect(HKDF.deriveSha512(salt, ikm, info, 16).length).toBe(16);
    expect(HKDF.deriveSha512(salt, ikm, info, 128).length).toBe(128);
  });

  it('is deterministic', () => {
    const a = HKDF.deriveSha512(salt, ikm, info, 48);
    const b = HKDF.deriveSha512(salt, ikm, info, 48);
    expect(a.equals(b)).toBe(true);
  });

  it('different salt → different output', () => {
    const a = HKDF.deriveSha512(Buffer.from('salt1'), ikm, info, 32);
    const b = HKDF.deriveSha512(Buffer.from('salt2'), ikm, info, 32);
    expect(a.equals(b)).toBe(false);
  });

  it('rejects zero length', () => {
    expect(() => HKDF.deriveSha512(salt, ikm, info, 0)).toThrow();
  });

  it('rejects non-Buffer salt', () => {
    expect(() => HKDF.deriveSha512('salt' as never, ikm, info, 32)).toThrow();
  });
});
