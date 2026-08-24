import { describe, it, expect } from 'vitest';

import { SHA3 } from '../src';

describe('SHA3-256', () => {
  // NIST FIPS 202 known-answer tests.
  it('hashes the empty string', () => {
    const d = SHA3.hash256(Buffer.from(''));
    expect(d.length).toBe(32);
    expect(d.toString('hex')).toBe(
      'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    );
  });

  it("hashes 'abc'", () => {
    expect(SHA3.hash256(Buffer.from('abc')).toString('hex')).toBe(
      '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    );
  });

  it('hashAll matches concatenated hash', () => {
    const a = SHA3.hash256All([Buffer.from('ab'), Buffer.from('c')]);
    const b = SHA3.hash256(Buffer.from('abc'));
    expect(a.equals(b)).toBe(true);
  });

  it('rejects non-Buffer input', () => {
    expect(() => SHA3.hash256('abc' as never)).toThrow();
  });
});

describe('SHA3-512', () => {
  it('hashes the empty string', () => {
    const d = SHA3.hash512(Buffer.from(''));
    expect(d.length).toBe(64);
    expect(d.toString('hex')).toBe(
      'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6' +
        '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
    );
  });

  it("hashes 'abc'", () => {
    expect(SHA3.hash512(Buffer.from('abc')).toString('hex')).toBe(
      'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e' +
        '10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
    );
  });

  it('produces different output than SHA3-256', () => {
    const a = SHA3.hash256(Buffer.from('same'));
    const b = SHA3.hash512(Buffer.from('same'));
    expect(a.equals(b.subarray(0, 32))).toBe(false);
  });

  it('rejects non-Buffer input', () => {
    expect(() => SHA3.hash512(42 as never)).toThrow();
  });
});
