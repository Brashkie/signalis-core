import { describe, it, expect } from 'vitest';

import { BLAKE3 } from '../src';

// Official BLAKE3 test-vector conventions:
//   input   = bytes [0,1,2,...,250,0,1,...] (i % 251)
//   key     = "whats the Elvish word for friend" (32 bytes)
//   context = "BLAKE3 2019-12-27 16:29:52 test vectors context"
const KEY = Buffer.from('whats the Elvish word for friend');
const CTX = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
const makeInput = (n: number) => Buffer.from(Array.from({ length: n }, (_, i) => i % 251));

describe('BLAKE3 hash', () => {
  it('hashes the empty input', () => {
    const d = BLAKE3.hash(Buffer.from(''));
    expect(d.length).toBe(32);
    expect(d.toString('hex')).toBe(
      'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
    );
  });

  it('hashes a 1-byte input', () => {
    expect(BLAKE3.hash(makeInput(1)).toString('hex')).toBe(
      '2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213',
    );
  });

  it('hashes a 1024-byte input', () => {
    expect(BLAKE3.hash(makeInput(1024)).toString('hex')).toBe(
      '42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7',
    );
  });

  it('rejects non-Buffer input', () => {
    expect(() => BLAKE3.hash('x' as never)).toThrow();
  });
});

describe('BLAKE3 keyed hash (MAC)', () => {
  it('matches KAT (empty input)', () => {
    expect(BLAKE3.keyedHash(KEY, Buffer.from('')).toString('hex')).toBe(
      '92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26',
    );
  });

  it('matches KAT (1024-byte input)', () => {
    expect(BLAKE3.keyedHash(KEY, makeInput(1024)).toString('hex')).toBe(
      '75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4',
    );
  });

  it('verifies its own tag in constant time', () => {
    const tag = BLAKE3.keyedHash(KEY, Buffer.from('message'));
    expect(BLAKE3.keyedHashVerify(KEY, Buffer.from('message'), tag)).toBe(true);
  });

  it('rejects a wrong tag', () => {
    expect(BLAKE3.keyedHashVerify(KEY, Buffer.from('message'), Buffer.alloc(32))).toBe(false);
  });

  it('rejects a non-32-byte key', () => {
    expect(() => BLAKE3.keyedHash(Buffer.alloc(16), Buffer.from('x'))).toThrow();
  });
});

describe('BLAKE3 derive_key', () => {
  it('matches KAT (empty key material)', () => {
    expect(BLAKE3.deriveKey(CTX, Buffer.from('')).toString('hex')).toBe(
      '2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d',
    );
  });

  it('matches KAT (1024-byte key material)', () => {
    expect(BLAKE3.deriveKey(CTX, makeInput(1024)).toString('hex')).toBe(
      '7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706',
    );
  });

  it('different contexts → different keys', () => {
    const a = BLAKE3.deriveKey('context A', makeInput(32));
    const b = BLAKE3.deriveKey('context B', makeInput(32));
    expect(a.equals(b)).toBe(false);
  });

  it('rejects an empty context', () => {
    expect(() => BLAKE3.deriveKey('', makeInput(32))).toThrow();
  });
});
