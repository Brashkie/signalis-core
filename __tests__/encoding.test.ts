/**
 * Tests for Base64, Hex, and Utf8 namespaces (NEW in v0.4.0).
 *
 * These wrap Rust-side implementations from the `sc-encoding` crate.
 * The Rust tests already cover RFC vectors thoroughly; here we focus
 * on the TypeScript wrapper behavior (input validation, error mapping,
 * end-to-end round trips).
 */

import { describe, it, expect } from 'vitest';
import { Base64, Hex, Utf8 } from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// Base64
// ═══════════════════════════════════════════════════════════════════════════

describe('Base64.encode / decode (standard)', () => {
  it('RFC 4648 §10 test vectors', () => {
    const cases: Array<[Buffer, string]> = [
      [Buffer.from(''), ''],
      [Buffer.from('f'), 'Zg=='],
      [Buffer.from('fo'), 'Zm8='],
      [Buffer.from('foo'), 'Zm9v'],
      [Buffer.from('foob'), 'Zm9vYg=='],
      [Buffer.from('fooba'), 'Zm9vYmE='],
      [Buffer.from('foobar'), 'Zm9vYmFy'],
    ];
    for (const [input, expected] of cases) {
      expect(Base64.encode(input)).toBe(expected);
      expect(Base64.decode(expected).equals(input)).toBe(true);
    }
  });

  it('round-trips arbitrary bytes', () => {
    const inputs = [
      Buffer.from([0x00]),
      Buffer.from([0xff]),
      Buffer.from([0xde, 0xad, 0xbe, 0xef]),
      Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    ];
    for (const input of inputs) {
      const encoded = Base64.encode(input);
      const decoded = Base64.decode(encoded);
      expect(decoded.equals(input)).toBe(true);
    }
  });

  it('rejects non-Buffer input to encode', () => {
    expect(() => Base64.encode('not a buffer' as never)).toThrow(TypeError);
    expect(() => Base64.encode(null as never)).toThrow(TypeError);
    expect(() => Base64.encode(undefined as never)).toThrow(TypeError);
  });

  it('rejects non-string input to decode', () => {
    expect(() => Base64.decode(Buffer.from('') as never)).toThrow(TypeError);
    expect(() => Base64.decode(null as never)).toThrow(TypeError);
    expect(() => Base64.decode(42 as never)).toThrow(TypeError);
  });

  it('rejects invalid Base64 characters', () => {
    expect(() => Base64.decode('aGVsbG8!')).toThrow();
  });

  it('rejects Base64 without padding (use encodeUrlSafe for that)', () => {
    // Standard Base64 requires padding
    expect(() => Base64.decode('Zg')).toThrow();
  });
});

describe('Base64.encodeUrlSafe / decodeUrlSafe', () => {
  it('produces URL-safe characters (- and _, no padding)', () => {
    // Bytes that produce + or / in standard should produce - or _ in url-safe
    const bytes = Buffer.from([0xff, 0xef, 0xff, 0xff]);
    const std = Base64.encode(bytes);
    const url = Base64.encodeUrlSafe(bytes);

    expect(std.includes('=') || std.includes('+') || std.includes('/')).toBe(true);
    expect(url.includes('+')).toBe(false);
    expect(url.includes('/')).toBe(false);
    expect(url.includes('=')).toBe(false);
  });

  it('round-trips', () => {
    const inputs = [
      Buffer.from('hello'),
      Buffer.from([0xff, 0xfe, 0xfd, 0xfc]),
      Buffer.from([]),
    ];
    for (const input of inputs) {
      const enc = Base64.encodeUrlSafe(input);
      const dec = Base64.decodeUrlSafe(enc);
      expect(dec.equals(input)).toBe(true);
    }
  });

  it('rejects standard Base64 characters (+, /)', () => {
    expect(() => Base64.decodeUrlSafe('a+bc')).toThrow();
    expect(() => Base64.decodeUrlSafe('a/bc')).toThrow();
  });

  it('rejects non-string input to decodeUrlSafe', () => {
    expect(() => Base64.decodeUrlSafe(42 as never)).toThrow(TypeError);
  });

  it('rejects non-Buffer input to encodeUrlSafe', () => {
    expect(() => Base64.encodeUrlSafe('x' as never)).toThrow(TypeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Hex
// ═══════════════════════════════════════════════════════════════════════════

describe('Hex.encode / decode', () => {
  it('encodes to lowercase', () => {
    expect(Hex.encode(Buffer.from([0xde, 0xad]))).toBe('dead');
    expect(Hex.encode(Buffer.from([0xff, 0x00]))).toBe('ff00');
  });

  it('encodeUpper produces uppercase', () => {
    expect(Hex.encodeUpper(Buffer.from([0xde, 0xad]))).toBe('DEAD');
  });

  it('decode is case-insensitive', () => {
    const expected = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    expect(Hex.decode('deadbeef').equals(expected)).toBe(true);
    expect(Hex.decode('DEADBEEF').equals(expected)).toBe(true);
    expect(Hex.decode('DeAdBeEf').equals(expected)).toBe(true);
  });

  it('round-trips arbitrary bytes', () => {
    const inputs = [
      Buffer.from([]),
      Buffer.from([0]),
      Buffer.from([255]),
      Buffer.from([0, 1, 2, 3, 4, 5]),
    ];
    for (const input of inputs) {
      expect(Hex.decode(Hex.encode(input)).equals(input)).toBe(true);
    }
  });

  it('all 256 byte values round-trip', () => {
    const bytes = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) bytes[i] = i;
    const encoded = Hex.encode(bytes);
    expect(encoded.length).toBe(512);
    expect(Hex.decode(encoded).equals(bytes)).toBe(true);
  });

  it('rejects odd-length input', () => {
    expect(() => Hex.decode('abc')).toThrow();
    expect(() => Hex.decode('f')).toThrow();
  });

  it('rejects non-hex characters', () => {
    expect(() => Hex.decode('gg')).toThrow();
    expect(() => Hex.decode('de ad')).toThrow(); // space not allowed
    expect(() => Hex.decode('0x00')).toThrow(); // prefix not stripped
  });

  it('rejects non-string input to decode', () => {
    expect(() => Hex.decode(Buffer.from('deadbeef') as never)).toThrow(TypeError);
    expect(() => Hex.decode(42 as never)).toThrow(TypeError);
  });

  it('rejects non-Buffer input to encode', () => {
    expect(() => Hex.encode('not a buffer' as never)).toThrow(TypeError);
    expect(() => Hex.encodeUpper(42 as never)).toThrow(TypeError);
  });
});

describe('Hex.isValid', () => {
  it('returns true for valid hex', () => {
    expect(Hex.isValid('')).toBe(true);
    expect(Hex.isValid('00')).toBe(true);
    expect(Hex.isValid('deadbeef')).toBe(true);
    expect(Hex.isValid('DEADBEEF')).toBe(true);
    expect(Hex.isValid('DeAdBeEf')).toBe(true);
  });

  it('returns false for invalid hex', () => {
    expect(Hex.isValid('a')).toBe(false); // odd
    expect(Hex.isValid('gg')).toBe(false); // non-hex char
    expect(Hex.isValid('de ad')).toBe(false); // space
    expect(Hex.isValid('0x00')).toBe(false); // 0x prefix
  });

  it('rejects non-string input', () => {
    expect(() => Hex.isValid(42 as never)).toThrow(TypeError);
    expect(() => Hex.isValid(Buffer.from('deadbeef') as never)).toThrow(TypeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Utf8
// ═══════════════════════════════════════════════════════════════════════════

describe('Utf8.encode / decode', () => {
  it('handles ASCII', () => {
    expect(Utf8.encode('hello').equals(Buffer.from('hello'))).toBe(true);
    expect(Utf8.decode(Buffer.from('hello'))).toBe('hello');
  });

  it('handles multi-byte characters', () => {
    // ñ = 2 bytes
    expect(Utf8.encode('ñ').equals(Buffer.from([0xc3, 0xb1]))).toBe(true);
    expect(Utf8.decode(Buffer.from([0xc3, 0xb1]))).toBe('ñ');

    // 🦀 = 4 bytes
    expect(Utf8.encode('🦀').equals(Buffer.from([0xf0, 0x9f, 0xa6, 0x80]))).toBe(true);
    expect(Utf8.decode(Buffer.from([0xf0, 0x9f, 0xa6, 0x80]))).toBe('🦀');
  });

  it('round-trips diverse strings', () => {
    const cases = ['', 'hello', 'Hola, mundo!', '日本語', '🦀 crab', '¡buen día!'];
    for (const s of cases) {
      expect(Utf8.decode(Utf8.encode(s))).toBe(s);
    }
  });

  it('rejects invalid UTF-8 in decode (unlike Buffer.toString)', () => {
    expect(() => Utf8.decode(Buffer.from([0xff]))).toThrow();
    expect(() => Utf8.decode(Buffer.from([0x80]))).toThrow(); // lone continuation
    expect(() => Utf8.decode(Buffer.from([0xe2]))).toThrow(); // truncated 3-byte

    // Sanity: Buffer.toString('utf-8') silently substitutes U+FFFD for these
    // — that's exactly what we're avoiding.
    expect(Buffer.from([0xff]).toString('utf-8')).not.toBe(''); // has replacement
  });

  it('rejects non-string input to encode', () => {
    expect(() => Utf8.encode(Buffer.from('hi') as never)).toThrow(TypeError);
    expect(() => Utf8.encode(42 as never)).toThrow(TypeError);
  });

  it('rejects non-Buffer input to decode', () => {
    expect(() => Utf8.decode('hi' as never)).toThrow(TypeError);
    expect(() => Utf8.decode(42 as never)).toThrow(TypeError);
  });
});

describe('Utf8.isValid', () => {
  it('returns true for valid UTF-8', () => {
    expect(Utf8.isValid(Buffer.from(''))).toBe(true);
    expect(Utf8.isValid(Buffer.from('hello'))).toBe(true);
    expect(Utf8.isValid(Buffer.from([0xc3, 0xb1]))).toBe(true); // ñ
    expect(Utf8.isValid(Buffer.from([0xf0, 0x9f, 0xa6, 0x80]))).toBe(true); // 🦀
  });

  it('returns false for invalid UTF-8', () => {
    expect(Utf8.isValid(Buffer.from([0xff]))).toBe(false);
    expect(Utf8.isValid(Buffer.from([0x80]))).toBe(false); // lone continuation
    expect(Utf8.isValid(Buffer.from([0xe2]))).toBe(false); // truncated
  });

  it('rejects non-Buffer input', () => {
    expect(() => Utf8.isValid('hi' as never)).toThrow(TypeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Cross-module interop
// ═══════════════════════════════════════════════════════════════════════════

describe('Encoding namespaces cross-round-trip', () => {
  it('Utf8 → Base64 → Utf8', () => {
    const original = 'Hola 🦀';
    const bytes = Utf8.encode(original);
    const b64 = Base64.encode(bytes);
    const decoded = Base64.decode(b64);
    const roundTripped = Utf8.decode(decoded);
    expect(roundTripped).toBe(original);
  });

  it('Utf8 → Hex → Utf8', () => {
    const original = 'Hola 🦀';
    const bytes = Utf8.encode(original);
    const hex = Hex.encode(bytes);
    const decoded = Hex.decode(hex);
    const roundTripped = Utf8.decode(decoded);
    expect(roundTripped).toBe(original);
  });

  it('all three encodings agree on identity for pure ASCII', () => {
    const ascii = 'hello world';
    const bytes = Utf8.encode(ascii);
    expect(bytes.toString('ascii')).toBe(ascii);
    expect(Hex.encode(bytes)).toBe('68656c6c6f20776f726c64');
    expect(Base64.encode(bytes)).toBe('aGVsbG8gd29ybGQ=');
  });
});
