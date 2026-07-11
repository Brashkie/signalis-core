import { describe, it, expect } from 'vitest';
import {
  // Crypto
  Curve25519,
  HKDF,
  AES_GCM,
  AES_CBC,
  HMAC,
  SHA256,
  // Random
  secureRandom,
  randomNonce,
  randomIv,
  randomKey,
  // Encoding
  toHex,
  fromHex,
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
  bufferToString,
  stringToBuffer,
  // Security utils
  constantTimeEqual,
  concat,
  zeroize,
  xor,
  // Validators
  assertBuffer,
  assertBufferLength,
  assertBufferOfSize,
  assertPositiveInteger,
  assertHkdfLength,
  buffersSameLength,
  // Errors
  SignalisError,
  ValidationError,
  CryptoError,
  AuthenticationError,
  KeyDerivationError,
  LengthError,
  // Type helpers
  asPublicKey,
  asPrivateKey,
  asSharedSecret,
  // Constants
  CURVE25519_PRIVATE_KEY_SIZE,
  CURVE25519_PUBLIC_KEY_SIZE,
  CURVE25519_SHARED_SECRET_SIZE,
  HKDF_PRK_SIZE,
  HKDF_MAX_OUTPUT_SIZE,
  AES_256_KEY_SIZE,
  AES_256_GCM_NONCE_SIZE,
  AES_256_GCM_TAG_SIZE,
  AES_256_CBC_IV_SIZE,
  AES_BLOCK_SIZE,
  SHA256_OUTPUT_SIZE,
  HMAC_SHA256_TAG_SIZE,
  SHA256_BLOCK_SIZE,
  // Version
  VERSION,
  nativeVersion,
} from '../src';
import SignalisCoreDefault from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// Module Exports
// ═══════════════════════════════════════════════════════════════════════════

describe('Module exports', () => {
  it('exports VERSION as 0.4.0', () => {
    expect(VERSION).toBe('0.4.0');
  });

  it('exports nativeVersion as string', () => {
    expect(typeof nativeVersion).toBe('string');
    expect(nativeVersion.length).toBeGreaterThan(0);
  });

  it('exports all crypto namespaces', () => {
    expect(Curve25519).toBeDefined();
    expect(HKDF).toBeDefined();
    expect(AES_GCM).toBeDefined();
    expect(AES_CBC).toBeDefined();
    expect(HMAC).toBeDefined();
    expect(SHA256).toBeDefined();
  });

  it('exposes size constants on crypto namespaces', () => {
    expect(Curve25519.PRIVATE_KEY_SIZE).toBe(32);
    expect(Curve25519.PUBLIC_KEY_SIZE).toBe(32);
    expect(Curve25519.SHARED_SECRET_SIZE).toBe(32);
    expect(HKDF.PRK_SIZE).toBe(32);
    expect(AES_GCM.KEY_SIZE).toBe(32);
    expect(AES_GCM.NONCE_SIZE).toBe(12);
    expect(AES_GCM.TAG_SIZE).toBe(16);
    expect(AES_CBC.KEY_SIZE).toBe(32);
    expect(AES_CBC.IV_SIZE).toBe(16);
    expect(HMAC.TAG_SIZE).toBe(32);
    expect(SHA256.OUTPUT_SIZE).toBe(32);
  });

  it('exports all top-level constants', () => {
    expect(CURVE25519_PRIVATE_KEY_SIZE).toBe(32);
    expect(CURVE25519_PUBLIC_KEY_SIZE).toBe(32);
    expect(CURVE25519_SHARED_SECRET_SIZE).toBe(32);
    expect(HKDF_PRK_SIZE).toBe(32);
    expect(HKDF_MAX_OUTPUT_SIZE).toBe(8160);
    expect(AES_256_KEY_SIZE).toBe(32);
    expect(AES_256_GCM_NONCE_SIZE).toBe(12);
    expect(AES_256_GCM_TAG_SIZE).toBe(16);
    expect(AES_256_CBC_IV_SIZE).toBe(16);
    expect(AES_BLOCK_SIZE).toBe(16);
    expect(SHA256_OUTPUT_SIZE).toBe(32);
    expect(HMAC_SHA256_TAG_SIZE).toBe(32);
    expect(SHA256_BLOCK_SIZE).toBe(64);
  });

  it('exports default namespace with everything', () => {
    expect(SignalisCoreDefault.Curve25519).toBeDefined();
    expect(SignalisCoreDefault.HKDF).toBeDefined();
    expect(SignalisCoreDefault.AES_GCM).toBeDefined();
    expect(SignalisCoreDefault.AES_CBC).toBeDefined();
    expect(SignalisCoreDefault.HMAC).toBeDefined();
    expect(SignalisCoreDefault.SHA256).toBeDefined();
    expect(SignalisCoreDefault.VERSION).toBe('0.4.0');
    expect(typeof SignalisCoreDefault.secureRandom).toBe('function');
    expect(Object.isFrozen(SignalisCoreDefault)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Curve25519
// ═══════════════════════════════════════════════════════════════════════════

describe('Curve25519', () => {
  it('generates 32-byte keypair', () => {
    const kp = Curve25519.generateKeyPair();
    expect(kp.privateKey.length).toBe(CURVE25519_PRIVATE_KEY_SIZE);
    expect(kp.publicKey.length).toBe(32);
  });

  it('keypair is frozen (immutable)', () => {
    const kp = Curve25519.generateKeyPair();
    expect(Object.isFrozen(kp)).toBe(true);
  });

  it('different generations produce different keys', () => {
    const kp1 = Curve25519.generateKeyPair();
    const kp2 = Curve25519.generateKeyPair();
    expect(kp1.privateKey.equals(kp2.privateKey)).toBe(false);
  });

  it('alice and bob agree on shared secret', () => {
    const alice = Curve25519.generateKeyPair();
    const bob = Curve25519.generateKeyPair();

    const aliceShared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
    const bobShared = Curve25519.diffieHellman(bob.privateKey, alice.publicKey);

    expect(aliceShared.equals(bobShared)).toBe(true);
  });

  it('throws ValidationError on invalid private key size', () => {
    expect(() => Curve25519.diffieHellman(Buffer.alloc(31), Buffer.alloc(32)))
      .toThrow(ValidationError);
  });

  it('throws ValidationError on invalid public key size', () => {
    expect(() => Curve25519.diffieHellman(Buffer.alloc(32), Buffer.alloc(33)))
      .toThrow(ValidationError);
  });

  it('throws ValidationError if private key is not a Buffer', () => {
    expect(() => Curve25519.diffieHellman('not-a-buffer' as any, Buffer.alloc(32)))
      .toThrow(ValidationError);
  });

  it('throws ValidationError if public key is not a Buffer', () => {
    expect(() => Curve25519.diffieHellman(Buffer.alloc(32), 'not-buffer' as any))
      .toThrow(ValidationError);
  });

  it('throws ValidationError if private key is null', () => {
    expect(() => Curve25519.diffieHellman(null as any, Buffer.alloc(32)))
      .toThrow(ValidationError);
  });

  it('publicFromPrivate is deterministic', () => {
    const kp = Curve25519.generateKeyPair();
    const derived = Curve25519.publicFromPrivate(kp.privateKey);
    expect(derived.equals(kp.publicKey)).toBe(true);
  });

  it('publicFromPrivate rejects invalid size', () => {
    expect(() => Curve25519.publicFromPrivate(Buffer.alloc(31)))
      .toThrow(ValidationError);
  });

  it('publicFromPrivate rejects non-Buffer', () => {
    expect(() => Curve25519.publicFromPrivate({} as any))
      .toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// HKDF
// ═══════════════════════════════════════════════════════════════════════════

describe('HKDF', () => {
  it('extract produces 32 bytes', () => {
    const prk = HKDF.extract(Buffer.from('salt'), Buffer.from('ikm'));
    expect(prk.length).toBe(32);
  });

  it('extract throws on non-Buffer salt', () => {
    expect(() => HKDF.extract('salt' as any, Buffer.from('ikm')))
      .toThrow(ValidationError);
  });

  it('extract throws on non-Buffer ikm', () => {
    expect(() => HKDF.extract(Buffer.from('salt'), 'ikm' as any))
      .toThrow(ValidationError);
  });

  it('expand produces requested length', () => {
    const prk = HKDF.extract(Buffer.from('salt'), Buffer.from('ikm'));
    const okm = HKDF.expand(prk, Buffer.from('info'), 64);
    expect(okm.length).toBe(64);
  });

  it('expand throws on PRK with wrong size', () => {
    expect(() => HKDF.expand(Buffer.alloc(31), Buffer.alloc(0), 32))
      .toThrow(ValidationError);
  });

  it('expand throws on non-Buffer info', () => {
    expect(() => HKDF.expand(Buffer.alloc(32), 'info' as any, 32))
      .toThrow(ValidationError);
  });

  it('derive is deterministic', () => {
    const okm1 = HKDF.derive(Buffer.from('salt'), Buffer.from('ikm'), Buffer.from('info'), 32);
    const okm2 = HKDF.derive(Buffer.from('salt'), Buffer.from('ikm'), Buffer.from('info'), 32);
    expect(okm1.equals(okm2)).toBe(true);
  });

  it('different salt gives different output', () => {
    const okm1 = HKDF.derive(Buffer.from('salt1'), Buffer.from('ikm'), Buffer.from('info'), 32);
    const okm2 = HKDF.derive(Buffer.from('salt2'), Buffer.from('ikm'), Buffer.from('info'), 32);
    expect(okm1.equals(okm2)).toBe(false);
  });

  it('derive throws on non-Buffer arguments', () => {
    expect(() => HKDF.derive('salt' as any, Buffer.alloc(0), Buffer.alloc(0), 32))
      .toThrow(ValidationError);
    expect(() => HKDF.derive(Buffer.alloc(0), 'ikm' as any, Buffer.alloc(0), 32))
      .toThrow(ValidationError);
    expect(() => HKDF.derive(Buffer.alloc(0), Buffer.alloc(0), 'info' as any, 32))
      .toThrow(ValidationError);
  });

  it('throws LengthError when length > HKDF_MAX_OUTPUT_SIZE', () => {
    expect(() => HKDF.expand(Buffer.alloc(32), Buffer.alloc(0), HKDF_MAX_OUTPUT_SIZE + 1))
      .toThrow(LengthError);
  });

  it('throws LengthError when length is 0', () => {
    expect(() => HKDF.expand(Buffer.alloc(32), Buffer.alloc(0), 0))
      .toThrow(LengthError);
  });

  it('throws ValidationError when length is negative', () => {
    expect(() => HKDF.expand(Buffer.alloc(32), Buffer.alloc(0), -1))
      .toThrow(ValidationError);
  });

  it('throws ValidationError when length is not an integer', () => {
    expect(() => HKDF.expand(Buffer.alloc(32), Buffer.alloc(0), 3.14))
      .toThrow(ValidationError);
  });

  it('deriveMultiple splits output into requested chunks', () => {
    const [a, b, c] = HKDF.deriveMultiple(
      Buffer.from('salt'),
      Buffer.from('ikm'),
      Buffer.from('info'),
      [16, 32, 16],
    );
    expect(a!.length).toBe(16);
    expect(b!.length).toBe(32);
    expect(c!.length).toBe(16);
  });

  it('deriveMultiple throws on empty array', () => {
    expect(() => HKDF.deriveMultiple(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0), []))
      .toThrow(TypeError);
  });

  it('deriveMultiple throws on non-array', () => {
    expect(() => HKDF.deriveMultiple(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0), 32 as any))
      .toThrow(TypeError);
  });

  it('deriveFromParams works', () => {
    const okm = HKDF.deriveFromParams({
      salt: Buffer.from('salt'),
      ikm: Buffer.from('ikm'),
      info: Buffer.from('info'),
      length: 32,
    });
    expect(okm.length).toBe(32);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// AES-256-GCM
// ═══════════════════════════════════════════════════════════════════════════

describe('AES-256-GCM', () => {
  it('encrypts and decrypts correctly', () => {
    const key = randomKey();
    const nonce = randomNonce();
    const plaintext = Buffer.from('Hello Signalis');
    const ct = AES_GCM.encrypt(key, nonce, plaintext);
    const pt = AES_GCM.decrypt(key, nonce, ct);
    expect(pt.equals(plaintext)).toBe(true);
  });

  it('ciphertext is plaintext.length + 16', () => {
    const ct = AES_GCM.encrypt(randomKey(), randomNonce(), Buffer.from('test'));
    expect(ct.length).toBe(4 + AES_GCM.TAG_SIZE);
  });

  it('throws AuthenticationError on tampered ciphertext', () => {
    const key = randomKey();
    const nonce = randomNonce();
    const ct = AES_GCM.encrypt(key, nonce, Buffer.from('important'));
    ct[0] ^= 0xff;
    expect(() => AES_GCM.decrypt(key, nonce, ct)).toThrow(AuthenticationError);
  });

  it('throws AuthenticationError with wrong key', () => {
    const key = randomKey();
    const wrongKey = randomKey();
    const nonce = randomNonce();
    const ct = AES_GCM.encrypt(key, nonce, Buffer.from('msg'));
    expect(() => AES_GCM.decrypt(wrongKey, nonce, ct)).toThrow(AuthenticationError);
  });

  it('throws CryptoError when ciphertext is shorter than tag size', () => {
    expect(() => AES_GCM.decrypt(randomKey(), randomNonce(), Buffer.alloc(15)))
      .toThrow(CryptoError);
  });

  it('throws ValidationError on wrong key size', () => {
    expect(() => AES_GCM.encrypt(Buffer.alloc(31), randomNonce(), Buffer.from('x')))
      .toThrow(ValidationError);
  });

  it('throws ValidationError on wrong nonce size', () => {
    expect(() => AES_GCM.encrypt(randomKey(), Buffer.alloc(11), Buffer.from('x')))
      .toThrow(ValidationError);
  });

  it('decrypt throws ValidationError on wrong key size', () => {
    const key = randomKey();
    const nonce = randomNonce();
    const ct = AES_GCM.encrypt(key, nonce, Buffer.from('msg'));
    expect(() => AES_GCM.decrypt(Buffer.alloc(31), nonce, ct))
      .toThrow(ValidationError);
  });

  it('decrypt throws ValidationError on wrong nonce size', () => {
    const key = randomKey();
    const nonce = randomNonce();
    const ct = AES_GCM.encrypt(key, nonce, Buffer.from('msg'));
    expect(() => AES_GCM.decrypt(key, Buffer.alloc(13), ct))
      .toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// AES-256-CBC
// ═══════════════════════════════════════════════════════════════════════════

describe('AES-256-CBC', () => {
  it('encrypts and decrypts with PKCS#7 padding', () => {
    const key = randomKey();
    const iv = randomIv();
    const plaintext = Buffer.from('Variable length message');
    const ct = AES_CBC.encrypt(key, iv, plaintext);
    const pt = AES_CBC.decrypt(key, iv, ct);
    expect(pt.equals(plaintext)).toBe(true);
  });

  it('ciphertext is padded to 16-byte block', () => {
    const ct = AES_CBC.encrypt(randomKey(), randomIv(), Buffer.from('x'));
    expect(ct.length).toBe(16);
  });

  it('encrypt throws ValidationError on wrong key size', () => {
    expect(() => AES_CBC.encrypt(Buffer.alloc(31), randomIv(), Buffer.from('x')))
      .toThrow(ValidationError);
  });

  it('encrypt throws ValidationError on wrong IV size', () => {
    expect(() => AES_CBC.encrypt(randomKey(), Buffer.alloc(15), Buffer.from('x')))
      .toThrow(ValidationError);
  });

  it('decrypt throws on tampered/invalid padding', () => {
    expect(() => AES_CBC.decrypt(randomKey(), randomIv(), Buffer.alloc(16)))
      .toThrow(CryptoError);
  });

  it('decrypt throws ValidationError on wrong key size', () => {
    expect(() => AES_CBC.decrypt(Buffer.alloc(31), randomIv(), Buffer.alloc(16)))
      .toThrow(ValidationError);
  });

  it('decrypt throws ValidationError on wrong IV size', () => {
    expect(() => AES_CBC.decrypt(randomKey(), Buffer.alloc(15), Buffer.alloc(16)))
      .toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// HMAC
// ═══════════════════════════════════════════════════════════════════════════

describe('HMAC-SHA256', () => {
  it('produces 32-byte tag', () => {
    expect(HMAC.sha256(Buffer.from('key'), Buffer.from('data')).length).toBe(32);
  });

  it('verifies correct tag', () => {
    const key = Buffer.from('secret');
    const data = Buffer.from('message');
    const tag = HMAC.sha256(key, data);
    expect(HMAC.verifySha256(key, data, tag)).toBe(true);
  });

  it('rejects wrong tag', () => {
    expect(HMAC.verifySha256(Buffer.from('secret'), Buffer.from('msg'), Buffer.alloc(32)))
      .toBe(false);
  });

  it('sha256 throws on non-Buffer key', () => {
    expect(() => HMAC.sha256('key' as any, Buffer.from('data')))
      .toThrow(ValidationError);
  });

  it('sha256 throws on non-Buffer data', () => {
    expect(() => HMAC.sha256(Buffer.from('key'), 'data' as any))
      .toThrow(ValidationError);
  });

  it('verifySha256 throws on non-Buffer arguments', () => {
    expect(() => HMAC.verifySha256('k' as any, Buffer.alloc(0), Buffer.alloc(32)))
      .toThrow(ValidationError);
    expect(() => HMAC.verifySha256(Buffer.alloc(0), 'd' as any, Buffer.alloc(32)))
      .toThrow(ValidationError);
    expect(() => HMAC.verifySha256(Buffer.alloc(0), Buffer.alloc(0), 't' as any))
      .toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SHA-256
// ═══════════════════════════════════════════════════════════════════════════

describe('SHA-256', () => {
  it('produces 32-byte hash', () => {
    expect(SHA256.hash(Buffer.from('hello')).length).toBe(32);
  });

  it('empty input matches NIST vector', () => {
    expect(SHA256.hash(Buffer.alloc(0)).toString('hex'))
      .toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('"abc" matches NIST vector', () => {
    expect(SHA256.hash(Buffer.from('abc')).toString('hex'))
      .toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('throws on non-Buffer input', () => {
    expect(() => SHA256.hash('hello' as any)).toThrow(ValidationError);
  });

  it('hashAll matches concatenated hash', () => {
    const result1 = SHA256.hashAll([Buffer.from('hello'), Buffer.from(' world')]);
    const result2 = SHA256.hash(Buffer.from('hello world'));
    expect(result1.equals(result2)).toBe(true);
  });

  it('hashAll throws on non-array', () => {
    expect(() => SHA256.hashAll('not array' as any)).toThrow(TypeError);
  });

  it('hashAll throws if array item is not a Buffer', () => {
    expect(() => SHA256.hashAll(['string' as any]))
      .toThrow(ValidationError);
  });

  it('hashAll works with empty array', () => {
    // Empty array → SHA-256 of empty buffer
    const hash = SHA256.hashAll([]);
    expect(hash.toString('hex'))
      .toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// secureRandom + helpers
// ═══════════════════════════════════════════════════════════════════════════

describe('secureRandom', () => {
  it('generates requested number of bytes', () => {
    expect(secureRandom(32).length).toBe(32);
    expect(secureRandom(16).length).toBe(16);
    expect(secureRandom(0).length).toBe(0);
  });

  it('throws on negative length', () => {
    expect(() => secureRandom(-1)).toThrow(RangeError);
  });

  it('throws on non-integer length', () => {
    expect(() => secureRandom(3.14)).toThrow(RangeError);
  });

  it('produces different values each call', () => {
    expect(secureRandom(32).equals(secureRandom(32))).toBe(false);
  });

  it('helper randomNonce returns 12 bytes', () => {
    expect(randomNonce().length).toBe(AES_256_GCM_NONCE_SIZE);
  });

  it('helper randomIv returns 16 bytes', () => {
    expect(randomIv().length).toBe(16);
  });

  it('helper randomKey returns 32 bytes', () => {
    expect(randomKey().length).toBe(32);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Encoding helpers
// ═══════════════════════════════════════════════════════════════════════════

describe('Encoding helpers', () => {
  it('toHex / fromHex round-trip', () => {
    const original = Buffer.from([0x01, 0x02, 0xff, 0xab]);
    const hex = toHex(original);
    expect(hex).toBe('0102ffab');
    expect(fromHex(hex).equals(original)).toBe(true);
  });

  it('fromHex throws on non-hex characters', () => {
    expect(() => fromHex('not-hex-XX')).toThrow();
  });

  it('fromHex throws on odd-length string', () => {
    expect(() => fromHex('abc')).toThrow();
  });

  it('fromHex accepts empty string', () => {
    expect(fromHex('').length).toBe(0);
  });

  it('fromHex accepts uppercase hex', () => {
    expect(fromHex('FF00').toString('hex')).toBe('ff00');
  });

  it('toBase64 / fromBase64 round-trip', () => {
    const original = Buffer.from('Hello, World!');
    expect(fromBase64(toBase64(original)).equals(original)).toBe(true);
  });

  it('toBase64Url / fromBase64Url round-trip', () => {
    const original = Buffer.from([0xff, 0xfe, 0xfd]);
    expect(fromBase64Url(toBase64Url(original)).equals(original)).toBe(true);
  });

  it('bufferToString default encoding is hex', () => {
    expect(bufferToString(Buffer.from([0xff]))).toBe('ff');
  });

  it('bufferToString with base64', () => {
    expect(bufferToString(Buffer.from('hi'), 'base64')).toBe('aGk=');
  });

  it('bufferToString with utf8', () => {
    expect(bufferToString(Buffer.from('hello'), 'utf8')).toBe('hello');
  });

  it('stringToBuffer default encoding is hex', () => {
    expect(stringToBuffer('ff').toString('hex')).toBe('ff');
  });

  it('stringToBuffer with utf8', () => {
    expect(stringToBuffer('hello', 'utf8').toString('utf8')).toBe('hello');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// constantTimeEqual
// ═══════════════════════════════════════════════════════════════════════════

describe('constantTimeEqual', () => {
  it('returns true for equal buffers', () => {
    expect(constantTimeEqual(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
  });

  it('returns false for different content (same length)', () => {
    expect(constantTimeEqual(Buffer.from('abc'), Buffer.from('abd'))).toBe(false);
  });

  it('returns false for different lengths', () => {
    expect(constantTimeEqual(Buffer.from('abc'), Buffer.from('abcd'))).toBe(false);
  });

  it('returns true for empty buffers', () => {
    expect(constantTimeEqual(Buffer.alloc(0), Buffer.alloc(0))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Buffer manipulation
// ═══════════════════════════════════════════════════════════════════════════

describe('Buffer helpers', () => {
  it('concat concatenates buffers', () => {
    const result = concat([Buffer.from('a'), Buffer.from('b'), Buffer.from('c')]);
    expect(result.toString()).toBe('abc');
  });

  it('concat works with empty array', () => {
    expect(concat([]).length).toBe(0);
  });

  it('zeroize fills buffer with zeros', () => {
    const buf = Buffer.from([1, 2, 3, 4]);
    zeroize(buf);
    expect(buf.every((b) => b === 0)).toBe(true);
  });

  it('zeroize works on empty buffer', () => {
    expect(() => zeroize(Buffer.alloc(0))).not.toThrow();
  });

  it('xor combines buffers', () => {
    const a = Buffer.from([0xff, 0x00, 0xaa]);
    const b = Buffer.from([0x0f, 0xff, 0x55]);
    const result = xor(a, b);
    expect(result[0]).toBe(0xf0);
    expect(result[1]).toBe(0xff);
    expect(result[2]).toBe(0xff);
  });

  it('xor throws on unequal lengths', () => {
    expect(() => xor(Buffer.alloc(3), Buffer.alloc(4))).toThrow();
  });

  it('xor works on empty buffers', () => {
    expect(xor(Buffer.alloc(0), Buffer.alloc(0)).length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Validators
// ═══════════════════════════════════════════════════════════════════════════

describe('Validators', () => {
  it('assertBuffer passes for a Buffer', () => {
    expect(() => assertBuffer(Buffer.alloc(10), 'test')).not.toThrow();
  });

  it('assertBuffer throws for non-Buffer', () => {
    expect(() => assertBuffer('string', 'param')).toThrow(ValidationError);
    expect(() => assertBuffer(123, 'param')).toThrow(ValidationError);
    expect(() => assertBuffer(null, 'param')).toThrow(ValidationError);
    expect(() => assertBuffer(undefined, 'param')).toThrow(ValidationError);
    expect(() => assertBuffer({}, 'param')).toThrow(ValidationError);
  });

  it('assertBufferLength passes for correct length', () => {
    expect(() => assertBufferLength(Buffer.alloc(32), 32, 'key')).not.toThrow();
  });

  it('assertBufferLength throws on wrong length', () => {
    expect(() => assertBufferLength(Buffer.alloc(31), 32, 'key'))
      .toThrow(ValidationError);
  });

  it('assertBufferOfSize combines both checks', () => {
    expect(() => assertBufferOfSize(Buffer.alloc(32), 32, 'key')).not.toThrow();
    expect(() => assertBufferOfSize('string', 32, 'key')).toThrow(ValidationError);
    expect(() => assertBufferOfSize(Buffer.alloc(31), 32, 'key')).toThrow(ValidationError);
  });

  it('assertPositiveInteger passes for valid integers', () => {
    expect(() => assertPositiveInteger(0, 'len')).not.toThrow();
    expect(() => assertPositiveInteger(100, 'len')).not.toThrow();
  });

  it('assertPositiveInteger throws for negative', () => {
    expect(() => assertPositiveInteger(-1, 'len')).toThrow(ValidationError);
  });

  it('assertPositiveInteger throws for floats', () => {
    expect(() => assertPositiveInteger(3.14, 'len')).toThrow(ValidationError);
  });

  it('assertPositiveInteger throws for non-numbers', () => {
    expect(() => assertPositiveInteger('5', 'len')).toThrow(ValidationError);
    expect(() => assertPositiveInteger(null, 'len')).toThrow(ValidationError);
  });

  it('assertHkdfLength validates range', () => {
    expect(() => assertHkdfLength(1)).not.toThrow();
    expect(() => assertHkdfLength(8160)).not.toThrow();
    expect(() => assertHkdfLength(0)).toThrow(LengthError);
    expect(() => assertHkdfLength(8161)).toThrow(LengthError);
    expect(() => assertHkdfLength(-1)).toThrow(ValidationError);
    expect(() => assertHkdfLength('32')).toThrow(ValidationError);
  });

  it('buffersSameLength compares lengths', () => {
    expect(buffersSameLength(Buffer.alloc(10), Buffer.alloc(10))).toBe(true);
    expect(buffersSameLength(Buffer.alloc(10), Buffer.alloc(11))).toBe(false);
    expect(buffersSameLength(Buffer.alloc(0), Buffer.alloc(0))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Error types
// ═══════════════════════════════════════════════════════════════════════════

describe('Error types', () => {
  it('SignalisError has name and code', () => {
    const err = new SignalisError('test', 'TEST_CODE');
    expect(err.name).toBe('SignalisError');
    expect(err.code).toBe('TEST_CODE');
    expect(err.message).toBe('test');
    expect(err instanceof Error).toBe(true);
  });

  it('ValidationError exposes parameter and expected', () => {
    try {
      Curve25519.diffieHellman(Buffer.alloc(31), Buffer.alloc(32));
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
      expect((e as ValidationError).parameter).toBe('privateKey');
      expect((e as ValidationError).code).toBe('VALIDATION_ERROR');
    }
  });

  it('ValidationError with no options object', () => {
    const err = new ValidationError('test');
    expect(err.name).toBe('ValidationError');
    expect(err.parameter).toBeUndefined();
  });

  it('CryptoError has operation', () => {
    const err = new CryptoError('failed', 'encrypt');
    expect(err.name).toBe('CryptoError');
    expect(err.operation).toBe('encrypt');
    expect(err.code).toBe('CRYPTO_ERROR');
  });

  it('AuthenticationError default message', () => {
    const err = new AuthenticationError();
    expect(err.name).toBe('AuthenticationError');
    expect(err.message).toBe('Authentication tag verification failed');
    expect(err.operation).toBe('authenticate');
  });

  it('AuthenticationError custom message', () => {
    const err = new AuthenticationError('custom failure');
    expect(err.message).toBe('custom failure');
  });

  it('AuthenticationError on tampered ciphertext', () => {
    const key = randomKey();
    const nonce = randomNonce();
    const ct = AES_GCM.encrypt(key, nonce, Buffer.from('data'));
    ct[0] ^= 0xff;
    try {
      AES_GCM.decrypt(key, nonce, ct);
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(AuthenticationError);
      expect((e as AuthenticationError).operation).toBe('authenticate');
    }
  });

  it('KeyDerivationError extends CryptoError', () => {
    const err = new KeyDerivationError('derive failed');
    expect(err).toBeInstanceOf(CryptoError);
    expect(err).toBeInstanceOf(SignalisError);
    expect(err.name).toBe('KeyDerivationError');
    expect(err.operation).toBe('derive_key');
  });

  it('LengthError extends ValidationError', () => {
    const err = new LengthError('too long', { expected: '<=100', actual: 200 });
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.name).toBe('LengthError');
    expect(err.expected).toBe('<=100');
    expect(err.actual).toBe(200);
  });

  it('LengthError without options', () => {
    const err = new LengthError('too long');
    expect(err.name).toBe('LengthError');
  });

  it('all errors are instanceof SignalisError', () => {
    expect(new ValidationError('x')).toBeInstanceOf(SignalisError);
    expect(new CryptoError('x', 'op')).toBeInstanceOf(SignalisError);
    expect(new AuthenticationError()).toBeInstanceOf(SignalisError);
    expect(new KeyDerivationError('x')).toBeInstanceOf(SignalisError);
    expect(new LengthError('x')).toBeInstanceOf(SignalisError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Type helpers (branding)
// ═══════════════════════════════════════════════════════════════════════════

describe('Type helpers', () => {
  it('asPublicKey returns the buffer unchanged', () => {
    const buf = Buffer.alloc(32);
    expect(asPublicKey(buf)).toBe(buf);
  });

  it('asPrivateKey returns the buffer unchanged', () => {
    const buf = Buffer.alloc(32);
    expect(asPrivateKey(buf)).toBe(buf);
  });

  it('asSharedSecret returns the buffer unchanged', () => {
    const buf = Buffer.alloc(32);
    expect(asSharedSecret(buf)).toBe(buf);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Integration: E2E Secure Channel
// ═══════════════════════════════════════════════════════════════════════════

describe('Integration: E2E Secure Channel', () => {
  it('establishes E2E encryption between Alice and Bob', () => {
    const alice = Curve25519.generateKeyPair();
    const bob = Curve25519.generateKeyPair();

    const aliceShared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
    const bobShared = Curve25519.diffieHellman(bob.privateKey, alice.publicKey);
    expect(aliceShared.equals(bobShared)).toBe(true);

    const salt = Buffer.from('signalis-channel-v1');
    const info = Buffer.from('aes-256-gcm-key');
    const aliceKey = HKDF.derive(salt, aliceShared, info, 32);
    const bobKey = HKDF.derive(salt, bobShared, info, 32);
    expect(aliceKey.equals(bobKey)).toBe(true);

    const nonce = randomNonce();
    const message = Buffer.from('Top secret message');
    const ciphertext = AES_GCM.encrypt(aliceKey, nonce, message);
    const decrypted = AES_GCM.decrypt(bobKey, nonce, ciphertext);

    expect(decrypted.equals(message)).toBe(true);
  });

  it('demonstrates encrypt-then-MAC with CBC', () => {
    const alice = Curve25519.generateKeyPair();
    const bob = Curve25519.generateKeyPair();
    const shared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);

    const [encKey, macKey] = HKDF.deriveMultiple(
      Buffer.from('salt'),
      shared,
      Buffer.from('cbc+hmac'),
      [32, 32],
    );

    const iv = randomIv();
    const message = Buffer.from('legacy message');

    const ct = AES_CBC.encrypt(encKey!, iv, message);
    const macInput = concat([iv, ct]);
    const tag = HMAC.sha256(macKey!, macInput);

    expect(HMAC.verifySha256(macKey!, macInput, tag)).toBe(true);
    const pt = AES_CBC.decrypt(encKey!, iv, ct);

    expect(pt.equals(message)).toBe(true);
  });

  it('multiple messages with different nonces', () => {
    const key = randomKey();
    const messages = ['msg1', 'msg2', 'msg3'].map((m) => Buffer.from(m));

    const cts = messages.map((m) => {
      const nonce = randomNonce();
      const ct = AES_GCM.encrypt(key, nonce, m);
      return { nonce, ct };
    });

    cts.forEach(({ nonce, ct }, i) => {
      expect(AES_GCM.decrypt(key, nonce, ct).equals(messages[i]!)).toBe(true);
    });
  });
});
