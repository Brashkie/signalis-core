/**
 * Test in pure ESM — verifies the ESM export of dist/index.mjs.
 *
 * Run with: node __tests__/esm.test.mjs
 */

import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

// ESM imports
import {
  // Crypto
  Curve25519,
  HKDF,
  AES_GCM,
  AES_CBC,
  HMAC,
  SHA256,
  // Utilities
  secureRandom,
  randomNonce,
  randomIv,
  randomKey,
  toHex,
  fromHex,
  toBase64,
  fromBase64,
  constantTimeEqual,
  concat,
  xor,
  // Errors
  SignalisError,
  ValidationError,
  AuthenticationError,
  CryptoError,
  LengthError,
  // Constants
  CURVE25519_PRIVATE_KEY_SIZE,
  AES_256_GCM_NONCE_SIZE,
  AES_256_GCM_TAG_SIZE,
  SHA256_OUTPUT_SIZE,
  // Version
  VERSION,
  nativeVersion,
} from '../dist/index.mjs';

// Default import
import sc from '../dist/index.mjs';

console.log('🧪 Testing ESM export...\n');

// ─── Test 1: All named imports work ──────────────────────────────────────
assert.ok(Curve25519, 'Curve25519 should be importable');
assert.ok(HKDF, 'HKDF should be importable');
assert.ok(AES_GCM, 'AES_GCM should be importable');
assert.ok(AES_CBC, 'AES_CBC should be importable');
assert.ok(HMAC, 'HMAC should be importable');
assert.ok(SHA256, 'SHA256 should be importable');
assert.equal(VERSION, '0.1.0', 'VERSION should be 0.1.0');
assert.ok(typeof nativeVersion === 'string', 'nativeVersion should be string');
console.log('✅ All named imports work');

// ─── Test 2: Error classes importable ────────────────────────────────────
assert.ok(typeof SignalisError === 'function');
assert.ok(typeof ValidationError === 'function');
assert.ok(typeof AuthenticationError === 'function');
assert.ok(typeof CryptoError === 'function');
assert.ok(typeof LengthError === 'function');
console.log('✅ Error classes importable');

// ─── Test 3: Constants importable ────────────────────────────────────────
assert.equal(CURVE25519_PRIVATE_KEY_SIZE, 32);
assert.equal(AES_256_GCM_NONCE_SIZE, 12);
assert.equal(AES_256_GCM_TAG_SIZE, 16);
assert.equal(SHA256_OUTPUT_SIZE, 32);
console.log('✅ Constants importable');

// ─── Test 4: Default import works ────────────────────────────────────────
assert.ok(sc.Curve25519, 'Default import should have Curve25519');
assert.equal(sc.VERSION, '0.1.0');
console.log('✅ Default import works');

// ─── Test 5: Curve25519 ECDH ─────────────────────────────────────────────
const alice = Curve25519.generateKeyPair();
const bob = Curve25519.generateKeyPair();
const aliceShared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
const bobShared = Curve25519.diffieHellman(bob.privateKey, alice.publicKey);
assert.ok(aliceShared.equals(bobShared), 'ECDH should match');
console.log('✅ Curve25519 ECDH works');

// ─── Test 6: HKDF ────────────────────────────────────────────────────────
const key = HKDF.derive(
  Buffer.from('salt'),
  aliceShared,
  Buffer.from('esm-test'),
  32,
);
assert.equal(key.length, 32);
console.log('✅ HKDF works');

// ─── Test 7: HKDF.deriveMultiple ─────────────────────────────────────────
const [k1, k2] = HKDF.deriveMultiple(
  Buffer.from('salt'),
  aliceShared,
  Buffer.from('split'),
  [16, 32],
);
assert.equal(k1.length, 16);
assert.equal(k2.length, 32);
console.log('✅ HKDF.deriveMultiple works');

// ─── Test 8: AES-256-GCM round-trip ──────────────────────────────────────
const nonce = randomNonce();
const plaintext = Buffer.from('Hello ESM!');
const ciphertext = AES_GCM.encrypt(key, nonce, plaintext);
const decrypted = AES_GCM.decrypt(key, nonce, ciphertext);
assert.ok(decrypted.equals(plaintext), 'AES-GCM round-trip should match');
console.log('✅ AES-GCM round-trip works');

// ─── Test 9: AuthenticationError thrown on tamper ───────────────────────
const tampered = Buffer.from(ciphertext);
tampered[0] ^= 0xff;
try {
  AES_GCM.decrypt(key, nonce, tampered);
  assert.fail('Should have thrown AuthenticationError');
} catch (e) {
  assert.ok(e instanceof AuthenticationError, 'Should be AuthenticationError');
}
console.log('✅ AuthenticationError works');

// ─── Test 10: ValidationError on wrong size ─────────────────────────────
try {
  Curve25519.diffieHellman(Buffer.alloc(31), Buffer.alloc(32));
  assert.fail('Should have thrown ValidationError');
} catch (e) {
  assert.ok(e instanceof ValidationError, 'Should be ValidationError');
  assert.equal(e.parameter, 'privateKey');
}
console.log('✅ ValidationError exposes parameter');

// ─── Test 11: SHA-256 NIST vector ───────────────────────────────────────
const sha = SHA256.hash(Buffer.alloc(0));
assert.equal(
  sha.toString('hex'),
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
);
console.log('✅ SHA-256 NIST vector matches');

// ─── Test 12: HMAC ──────────────────────────────────────────────────────
const tag = HMAC.sha256(Buffer.from('secret'), Buffer.from('message'));
assert.equal(tag.length, 32);
assert.ok(HMAC.verifySha256(Buffer.from('secret'), Buffer.from('message'), tag));
console.log('✅ HMAC works');

// ─── Test 13: constantTimeEqual ─────────────────────────────────────────
assert.ok(constantTimeEqual(Buffer.from('abc'), Buffer.from('abc')));
assert.ok(!constantTimeEqual(Buffer.from('abc'), Buffer.from('abd')));
assert.ok(!constantTimeEqual(Buffer.from('abc'), Buffer.from('abcd')));
console.log('✅ constantTimeEqual works');

// ─── Test 14: Encoding round-trips ──────────────────────────────────────
const buf = Buffer.from([0x01, 0x02, 0xff]);
assert.equal(toHex(buf), '0102ff');
assert.ok(fromHex('0102ff').equals(buf));
const b64 = toBase64(buf);
assert.ok(fromBase64(b64).equals(buf));
console.log('✅ Encoding helpers work');

// ─── Test 15: xor ───────────────────────────────────────────────────────
const xorResult = xor(Buffer.from([0xff, 0x00]), Buffer.from([0x0f, 0xff]));
assert.equal(xorResult[0], 0xf0);
assert.equal(xorResult[1], 0xff);
console.log('✅ xor works');

console.log('\n🎉 ALL ESM TESTS PASSED!\n');
