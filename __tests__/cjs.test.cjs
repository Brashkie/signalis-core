/**
 * Test in pure CommonJS — verifies the CJS export of dist/index.cjs.
 *
 * Run with: node __tests__/cjs.test.cjs
 */

const { strict: assert } = require('node:assert');
const { randomBytes } = require('node:crypto');

// CommonJS require
const sc = require('../dist/index.cjs');

console.log('🧪 Testing CommonJS export...\n');

// ─── Test 1: All exports present ──────────────────────────────────────────
assert.ok(sc.Curve25519, 'Curve25519 should be exported');
assert.ok(sc.HKDF, 'HKDF should be exported');
assert.ok(sc.AES_GCM, 'AES_GCM should be exported');
assert.ok(sc.AES_CBC, 'AES_CBC should be exported');
assert.ok(sc.HMAC, 'HMAC should be exported');
assert.ok(sc.SHA256, 'SHA256 should be exported');
assert.ok(typeof sc.VERSION === 'string', 'VERSION should be exported as string');
assert.ok(typeof sc.nativeVersion === 'string', 'nativeVersion should be exported');
assert.equal(sc.VERSION, '0.2.0', 'VERSION should be 0.1.0');
console.log('✅ All exports present');

// ─── Test 2: Error classes are exported ──────────────────────────────────
assert.ok(typeof sc.SignalisError === 'function', 'SignalisError class should be exported');
assert.ok(typeof sc.ValidationError === 'function', 'ValidationError class should be exported');
assert.ok(typeof sc.AuthenticationError === 'function', 'AuthenticationError class should be exported');
assert.ok(typeof sc.CryptoError === 'function', 'CryptoError class should be exported');
assert.ok(typeof sc.LengthError === 'function', 'LengthError class should be exported');
console.log('✅ All error classes exported');

// ─── Test 3: Utility helpers are exported ────────────────────────────────
assert.ok(typeof sc.secureRandom === 'function', 'secureRandom should be exported');
assert.ok(typeof sc.randomNonce === 'function', 'randomNonce should be exported');
assert.ok(typeof sc.randomIv === 'function', 'randomIv should be exported');
assert.ok(typeof sc.randomKey === 'function', 'randomKey should be exported');
assert.ok(typeof sc.toHex === 'function', 'toHex should be exported');
assert.ok(typeof sc.fromHex === 'function', 'fromHex should be exported');
assert.ok(typeof sc.constantTimeEqual === 'function', 'constantTimeEqual should be exported');
assert.ok(typeof sc.concat === 'function', 'concat should be exported');
assert.ok(typeof sc.xor === 'function', 'xor should be exported');
console.log('✅ All utility helpers exported');

// ─── Test 4: Constants are exported ──────────────────────────────────────
assert.equal(sc.CURVE25519_PRIVATE_KEY_SIZE, 32);
assert.equal(sc.AES_256_GCM_NONCE_SIZE, 12);
assert.equal(sc.AES_256_GCM_TAG_SIZE, 16);
assert.equal(sc.SHA256_OUTPUT_SIZE, 32);
console.log('✅ All constants exported');

// ─── Test 5: Curve25519 ECDH ─────────────────────────────────────────────
const alice = sc.Curve25519.generateKeyPair();
const bob = sc.Curve25519.generateKeyPair();
const aliceShared = sc.Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
const bobShared = sc.Curve25519.diffieHellman(bob.privateKey, alice.publicKey);
assert.ok(aliceShared.equals(bobShared), 'ECDH should match');
console.log('✅ Curve25519 ECDH works');

// ─── Test 6: HKDF ────────────────────────────────────────────────────────
const key = sc.HKDF.derive(
  Buffer.from('salt'),
  aliceShared,
  Buffer.from('test-info'),
  32,
);
assert.equal(key.length, 32, 'Derived key should be 32 bytes');
console.log('✅ HKDF works');

// ─── Test 7: HKDF.deriveMultiple ─────────────────────────────────────────
const [k1, k2] = sc.HKDF.deriveMultiple(
  Buffer.from('salt'),
  aliceShared,
  Buffer.from('multi'),
  [16, 32],
);
assert.equal(k1.length, 16);
assert.equal(k2.length, 32);
console.log('✅ HKDF.deriveMultiple works');

// ─── Test 8: AES-256-GCM round-trip ──────────────────────────────────────
const nonce = sc.randomNonce();
const plaintext = Buffer.from('Hello CommonJS!');
const ciphertext = sc.AES_GCM.encrypt(key, nonce, plaintext);
const decrypted = sc.AES_GCM.decrypt(key, nonce, ciphertext);
assert.ok(decrypted.equals(plaintext), 'AES-GCM round-trip should match');
console.log('✅ AES-GCM round-trip works');

// ─── Test 9: AuthenticationError is thrown ───────────────────────────────
const tampered = Buffer.from(ciphertext);
tampered[0] ^= 0xff;
try {
  sc.AES_GCM.decrypt(key, nonce, tampered);
  assert.fail('Should have thrown AuthenticationError');
} catch (e) {
  assert.ok(e instanceof sc.AuthenticationError, 'Should be AuthenticationError');
}
console.log('✅ AuthenticationError works');

// ─── Test 10: SHA-256 NIST vector ────────────────────────────────────────
const sha = sc.SHA256.hash(Buffer.alloc(0));
assert.equal(
  sha.toString('hex'),
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
);
console.log('✅ SHA-256 NIST vector matches');

// ─── Test 11: Encoding round-trip ────────────────────────────────────────
const buf = Buffer.from([0x01, 0x02, 0xff]);
assert.equal(sc.toHex(buf), '0102ff');
assert.ok(sc.fromHex('0102ff').equals(buf));
console.log('✅ Encoding helpers work');

// ─── Test 12: Default export ─────────────────────────────────────────────
const defaultExport = require('../dist/index.cjs').default;
assert.ok(defaultExport && defaultExport.Curve25519, 'Default export should work');
console.log('✅ Default export works');

console.log('\n🎉 ALL CJS TESTS PASSED!\n');
