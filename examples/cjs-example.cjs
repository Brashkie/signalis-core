/**
 * 🔐 Signalis Core - CommonJS Example
 *
 * Ejecutar: node examples/cjs-example.cjs
 *
 * Demuestra todas las primitivas crypto de la librería.
 */

const sc = require('../dist/index.cjs');
const { randomBytes } = require('node:crypto');

console.log('═══════════════════════════════════════════════════════');
console.log('🔐 SIGNALIS CORE - CommonJS Example');
console.log(`   Library: v${sc.VERSION}`);
console.log(`   Native:  v${sc.nativeVersion}`);
console.log('═══════════════════════════════════════════════════════\n');

// ─────────────────────────────────────────────────────────────────────────
// 1. Generación de keypairs Curve25519
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 1: Generar keypairs');
console.log('───────────────────────────────────────────────────────');

const alice = sc.Curve25519.generateKeyPair();
const bob = sc.Curve25519.generateKeyPair();

console.log(`Alice public key:  ${sc.toHex(alice.publicKey).slice(0, 32)}...`);
console.log(`Bob public key:    ${sc.toHex(bob.publicKey).slice(0, 32)}...`);
console.log('✅ 2 keypairs generados\n');

// ─────────────────────────────────────────────────────────────────────────
// 2. Diffie-Hellman key agreement (X25519)
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 2: ECDH key agreement');
console.log('───────────────────────────────────────────────────────');

const aliceShared = sc.Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
const bobShared = sc.Curve25519.diffieHellman(bob.privateKey, alice.publicKey);

const sharedMatch = aliceShared.equals(bobShared);
console.log(`Alice shared:  ${sc.toHex(aliceShared).slice(0, 32)}...`);
console.log(`Bob shared:    ${sc.toHex(bobShared).slice(0, 32)}...`);
console.log(`✅ Shared secrets match: ${sharedMatch}\n`);

// ─────────────────────────────────────────────────────────────────────────
// 3. Derivar session key con HKDF
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 3: HKDF key derivation');
console.log('───────────────────────────────────────────────────────');

const sessionKey = sc.HKDF.derive(
  Buffer.from('signalis-demo-salt'),
  aliceShared,
  Buffer.from('aes-256-gcm-key'),
  32,
);

console.log(`Session key:   ${sc.toHex(sessionKey)}`);
console.log(`Length:        ${sessionKey.length} bytes`);
console.log('✅ Session key derivada\n');

// ─────────────────────────────────────────────────────────────────────────
// 4. Derivar MÚLTIPLES keys (envío + recepción)
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 4: HKDF múltiple (envío + recepción)');
console.log('───────────────────────────────────────────────────────');

const [sendKey, recvKey] = sc.HKDF.deriveMultiple(
  Buffer.from('signalis-channel-v1'),
  aliceShared,
  Buffer.from('dual-keys'),
  [32, 32],
);

console.log(`Send key:      ${sc.toHex(sendKey).slice(0, 32)}...`);
console.log(`Recv key:      ${sc.toHex(recvKey).slice(0, 32)}...`);
console.log('✅ 2 keys derivadas en una llamada\n');

// ─────────────────────────────────────────────────────────────────────────
// 5. Cifrar/descifrar con AES-256-GCM
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 5: AES-256-GCM (authenticated encryption)');
console.log('───────────────────────────────────────────────────────');

const nonce = sc.randomNonce();
const message = Buffer.from('🔒 Top secret: HepeinBaileys conquistará el mundo!');

const ciphertext = sc.AES_GCM.encrypt(sessionKey, nonce, message);
console.log(`Plaintext:     "${message.toString()}"`);
console.log(`Ciphertext:    ${sc.toBase64(ciphertext)}`);
console.log(`Length:        ${message.length} → ${ciphertext.length} bytes (+${ciphertext.length - message.length} tag)`);

const decrypted = sc.AES_GCM.decrypt(sessionKey, nonce, ciphertext);
console.log(`Decrypted:     "${decrypted.toString()}"`);
console.log(`✅ Round-trip: ${decrypted.equals(message)}\n`);

// ─────────────────────────────────────────────────────────────────────────
// 6. Detección de tampering (AuthenticationError)
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 6: Detección de tampering');
console.log('───────────────────────────────────────────────────────');

const tampered = Buffer.from(ciphertext);
tampered[0] ^= 0xff; // Modificar 1 byte
console.log(`Tampered:      ${sc.toBase64(tampered)}`);

try {
  sc.AES_GCM.decrypt(sessionKey, nonce, tampered);
  console.log('❌ No detectó el tampering!');
} catch (e) {
  if (e instanceof sc.AuthenticationError) {
    console.log(`✅ AuthenticationError detectado: ${e.message}`);
  }
}
console.log();

// ─────────────────────────────────────────────────────────────────────────
// 7. HMAC-SHA256 para autenticación
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 7: HMAC-SHA256 (message authentication)');
console.log('───────────────────────────────────────────────────────');

const macKey = sc.randomKey();
const macMessage = Buffer.from('Message to authenticate');
const tag = sc.HMAC.sha256(macKey, macMessage);

console.log(`Message:       "${macMessage.toString()}"`);
console.log(`HMAC tag:      ${sc.toHex(tag).slice(0, 32)}...`);
console.log(`Length:        ${tag.length} bytes`);

const valid = sc.HMAC.verifySha256(macKey, macMessage, tag);
console.log(`✅ Verify (correct): ${valid}`);

const invalid = sc.HMAC.verifySha256(macKey, macMessage, Buffer.alloc(32));
console.log(`✅ Verify (wrong tag): ${invalid}\n`);

// ─────────────────────────────────────────────────────────────────────────
// 8. SHA-256 hashing
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 8: SHA-256 hashing');
console.log('───────────────────────────────────────────────────────');

const data = Buffer.from('Hola desde Brashkie!');
const hash = sc.SHA256.hash(data);
console.log(`Input:         "${data.toString()}"`);
console.log(`SHA-256:       ${sc.toHex(hash)}`);

const multiHash = sc.SHA256.hashAll([Buffer.from('Hello, '), Buffer.from('World!')]);
console.log(`hashAll:       ${sc.toHex(multiHash)}\n`);

// ─────────────────────────────────────────────────────────────────────────
// 9. AES-256-CBC + HMAC (encrypt-then-MAC)
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 9: AES-CBC + HMAC (encrypt-then-MAC)');
console.log('───────────────────────────────────────────────────────');

const [cbcEncKey, cbcMacKey] = sc.HKDF.deriveMultiple(
  Buffer.from('cbc-demo'),
  aliceShared,
  Buffer.from('enc+mac'),
  [32, 32],
);

const iv = sc.randomIv();
const cbcMessage = Buffer.from('Legacy Signal Protocol message');

const cbcCt = sc.AES_CBC.encrypt(cbcEncKey, iv, cbcMessage);
const macInput = sc.concat([iv, cbcCt]);
const cbcTag = sc.HMAC.sha256(cbcMacKey, macInput);

console.log(`Plaintext:     "${cbcMessage.toString()}"`);
console.log(`IV:            ${sc.toHex(iv)}`);
console.log(`Ciphertext:    ${sc.toHex(cbcCt).slice(0, 48)}...`);
console.log(`HMAC tag:      ${sc.toHex(cbcTag).slice(0, 32)}...`);

// Verificar y descifrar
const macValid = sc.HMAC.verifySha256(cbcMacKey, macInput, cbcTag);
if (macValid) {
  const cbcPt = sc.AES_CBC.decrypt(cbcEncKey, iv, cbcCt);
  console.log(`Decrypted:     "${cbcPt.toString()}"`);
  console.log(`✅ Verify-then-decrypt OK\n`);
}

// ─────────────────────────────────────────────────────────────────────────
// 10. Utilidades de encoding
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Paso 10: Utilidades de encoding');
console.log('───────────────────────────────────────────────────────');

const sample = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
console.log(`Buffer:        ${[...sample].map((b) => '0x' + b.toString(16)).join(' ')}`);
console.log(`toHex:         ${sc.toHex(sample)}`);
console.log(`toBase64:      ${sc.toBase64(sample)}`);
console.log(`toBase64Url:   ${sc.toBase64Url(sample)}`);

// Round-trip
const restored = sc.fromHex('deadbeefcafe');
console.log(`Round-trip:    ${sc.toHex(restored)} ✅\n`);

// ─────────────────────────────────────────────────────────────────────────
// Resumen final
// ─────────────────────────────────────────────────────────────────────────
console.log('═══════════════════════════════════════════════════════');
console.log('🎉 TODOS LOS EJEMPLOS EJECUTADOS CON ÉXITO');
console.log('═══════════════════════════════════════════════════════');
console.log(`✅ Curve25519 keypair generation`);
console.log(`✅ X25519 ECDH key agreement`);
console.log(`✅ HKDF-SHA256 key derivation`);
console.log(`✅ HKDF deriveMultiple`);
console.log(`✅ AES-256-GCM encryption + decryption`);
console.log(`✅ AuthenticationError detection`);
console.log(`✅ HMAC-SHA256 + constant-time verify`);
console.log(`✅ SHA-256 hashing + hashAll`);
console.log(`✅ AES-256-CBC + HMAC (encrypt-then-MAC)`);
console.log(`✅ Encoding utilities (hex/base64/base64url)`);
console.log('═══════════════════════════════════════════════════════\n');
