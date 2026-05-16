/**
 * 🔐 Signalis Core - ESM Example
 *
 * Ejecutar: node examples/esm-example.mjs
 */

import {
  Curve25519,
  HKDF,
  AES_GCM,
  AES_CBC,
  HMAC,
  SHA256,
  secureRandom,
  randomNonce,
  randomIv,
  randomKey,
  toHex,
  toBase64,
  fromHex,
  concat,
  constantTimeEqual,
  AuthenticationError,
  VERSION,
  nativeVersion,
} from '../dist/index.mjs';

console.log('═══════════════════════════════════════════════════════');
console.log('🔐 SIGNALIS CORE - ESM Example');
console.log(`   Library: v${VERSION}`);
console.log(`   Native:  v${nativeVersion}`);
console.log('═══════════════════════════════════════════════════════\n');

// ─────────────────────────────────────────────────────────────────────────
// Demo: Comunicación E2E entre Alice y Bob
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Demo: Comunicación E2E Alice ↔ Bob\n');

// Paso 1: Cada uno genera su keypair
const alice = Curve25519.generateKeyPair();
const bob = Curve25519.generateKeyPair();
console.log('✅ Keypairs generados');

// Paso 2: Intercambian públicas y calculan shared secret
const aliceShared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
const bobShared = Curve25519.diffieHellman(bob.privateKey, alice.publicKey);
console.log(`✅ ECDH match: ${constantTimeEqual(aliceShared, bobShared)}`);

// Paso 3: Derivan session keys idénticas
const aliceKey = HKDF.derive(
  Buffer.from('signalis-channel-v1'),
  aliceShared,
  Buffer.from('aes-gcm-key'),
  32,
);
const bobKey = HKDF.derive(
  Buffer.from('signalis-channel-v1'),
  bobShared,
  Buffer.from('aes-gcm-key'),
  32,
);
console.log(`✅ Session keys derivadas (match: ${constantTimeEqual(aliceKey, bobKey)})\n`);

// ─────────────────────────────────────────────────────────────────────────
// Alice envía 3 mensajes a Bob
// ─────────────────────────────────────────────────────────────────────────
console.log('📨 Alice envía 3 mensajes a Bob:\n');

const messages = [
  'Hola Bob! 👋',
  '¿Cómo estás?',
  'Saludos desde Hepein 🚀',
];

const transmitted = messages.map((msg) => {
  const nonce = randomNonce();
  const plaintext = Buffer.from(msg);
  const ciphertext = AES_GCM.encrypt(aliceKey, nonce, plaintext);
  return { nonce, ciphertext, original: msg };
});

transmitted.forEach((tx, i) => {
  console.log(`Mensaje ${i + 1}:`);
  console.log(`  📤 Plaintext:  "${tx.original}"`);
  console.log(`  🔒 Ciphertext: ${toBase64(tx.ciphertext)}`);
  console.log(`  🎲 Nonce:      ${toHex(tx.nonce)}`);
});

console.log('\n📥 Bob descifra los 3 mensajes:\n');

transmitted.forEach((tx, i) => {
  const decrypted = AES_GCM.decrypt(bobKey, tx.nonce, tx.ciphertext);
  const match = decrypted.toString() === tx.original;
  console.log(`Mensaje ${i + 1}: "${decrypted.toString()}" ${match ? '✅' : '❌'}`);
});

// ─────────────────────────────────────────────────────────────────────────
// Test de seguridad: detectar tampering
// ─────────────────────────────────────────────────────────────────────────
console.log('\n📌 Test de seguridad: detectar tampering\n');

const attackerCt = Buffer.from(transmitted[0].ciphertext);
attackerCt[0] ^= 0xff; // Atacante modifica el ciphertext

console.log('🦹 Atacante modifica el ciphertext...');
try {
  AES_GCM.decrypt(bobKey, transmitted[0].nonce, attackerCt);
  console.log('❌ Bob aceptó el mensaje modificado!');
} catch (e) {
  if (e instanceof AuthenticationError) {
    console.log(`🛡️  Bob rechaza el mensaje: AuthenticationError`);
    console.log(`   Operación: ${e.operation}`);
    console.log(`   Código:    ${e.code}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Hash de un archivo (simulado)
// ─────────────────────────────────────────────────────────────────────────
console.log('\n📌 SHA-256 de datos\n');

const fileData = Buffer.from('Imagine que esto es un archivo grande...');
const fileHash = SHA256.hash(fileData);
console.log(`Data:      "${fileData.toString()}"`);
console.log(`SHA-256:   ${toHex(fileHash)}`);

// ─────────────────────────────────────────────────────────────────────────
// Random utilities
// ─────────────────────────────────────────────────────────────────────────
console.log('\n📌 Secure random utilities\n');
console.log(`secureRandom(8):  ${toHex(secureRandom(8))}`);
console.log(`randomNonce():    ${toHex(randomNonce())} (12 bytes)`);
console.log(`randomIv():       ${toHex(randomIv())} (16 bytes)`);
console.log(`randomKey():      ${toHex(randomKey())} (32 bytes)`);

console.log('\n═══════════════════════════════════════════════════════');
console.log('🎉 ESM example completado');
console.log('═══════════════════════════════════════════════════════\n');
