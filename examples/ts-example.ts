/**
 * 🔐 Signalis Core - TypeScript Example
 *
 * Ejecutar: npx tsx examples/ts-example.ts
 *
 * Demuestra el uso con tipos completos.
 */

import {
  Curve25519,
  HKDF,
  AES_GCM,
  HMAC,
  SHA256,
  randomNonce,
  randomKey,
  toHex,
  toBase64,
  concat,
  AuthenticationError,
  ValidationError,
  type KeyPair,
  type HkdfParams,
  VERSION,
} from '../src';

console.log('═══════════════════════════════════════════════════════');
console.log('🔐 SIGNALIS CORE - TypeScript Example');
console.log(`   Library: v${VERSION}`);
console.log('═══════════════════════════════════════════════════════\n');

// ─────────────────────────────────────────────────────────────────────────
// Demo 1: Tipo `KeyPair` con type safety
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Demo 1: Tipo KeyPair con type safety\n');

function generateUserKeypair(name: string): { name: string; keypair: KeyPair } {
  return {
    name,
    keypair: Curve25519.generateKeyPair(),
  };
}

const alice = generateUserKeypair('Alice');
const bob = generateUserKeypair('Bob');

console.log(`${alice.name}: ${toHex(alice.keypair.publicKey).slice(0, 32)}...`);
console.log(`${bob.name}:   ${toHex(bob.keypair.publicKey).slice(0, 32)}...`);

// Type safety: esto es un error en TypeScript
// alice.keypair.privateKey = bob.keypair.privateKey; // ❌ TS Error: readonly

console.log();

// ─────────────────────────────────────────────────────────────────────────
// Demo 2: HKDF con interface tipada (HkdfParams)
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Demo 2: HKDF con params tipados\n');

const shared: Buffer = Curve25519.diffieHellman(
  alice.keypair.privateKey,
  bob.keypair.publicKey,
);

// Usando la interfaz HkdfParams para mejor legibilidad
const params: HkdfParams = {
  salt: Buffer.from('signalis-v1'),
  ikm: shared,
  info: Buffer.from('aes-gcm-encryption'),
  length: 32,
};

const sessionKey: Buffer = HKDF.deriveFromParams(params);
console.log(`Session key: ${toHex(sessionKey)}`);
console.log();

// ─────────────────────────────────────────────────────────────────────────
// Demo 3: Función tipada de envío/recepción
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Demo 3: Funciones tipadas\n');

interface EncryptedMessage {
  readonly nonce: Buffer;
  readonly ciphertext: Buffer;
  readonly timestamp: number;
}

function sendMessage(key: Buffer, plaintext: string): EncryptedMessage {
  const nonce = randomNonce();
  const ciphertext = AES_GCM.encrypt(key, nonce, Buffer.from(plaintext));
  return {
    nonce,
    ciphertext,
    timestamp: Date.now(),
  };
}

function receiveMessage(key: Buffer, message: EncryptedMessage): string {
  const plaintext = AES_GCM.decrypt(key, message.nonce, message.ciphertext);
  return plaintext.toString('utf8');
}

// Alice envía
const msg = sendMessage(sessionKey, '¡Hola Bob! Mensaje firmado y cifrado 🔐');
console.log(`📤 Alice envía:`);
console.log(`   Timestamp:  ${new Date(msg.timestamp).toISOString()}`);
console.log(`   Nonce:      ${toHex(msg.nonce)}`);
console.log(`   Ciphertext: ${toBase64(msg.ciphertext)}`);

// Bob recibe
const received = receiveMessage(sessionKey, msg);
console.log(`📥 Bob recibe: "${received}"`);
console.log();

// ─────────────────────────────────────────────────────────────────────────
// Demo 4: Error handling tipado
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Demo 4: Error handling tipado\n');

function safeDecrypt(
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
): { ok: true; data: Buffer } | { ok: false; error: string } {
  try {
    const data = AES_GCM.decrypt(key, nonce, ciphertext);
    return { ok: true, data };
  } catch (e) {
    if (e instanceof AuthenticationError) {
      return { ok: false, error: `Mensaje alterado: ${e.message}` };
    }
    if (e instanceof ValidationError) {
      return { ok: false, error: `Parámetro inválido: ${e.parameter}` };
    }
    return { ok: false, error: 'Error desconocido' };
  }
}

// Caso 1: descifrar válido
const result1 = safeDecrypt(sessionKey, msg.nonce, msg.ciphertext);
console.log(`Caso 1 (válido):    ${result1.ok ? '✅' : '❌'} ${result1.ok ? result1.data.toString() : result1.error}`);

// Caso 2: ciphertext alterado
const tampered = Buffer.from(msg.ciphertext);
tampered[0] ^= 0xff;
const result2 = safeDecrypt(sessionKey, msg.nonce, tampered);
console.log(`Caso 2 (alterado):  ${result2.ok ? '❌ INSEGURO' : '✅ DETECTADO'} ${!result2.ok ? result2.error : ''}`);

// Caso 3: nonce inválido
const result3 = safeDecrypt(sessionKey, Buffer.alloc(11), msg.ciphertext);
console.log(`Caso 3 (nonce bad): ${result3.ok ? '❌' : '✅ DETECTADO'} ${!result3.ok ? result3.error : ''}`);

console.log();

// ─────────────────────────────────────────────────────────────────────────
// Demo 5: Encrypt-then-MAC con types
// ─────────────────────────────────────────────────────────────────────────
console.log('📌 Demo 5: Encrypt-then-MAC con types\n');

interface AuthenticatedMessage {
  readonly iv: Buffer;
  readonly ciphertext: Buffer;
  readonly mac: Buffer;
}

function authenticatedEncrypt(
  encKey: Buffer,
  macKey: Buffer,
  plaintext: Buffer,
): AuthenticatedMessage {
  const iv = randomNonce(); // 12 bytes (también sirve para nonce GCM, pero usar aleatorio)
  const ciphertext = AES_GCM.encrypt(encKey, iv, plaintext);
  const mac = HMAC.sha256(macKey, concat([iv, ciphertext]));
  return { iv, ciphertext, mac };
}

function authenticatedDecrypt(
  encKey: Buffer,
  macKey: Buffer,
  message: AuthenticatedMessage,
): Buffer {
  const macInput = concat([message.iv, message.ciphertext]);
  if (!HMAC.verifySha256(macKey, macInput, message.mac)) {
    throw new Error('MAC verification failed');
  }
  return AES_GCM.decrypt(encKey, message.iv, message.ciphertext);
}

const [encKey, macKey] = HKDF.deriveMultiple(
  Buffer.from('salt'),
  shared,
  Buffer.from('etm-keys'),
  [32, 32],
);

const authMsg = authenticatedEncrypt(encKey!, macKey!, Buffer.from('Double-protected!'));
console.log(`IV:        ${toHex(authMsg.iv)}`);
console.log(`CT length: ${authMsg.ciphertext.length} bytes`);
console.log(`MAC:       ${toHex(authMsg.mac).slice(0, 32)}...`);

const decrypted = authenticatedDecrypt(encKey!, macKey!, authMsg);
console.log(`Decrypted: "${decrypted.toString()}"`);

console.log('\n═══════════════════════════════════════════════════════');
console.log('🎉 TypeScript example completado');
console.log('═══════════════════════════════════════════════════════\n');
