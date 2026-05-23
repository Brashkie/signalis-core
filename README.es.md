<div align="center">

<img src="media/logo.png" alt="Signalis Core" width="200" />

# 🔐 Signalis Core

**Primitivas criptográficas para el Protocolo Signal — impulsadas por Rust, increíblemente rápidas.**

[![CI](https://github.com/Brashkie/signalis-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Brashkie/signalis-core/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@brashkie/signalis-core.svg?style=flat&color=cb3837)](https://www.npmjs.com/package/@brashkie/signalis-core)
[![npm downloads](https://img.shields.io/npm/dm/@brashkie/signalis-core.svg?style=flat&color=blue)](https://www.npmjs.com/package/@brashkie/signalis-core)
[![Licencia: Apache 2.0](https://img.shields.io/badge/Licencia-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-339933.svg)](https://nodejs.org/)
[![Cobertura](https://img.shields.io/badge/coverage-99%25-brightgreen.svg)](#testing)
[![Tests](https://img.shields.io/badge/tests-269%2B%20pasando-success.svg)](#testing)

[**English**](./README.md) · [**Español**](./README.es.md) · [Documentación](./docs) · [Roadmap](./ROADMAP.md) · [Changelog](./CHANGELOG.md)

</div>

---

## ✨ ¿Qué es Signalis Core?

`@brashkie/signalis-core` es una **librería criptográfica auditada de alto rendimiento** que proporciona las primitivas fundamentales para implementar el **Protocolo Signal** en aplicaciones Node.js.

Construida con **Rust** para seguridad y velocidad, expuesta a Node.js mediante [napi-rs](https://napi.rs), provee una API TypeScript limpia que funciona perfectamente en entornos CommonJS y ESM.

> **Parte del ecosistema [Hepein](https://github.com/Brashkie).**
> La base para `@brashkie/signalis` (Protocolo Signal), `@brashkie/waproto` (Protocolo WhatsApp), y eventualmente una alternativa a Baileys construida desde cero.

---

## 🎉 Novedades en v0.2.0

**v0.2.0 introduce firmas digitales y cifrado autenticado con AAD — totalmente retrocompatible con v0.1.0.**

| Nuevo | Descripción |
|-------|-------------|
| 🆕 **Ed25519** | Firmas digitales estándar (RFC 8032) — determinísticas |
| 🆕 **XEd25519** | Firmas estilo Signal con llaves Curve25519 — una llave de identidad para ECDH + firmar |
| 🆕 **AES-GCM con AAD** | Datos Autenticados Adicionales para vincular metadatos al cifrado |
| 🆕 **SignatureError** | Nueva clase de error tipada para fallos de firma |
| 🆕 **Tipo Signature** | Tipo branded con helper `asSignature()` |

Ver [MIGRATION.md](./MIGRATION.md) para detalles de upgrade (es un drop-in replacement).

---

## 📋 Tabla de Contenido

- [Características](#-características)
- [¿Por qué Signalis Core?](#-por-qué-signalis-core)
- [Instalación](#-instalación)
- [Inicio Rápido](#-inicio-rápido)
- [Referencia de API](#-referencia-de-api)
- [Ejemplos](#-ejemplos)
- [Arquitectura](#-arquitectura)
- [Seguridad](#-seguridad)
- [Rendimiento](#-rendimiento)
- [Testing](#-testing)
- [Compilar desde fuente](#-compilar-desde-fuente)
- [Roadmap](#-roadmap)
- [Contribuir](#-contribuir)
- [Agradecimientos](#-agradecimientos)
- [Licencia](#-licencia)

---

## 🚀 Características

| Característica | Descripción |
|----------------|-------------|
| 🔥 **Velocidad Extrema** | Implementación nativa en Rust vía napi-rs (10-100x más rápido que JS puro) |
| 🛡️ **Crypto Auditada** | Basada en `curve25519-dalek`, `ed25519-dalek`, suite RustCrypto — librerías probadas en batalla |
| ✍️ **Firmas Digitales** | Ed25519 (RFC 8032) y XEd25519 (estilo Signal) — **NUEVO v0.2.0** |
| 🔐 **AEAD con AAD** | AES-256-GCM con Datos Autenticados Adicionales — **NUEVO v0.2.0** |
| 📦 **Paquete Dual** | Funciona en proyectos CommonJS, ESM y TypeScript |
| 🎯 **Tipado Estricto** | Definiciones TypeScript completas con tipos branded y clases de error |
| ✅ **Vectores de Test** | Validado contra RFC 5869, RFC 7748, RFC 8032, RFC 4231 y vectores NIST |
| 🌍 **Multi-Plataforma** | Binarios pre-compilados para Windows, macOS, Linux (x64, ARM) |
| 🔒 **Tiempo Constante** | Comparaciones resistentes a side-channel via crate `subtle` |
| 🧹 **Auto-Borrado** | Secretos se borran de memoria automáticamente |
| 📊 **Cobertura 99%+** | Suite de tests con 269+ aserciones |
| 📖 **Bien Documentada** | JSDoc completo + ejemplos inline para cada función |

---

## 🤔 ¿Por qué Signalis Core?

### vs. el módulo `crypto` nativo de Node

```javascript
// ❌ crypto de Node — verboso, propenso a errores, sin Curve25519 nativo
const { createDiffieHellman, createCipheriv, randomBytes } = require('crypto');
// ... 20+ líneas de boilerplate por operación

// ✅ Signalis Core — limpio, tipado, auditado
const shared = Curve25519.diffieHellman(myPriv, theirPub);
const ct = AES_GCM.encrypt(key, nonce, plaintext);
```

### vs. librerías JS puras (`tweetnacl`, `libsodium-js`)

| | Signalis Core | tweetnacl-js | libsodium-js |
|---|---|---|---|
| **Velocidad** | 🟢 Rust nativo | 🟡 JS puro | 🟡 WASM |
| **Tamaño** | 🟢 ~80KB nativo | 🟢 ~50KB | 🔴 ~800KB |
| **TypeScript** | 🟢 First-class | 🟡 Tipos vía @types | 🟡 Tipos vía @types |
| **API Moderna** | 🟢 Async-ready | 🔴 Callbacks | 🟡 Solo sync |
| **Tree-Shakeable** | 🟢 Sí | 🟢 Sí | 🔴 No |

---

## 📥 Instalación

```bash
# npm
npm install @brashkie/signalis-core

# pnpm
pnpm add @brashkie/signalis-core

# yarn
yarn add @brashkie/signalis-core

# bun
bun add @brashkie/signalis-core
```

**Requisitos:**
- Node.js ≥ 18
- Una de: Windows (x64), macOS (x64/arm64) o Linux (x64/arm64) con binarios pre-compilados
- O: Rust 1.80+ para compilar desde fuente

---

## ⚡ Inicio Rápido

### Establecer un canal cifrado end-to-end

```typescript
import {
  Curve25519,
  HKDF,
  AES_GCM,
  randomNonce,
} from '@brashkie/signalis-core';

// 1. Ambas partes generan keypairs
const alice = Curve25519.generateKeyPair();
const bob = Curve25519.generateKeyPair();

// 2. Acuerdo de claves ECDH (X25519)
const secretoCompartido = Curve25519.diffieHellman(
  alice.privateKey,
  bob.publicKey,
);

// 3. Derivar clave de sesión via HKDF
const claveSession = HKDF.derive(
  Buffer.from('mi-app-v1'),               // salt
  secretoCompartido,                      // IKM
  Buffer.from('clave-cifrado'),           // info
  32,                                     // longitud
);

// 4. Cifrar un mensaje
const nonce = randomNonce();              // 12 bytes aleatorios
const texto = Buffer.from('¡Hola Mundo!');
const cifrado = AES_GCM.encrypt(claveSession, nonce, texto);

// 5. Descifrar
const descifrado = AES_GCM.decrypt(claveSession, nonce, cifrado);
console.log(descifrado.toString()); // → "¡Hola Mundo!"
```

### CommonJS

```javascript
const sc = require('@brashkie/signalis-core');

const alice = sc.Curve25519.generateKeyPair();
const bob = sc.Curve25519.generateKeyPair();
const shared = sc.Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
```

### Import por defecto

```typescript
import sc from '@brashkie/signalis-core';

const keypair = sc.Curve25519.generateKeyPair();
const nonce = sc.randomNonce();
```

---

## 📚 Referencia de API

### Curve25519 / X25519

Operaciones de curva elíptica para acuerdo de claves.

```typescript
import { Curve25519, type KeyPair } from '@brashkie/signalis-core';

// Generar nuevo keypair (usa OS CSPRNG)
const kp: KeyPair = Curve25519.generateKeyPair();
// → { privateKey: Buffer(32), publicKey: Buffer(32) }

// Derivar clave pública desde privada
const pub = Curve25519.publicFromPrivate(privateKey);

// Acuerdo X25519 ECDH
const shared = Curve25519.diffieHellman(miPriv, suPub);
// ⚠️ ¡SIEMPRE pasar por HKDF antes de usar!

// Constantes
Curve25519.PRIVATE_KEY_SIZE;      // 32
Curve25519.PUBLIC_KEY_SIZE;       // 32
Curve25519.SHARED_SECRET_SIZE;    // 32
```

### Ed25519

**NUEVO en v0.2.0.** Firmas digitales Ed25519 estándar (RFC 8032). Determinístico — la misma entrada siempre produce la misma firma.

```typescript
import { Ed25519, type KeyPair, type Signature } from '@brashkie/signalis-core';

// Generar nuevo keypair para firmar
const keys: KeyPair = Ed25519.generateKeyPair();
// → { privateKey: Buffer(32), publicKey: Buffer(32) }

// Determinístico desde una semilla de 32 bytes
const fromSeed = Ed25519.keyPairFromSeed(seed);

// Derivar pública desde privada
const pub = Ed25519.publicFromPrivate(privateKey);

// Firmar un mensaje → firma de 64 bytes
const sig: Signature = Ed25519.sign(privateKey, message);

// Verificar (lanza SignatureError si falla)
Ed25519.verify(publicKey, message, sig);

// Verificar (retorna boolean, no lanza)
const ok = Ed25519.verifyBool(publicKey, message, sig);

// Constantes
Ed25519.PRIVATE_KEY_SIZE;    // 32
Ed25519.PUBLIC_KEY_SIZE;     // 32
Ed25519.SIGNATURE_SIZE;      // 64
Ed25519.SEED_SIZE;           // 32
```

### XEd25519

**NUEVO en v0.2.0.** Firmar con el **MISMO** keypair Curve25519 que se usa para ECDH. Esto es lo que el Protocolo Signal usa para las llaves de identidad.

```typescript
import { Curve25519, XEd25519 } from '@brashkie/signalis-core';

// UN solo keypair para ECDH y firmar
const identidad = Curve25519.generateKeyPair();

// Para ECDH:
const shared = Curve25519.diffieHellman(identidad.privateKey, peerPublic);

// La MISMA llave para firmar:
const sig = XEd25519.sign(identidad.privateKey, message);

// Verificar con la MISMA llave pública Curve25519
XEd25519.verify(identidad.publicKey, message, sig);

// Las firmas XEd25519 NO son determinísticas (usan OS RNG)
const sig1 = XEd25519.sign(identidad.privateKey, message);
const sig2 = XEd25519.sign(identidad.privateKey, message);
// sig1.equals(sig2) → false (intencionalmente probabilístico)

// Para firmas determinísticas (tests), pasa el random de 64 bytes:
const random = secureRandom(64);
const detSig = XEd25519.signWithRandom(identidad.privateKey, message, random);

// Verificar (boolean, no lanza)
const ok = XEd25519.verifyBool(identidad.publicKey, message, sig);

// Constantes
XEd25519.PRIVATE_KEY_SIZE;   // 32 (igual que Curve25519)
XEd25519.PUBLIC_KEY_SIZE;    // 32 (igual que Curve25519)
XEd25519.SIGNATURE_SIZE;     // 64
XEd25519.RANDOM_SIZE;        // 64
```

**¿Cuándo usar Ed25519 vs XEd25519?**

| Necesitas | Usa |
|-----------|-----|
| Ed25519 estándar, determinístico, compatible con RFC 8032 | **Ed25519** |
| Una sola llave de identidad para ECDH + firmar (estilo Signal) | **XEd25519** |
| Firmas reproducibles desde semilla | **Ed25519** |
| Compatibilidad con semántica del Protocolo Signal | **XEd25519** |

### HKDF-SHA256

Derivación de claves según RFC 5869.

```typescript
import { HKDF } from '@brashkie/signalis-core';

// One-shot (recomendado)
const okm = HKDF.derive(salt, ikm, info, longitud);

// Dos pasos
const prk = HKDF.extract(salt, ikm);          // → 32 bytes
const okm = HKDF.expand(prk, info, 64);       // → 64 bytes

// Derivar múltiples claves a la vez
const [claveCifrado, claveMac, claveIv] = HKDF.deriveMultiple(
  salt,
  ikm,
  info,
  [32, 32, 16],
);

// API basada en objeto
const okm = HKDF.deriveFromParams({
  salt: Buffer.from('salt'),
  ikm: secretoCompartido,
  info: Buffer.from('aes-key'),
  length: 32,
});
```

### AES-256-GCM

Cifrado autenticado (recomendado para la mayoría de casos).

```typescript
import { AES_GCM, randomNonce } from '@brashkie/signalis-core';

const clave = randomKey();             // 32 bytes
const nonce = randomNonce();           // 12 bytes (DEBE ser único por mensaje)

// Cifrar → texto_cifrado || tag de 16 bytes
const ct = AES_GCM.encrypt(clave, nonce, textoPlano);

// Descifrar + verificar tag
const pt = AES_GCM.decrypt(clave, nonce, ct);
// Lanza AuthenticationError si fue modificado
```

**Con Datos Autenticados Adicionales (AAD) — NUEVO en v0.2.0:**

```typescript
import { AES_GCM } from '@brashkie/signalis-core';

// AAD se autentica pero NO se cifra — útil para cabeceras/metadatos
const cabecera = Buffer.from('msg_id=42|emisor=alice');
const cuerpo = Buffer.from('contenido cifrado del cuerpo');

const ct = AES_GCM.encryptWithAad(clave, nonce, cuerpo, cabecera);

// Descifrar — DEBE pasar el mismo AAD, o AuthenticationError
const pt = AES_GCM.decryptWithAad(clave, nonce, ct, cabecera);

// Modificar la cabecera (AAD) → falla
const tampered = Buffer.from(cabecera);
tampered[0] ^= 0xff;
AES_GCM.decryptWithAad(clave, nonce, ct, tampered);  // lanza AuthenticationError
```

> **⚠️ CRÍTICO:** Nunca reutilizar un par `(clave, nonce)`. Usa `randomNonce()` para cada mensaje, o usa un contador determinístico bajo la misma clave (máx 2³² mensajes).

### AES-256-CBC

Cipher de bloques (pair con HMAC para integridad).

```typescript
import { AES_CBC, HMAC, randomIv, concat } from '@brashkie/signalis-core';

// Patrón Encrypt-then-MAC (la única forma segura de usar CBC)
const iv = randomIv();
const ct = AES_CBC.encrypt(encKey, iv, textoPlano);
const tag = HMAC.sha256(macKey, concat([iv, ct]));

// Para descifrar: verificar MAC primero, luego descifrar
if (HMAC.verifySha256(macKey, concat([iv, ct]), tag)) {
  const pt = AES_CBC.decrypt(encKey, iv, ct);
}
```

### HMAC-SHA256

Autenticación de mensajes.

```typescript
import { HMAC } from '@brashkie/signalis-core';

const tag = HMAC.sha256(clave, datos);                  // 32 bytes
const valido = HMAC.verifySha256(clave, datos, tag);    // tiempo-constante
```

### SHA-256

Hashing criptográfico.

```typescript
import { SHA256 } from '@brashkie/signalis-core';

const hash = SHA256.hash(datos);                        // 32 bytes
const hash2 = SHA256.hashAll([buf1, buf2, buf3]);       // hash concatenado
```

### Utilidades

```typescript
import {
  // Random seguro
  secureRandom,    // (longitud) → Buffer
  randomNonce,     // → Buffer de 12 bytes (para GCM)
  randomIv,        // → Buffer de 16 bytes (para CBC)
  randomKey,       // → Buffer de 32 bytes

  // Codificación
  toHex,           // Buffer → string
  fromHex,         // string → Buffer
  toBase64,        // Buffer → string
  fromBase64,      // string → Buffer
  toBase64Url,     // Buffer → string URL-safe (sin padding)
  fromBase64Url,

  // Seguridad
  constantTimeEqual,  // (a, b) → boolean (timing-safe)

  // Operaciones Buffer
  concat,          // (buffers[]) → Buffer
  xor,             // (a, b) → Buffer
  zeroize,         // (buf) → void (borra in-place)
} from '@brashkie/signalis-core';
```

### Errores

Todos los errores extienden `SignalisError`:

```typescript
import {
  SignalisError,            // Clase base
  ValidationError,          // Input inválido (tamaño, tipo)
  CryptoError,              // Op crypto falló
  AuthenticationError,      // Verificación Tag/MAC falló (extiende CryptoError)
  KeyDerivationError,       // HKDF o similar falló (extiende CryptoError)
  SignatureError,           // Verificación Ed25519/XEd25519 falló (extiende CryptoError) — NUEVO v0.2.0
  LengthError,              // Longitud fuera de rango (extiende ValidationError)
} from '@brashkie/signalis-core';

try {
  AES_GCM.decrypt(clave, nonce, textoCifradoModificado);
} catch (e) {
  if (e instanceof AuthenticationError) {
    console.error('¡Tampering detectado!');
  } else if (e instanceof ValidationError) {
    console.error(`Parámetro inválido: ${e.parameter}`);
  } else if (e instanceof SignatureError) {
    console.error('¡Firma inválida!');
  }
}
```

---

## 💡 Ejemplos

El directorio `examples/` contiene demos completos funcionales:

```bash
npm run example:cjs        # CommonJS (10 demos)
npm run example:esm        # ESM (canal Alice ↔ Bob)
npm run example:ts         # TypeScript (patrones type-safe)
npm run example:signing    # Ed25519 + XEd25519 — NUEVO v0.2.0
npm run example:aad        # AES-GCM con AAD — NUEVO v0.2.0
npm run example:e2e        # Canal E2E completo — NUEVO v0.2.0
npm run examples           # Ejecutar todos
```

### Ejemplo: Cifrado seguro de archivos

```typescript
import { AES_GCM, HKDF, randomKey, randomNonce } from '@brashkie/signalis-core';
import { readFile, writeFile } from 'fs/promises';

async function cifrarArchivo(rutaEntrada: string, rutaSalida: string, password: string) {
  const claveMaestra = randomKey();
  const claveArchivo = HKDF.derive(
    Buffer.from('cifrado-archivo-v1'),
    Buffer.from(password),
    Buffer.from(rutaEntrada),
    32,
  );

  const textoPlano = await readFile(rutaEntrada);
  const nonce = randomNonce();
  const cifrado = AES_GCM.encrypt(claveArchivo, nonce, textoPlano);

  // Salida: [nonce 12 bytes][cifrado + tag 16 bytes]
  await writeFile(rutaSalida, Buffer.concat([nonce, cifrado]));
}
```

### Ejemplo: "Triple DH" estilo Signal

```typescript
import { Curve25519, HKDF, concat } from '@brashkie/signalis-core';

// Alice tiene: clave identidad (IK_A), clave efímera (EK_A)
// Bob tiene:   clave identidad (IK_B), pre-clave firmada (SPK_B)

function tripleDH(IK_A_priv: Buffer, EK_A_priv: Buffer,
                  IK_B_pub: Buffer, SPK_B_pub: Buffer): Buffer {
  const dh1 = Curve25519.diffieHellman(IK_A_priv, SPK_B_pub);
  const dh2 = Curve25519.diffieHellman(EK_A_priv, IK_B_pub);
  const dh3 = Curve25519.diffieHellman(EK_A_priv, SPK_B_pub);

  return HKDF.derive(
    Buffer.alloc(32),                          // salt vacío
    concat([dh1, dh2, dh3]),                   // DHs concatenados como IKM
    Buffer.from('Signal_X3DH_v1'),             // info
    64,                                        // root_key (32) + chain_key (32)
  );
}
```

### Ejemplo: Firmar aserciones de identidad (NUEVO v0.2.0)

```typescript
import { Curve25519, XEd25519 } from '@brashkie/signalis-core';

// Clave de identidad de largo plazo de Alice (Curve25519/XEd25519)
const aliceIdentidad = Curve25519.generateKeyPair();

// Alice genera una clave efímera para la sesión
const aliceEfimera = Curve25519.generateKeyPair();

// Alice firma su efímera con su identidad — prueba "esta efímera es mía"
const pruebaAuth = XEd25519.sign(
  aliceIdentidad.privateKey,
  aliceEfimera.publicKey,
);

// Bob verifica la autorización:
// 1. Tiene la clave pública de identidad de Alice de fuente confiable
// 2. Recibe la efímera + firma
try {
  XEd25519.verify(aliceIdentidad.publicKey, aliceEfimera.publicKey, pruebaAuth);
  // ✅ Bob confía que la efímera pertenece a Alice
} catch {
  // ❌ Mallory intentó MITM con su propia efímera
}
```

### Ejemplo: Mensajes cifrados con cabeceras autenticadas (NUEVO v0.2.0)

```typescript
import { AES_GCM, secureRandom } from '@brashkie/signalis-core';

const claveSesion = derivadaDesdeECDHyHKDF;

function enviarMensaje(cuerpo: Buffer, msgId: number) {
  const nonce = secureRandom(12);
  const cabecera = Buffer.from(JSON.stringify({
    msg_id: msgId,
    timestamp: Date.now(),
    emisor: 'alice',
  }));

  // Cabecera autenticada pero NO cifrada (receptor la necesita en claro)
  const cifrado = AES_GCM.encryptWithAad(claveSesion, nonce, cuerpo, cabecera);

  return { cabecera, nonce, cifrado };
}

function recibirMensaje(paquete: { cabecera: Buffer; nonce: Buffer; cifrado: Buffer }) {
  // Falla la descifrado si SE MODIFICÓ ciphertext O cabecera
  return AES_GCM.decryptWithAad(
    claveSesion,
    paquete.nonce,
    paquete.cifrado,
    paquete.cabecera,
  );
}
```

---

## 🏗️ Arquitectura

```
@brashkie/signalis-core
│
├── 🦀 Workspace Rust (8 crates)
│   ├── sc-curve25519    →  Operaciones X25519 ECDH
│   ├── sc-ed25519       →  Firmas Ed25519 (RFC 8032) — NUEVO v0.2.0
│   ├── sc-xed25519      →  Firmas XEd25519 estilo Signal — NUEVO v0.2.0
│   ├── sc-hkdf          →  Derivación HKDF-SHA256
│   ├── sc-aes           →  AES-256-GCM (con AAD) y CBC
│   ├── sc-hmac          →  HMAC-SHA256 con verificación tiempo-constante
│   ├── sc-sha256        →  Hashing SHA-256
│   └── sc-node          →  Bindings NAPI-RS (cdylib)
│
└── 📦 Capa TypeScript
    ├── core.ts          →  Wrappers crypto con validación
    ├── types.ts         →  Definiciones de tipos (KeyPair, Signature, etc.)
    ├── errors.ts        →  Clases de error tipadas (incl. SignatureError)
    ├── validators.ts    →  Aserciones de input
    ├── utils.ts         →  Codificación + random + helpers
    ├── constants.ts     →  Constantes públicas (tamaños, límites)
    └── index.ts         →  Superficie API pública
```

---

## 🛡️ Seguridad

### Primitivas Criptográficas

| Primitiva | Especificación | Implementación |
|-----------|---------------|----------------|
| X25519 | [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) | [`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek) |
| Ed25519 | [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) | [`ed25519-dalek`](https://github.com/dalek-cryptography/ed25519-dalek) — **NUEVO v0.2.0** |
| XEd25519 | [Signal Spec](https://signal.org/docs/specifications/xeddsa/) | Impl custom sobre `curve25519-dalek` — **NUEVO v0.2.0** |
| HKDF-SHA256 | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | [`hkdf`](https://github.com/RustCrypto/KDFs) |
| AES-256-GCM | [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) | [`aes-gcm`](https://github.com/RustCrypto/AEADs) (con soporte AAD) |
| AES-256-CBC | [NIST SP 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final) | [`aes`](https://github.com/RustCrypto/block-ciphers) |
| HMAC-SHA256 | [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) | [`hmac`](https://github.com/RustCrypto/MACs) |
| SHA-256 | [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) | [`sha2`](https://github.com/RustCrypto/hashes) |

### Propiedades de Seguridad

- ✅ **Sin código Rust `unsafe`** en nuestros wrappers
- ✅ **Tiempo constante** en comparaciones via crate `subtle`
- ✅ **Auto-borrado** de claves privadas (via crate `zeroize`)
- ✅ **CSPRNG del OS** para toda generación aleatoria
- ✅ **Vectores de test oficiales** para cada primitiva
- ✅ **CI en cada PR**: tests + clippy + `cargo audit`

### Reportar una Vulnerabilidad

**Por favor NO abras un issue público.**

Usa el [reporte privado de vulnerabilidades de GitHub](https://github.com/Brashkie/signalis-core/security/advisories/new).

Ver [SECURITY.md](./SECURITY.md) para la política completa.

---

## ⚡ Rendimiento

Benchmarks (Node 22, x86_64):

| Operación | Throughput | vs. JS puro |
|-----------|------------|-------------|
| Generación keypair Curve25519 | ~50,000 ops/seg | **15×** más rápido que tweetnacl |
| X25519 ECDH | ~25,000 ops/seg | **20×** más rápido |
| Ed25519 firmar | ~25,000 ops/seg | **20×** más rápido — NUEVO v0.2.0 |
| Ed25519 verificar | ~10,000 ops/seg | **15×** más rápido — NUEVO v0.2.0 |
| XEd25519 firmar | ~20,000 ops/seg | — — NUEVO v0.2.0 |
| XEd25519 verificar | ~10,000 ops/seg | — — NUEVO v0.2.0 |
| Derivación HKDF (32 bytes) | ~500,000 ops/seg | **30×** más rápido |
| AES-256-GCM cifrado (1 KB) | ~2 GB/seg | **80×** más rápido |
| AES-GCM con AAD | <5% overhead vs sin AAD | — NUEVO v0.2.0 |
| SHA-256 (1 KB) | ~3 GB/seg | **50×** más rápido |
| HMAC-SHA256 (1 KB) | ~2.5 GB/seg | **40×** más rápido |

---

## 🧪 Testing

```bash
# Suite completa (Rust + Vitest + Dual ESM/CJS)
npm test

# Reporte de cobertura
npm run test:coverage

# Abrir HTML de cobertura
npm run coverage:open
```

### Cobertura

| Archivo | Statements | Branches | Functions | Lines |
|---------|-----------|----------|-----------|-------|
| `core.ts` | 99% | 97% | 100% | 99% |
| `constants.ts` | 100% | 100% | 100% | 100% |
| `errors.ts` | 100% | 100% | 100% | 100% |
| `utils.ts` | 100% | 100% | 100% | 100% |
| `validators.ts` | 100% | 100% | 100% | 100% |
| **Total** | **~99%** | **~97%** | **100%** | **~99%** |

---

## 🔨 Compilar desde Fuente

```bash
# Clonar
git clone https://github.com/Brashkie/signalis-core.git
cd signalis-core

# Instalar dependencias
npm install

# Build (release)
npm run build

# Build (debug)
npm run build:debug

# Tests
npm test

# Ejemplos
npm run examples
```

**Prerequisitos:**
- Rust 1.80+ (`rustup install stable`)
- Node.js 18+
- Herramientas de compilación C/C++:
  - Windows: [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
  - macOS: `xcode-select --install`
  - Linux: `apt install build-essential`

---

## 🗺️ Roadmap

Ver [ROADMAP.md](./ROADMAP.md) para detalles.

**TL;DR:**
- **v0.1** ✅ — Primitivas criptográficas (Curve25519, HKDF, AES, HMAC, SHA-256)
- **v0.2** ✅ — Ed25519, XEd25519, AES-GCM con AAD (release actual)
- **v0.3** — Benchmarks, soporte X448, más vectores de test
- **v1.0** — API estable, auditoría externa
- **Luego:** [@brashkie/signalis](https://github.com/Brashkie/signalis) (X3DH + Double Ratchet)
- **Luego:** [@brashkie/waproto](https://github.com/Brashkie/waproto) (Protocolo WhatsApp)
- **Luego:** HepeinBaileys 2.0 (cliente WhatsApp completo desde cero)

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Ver [CONTRIBUTING.md](./CONTRIBUTING.md).

**El código criptográfico requiere cuidado extra.** Todo PR que toque crypto debe:
- Pasar todos los vectores RFC/NIST
- Incluir tests relevantes de seguridad
- Ser revisado antes de merge

Por favor también lee nuestro [Código de Conducta](./CODE_OF_CONDUCT.md).

---

## 🙏 Agradecimientos

Construido sobre los hombros de gigantes:

- **[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)** — Curve25519 en Rust puro
- **[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)** — Ed25519 en Rust puro (agregado en v0.2.0)
- **[RustCrypto](https://github.com/RustCrypto)** — `aes`, `hkdf`, `hmac`, `sha2`
- **[napi-rs](https://napi.rs)** — Bindings Rust ↔ Node
- **Signal Foundation** — [Especificaciones del protocolo](https://signal.org/docs/) (incluyendo [XEd25519](https://signal.org/docs/specifications/xeddsa/))
- **[tsup](https://tsup.egoist.dev/)** — Bundler dual ESM/CJS
- **[Vitest](https://vitest.dev/)** — Test runner moderno

---

## 📄 Licencia

**Apache License 2.0** © [Brashkie](https://github.com/Brashkie)

Ver [LICENSE](./LICENSE) y [NOTICE](./NOTICE) para detalles completos.

---

<div align="center">

**Construido con 🦀 por [Hepein](https://github.com/Brashkie)**

[GitHub](https://github.com/Brashkie) · [npm](https://www.npmjs.com/~brashkie)

</div>