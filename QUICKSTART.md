# 🚀 Quickstart - Signalis Core

## 📁 Estructura del Proyecto

```
signalis-core/                       ← RAÍZ
├── Cargo.toml                       ← Workspace Rust
├── package.json                     ← NPM (raíz, no en subcarpeta)
├── tsconfig.json
├── vitest.config.ts
├── .gitignore
├── README.md
├── LICENSE
│
├── src/                             ← TypeScript wrapper
│   └── index.ts
│
├── __tests__/                       ← Tests Vitest
│   └── index.test.ts
│
├── index.js                         ← AUTO-GENERADO por napi (no commitear)
├── index.d.ts                       ← AUTO-GENERADO por napi (no commitear)
├── *.node                           ← AUTO-GENERADO (binario nativo)
│
├── crates/                          ← Rust workspace members
│   ├── sc-curve25519/
│   ├── sc-hkdf/
│   ├── sc-aes/
│   ├── sc-hmac/
│   ├── sc-sha256/
│   └── sc-node/                     ← Cdylib NAPI
│
└── .github/workflows/
    └── ci.yml
```

## 🛠️ Setup Inicial

```powershell
# 1. Clonar tu repo
cd F:\Brashkie\PROYECTOS\NPM
git clone https://github.com/Brashkie/signalis-core
cd signalis-core

# 2. Aplicar este ZIP

# 3. Actualizar Rust (importante: napi-rs requiere 1.80+)
rustup update stable

# 4. Verificar versión
rustc --version  # Debe ser >= 1.80
```

## 🦀 Build & Test Rust

```powershell
# Tests de las 5 crates puras (sin NAPI)
cargo test --workspace --exclude sc-node

# Build de todo el workspace
cargo build --workspace --release
```

## 📦 Build & Test NPM

```powershell
# Instalar dependencias Node
npm install

# Build del binario nativo (genera index.js, index.d.ts, *.node)
npm run build:debug

# Tests
npm test
```

## 🧪 Tu Primer Test E2E

Crea `examples/demo.ts`:

```typescript
import { Curve25519, HKDF, AES_GCM } from '../src';
import { randomBytes } from 'crypto';

console.log('🔐 Signalis Core Demo\n');

const alice = Curve25519.generateKeyPair();
const bob = Curve25519.generateKeyPair();
console.log('✅ Keypairs generados');

const aliceShared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
const bobShared = Curve25519.diffieHellman(bob.privateKey, alice.publicKey);
console.log('✅ ECDH match:', aliceShared.equals(bobShared));

const key = HKDF.derive(
  Buffer.from('demo'),
  aliceShared,
  Buffer.from('key'),
  32,
);
console.log('✅ Session key derivada');

const nonce = randomBytes(12);
const ct = AES_GCM.encrypt(key, nonce, Buffer.from('Hola mundo!'));
const pt = AES_GCM.decrypt(key, nonce, ct);
console.log('✅ Mensaje:', pt.toString());

console.log('\n🎉 ¡Funciona!');
```

```powershell
npx tsx examples/demo.ts
```

## ❓ Si Algo Falla

### Error: "cargo:: syntax requires Rust 1.77+"

```powershell
rustup update stable
rustc --version  # Debe mostrar 1.80+
```

### Error: "could not compile sc-node"

```powershell
# Limpiar y reconstruir
cargo clean
cargo build --workspace
```

### Error: "napi: command not found"

```powershell
npm install
# El comando napi viene de @napi-rs/cli (devDependency)
```

### Build de NAPI falla

```powershell
# Verificar que tienes los build tools
# Windows: instalar Visual Studio Build Tools
# https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Verificar Node
node --version  # >= 18
```

## ✅ Resultado Esperado

```
$ cargo test --workspace --exclude sc-node

   Compiling sc-curve25519 v0.1.0
   ...
running 5 tests
test test_generate_keypair ... ok
test test_diffie_hellman_agreement ... ok
test test_invalid_length_private_key ... ok
test test_public_key_serialization_roundtrip ... ok
test test_private_key_clamping ... ok

running 3 tests (RFC 7748)
test rfc7748_test_vector_1 ... ok
test rfc7748_test_vector_2 ... ok
test rfc7748_alice_bob_ecdh ... ok

running 6 tests (sc-hkdf)
...
running 2 tests (RFC 5869)
...

Total: 20+ tests passed
```

```
$ npm test

 ✓ Curve25519 (5 tests)
 ✓ HKDF (6 tests)
 ✓ AES-256-GCM (4 tests)
 ✓ AES-256-CBC (2 tests)
 ✓ HMAC-SHA256 (3 tests)
 ✓ SHA-256 (3 tests)
 ✓ Integration: Secure Channel (1 test)

 Tests  24 passed (24)
```

## 🎯 Siguientes Pasos

Después de verificar que todo compila:

1. **Push a GitHub**
   ```powershell
   git add .
   git commit -m "feat: initial Rust workspace + NAPI bindings"
   git push -u origin main
   ```

2. **Verificar CI pasa** (GitHub Actions)

3. **Publicar a crates.io** (una crate por vez):
   ```powershell
   cd crates/sc-curve25519
   cargo publish --dry-run  # Verificar
   cargo publish
   ```

4. **Publicar a npm**:
   ```powershell
   npm run build  # Build de producción
   npm publish --access public
   ```
