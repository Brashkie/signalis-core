# 🚀 signalis-core v0.2.0 — Apply Instructions

## 📋 Archivos Incluidos

```
signalis-core-v0.2.0/
├── Cargo.toml                          ← Workspace v0.2.0
├── CHANGELOG.md                        ← Documentación de cambios
├── package-json-changes.md             ← Cambios a aplicar en package.json
│
├── crates/
│   ├── sc-ed25519/                     ← NUEVO crate Rust
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── sc-xed25519/                    ← NUEVO crate Rust
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── sc-aes/                         ← ACTUALIZADO (agrega AAD)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── sc-node/                        ← ACTUALIZADO (NAPI bindings)
│       ├── Cargo.toml
│       ├── build.rs
│       └── src/lib.rs
│
├── src/
│   ├── index.ts                        ← ACTUALIZADO (exports v0.2.0)
│   ├── constants.ts                    ← ACTUALIZADO (nuevas constantes)
│   └── core.ts                         ← ACTUALIZADO (Ed25519, XEd25519, AAD)
│
└── __tests__/
    ├── ed25519.test.ts                 ← NUEVO
    ├── xed25519.test.ts                ← NUEVO
    └── aes-gcm-aad.test.ts             ← NUEVO
```

## 🎯 Pasos Para Aplicar

### Paso 1: Backup (CRUCIAL)

```powershell
cd F:\Brashkie\PROYECTOS\NPM\signalis-core
git status
git add .
git commit -m "Checkpoint before v0.2.0 upgrade"
git tag backup-pre-v0.2.0
```

### Paso 2: Aplicar Archivos

**Cargo.toml (raíz):**
- Reemplazar completamente con el del ZIP

**Crates nuevos:**
- Copiar `crates/sc-ed25519/` completo
- Copiar `crates/sc-xed25519/` completo

**Crates actualizados:**
- Reemplazar `crates/sc-aes/Cargo.toml` y `src/lib.rs`
- Reemplazar `crates/sc-node/Cargo.toml`, `build.rs`, y `src/lib.rs`

**TypeScript:**
- Reemplazar `src/constants.ts`
- Reemplazar `src/index.ts`
- Reemplazar `src/core.ts`
- (NO toques `src/errors.ts`, `src/utils.ts`, `src/validators.ts` — no cambian)

**Tests:**
- Agregar `__tests__/ed25519.test.ts`
- Agregar `__tests__/xed25519.test.ts`
- Agregar `__tests__/aes-gcm-aad.test.ts`

**Documentación:**
- Copiar `CHANGELOG.md` a la raíz
- Actualizar `package.json` según `package-json-changes.md`

### Paso 3: Verificar Cargo Build

```powershell
# Construir Rust
cargo build --release

# Si hay errores, repórtamelos
```

### Paso 4: Construir el módulo nativo

```powershell
# Crear el .node file
npm run build:native

# Esto debería generar signalis-core.win32-x64-msvc.node
```

### Paso 5: Construir TypeScript

```powershell
npm run build:ts
```

### Paso 6: Tests Locales (RAPID CHECK)

```powershell
npm test
```

**Resultado esperado:**
```
✓ existing v0.1.0 tests (27)
✓ ed25519.test.ts (~16 new)
✓ xed25519.test.ts (~14 new)
✓ aes-gcm-aad.test.ts (~9 new)

Test Files  N passed (N)
     Tests  ~66 passed (~66)
```

### Paso 7: Commit + Tag

```powershell
git add .
git commit -m "feat: v0.2.0 - Add Ed25519, XEd25519, and AES-GCM with AAD"
git tag v0.2.0
git push origin main
git push origin v0.2.0
```

### Paso 8: GitHub Actions Build

El workflow CI/CD ya está configurado. Al pushear el tag `v0.2.0`:

1. ✅ Build automático para 7 plataformas
2. ✅ Tests en cada plataforma
3. ✅ Publish a npm

**Espera ~30-40 min para el build completo**, luego verifica:
- https://github.com/Brashkie/signalis-core/actions
- https://www.npmjs.com/package/@brashkie/signalis-core

### Paso 9: Verificar publicación

```powershell
# En carpeta de pruebas
cd F:\Brashkie\PROYECTOS\PRUEBAS

npm install @brashkie/signalis-core@latest

node -e "const sc = require('@brashkie/signalis-core'); console.log('Version:', sc.VERSION); console.log('Native:', sc.nativeVersion);"
```

**Resultado esperado:**
```
Version: 0.2.0
Native: 0.2.0
```

## 🧪 Test Rápido Post-Publicación

```typescript
import { Curve25519, Ed25519, XEd25519, AES_GCM } from '@brashkie/signalis-core';

// 1. Ed25519 funciona
const ed = Ed25519.generateKeyPair();
const sig1 = Ed25519.sign(ed.privateKey, Buffer.from('test'));
Ed25519.verify(ed.publicKey, Buffer.from('test'), sig1);
console.log('✅ Ed25519 OK');

// 2. XEd25519 con Curve25519 keys
const x = Curve25519.generateKeyPair();
const sig2 = XEd25519.sign(x.privateKey, Buffer.from('test'));
XEd25519.verify(x.publicKey, Buffer.from('test'), sig2);
console.log('✅ XEd25519 OK');

// 3. AES-GCM con AAD
const key = sc.secureRandom(32);
const nonce = sc.secureRandom(12);
const ct = AES_GCM.encryptWithAad(key, nonce, Buffer.from('msg'), Buffer.from('aad'));
const pt = AES_GCM.decryptWithAad(key, nonce, ct, Buffer.from('aad'));
console.log('✅ AES-GCM AAD OK');
```

## ⚠️ Posibles Problemas

### Error: "edition2024 not supported"

Si tu Rust es viejo (1.78 o menor):
```powershell
rustup update stable
rustc --version  # debe ser 1.82+
```

### Error en sc-xed25519: "hazmat feature"

`ed25519-dalek` requiere feature `hazmat` para low-level access. Si falla:
```toml
# Verificar en crates/sc-xed25519/Cargo.toml
ed25519-dalek = { workspace = true, features = ["hazmat"] }
```

### Error: "cannot find function 'curve25519GenerateKeypair'"

Significa que el build de TypeScript se ejecutó ANTES del build nativo.
```powershell
npm run build:native  # PRIMERO
npm run build:ts      # DESPUÉS
# O usa:
npm run build         # Hace ambos en orden
```

## 🎯 Después de Publicar v0.2.0

Cuando v0.2.0 esté en npm, vamos a:

1. ✅ Actualizar `@brashkie/signalis` para usar XEd25519 (en vez de HMAC)
2. ✅ Quitar todas las notas de "v0.1.0 limitation"
3. ✅ Tests verificarán con PUBLIC key (no private)
4. ✅ Empezar **Sprint 2: X3DH** sin restricciones

## 📊 Resumen

```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   📦 signalis-core v0.2.0                                  ║
║                                                            ║
║   New Primitives:                                          ║
║   ✅ Ed25519 (RFC 8032 compliant)                          ║
║   ✅ XEd25519 (Signal Protocol style)                      ║
║   ✅ AES-GCM with AAD                                      ║
║                                                            ║
║   New Constants:                                           ║
║   ✅ ED25519_*, XED25519_*, SHARED_SECRET_SIZE             ║
║                                                            ║
║   Rust Crates:                                             ║
║   ✅ sc-ed25519 (~250 lines)                               ║
║   ✅ sc-xed25519 (~290 lines)                              ║
║   ✅ sc-aes updated (+100 lines for AAD)                   ║
║   ✅ sc-node updated (+150 lines NAPI bindings)            ║
║                                                            ║
║   TypeScript:                                              ║
║   ✅ Full namespace API                                    ║
║   ✅ All sizes as constants                                ║
║   ✅ Validation everywhere                                 ║
║                                                            ║
║   Tests:                                                   ║
║   ✅ ~39 new tests across 3 files                          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```
