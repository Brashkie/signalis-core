# 🦀 signalis-core v0.4.10 — SHA-3 (SHA3-256 + SHA3-512)

## 🎯 Qué Trae

**SHA-3** (FIPS 202, basado en Keccak) — estructuralmente distinto de SHA-2.
Namespace `SHA3` con las dos variantes más usadas:

```
SHA3.hash256(data)     → 32 bytes (SHA3-256)
SHA3.hash512(data)     → 64 bytes (SHA3-512)
SHA3.hash256All([...]) → hash de buffers concatenados
```

## 🏗️ Qué Cambió (Toca Rust)

| Capa | Cambio |
|------|--------|
| **nuevo crate** `sc-sha3` | sobre el `sha3` auditado (RustCrypto), SHA3-256 + SHA3-512 + hashers streaming |
| workspace | + member, + dep `sha3 0.10`, + dep interna |
| `sc-node` | bindings `sha3256` / `sha3512` |
| `core.ts` / `index.ts` | namespace `SHA3` + exports |
| tests | `sha3.test.ts` |
| README EN + ES | sección API + What's New |

## ✅ Verificado Por Claude

```
✅ KATs oficiales de NIST FIPS 202 (los 4 coinciden):
   SHA3-256('')   = a7ffc6f8...80f8434a
   SHA3-256('abc')= 3a985da7...11431532
   SHA3-512('')   = a69f73cc...281dcd26
   SHA3-512('abc')= b751850b...eec53f0
✅ Verificado con hashlib Y contra Node crypto (sha3-256/sha3-512)
✅ Harness end-to-end vs Node crypto → 8 tests pasan
✅ 6 tests Rust (KATs + streaming)
✅ typecheck + eslint limpios
```

## 🔑 Nota Sobre El Naming Del Binding

Nombré las funciones del binding `sha3256` / `sha3512` **sin guión bajo** antes
de los dígitos, a propósito: así napi NO hace conversión snake→camel y el nombre
JS es idéntico garantizado (`native.sha3256`). Elimina el riesgo de casing que
tuvimos con `argon2IdDerive`.

## 🚀 Publicar v0.4.10

**⚠️ Toca Rust** (crate nuevo + bindings):

```powershell
cd F:\Brashkie\PROYECTOS\NPM\signalis-core
# Extraer el zip encima

cargo build            # Cargo.lock con el crate sha3 nuevo
npm run test:rust      # incl. los 6 tests de sc-sha3 (KATs NIST)
npm run build:native   # regenera binding con sha3256/sha3512
npm run build          # ⚠️ regenera dist con VERSION 0.4.10
npm test               # rust + vitest (incl. sha3) + dual
npm run test:coverage

git add -A             # ⚠️ desde la RAÍZ del repo
git commit -m "feat: SHA-3 (SHA3-256 + SHA3-512) (v0.4.10)

New sc-sha3 crate + SHA3 namespace, built on the audited RustCrypto sha3 crate.
Verified against NIST FIPS 202 KATs. Phase 4 → 8/9 (only BLAKE3 remains)."
git push origin main

# ⚠️ ANTES del tag, confirmá la versión del commit:
git show HEAD:package.json | Select-String '"version"'   # debe decir 0.4.10

# CI verde → git tag v0.4.10 && git push origin v0.4.10
```

## ✅ Confirmar Después

```powershell
npm install @brashkie/signalis-core@0.4.10
node -e "const c=require('@brashkie/signalis-core'); const h=c.SHA3.hash256(Buffer.from('abc')); console.log('SHA3-256 KAT ok:', h.toString('hex')==='3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532')"
# → SHA3-256 KAT ok: true
```

## 📋 Roadmap

```
✅ Fase 4: 8/9 (+ SHA-3)
🎯 Falta SOLO BLAKE3 para cerrar Fase 4 → ese es el 0.5.0 con sustancia
```

---

🦀 + ❤️ Hepein Oficial
