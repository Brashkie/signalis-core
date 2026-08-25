# 🎉 signalis-core v0.5.0 — BLAKE3 (cierra Fase 4)

## 🏁 El Hito

Este es el **0.5.0** que veníamos reservando. BLAKE3 completa **Fase 4 → 9/9
(100%)**: todas las primitivas modernas listas. Y cruzamos el 50% total del roadmap.

## 🎯 Qué Trae — BLAKE3 (3 modos)

```
BLAKE3.hash(data)                        → 32 bytes (hash rápido)
BLAKE3.keyedHash(key32, data)            → MAC (alternativa a HMAC)
BLAKE3.keyedHashVerify(key32, data, tag) → boolean (constant-time)
BLAKE3.deriveKey(context, keyMaterial)   → 32 bytes (alternativa a HKDF)
```

El modo XOF (salida variable) queda deliberadamente afuera (futuro).

## 🏗️ Qué Cambió (Toca Rust)

| Capa | Cambio |
|------|--------|
| **nuevo crate** `sc-blake3` | sobre el crate oficial `blake3`, 3 modos + verify constant-time |
| workspace | + member, + dep `blake3 1`, + dep interna |
| `sc-node` | bindings `blake3_hash`, `blake3_keyed_hash`, `blake3_keyed_hash_verify`, `blake3_derive_key` |
| `core.ts` / `index.ts` | namespace `BLAKE3` + exports |
| tests | `blake3.test.ts` |
| README EN + ES | sección API + What's New (marca cierre de Fase 4) |

## ✅ Verificado Por Claude

```
✅ KATs oficiales de BLAKE3 (los 3 modos, inputs de 0/1/1024 bytes):
   hash('')       = af1349b9...41f3262  (coincide con vector oficial)
   keyed_hash('') = 92b2b756...ed60d26
   derive_key('') = 2cc39783...b7e50d7d
✅ Verificado con la lib oficial blake3 (Python) end-to-end → 13 tests pasan
✅ 7 tests Rust (KATs 3 modos + verify + separación de modos)
✅ keyed_hash usa verify en tiempo constante (es un MAC)
✅ napi casing verificado: blake3_hash→blake3Hash, blake3_keyed_hash→blake3KeyedHash,
   blake3_derive_key→blake3DeriveKey (limpios, el 3 queda al final de "blake3")
✅ typecheck + eslint limpios
```

## 🚀 Publicar v0.5.0

**⚠️ Toca Rust** (crate nuevo + bindings):

```powershell
cd F:\Brashkie\PROYECTOS\NPM\signalis-core
# Extraer el zip encima

cargo build            # Cargo.lock con el crate blake3 nuevo
npm run test:rust      # incl. los 7 tests de sc-blake3 (KATs oficiales)
npm run build:native   # regenera binding con las 4 funciones blake3
npm run build          # ⚠️ regenera dist con VERSION 0.5.0
npm test               # rust + vitest (incl. blake3) + dual
npm run test:coverage

git add -A             # ⚠️ desde la RAÍZ del repo
git commit -m "feat: BLAKE3 (hash/keyed_hash/derive_key) — closes Phase 4 (v0.5.0)

New sc-blake3 crate + BLAKE3 namespace over the official blake3 crate: hash,
keyed_hash (MAC, constant-time verify), and derive_key (KDF). Verified against
official BLAKE3 test vectors. Completes Phase 4 (9/9 modern primitives)."
git push origin main

# ⚠️ ANTES del tag, confirmá la versión del commit:
git show HEAD:package.json | Select-String '"version"'   # debe decir 0.5.0

# CI verde → git tag v0.5.0 && git push origin v0.5.0
```

## ✅ Confirmar Después

```powershell
npm install @brashkie/signalis-core@0.5.0
node -e "const c=require('@brashkie/signalis-core'); const h=c.BLAKE3.hash(Buffer.from('')); console.log('BLAKE3 KAT ok:', h.toString('hex')==='af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262')"
# → BLAKE3 KAT ok: true
```

## 📋 Roadmap — Después Del 0.5.0

```
✅ Fase 1 (foundation): completa + endurecida
✅ Fase 3 (utilities): completa
✅ Fase 4 (modern primitives): COMPLETA (9/9) 🎉
🔜 Fase 6 (hardening): Miri, sanitizers, side-channel review
🔜 Fase 5 (performance): sha2 0.11 documentado
🍎 Fase 2: Apple binding (futuro)
🔜 BLAKE3 XOF si más adelante lo necesitás
```

---

🎉 **Fase 4 cerrada. Felicitaciones por el 0.5.0.**

🦀 + ❤️ Hepein Oficial
