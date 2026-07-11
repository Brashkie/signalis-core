# 📝 Signalis Core v0.4.0 — Docs Update

## 🎯 Lo Que Trae

3 archivos de documentación actualizados para v0.4.0:

| Archivo | Cambios |
|---------|---------|
| `README.md` (EN) | Sección "What's New v0.4.0" + tabla de plataformas 10 + Base64/Hex/Utf8 en API Reference + Cross-Platform row |
| `README.es.md` (ES) | Espejo del inglés, todo traducido con estilo natural en español |
| `ROADMAP.md` | **Reescrito completamente** con formato de fases (12 phases) tal como me mandaste, con `[x]` marcados hasta v0.4.0 |

## 📊 Detalle De Cambios

### README.md (inglés)

**Nueva sección "What's New in v0.4.0":**
- Tabla de features nuevos con emojis 🆕
- Ejemplo de código Base64/Hex/Utf8
- Explicación de por qué UTF-8 strict validation importa
- Casos de uso de Android x86_64 (Emulator, Chromebooks, tablets)

**Tabla de plataformas actualizada:**
- De 9 → 10 platforms
- Nueva fila para `signalis-core-android-x64` marcada 🆕 v0.4.0
- Actualizado el "Coming in future releases" (sacado v0.4.0, agregado RISC-V)
- Sección "Android Installation" ampliada con casos Chromebook + Emulator

**API Reference:**
- Nueva sección "Base64 / Hex / UTF-8 🆕" insertada antes de HMAC-SHA256
- Ejemplos de código para cada namespace
- Sección "Why not just use Node's `Buffer.toString('base64')`?" con la comparación honesta
- Nota de performance (NAPI overhead vs Buffer.toString built-in)

**Table of Contents:**
- Agregada entrada "What's New in v0.4.0"

**Feature table:**
- Cross-Platform row menciona `arm64/armv7/x86_64` en Android

### README.es.md (español)

Mismo patrón que el inglés pero traducido:
- "Novedades en v0.4.0" al inicio
- Tabla 10 platforms con las mismas 🆕 v0.4.0 marcas
- Sección API "Base64 / Hex / UTF-8 🆕" antes de HMAC-SHA256
- Fila "Multi-Plataforma" con Android arm64/armv7/x86_64

### ROADMAP.md (reescrito completo)

**Antes:** roadmap "por versión" (v0.1.0, v0.2.0, ...) — poco escalable.

**Ahora:** roadmap "por fases" (Phase 1-12) — el formato que me mandaste. Ventajas:
- Fácil ver qué falta en cada área (crypto, platform, security, etc.)
- Cada fase tiene checkboxes `[x]` / `[ ]` con annotations "(v0.3.0)" para saber en qué release entró cada item
- Al final: tabla de progreso global (44/119 = 37%)
- Sección "Near-term Focus" con menú de candidatos para v0.5.0
- Sección "Notes on Deferred Items" con explicación honesta de por qué iOS y WASM están donde están

**Items marcados `[x]` que refleja v0.4.0:**
- Phase 2: Android x86_64 (10/14 targets)
- Phase 3: Base64, Hex, UTF-8 (6/11 utilities)
- Phase 7: `sc-encoding` crate agregado (6/8 modular)

## 🚀 Aplicar

```powershell
cd F:\Brashkie\PROYECTOS\NPM\signalis-core

# Extraer signalis-core-v0.4.0-docs.zip (sobrescribe 3 archivos)

# Verificar preview local
code README.md README.es.md ROADMAP.md
# Ctrl+Shift+V en VS Code para markdown preview

# Verificar links internos con VS Code Markdown Preview
# (tabla de contenidos debe navegar correctamente)
```

## ✅ Commit

```powershell
git add README.md README.es.md ROADMAP.md
git commit -m "docs: update README (EN + ES) + ROADMAP for v0.4.0

- README.md: What's New v0.4.0 section, 10-platform table, Base64/Hex/Utf8 API docs
- README.es.md: mirrors English version in Spanish
- ROADMAP.md: rewritten with 12-phase format, [x] marks up to v0.4.0
  Total progress: 44/119 items (37%)"

git push origin main
```

## 🎯 Próximos Documentos A Actualizar (Opcional, No Bloqueante)

Cuando tengas tiempo, también podrías actualizar:

- `MIGRATION.md` — agregar sección "Upgrading to v0.4.0" (drop-in, solo aditivo)
- `docs/api-reference.md` (si existe) — detalles de Base64/Hex/Utf8

Pero ninguno bloquea el release. Los usuarios reales llegan por README + CHANGELOG.

---

🔐 + ❤️ Hepein Oficial
