# 🚀 Setup GitHub Actions Multi-Platform — Guía Para Ti

Este documento te guía para configurar el sistema profesional de builds multi-plataforma con GitHub Actions y publish automático a npm.

## 📋 Lo Que Ya Tienes

```
.github/
└── workflows/
    ├── ci.yml         ← Tests en cada PR
    └── release.yml    ← Publica a npm cuando creas un tag v*
```

## 🎯 Lo Que Vas a Hacer

```
1. ✅ Crear NPM_TOKEN en npmjs.com
2. ✅ Agregar NPM_TOKEN como secret en GitHub
3. ✅ Push de los workflows
4. ✅ Crear primer release con tag v0.1.0
5. ✅ GitHub Actions construye en 11 plataformas
6. ✅ GitHub Actions publica a npm automáticamente
7. 🎉 Tu paquete disponible en TODO el mundo
```

---

## 📝 Paso 1: Crear NPM Access Token

### 1.1 Login en npmjs.com

Ve a https://www.npmjs.com/ y haz login.

### 1.2 Crear token

1. Click en tu avatar (esquina superior derecha)
2. **Access Tokens** → **Generate New Token** → **Classic Token**
3. **Nombre**: `signalis-core-github-actions`
4. **Type**: 
   - ⦿ **Automation** ✅ (para CI/CD, no requiere 2FA)
   - ○ Publish (requiere OTP cada vez)
5. **Expiration**: 365 days (renovar anualmente)
6. Click **Generate Token**

### 1.3 Copiar el token

Te mostrará algo como:
```
npm_1234567890abcdefghijklmnopqrstuvwxyz
```

**⚠️ Cópialo AHORA**, solo lo verás una vez.

---

## 🔐 Paso 2: Agregar Secret en GitHub

### 2.1 Ir a Settings del repo

```
https://github.com/Brashkie/signalis-core/settings/secrets/actions
```

### 2.2 Crear secret

1. Click **New repository secret**
2. **Name**: `NPM_TOKEN` (exactamente así, mayúsculas)
3. **Value**: pega el token que copiaste de npm
4. Click **Add secret**

### 2.3 Verificar

Deberías ver:
```
Repository secrets
└── 🔒 NPM_TOKEN    Updated now
```

---

## 🚀 Paso 3: Push de los Workflows

```powershell
cd F:\Brashkie\PROYECTOS\NPM\signalis-core

# Aplicar el ZIP con workflows + package.json actualizado

# Verificar archivos nuevos
git status
# Deberías ver:
#   modified: .github/workflows/ci.yml
#   new file: .github/workflows/release.yml
#   modified: package.json

# Commit
git add .
git commit -m "ci: add multi-platform GitHub Actions workflows

- ci.yml: build + test on 11 platforms in every PR
- release.yml: auto-publish to npm on git tag v*
- package.json: add optionalDependencies for platform packages"

git push origin main
```

---

## 🎯 Paso 4: Crear Primer Release (Auto-Publica a npm)

### 4.1 Verificar versión

```powershell
# Ver versión actual
node -p "require('./package.json').version"
# Output: 0.1.0
```

### 4.2 Crear tag y push

```powershell
# Crear tag local
git tag v0.1.0

# Push del tag (esto TRIGGERIA el workflow de release)
git push origin v0.1.0
```

### 4.3 Ver el progreso

Ve a:
```
https://github.com/Brashkie/signalis-core/actions
```

Verás el workflow **Release** corriendo:

```
🟡 Release v0.1.0
├── 🟡 Build - aarch64-apple-darwin       (~5 min)
├── 🟡 Build - x86_64-apple-darwin        (~5 min)
├── 🟡 Build - x86_64-pc-windows-msvc     (~7 min)
├── 🟡 Build - aarch64-pc-windows-msvc    (~7 min)
├── 🟡 Build - i686-pc-windows-msvc       (~7 min)
├── 🟡 Build - x86_64-unknown-linux-gnu   (~6 min)
├── 🟡 Build - x86_64-unknown-linux-musl  (~6 min)
├── 🟡 Build - aarch64-unknown-linux-gnu  (~8 min)
├── 🟡 Build - aarch64-unknown-linux-musl (~8 min)
├── 🟡 Build - armv7-unknown-linux-gnueabihf (~8 min)
├── 🟡 Build - aarch64-linux-android      (~6 min)
└── 🟡 Publish to npm                     (después de todos)
```

**Tiempo total estimado: 15-20 minutos** (corren en paralelo)

### 4.4 Cuando termine

Verás:
```
✅ Release v0.1.0
├── ✅ All builds passed
└── ✅ Published @brashkie/signalis-core@0.1.0
```

### 4.5 Verificar en npm

```powershell
# Esperar 1-2 minutos
npm view @brashkie/signalis-core
```

Deberías ver el paquete con todas las plataformas listadas.

URL pública:
```
https://www.npmjs.com/package/@brashkie/signalis-core
```

---

## 🧪 Paso 5: Probar en Diferentes Plataformas

### En Windows (donde ya estás):

```powershell
mkdir test-signalis
cd test-signalis
npm init -y
npm install @brashkie/signalis-core

node -e "const sc = require('@brashkie/signalis-core'); console.log('✅', sc.VERSION); console.log(sc.SHA256.hash(Buffer.from('test')).toString('hex'));"
```

### En macOS / Linux:

Si tienes acceso a una Mac o Linux:
```bash
mkdir test-signalis && cd test-signalis
npm init -y
npm install @brashkie/signalis-core
```

**npm automáticamente descarga el binario correcto** según la plataforma.

---

## 🔄 Workflow Normal de Releases Futuros

Cuando quieras publicar una nueva versión:

### Para parches (0.1.0 → 0.1.1)

```powershell
# Bump version
npm version patch
# Esto:
#   1. Actualiza package.json a 0.1.1
#   2. Crea commit "0.1.1"
#   3. Crea tag v0.1.1

# Push con tags
git push --follow-tags
```

### Para minor (0.1.0 → 0.2.0)

```powershell
npm version minor
git push --follow-tags
```

### Para major (0.1.0 → 1.0.0)

```powershell
npm version major
git push --follow-tags
```

**El workflow `release.yml` se dispara automáticamente** con el push del tag.

---

## 📊 Monitoreo

### GitHub Actions

```
https://github.com/Brashkie/signalis-core/actions
```

Aquí ves:
- ✅ Tests pasando en cada PR
- 🚀 Releases publicados
- ⏱️ Tiempos de build
- ❌ Fallos (si los hay)

### NPM Downloads

```
https://www.npmjs.com/package/@brashkie/signalis-core
```

Ve descargas semanales, versiones publicadas, etc.

### Badge para README

Actualiza tu README con badge real:
```markdown
[![CI](https://github.com/Brashkie/signalis-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Brashkie/signalis-core/actions/workflows/ci.yml)
[![Release](https://github.com/Brashkie/signalis-core/actions/workflows/release.yml/badge.svg)](https://github.com/Brashkie/signalis-core/actions/workflows/release.yml)
```

---

## 🚨 Troubleshooting

### Build falla en Linux ARM
**Causa**: Docker image lenta de descargar
**Solución**: Re-run el workflow desde GitHub Actions UI

### "401 Unauthorized" al publicar
**Causa**: NPM_TOKEN inválido o expirado
**Solución**: Crear nuevo token en npmjs.com y actualizar el secret

### "Package already exists"
**Causa**: Ya publicaste esa versión
**Solución**: Bump la versión con `npm version patch`

### Algunas plataformas fallan
**Causa**: Issue específico (ej: ARM toolchain)
**Solución**: Marcar `continue-on-error: true` en esa plataforma temporalmente

---

## 🎯 Resumen Visual

```
┌────────────────────────────────────────────────────────────┐
│                                                            │
│   git tag v0.1.0                                          │
│   git push origin v0.1.0                                  │
│            │                                              │
│            ▼                                              │
│   ┌─────────────────────┐                                 │
│   │  GitHub Actions     │                                 │
│   │  release.yml        │                                 │
│   └─────────────────────┘                                 │
│            │                                              │
│            ├─── 🪟 Windows x64 binary                     │
│            ├─── 🪟 Windows arm64 binary                   │
│            ├─── 🍎 macOS x64 binary                       │
│            ├─── 🍎 macOS arm64 binary                     │
│            ├─── 🐧 Linux x64 GNU binary                   │
│            ├─── 🐧 Linux x64 musl binary                  │
│            ├─── 🐧 Linux arm64 GNU binary                 │
│            └─── 🤖 Android arm64 binary                   │
│                       │                                   │
│                       ▼                                   │
│            ┌─────────────────────┐                       │
│            │  Publish to npm     │                       │
│            └─────────────────────┘                       │
│                       │                                   │
│                       ▼                                   │
│            ┌─────────────────────┐                       │
│            │  GitHub Release     │                       │
│            └─────────────────────┘                       │
│                                                          │
└────────────────────────────────────────────────────────────┘
```

---

## ✅ Checklist Final

- [ ] NPM_TOKEN creado en npmjs.com
- [ ] NPM_TOKEN agregado como secret en GitHub
- [ ] Workflows aplicados al repo
- [ ] package.json actualizado con optionalDependencies
- [ ] Push de los cambios a `main`
- [ ] Tag v0.1.0 creado y pusheado
- [ ] Workflow `Release` ejecutándose en GitHub Actions
- [ ] Esperar 15-20 minutos
- [ ] Verificar paquete en npmjs.com
- [ ] Probar instalación: `npm install @brashkie/signalis-core`
- [ ] 🎉 Celebrar

---

🦀 **Brashkie, este es el flujo profesional que usan Prisma, SWC, Parcel, etc.**

Configura los pasos 1-3, después haz el primer release, y compárteme:
1. Output del workflow en GitHub Actions
2. Link a tu paquete publicado en npm

¡Vamos a hacerlo! 🚀
