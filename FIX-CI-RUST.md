# 🔧 Fix: Rust Version Incompatibility in CI

## El Problema

Los workflows fallaban con:

```
error: rustc 1.82.0 is not supported by the following packages:
  napi-build@2.3.1 requires rustc 1.88
  unicode-segmentation@1.13.2 requires rustc 1.85.0
```

## Causa

- Las imágenes Docker `napi-rs/nodejs-rust` tienen Rust 1.82-1.83
- `napi-build` v2.3.1 (instalado por defecto) requiere Rust 1.88
- `cargo` no puede compilar porque la versión de Rust es muy vieja para esas deps

## La Solución (2 capas)

### Capa 1: Actualizar Rust en el container
Agregamos `rustup update stable` antes de cada build en Docker:

```yaml
build: |
  rustup update stable
  npm run build:native -- --target ...
```

Esto baja Rust 1.90+ y permite compilar `napi-build@2.3.1`.

### Capa 2: Pinear `napi-build` en Cargo.toml
Forzamos versión 2.1.3 (la última que funciona con Rust 1.82):

```toml
napi-build = "=2.1.3"  # antes: "2.1"
```

El `=` indica versión exacta, no permite que cargo escoja v2.3.x.

## Adicional: `--use-napi-cross` para ARM64

Para cross-compilation aarch64, agregamos el flag:

```yaml
build: |
  rustup update stable
  npm run build:native -- --target aarch64-unknown-linux-gnu --use-napi-cross
```

Esto le dice a `napi-cli` que use la herramienta de cross-compilation correcta sin necesitar `zig`.

## Aplicar el Fix

```powershell
# 1. Aplicar el ZIP signalis-FIX-CI-RUST.zip
# 2. Commit + push
git add .github/workflows/ Cargo.toml
git commit -m "fix(ci): pin napi-build to 2.1.3, update rust in docker"
git push origin main

# 3. Eliminar el tag anterior (opcional, para retry limpio)
git tag -d v0.1.0
git push origin :refs/tags/v0.1.0

# 4. Crear nuevo tag para retry
git tag v0.1.0
git push origin v0.1.0
```

## Resultado Esperado

- ✅ Rust se actualiza a 1.90+ en cada container
- ✅ `napi-build@2.1.3` compila sin problemas
- ✅ Cross-compilation funciona
- ✅ Builds pasan en todas las plataformas
