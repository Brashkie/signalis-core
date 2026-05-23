# 🤝 Contributing to signalis-core

Thanks for your interest in contributing! This guide will help you get started.

---

## 📋 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [How to Contribute](#-how-to-contribute)
- [Development Setup](#-development-setup)
- [Building from Source](#-building-from-source)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Code Style](#-code-style)
- [Adding New Primitives](#-adding-new-primitives)
- [Pull Request Process](#-pull-request-process)
- [Release Process](#-release-process)

---

## 📜 Code of Conduct

We follow the [Contributor Covenant](https://www.contributor-covenant.org/). Be respectful, inclusive, and constructive. Harassment, discrimination, or toxic behavior won't be tolerated.

---

## 🚀 How to Contribute

There are many ways to contribute:

| Type | What to do |
|------|------------|
| 🐛 **Bug report** | Open an issue with reproduction steps |
| 💡 **Feature request** | Open a discussion first, then an issue |
| 📖 **Docs** | Fix typos, improve examples, translate |
| 🧪 **Tests** | Add edge cases, increase coverage |
| ⚡ **Performance** | Benchmark and optimize hot paths |
| 🦀 **Rust crates** | Add new primitives (see [Roadmap](./ROADMAP.md)) |
| 💻 **TypeScript** | Improve types, add validators, helpers |
| 🛡️ **Security** | Review code, suggest hardening (see [SECURITY.md](./SECURITY.md)) |

**Before starting work** on a non-trivial change, please open an issue/discussion. This saves you time if the change doesn't fit the project direction.

---

## 🛠️ Development Setup

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Node.js | >= 18 | https://nodejs.org/ |
| Rust | >= 1.82 | https://rustup.rs/ |
| Git | Latest | https://git-scm.com/ |

### Platform-specific

**Windows:**
- Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) (C++ workload)
- Or use WSL2 for a Linux experience

**macOS:**
- Xcode Command Line Tools: `xcode-select --install`

**Linux:**
```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
```

### Clone & Install

```bash
git clone https://github.com/Brashkie/signalis-core.git
cd signalis-core
npm install
```

---

## 🏗️ Building from Source

### Quick Build

```bash
npm run build
```

This does:
1. `cargo build --release` (compile Rust)
2. `napi build --release` (generate `.node` file)
3. `tsup` (compile TypeScript → `dist/`)

### Step-by-Step

```bash
# Just Rust
npm run build:native

# Just TypeScript (requires .node file from previous step)
npm run build:ts
```

### Cross-Compilation

To build for other targets:

```bash
# Linux x64 musl (Alpine)
rustup target add x86_64-unknown-linux-musl
npm run build -- --target x86_64-unknown-linux-musl

# Linux ARM64
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu
npm run build -- --target aarch64-unknown-linux-gnu

# macOS x64 (from Apple Silicon)
rustup target add x86_64-apple-darwin
npm run build -- --target x86_64-apple-darwin
```

---

## 📁 Project Structure

```
signalis-core/
├── Cargo.toml                    # Rust workspace config
├── package.json                  # npm config + scripts
├── tsconfig.json                 # TypeScript config
├── tsup.config.ts                # Bundler config
│
├── crates/                       # Rust source
│   ├── sc-curve25519/            # ECDH primitives
│   ├── sc-ed25519/               # Standard signatures
│   ├── sc-xed25519/              # Signal-style signatures
│   ├── sc-hkdf/                  # Key derivation
│   ├── sc-aes/                   # AES-GCM + AES-CBC
│   ├── sc-hmac/                  # Message authentication
│   ├── sc-sha256/                # Hashing
│   └── sc-node/                  # NAPI bindings (glue)
│
├── src/                          # TypeScript source
│   ├── index.ts                  # Public API
│   ├── core.ts                   # Namespace wrappers
│   ├── constants.ts              # Size constants
│   ├── errors.ts                 # Error classes
│   ├── types.ts                  # Type definitions
│   ├── utils.ts                  # Encoding helpers
│   └── validators.ts             # Input validation
│
├── __tests__/                    # TypeScript tests (Vitest)
│   ├── curve25519.test.ts
│   ├── ed25519.test.ts
│   ├── xed25519.test.ts
│   ├── aes-gcm.test.ts
│   ├── aes-gcm-aad.test.ts
│   └── ...
│
├── npm/                          # Platform-specific packages
│   ├── win32-x64-msvc/
│   ├── darwin-arm64/
│   └── ...
│
├── .github/workflows/            # CI/CD
│   └── ci.yml                    # Build, test, publish
│
└── docs/                         # Additional docs
    ├── README.md
    ├── ROADMAP.md
    ├── SECURITY.md
    ├── MIGRATION.md
    └── CONTRIBUTING.md           # this file
```

---

## 🧪 Testing

### Run All Tests

```bash
npm test                # All tests once
npm run test:watch      # Watch mode
npm run test:coverage   # With coverage report
```

### Run Specific Tests

```bash
# Single file
npm test ed25519

# Pattern
npm test -- --testPathPattern=signatures
```

### Rust Tests

```bash
cd crates/sc-ed25519
cargo test

# All Rust tests
cargo test --workspace
```

### Coverage Requirements

- Minimum overall: **85%**
- New primitives: **95%+** before merge
- Critical paths (signing, encryption): **100%**

### Testing Philosophy

- ✅ **Property-based** tests for invariants (when applicable)
- ✅ **RFC vectors** for standard primitives (Ed25519 = RFC 8032)
- ✅ **NIST vectors** for AES, SHA, HMAC
- ✅ **Edge cases**: empty inputs, max sizes, malformed data
- ✅ **Tampering tests**: bit flips, key swaps, etc.
- ❌ **No mocks** for crypto primitives (use real implementations)

---

## 📐 Code Style

### Rust

```bash
# Format
cargo fmt --all

# Lint
cargo clippy --workspace -- -D warnings

# Check
cargo check --workspace
```

Style rules:
- Use `cargo fmt` defaults
- No `unsafe` without justification in comments
- All public APIs need rustdoc comments
- All errors via `thiserror`

### TypeScript

```bash
# Format
npm run format

# Lint
npm run lint

# Type check
npm run typecheck
```

Style rules:
- Use Prettier defaults
- All public APIs need JSDoc
- Prefer `Buffer` over `Uint8Array` (Node-first)
- Validate all inputs before passing to native bindings
- Use branded types for crypto material

### Naming Conventions

| Construct | Convention | Example |
|-----------|-----------|---------|
| TS classes | PascalCase | `Ed25519` |
| TS functions | camelCase | `secureRandom` |
| TS constants | SCREAMING_CASE | `PUBLIC_KEY_SIZE` |
| Rust modules | snake_case | `sc_ed25519` |
| Rust functions | snake_case | `generate_keypair` |
| NAPI exports | camelCase (auto) | `ed25519GenerateKeypair` |

---

## 🆕 Adding New Primitives

If you want to add a new cryptographic primitive (e.g., ChaCha20-Poly1305):

### Step 1: Discussion

Open an issue describing:
- What primitive
- Why (use case)
- Which Rust crate to use
- API design proposal

Wait for maintainer approval before writing code.

### Step 2: Create the Crate

```bash
mkdir -p crates/sc-chacha20/src
```

Create `crates/sc-chacha20/Cargo.toml`:

```toml
[package]
name = "sc-chacha20"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
chacha20poly1305 = { workspace = true }
rand = { workspace = true }
thiserror = { workspace = true }
```

Add to workspace `Cargo.toml`:

```toml
members = [
    # ...
    "crates/sc-chacha20",
]

[workspace.dependencies]
sc-chacha20 = { path = "crates/sc-chacha20" }
```

### Step 3: Implement Rust Logic

Follow existing patterns (e.g., `sc-aes`):

```rust
// crates/sc-chacha20/src/lib.rs
use thiserror::Error;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

#[derive(Debug, Error)]
pub enum ChaChaError { /* ... */ }

pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) 
    -> Result<Vec<u8>, ChaChaError> {
    // ...
}

#[cfg(test)]
mod tests {
    // RFC test vectors required
}
```

### Step 4: Add NAPI Bindings

Edit `crates/sc-node/src/lib.rs`:

```rust
#[napi]
pub fn chacha20_encrypt(key: Buffer, nonce: Buffer, plaintext: Buffer) 
    -> Result<Buffer> {
    sc_chacha20::encrypt(&key, &nonce, &plaintext)
        .map(Buffer::from)
        .map_err(|e| Error::from_reason(e.to_string()))
}
```

Add dependency in `crates/sc-node/Cargo.toml`:

```toml
sc-chacha20 = { workspace = true }
```

### Step 5: TypeScript Wrapper

Add to `src/core.ts`:

```typescript
export const ChaCha20 = Object.freeze({
  get KEY_SIZE() { return 32; },
  get NONCE_SIZE() { return 12; },

  encrypt(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
    validateBufferSize(key, 32, 'key');
    validateBufferSize(nonce, 12, 'nonce');
    return native.chacha20Encrypt(key, nonce, plaintext);
  },
  // ...
});
```

Export from `src/index.ts`.

### Step 6: Tests

Create `__tests__/chacha20.test.ts` with:
- Roundtrip tests
- Tampering tests
- Invalid input tests
- RFC test vectors

### Step 7: Documentation

Update:
- `README.md` (API reference section)
- `ROADMAP.md` (mark feature done)
- `CHANGELOG.md` (add entry)

---

## 📤 Pull Request Process

### Before Opening

1. ✅ Open an issue first (for non-trivial changes)
2. ✅ Get maintainer feedback on approach
3. ✅ Fork the repo
4. ✅ Create a branch: `feature/<name>` or `fix/<name>`

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ChaCha20-Poly1305 support
fix: prevent panic on empty input to HKDF
docs: update README with v0.3 examples
test: add edge cases for XEd25519
refactor: extract common validation
perf: speed up SHA-256 hash on small inputs
chore: bump dependencies
```

### PR Checklist

Before requesting review:

- [ ] Tests pass (`npm test` + `cargo test --workspace`)
- [ ] Coverage maintained or improved
- [ ] Linting passes (`npm run lint` + `cargo clippy`)
- [ ] Type check passes (`npm run typecheck`)
- [ ] Format applied (`npm run format` + `cargo fmt`)
- [ ] Documentation updated (README, JSDoc, rustdoc)
- [ ] CHANGELOG entry added
- [ ] No new compiler warnings

### Review Process

1. **Automated checks** run (CI)
2. **Maintainer review** (typically within 7 days)
3. **Iteration** on feedback
4. **Approval** + merge by maintainer

We use "squash and merge" to keep history clean.

---

## 🚢 Release Process

(Maintainers only — for reference)

### Versioning

We follow [semver](https://semver.org/).

### Release Steps

```bash
# 1. Update CHANGELOG
# 2. Bump version in package.json AND Cargo.toml workspace
npm version <patch|minor|major>

# 3. Push tag (triggers CI/CD)
git push origin main --tags

# 4. CI/CD builds + publishes
# 5. Verify on npm:
npm view @brashkie/signalis-core@latest version

# 6. Create GitHub Release with notes
```

### Hotfix Process

For urgent fixes:

```bash
git checkout -b hotfix/0.2.1 v0.2.0
# apply fix
git tag v0.2.1
git push --tags
```

---

## 🙏 Recognition

Contributors are recognized in:

- GitHub contributors page
- `CONTRIBUTORS.md` (created when PR #1 merges)
- Release notes (per-version)
- Twitter/social shoutouts (with permission)

---

## ❓ Questions?

- 💬 [GitHub Discussions](https://github.com/Brashkie/signalis-core/discussions)
- 📧 brashkie@hepein.com (for sensitive matters)
- 🐦 Twitter: @brashkie (for casual chat)

**Thank you for contributing! 🦀✨**
