# 🤝 Contributing to Signalis Core

First off, **thanks** for considering contributing! This project is built openly, and contributions of any kind are welcome.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Crypto-Specific Rules](#crypto-specific-rules)
- [Commit Convention](#commit-convention)

---

## Code of Conduct

This project adheres to a [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you agree to uphold its terms.

---

## How to Contribute

### 🐛 Reporting Bugs

Before opening an issue:
1. Check the [existing issues](https://github.com/Brashkie/signalis-core/issues)
2. Verify you're on the latest version
3. Create a minimal reproduction

**Good bug report includes:**
- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Node.js version, OS, architecture
- Stack trace (if applicable)

### 💡 Proposing Features

Open a [Discussion](https://github.com/Brashkie/signalis-core/discussions) first to gauge interest before implementing.

### 📝 Improving Documentation

Documentation improvements are **always welcome**. This includes:
- Typo fixes
- Clearer examples
- Better explanations
- Translations (especially Spanish, Portuguese, Chinese)

### 🧪 Adding Tests

We aim for >95% coverage. Tests are especially needed for:
- Edge cases
- Error paths
- Platform-specific behavior

---

## Development Setup

### Prerequisites

- **Rust** 1.80+ (`rustup install stable`)
- **Node.js** 18+ (LTS recommended)
- **C/C++ Build Tools**:
  - Windows: Visual Studio Build Tools or VS 2019+
  - macOS: `xcode-select --install`
  - Linux: `build-essential` package

### Initial Setup

```bash
# Clone the repo
git clone https://github.com/Brashkie/signalis-core.git
cd signalis-core

# Install Node dependencies
npm install

# Build native + TypeScript
npm run build:debug

# Run all tests
npm test
```

### Useful Commands

```bash
# Rust tests only
npm run test:rust

# TypeScript tests only
npm run test:vitest

# Dual ESM/CJS tests
npm run test:dual

# Coverage report
npm run test:coverage

# Watch mode
npm run test:watch

# Linting
npm run lint
npm run clippy

# Formatting
npm run format
npm run format:rust

# Clean build artifacts
npm run clean

# Run examples
npm run examples
```

---

## Pull Request Process

1. **Fork** the repo and create your branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** following the [coding standards](#coding-standards).

3. **Add tests** that cover your changes.

4. **Ensure all tests pass**:
   ```bash
   npm test
   ```

5. **Update documentation** if you changed APIs.

6. **Follow the commit convention** (see below).

7. **Open a Pull Request** with:
   - Clear title following commit convention
   - Description of changes
   - Link to related issue (if any)
   - Screenshots/logs (if applicable)

8. **Wait for review**. We aim to respond within 48 hours.

### Branch Naming

- `feat/` — New features
- `fix/` — Bug fixes
- `docs/` — Documentation only
- `refactor/` — Code restructuring
- `test/` — Adding tests
- `perf/` — Performance improvements
- `chore/` — Maintenance tasks

---

## Coding Standards

### TypeScript

- Use **strict mode** (already configured in `tsconfig.json`)
- Prefer `interface` over `type` for object shapes
- Document public APIs with **JSDoc**
- Use `Buffer` for binary data (not `Uint8Array`)
- Throw typed errors (extend `SignalisError`)

### Rust

- Follow `rustfmt` defaults (run `npm run format:rust`)
- Pass `cargo clippy -- -D warnings` (run `npm run clippy`)
- No `unwrap()` in library code — use proper error handling
- No `unsafe` code in our crates (already deny-listed)
- Document public items with `///` comments

### Tests

- **Every new function** needs at least one test
- Test happy paths AND error paths
- Use descriptive test names: `it('should reject keys of wrong size')`
- Group related tests with `describe()`

---

## Crypto-Specific Rules

**Cryptographic code requires extra care.** PRs touching crypto must:

### 1. Pass Test Vectors

If implementing a primitive, you MUST validate against official test vectors:
- RFCs (5869, 7748, 4231, 2104, etc.)
- NIST publications
- Vendor specifications

Add these as separate test files in `crates/*/tests/`.

### 2. Constant-Time Operations

When comparing secrets (MACs, keys, signatures):
- Use `subtle::ConstantTimeEq` (Rust)
- Use `crypto.timingSafeEqual` (Node)
- NEVER use `===`, `Buffer.equals()`, or array iteration

### 3. No Side-Channel Leakage

Avoid:
- Branching on secret data
- Lookups indexed by secret data
- Variable-time arithmetic on secrets

### 4. Zeroize Secrets

Use the `zeroize` crate for sensitive structs:

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey { /* ... */ }
```

### 5. Security Review

All crypto changes will be reviewed by the maintainer. Security-critical changes may require an external audit before merge.

---

## Commit Convention

We use **[Conventional Commits](https://www.conventionalcommits.org/)**:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation
- `style:` — Code style (no logic change)
- `refactor:` — Refactoring
- `perf:` — Performance
- `test:` — Tests
- `build:` — Build system
- `ci:` — CI/CD
- `chore:` — Maintenance
- `revert:` — Revert previous commit

### Scopes

- `curve25519`, `hkdf`, `aes`, `hmac`, `sha256`, `napi`
- `ts`, `types`, `utils`, `errors`, `validators`
- `docs`, `ci`, `deps`

### Examples

```
feat(curve25519): add Ed25519 signature support

Implements Ed25519 keypair generation and signature verification
per RFC 8032. Adds 8 new tests with official RFC test vectors.

Closes #42
```

```
fix(aes): correctly propagate authentication errors

Previously, AuthenticationError was wrapped in a generic CryptoError.
This restores the proper error type for downstream consumers.

Fixes #58
```

```
docs(readme): add Spanish translation
```

---

## ❓ Questions?

- 💬 [GitHub Discussions](https://github.com/Brashkie/signalis-core/discussions)
- 🐛 [GitHub Issues](https://github.com/Brashkie/signalis-core/issues)

---

**Thank you for making Signalis Core better!** 🦀
