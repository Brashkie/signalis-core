# 📦 package.json Changes for v0.2.0

## Overview

You only need to **update a few fields** in your existing `package.json`. The full file is NOT included here to avoid overwriting build scripts and napi config.

## Required Changes

Open `F:\Brashkie\PROYECTOS\NPM\signalis-core\package.json` and apply:

### 1. Version

```diff
- "version": "0.1.0",
+ "version": "0.2.0",
```

### 2. Description (improved)

```diff
- "description": "...",
+ "description": "High-performance cryptographic primitives for Signal Protocol — Curve25519, Ed25519, XEd25519, HKDF, AES-GCM (with AAD), HMAC, SHA-256",
```

### 3. Keywords (better discoverability on npm)

```diff
  "keywords": [
    "cryptography",
    "signal-protocol",
    "rust",
    "napi",
+   "ed25519",
+   "curve25519",
+   "xed25519",
+   "x25519",
+   "ecdh",
+   "diffie-hellman",
    "aes-gcm",
+   "aes-256-gcm",
+   "aead",
+   "hkdf",
+   "hmac",
+   "sha256",
+   "sha-256",
+   "encryption",
+   "e2e-encryption",
+   "end-to-end-encryption",
+   "digital-signature",
+   "hepein"
  ],
```

### 4. (Optional) Add `bugs` and `homepage`

```diff
+ "bugs": {
+   "url": "https://github.com/Brashkie/signalis-core/issues"
+ },
+ "homepage": "https://github.com/Brashkie/signalis-core#readme",
```

### 5. (Optional) Add funding URL if you want sponsors

```diff
+ "funding": {
+   "type": "github",
+   "url": "https://github.com/sponsors/Brashkie"
+ },
```

## Keep These Fields UNCHANGED

```json
"name": "@brashkie/signalis-core",
"main": "...",
"types": "...",
"napi": { ... },                  // ← DO NOT TOUCH
"scripts": { ... },               // ← Keep all build scripts
"devDependencies": { ... },       // ← Keep as-is
"optionalDependencies": { ... },  // ← Platform packages
"files": [ ... ],
"engines": { ... },
"repository": { ... },
"license": "Apache-2.0"
```

## After applying

```bash
npm install   # Refreshes package-lock.json
git diff package.json   # Verify changes
```
