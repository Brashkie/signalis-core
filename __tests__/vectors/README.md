# Test vectors

Third-party cryptographic test vectors used by the test suite. **Not shipped**
in the npm package (the `files` allow-list excludes `__tests__/`).

## Wycheproof

`aes_gcm_wycheproof.json` and `chacha20_poly1305_wycheproof.json` are curated
subsets of Google's Wycheproof project:

- Source: https://github.com/C2SP/wycheproof (`testvectors_v1/`)
- License: Apache License 2.0 (same as this project)
- Filter applied: only vectors matching this library's supported parameters
  (256-bit key, 96-bit nonce, 128-bit tag). Each retains its original `tcId`,
  `comment`, `result`, and `flags` for traceability back to the upstream set.

These vectors include deliberately malformed / adversarial inputs (tampered
tags, Poly1305 edge cases, boundary ciphertexts) to exercise the
authentication-failure paths, not just round-trips.
