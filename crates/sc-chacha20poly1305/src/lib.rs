//! ChaCha20-Poly1305 AEAD primitive.
//!
//! [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) AEAD construction.
//! Faster than AES-GCM on platforms without AES-NI hardware (mobile ARM, older
//! embedded). Same security properties: authenticated encryption with optional
//! additional authenticated data (AAD).
//!
//! ## Why ChaCha20-Poly1305 alongside AES-GCM?
//!
//! - **AES-GCM**: faster on x86_64 + modern ARM with AES-NI (servers, desktops)
//! - **ChaCha20-Poly1305**: faster on phones, IoT, anything without AES hardware
//!
//! On Android arm64-v8a *without* ARMv8 crypto extensions, ChaCha20 can be
//! 2-3x faster than AES-GCM. On servers, AES-GCM wins. Both are secure.
//!
//! ## API
//!
//! ```ignore
//! use sc_chacha20poly1305::ChaCha20Poly1305Cipher;
//!
//! let key = [0u8; 32];      // generate via secure random in real usage
//! let nonce = [1u8; 12];    // MUST be unique per (key, plaintext)
//! let cipher = ChaCha20Poly1305Cipher::new(&key)?;
//!
//! let ciphertext = cipher.encrypt(&nonce, b"hello", b"")?;
//! let plaintext  = cipher.decrypt(&nonce, &ciphertext, b"")?;
//! assert_eq!(plaintext, b"hello");
//! ```

#![deny(clippy::all)]
#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305 as ChaChaInner, Key, Nonce, XChaCha20Poly1305 as XChaChaInner, XNonce,
};
use thiserror::Error;

/// ChaCha20-Poly1305 key size (bytes). Shared by the XChaCha20 variant.
pub const KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size (bytes).
pub const NONCE_SIZE: usize = 12;

/// XChaCha20-Poly1305 extended nonce size (bytes).
pub const XNONCE_SIZE: usize = 24;

/// Poly1305 authentication tag size appended to every ciphertext.
pub const TAG_SIZE: usize = 16;

/// Errors emitted by this crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("ChaCha20Poly1305: invalid key length (expected {expected}, got {actual})")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("ChaCha20Poly1305: invalid nonce length (expected {expected}, got {actual})")]
    InvalidNonceLength { expected: usize, actual: usize },
    #[error("ChaCha20Poly1305: encryption failed")]
    EncryptionFailed,
    #[error(
        "ChaCha20Poly1305: decryption failed (authentication tag mismatch or ciphertext tampered)"
    )]
    DecryptionFailed,
}

type Result<T> = std::result::Result<T, Error>;

// ═══════════════════════════════════════════════════════════════════════════
// ChaCha20Poly1305Cipher
// ═══════════════════════════════════════════════════════════════════════════

/// Authenticated encryption with associated data (AEAD).
///
/// Wraps the audited [`chacha20poly1305`] crate with a thin, error-typed
/// interface compatible with the rest of `signalis-core`.
pub struct ChaCha20Poly1305Cipher {
    inner: ChaChaInner,
}

impl ChaCha20Poly1305Cipher {
    /// Construct a cipher from a 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: key.len(),
            });
        }
        let key = Key::from_slice(key);
        Ok(Self {
            inner: ChaChaInner::new(key),
        })
    }

    /// Encrypt `plaintext` under `nonce`, authenticating `aad`.
    ///
    /// Returns `ciphertext || tag` (tag appended, 16 bytes).
    ///
    /// **IMPORTANT**: `nonce` MUST be unique per `(key, plaintext)` pair.
    /// Reusing a nonce with the same key catastrophically breaks confidentiality.
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_SIZE {
            return Err(Error::InvalidNonceLength {
                expected: NONCE_SIZE,
                actual: nonce.len(),
            });
        }
        let nonce = Nonce::from_slice(nonce);
        self.inner
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::EncryptionFailed)
    }

    /// Decrypt `ciphertext_with_tag` under `nonce`, verifying `aad`.
    ///
    /// `ciphertext_with_tag` MUST include the 16-byte Poly1305 tag at the end
    /// (the output of [`encrypt`]).
    ///
    /// On any failure (wrong key, tampered ciphertext, wrong AAD, etc.) returns
    /// [`Error::DecryptionFailed`] without revealing which check failed (constant-time).
    pub fn decrypt(&self, nonce: &[u8], ciphertext_with_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_SIZE {
            return Err(Error::InvalidNonceLength {
                expected: NONCE_SIZE,
                actual: nonce.len(),
            });
        }
        let nonce = Nonce::from_slice(nonce);
        self.inner
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext_with_tag,
                    aad,
                },
            )
            .map_err(|_| Error::DecryptionFailed)
    }
}

impl core::fmt::Debug for ChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // NEVER print the key — even partially. Just identify the type.
        f.debug_struct("ChaCha20Poly1305Cipher")
            .field("key", &"<redacted>")
            .finish()
    }
}

// Drop: chacha20poly1305 crate's ChaChaInner already zeroizes internally.
// We add an explicit Drop bound just to document intent.
impl Drop for ChaCha20Poly1305Cipher {
    fn drop(&mut self) {
        // The underlying ChaCha20Poly1305 struct from RustCrypto zeroizes its
        // internal key on drop. We have nothing else to clean up here.
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// XChaCha20Poly1305Cipher
// ═══════════════════════════════════════════════════════════════════════════

/// XChaCha20-Poly1305 AEAD: the extended-nonce variant of ChaCha20-Poly1305.
///
/// Identical security and interface to [`ChaCha20Poly1305Cipher`], but with a
/// **24-byte nonce** instead of 12. The larger nonce makes it safe to generate
/// nonces randomly: with 192 bits of nonce, the probability of a collision is
/// negligible even across a very large number of messages, so you don't need a
/// counter or other uniqueness-tracking scheme. Prefer this when you can't
/// guarantee unique 12-byte nonces.
///
/// The construction has rough-consensus/running-code status (libsodium,
/// WireGuard) and is documented in the (expired) IETF draft
/// `draft-arciszewski-xchacha-03`. Key size is the same 32 bytes.
pub struct XChaCha20Poly1305Cipher {
    inner: XChaChaInner,
}

impl XChaCha20Poly1305Cipher {
    /// Construct a cipher from a 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: key.len(),
            });
        }
        let key = Key::from_slice(key);
        Ok(Self {
            inner: XChaChaInner::new(key),
        })
    }

    /// Encrypt `plaintext` under a 24-byte `nonce`, authenticating `aad`.
    ///
    /// Returns `ciphertext || tag` (tag appended, 16 bytes).
    ///
    /// With the 24-byte nonce, generating `nonce` from a secure RNG per message
    /// is safe (collision probability is negligible).
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != XNONCE_SIZE {
            return Err(Error::InvalidNonceLength {
                expected: XNONCE_SIZE,
                actual: nonce.len(),
            });
        }
        let nonce = XNonce::from_slice(nonce);
        self.inner
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::EncryptionFailed)
    }

    /// Decrypt `ciphertext_with_tag` under a 24-byte `nonce`, verifying `aad`.
    ///
    /// On any failure returns [`Error::DecryptionFailed`] without revealing
    /// which check failed (constant-time).
    pub fn decrypt(&self, nonce: &[u8], ciphertext_with_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != XNONCE_SIZE {
            return Err(Error::InvalidNonceLength {
                expected: XNONCE_SIZE,
                actual: nonce.len(),
            });
        }
        let nonce = XNonce::from_slice(nonce);
        self.inner
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext_with_tag,
                    aad,
                },
            )
            .map_err(|_| Error::DecryptionFailed)
    }
}

impl core::fmt::Debug for XChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // NEVER print the key — even partially. Just identify the type.
        f.debug_struct("XChaCha20Poly1305Cipher")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Drop for XChaCha20Poly1305Cipher {
    fn drop(&mut self) {
        // The underlying XChaCha20Poly1305 struct from RustCrypto zeroizes its
        // internal key on drop.
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// One-shot helpers (stateless API for simple cases)
// ═══════════════════════════════════════════════════════════════════════════

/// One-shot encrypt without AAD. Convenience wrapper around [`ChaCha20Poly1305Cipher`].
pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305Cipher::new(key)?.encrypt(nonce, plaintext, b"")
}

/// One-shot decrypt without AAD.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305Cipher::new(key)?.decrypt(nonce, ciphertext, b"")
}

/// One-shot encrypt with AAD.
pub fn encrypt_with_aad(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305Cipher::new(key)?.encrypt(nonce, plaintext, aad)
}

/// One-shot decrypt with AAD.
pub fn decrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    ChaCha20Poly1305Cipher::new(key)?.decrypt(nonce, ciphertext, aad)
}

// ═══════════════════════════════════════════════════════════════════════════
// One-shot helpers — XChaCha20-Poly1305 (24-byte nonce)
// ═══════════════════════════════════════════════════════════════════════════

/// One-shot XChaCha20 encrypt without AAD. Convenience wrapper around
/// [`XChaCha20Poly1305Cipher`].
pub fn xchacha_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305Cipher::new(key)?.encrypt(nonce, plaintext, b"")
}

/// One-shot XChaCha20 decrypt without AAD.
pub fn xchacha_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305Cipher::new(key)?.decrypt(nonce, ciphertext, b"")
}

/// One-shot XChaCha20 encrypt with AAD.
pub fn xchacha_encrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305Cipher::new(key)?.encrypt(nonce, plaintext, aad)
}

/// One-shot XChaCha20 decrypt with AAD.
pub fn xchacha_decrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305Cipher::new(key)?.decrypt(nonce, ciphertext, aad)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn fresh_key() -> [u8; KEY_SIZE] {
        // Deterministic-but-distinct key for tests (don't use in production)
        let mut k = [0u8; KEY_SIZE];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        k
    }

    fn fresh_nonce() -> [u8; NONCE_SIZE] {
        [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04,
        ]
    }

    #[test]
    fn round_trip_no_aad() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let plaintext = b"Hello, ChaCha!";

        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.encrypt(&nonce, plaintext, b"").unwrap();

        // ciphertext is plaintext.len() + 16 (tag)
        assert_eq!(ct.len(), plaintext.len() + TAG_SIZE);

        let pt = cipher.decrypt(&nonce, &ct, b"").unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn round_trip_with_aad() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let plaintext = b"secret data";
        let aad = b"public header";

        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let pt = cipher.decrypt(&nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn empty_plaintext() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        let ct = cipher.encrypt(&nonce, b"", b"header").unwrap();
        assert_eq!(ct.len(), TAG_SIZE); // just the tag

        let pt = cipher.decrypt(&nonce, &ct, b"header").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn long_plaintext() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let plaintext = vec![0x42u8; 10_000];

        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.encrypt(&nonce, &plaintext, b"").unwrap();
        let pt = cipher.decrypt(&nonce, &ct, b"").unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let mut ct = cipher.encrypt(&nonce, b"original", b"").unwrap();

        // Flip a bit in the ciphertext (not the tag)
        ct[0] ^= 0x01;

        let result = cipher.decrypt(&nonce, &ct, b"");
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn tampered_tag_fails() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let mut ct = cipher.encrypt(&nonce, b"original", b"").unwrap();

        // Flip a bit in the tag (last 16 bytes)
        let last = ct.len() - 1;
        ct[last] ^= 0x01;

        let result = cipher.decrypt(&nonce, &ct, b"");
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.encrypt(&nonce, b"data", b"header-1").unwrap();

        let result = cipher.decrypt(&nonce, &ct, b"header-2");
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = fresh_key();
        let n1 = fresh_nonce();
        let mut n2 = fresh_nonce();
        n2[0] ^= 0xff;

        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.encrypt(&n1, b"data", b"").unwrap();

        let result = cipher.decrypt(&n2, &ct, b"");
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = fresh_key();
        let mut k2 = fresh_key();
        k2[0] ^= 0xff;
        let nonce = fresh_nonce();

        let c1 = ChaCha20Poly1305Cipher::new(&k1).unwrap();
        let c2 = ChaCha20Poly1305Cipher::new(&k2).unwrap();

        let ct = c1.encrypt(&nonce, b"data", b"").unwrap();
        let result = c2.decrypt(&nonce, &ct, b"");
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn invalid_key_length() {
        let result = ChaCha20Poly1305Cipher::new(&[0u8; 16]);
        assert!(matches!(result, Err(Error::InvalidKeyLength { .. })));
    }

    #[test]
    fn invalid_nonce_length() {
        let key = fresh_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let result = cipher.encrypt(&[0u8; 8], b"data", b"");
        assert!(matches!(result, Err(Error::InvalidNonceLength { .. })));
    }

    /// RFC 8439 Section 2.8.2 test vector.
    #[test]
    fn rfc_8439_test_vector() {
        let key = hex!(
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
        );
        let nonce = hex!("070000004041424344454647");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.encrypt(&nonce, plaintext, &aad).unwrap();

        // Expected ciphertext from RFC 8439
        let expected_ct = hex!(
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116"
        );
        let expected_tag = hex!("1ae10b594f09e26a7e902ecbd0600691");

        assert_eq!(&ct[..plaintext.len()], &expected_ct[..]);
        assert_eq!(&ct[plaintext.len()..], &expected_tag[..]);

        let pt = cipher.decrypt(&nonce, &ct, &aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn one_shot_helpers() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let ct = encrypt(&key, &nonce, b"hello").unwrap();
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, b"hello");

        let ct2 = encrypt_with_aad(&key, &nonce, b"hello", b"aad").unwrap();
        let pt2 = decrypt_with_aad(&key, &nonce, &ct2, b"aad").unwrap();
        assert_eq!(pt2, b"hello");
    }

    #[test]
    fn debug_does_not_leak_key() {
        let key = fresh_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let dbg = format!("{:?}", cipher);
        assert!(dbg.contains("<redacted>"));
        // Make sure no hex of the key leaked
        let key_hex = hex::encode(key);
        assert!(!dbg.contains(&key_hex));
    }

    // ─── XChaCha20-Poly1305 ──────────────────────────────────────────────────

    fn fresh_xnonce() -> [u8; XNONCE_SIZE] {
        // 40 41 42 ... 57 (24 bytes)
        let mut n = [0u8; XNONCE_SIZE];
        for (i, b) in n.iter_mut().enumerate() {
            *b = 0x40 + i as u8;
        }
        n
    }

    #[test]
    fn xchacha_round_trip_no_aad() {
        let key = fresh_key();
        let nonce = fresh_xnonce();
        let plaintext = b"Hello, XChaCha!";

        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.encrypt(&nonce, plaintext, b"").unwrap();
        assert_eq!(ct.len(), plaintext.len() + TAG_SIZE);

        let pt = cipher.decrypt(&nonce, &ct, b"").unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn xchacha_round_trip_with_aad() {
        let key = fresh_key();
        let nonce = fresh_xnonce();
        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.encrypt(&nonce, b"secret", b"aad-data").unwrap();
        let pt = cipher.decrypt(&nonce, &ct, b"aad-data").unwrap();
        assert_eq!(pt, b"secret");
        // wrong AAD must fail
        assert!(cipher.decrypt(&nonce, &ct, b"wrong-aad").is_err());
    }

    #[test]
    fn xchacha_rejects_12_byte_nonce() {
        // Proves this is really the extended-nonce variant.
        let key = fresh_key();
        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
        let short_nonce = [0u8; 12];
        assert!(cipher.encrypt(&short_nonce, b"x", b"").is_err());
    }

    #[test]
    fn xchacha_rejects_tampered_ciphertext() {
        let key = fresh_key();
        let nonce = fresh_xnonce();
        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
        let mut ct = cipher.encrypt(&nonce, b"data", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(cipher.decrypt(&nonce, &ct, b"").is_err());
    }

    #[test]
    fn xchacha_known_answer_vs_libsodium() {
        // KAT generated with libsodium (PyNaCl crypto_aead_xchacha20poly1305_ietf).
        // Proves interoperability with the reference XChaCha20-Poly1305 (IETF).
        let key = fresh_key(); // == bytes (i*37 mod 256)
        let nonce = fresh_xnonce(); // 40..57
        let plaintext = b"Signalis XChaCha KAT";

        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();

        // With AAD "header-v1"
        let ct = cipher.encrypt(&nonce, plaintext, b"header-v1").unwrap();
        let expected = hex_literal::hex!(
            "20df03f87c3b34d02b52cf608be5cabd670faa5acc8b9aa8bc1e53cae2b273d0a3d28e02"
        );
        assert_eq!(ct, expected, "XChaCha ciphertext must match libsodium");

        // Without AAD
        let ct2 = cipher.encrypt(&nonce, plaintext, b"").unwrap();
        let expected2 = hex_literal::hex!(
            "20df03f87c3b34d02b52cf608be5cabd670faa5a19defa41298eceeaa9398789d9888d17"
        );
        assert_eq!(ct2, expected2);
    }

    #[test]
    fn xchacha_debug_does_not_leak_key() {
        let key = fresh_key();
        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
        let dbg = format!("{:?}", cipher);
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&hex::encode(key)));
    }
}

// Internal hex helper for tests only (avoid hex crate dep on main code)
#[cfg(test)]
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}
