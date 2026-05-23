//! # sc-aes
//!
//! AES-256-GCM (AEAD) and AES-256-CBC for Signalis Core.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use thiserror::Error;

/// Errors from AES operations.
#[derive(Debug, Error)]
pub enum AesError {
    /// Invalid key length.
    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// Invalid nonce length.
    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    InvalidNonceLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// GCM operation failed.
    #[error("AES-GCM operation failed: {0}")]
    GcmError(String),

    /// CBC padding error.
    #[error("AES-CBC padding error")]
    CbcPaddingError,
}

/// Result type.
pub type Result<T> = core::result::Result<T, AesError>;

/// AES-256-GCM cipher.
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// Create a new cipher from a 32-byte key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    /// Encrypt with 12-byte nonce.
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.cipher
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .map_err(|e| AesError::GcmError(e.to_string()))
    }

    /// Decrypt with 12-byte nonce.
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| AesError::GcmError(e.to_string()))
    }

    /// Encrypt with 12-byte nonce and Additional Authenticated Data (AAD).
    ///
    /// NEW in v0.2.0. The `aad` is authenticated but not encrypted.
    /// The same `aad` must be passed to [`Aes256GcmCipher::decrypt_with_aad`] to succeed.
    pub fn encrypt_with_aad(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        self.cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| AesError::GcmError(e.to_string()))
    }

    /// Decrypt with 12-byte nonce and Additional Authenticated Data (AAD).
    ///
    /// NEW in v0.2.0. The same `aad` used during encryption must be provided,
    /// otherwise decryption fails with a tag mismatch.
    pub fn decrypt_with_aad(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| AesError::GcmError(e.to_string()))
    }
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AES-256-CBC cipher (NOT authenticated - pair with HMAC).
pub struct Aes256CbcCipher {
    key: [u8; 32],
}

impl Aes256CbcCipher {
    /// Create a new cipher from a 32-byte key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Encrypt with 16-byte IV using PKCS#7 padding.
    #[must_use]
    pub fn encrypt(&self, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        use cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        let cipher = Aes256CbcEnc::new(&self.key.into(), iv.into());
        cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    /// Decrypt with 16-byte IV using PKCS#7 padding.
    pub fn decrypt(&self, iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        let cipher = Aes256CbcDec::new(&self.key.into(), iv.into());
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| AesError::CbcPaddingError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"Hello Signalis";

        let cipher = Aes256GcmCipher::new(&key);
        let ciphertext = cipher.encrypt(&nonce, plaintext).expect("encrypt");
        let decrypted = cipher.decrypt(&nonce, &ciphertext).expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_gcm_tag_verification_fails_on_tamper() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"Hello";

        let cipher = Aes256GcmCipher::new(&key);
        let mut ct = cipher.encrypt(&nonce, plaintext).expect("encrypt");
        ct[0] ^= 0xFF;

        let result = cipher.decrypt(&nonce, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_cbc_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 16];
        let plaintext = b"Block aligned 16";

        let cipher = Aes256CbcCipher::new(&key);
        let ct = cipher.encrypt(&iv, plaintext);
        let pt = cipher.decrypt(&iv, &ct).expect("decrypt");

        assert_eq!(pt, plaintext);
    }

    // ───────────────────────────────────────────────────────────────────────
    // NEW in v0.2.0: AAD tests
    // ───────────────────────────────────────────────────────────────────────

    #[test]
    fn test_gcm_with_aad_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"Secret message";
        let aad = b"public_header=42";

        let cipher = Aes256GcmCipher::new(&key);
        let ct = cipher
            .encrypt_with_aad(&nonce, plaintext, aad)
            .expect("encrypt");
        let pt = cipher.decrypt_with_aad(&nonce, &ct, aad).expect("decrypt");

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_gcm_aad_mismatch_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"msg";

        let cipher = Aes256GcmCipher::new(&key);
        let ct = cipher
            .encrypt_with_aad(&nonce, plaintext, b"correct_aad")
            .expect("encrypt");

        // Decryption with different AAD must fail
        let result = cipher.decrypt_with_aad(&nonce, &ct, b"wrong_aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_gcm_aad_empty_equals_no_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"hello";

        let cipher = Aes256GcmCipher::new(&key);
        let ct1 = cipher.encrypt(&nonce, plaintext).expect("encrypt");
        let ct2 = cipher
            .encrypt_with_aad(&nonce, plaintext, b"")
            .expect("encrypt");

        // Empty AAD produces same ciphertext as no AAD
        assert_eq!(ct1, ct2);
    }
}
