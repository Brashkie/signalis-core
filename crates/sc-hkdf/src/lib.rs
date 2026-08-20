//! # sc-hkdf
//!
//! HKDF-SHA256 (RFC 5869) key derivation.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use hkdf::Hkdf as HkdfImpl;
use sha2::{Sha256, Sha512};
use thiserror::Error;

/// Errors from HKDF operations.
#[derive(Debug, Error)]
pub enum HkdfError {
    /// Output length exceeds the HKDF maximum (255 * HashLen).
    #[error("invalid output length: {0}")]
    InvalidLength(usize),
}

/// Result type for HKDF operations.
pub type Result<T> = core::result::Result<T, HkdfError>;

/// HKDF-SHA256 namespace struct.
pub struct Hkdf;

impl Hkdf {
    /// HKDF-Extract: produces a 32-byte PRK.
    #[must_use]
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let (prk, _) = HkdfImpl::<Sha256>::extract(Some(salt), ikm);
        let mut output = [0u8; 32];
        output.copy_from_slice(&prk);
        output
    }

    /// HKDF-Expand: produces `length` bytes of OKM.
    pub fn expand(prk: &[u8; 32], info: &[u8], length: usize) -> Result<Vec<u8>> {
        if length > 8160 {
            return Err(HkdfError::InvalidLength(length));
        }

        let hk = HkdfImpl::<Sha256>::from_prk(prk).map_err(|_| HkdfError::InvalidLength(length))?;
        let mut okm = vec![0u8; length];
        hk.expand(info, &mut okm)
            .map_err(|_| HkdfError::InvalidLength(length))?;
        Ok(okm)
    }

    /// One-shot HKDF: extract + expand.
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, length)
    }
}

/// HKDF-SHA512 namespace struct. Same construction as [`Hkdf`] but built on
/// SHA-512 — 64-byte PRK and a larger maximum output (255 * 64 = 16320 bytes).
pub struct HkdfSha512;

impl HkdfSha512 {
    /// HKDF-Extract: produces a 64-byte PRK.
    #[must_use]
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
        let (prk, _) = HkdfImpl::<Sha512>::extract(Some(salt), ikm);
        let mut output = [0u8; 64];
        output.copy_from_slice(&prk);
        output
    }

    /// HKDF-Expand: produces `length` bytes of OKM (max 16320).
    pub fn expand(prk: &[u8; 64], info: &[u8], length: usize) -> Result<Vec<u8>> {
        if length > 16320 {
            return Err(HkdfError::InvalidLength(length));
        }

        let hk = HkdfImpl::<Sha512>::from_prk(prk).map_err(|_| HkdfError::InvalidLength(length))?;
        let mut okm = vec![0u8; length];
        hk.expand(info, &mut okm)
            .map_err(|_| HkdfError::InvalidLength(length))?;
        Ok(okm)
    }

    /// One-shot HKDF-SHA512: extract + expand.
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_produces_32_bytes() {
        let prk = Hkdf::extract(b"salt", b"ikm");
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn test_expand_produces_requested_length() {
        let prk = Hkdf::extract(b"salt", b"ikm");
        let okm = Hkdf::expand(&prk, b"info", 64).expect("valid");
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_derive_one_shot() {
        let okm = Hkdf::derive(b"salt", b"ikm", b"info", 42).expect("valid");
        assert_eq!(okm.len(), 42);
    }

    #[test]
    fn test_max_length_exceeded() {
        let prk = [0u8; 32];
        let result = Hkdf::expand(&prk, b"", 8161);
        assert!(matches!(result, Err(HkdfError::InvalidLength(8161))));
    }

    #[test]
    fn test_deterministic_output() {
        let okm1 = Hkdf::derive(b"salt", b"ikm", b"info", 32).expect("valid");
        let okm2 = Hkdf::derive(b"salt", b"ikm", b"info", 32).expect("valid");
        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_different_salt_different_output() {
        let okm1 = Hkdf::derive(b"salt1", b"ikm", b"info", 32).expect("valid");
        let okm2 = Hkdf::derive(b"salt2", b"ikm", b"info", 32).expect("valid");
        assert_ne!(okm1, okm2);
    }

    // ─── HKDF-SHA512 ─────────────────────────────────────────────────────────

    #[test]
    fn sha512_extract_produces_64_bytes() {
        let prk = HkdfSha512::extract(b"salt", b"ikm");
        assert_eq!(prk.len(), 64);
    }

    #[test]
    fn sha512_kat_derive() {
        // Generated with the `cryptography` reference (HKDF-SHA512),
        // RFC 5869 A.1-style inputs adapted to SHA-512.
        use hex_literal::hex;
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let okm = HkdfSha512::derive(&salt, &ikm, &info, 42).expect("valid");
        assert_eq!(
            okm[..],
            hex!("832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb")
        );
    }

    #[test]
    fn sha512_kat_extract_prk() {
        use hex_literal::hex;
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let prk = HkdfSha512::extract(&salt, &ikm);
        assert_eq!(
            prk,
            hex!("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237")
        );
    }

    #[test]
    fn sha512_max_length() {
        let prk = [0u8; 64];
        assert!(matches!(
            HkdfSha512::expand(&prk, b"", 16321),
            Err(HkdfError::InvalidLength(16321))
        ));
        // 16320 is the max valid length.
        assert!(HkdfSha512::expand(&prk, b"", 16320).is_ok());
    }

    #[test]
    fn sha512_deterministic() {
        let a = HkdfSha512::derive(b"salt", b"ikm", b"info", 48).expect("valid");
        let b = HkdfSha512::derive(b"salt", b"ikm", b"info", 48).expect("valid");
        assert_eq!(a, b);
    }
}
