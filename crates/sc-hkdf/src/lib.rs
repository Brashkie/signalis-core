//! # sc-hkdf
//!
//! HKDF-SHA256 (RFC 5869) key derivation.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use hkdf::Hkdf as HkdfImpl;
use sha2::Sha256;
use thiserror::Error;

/// Errors from HKDF operations.
#[derive(Debug, Error)]
pub enum HkdfError {
    /// Output length exceeds HKDF maximum (255 * 32 = 8160 bytes).
    #[error("invalid output length: {0} (max 8160 for HKDF-SHA256)")]
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
}
