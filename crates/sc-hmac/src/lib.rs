//! # sc-hmac
//!
//! HMAC-SHA256 with constant-time verification.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// HMAC errors.
#[derive(Debug, Error)]
pub enum HmacError {
    /// Verification failed.
    #[error("HMAC verification failed")]
    VerificationFailed,
}

/// Result type.
pub type Result<T> = core::result::Result<T, HmacError>;

/// Compute HMAC-SHA256. Returns 32 bytes.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Verify HMAC-SHA256 in constant time.
pub fn verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()> {
    let computed = hmac_sha256(key, data);
    if computed.ct_eq(expected_tag).into() {
        Ok(())
    } else {
        Err(HmacError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn rfc4231_test_case_1() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_verify_success() {
        let key = b"secret";
        let data = b"message";
        let tag = hmac_sha256(key, data);

        assert!(verify(key, data, &tag).is_ok());
    }

    #[test]
    fn test_verify_failure() {
        let key = b"secret";
        let data = b"message";
        let wrong_tag = [0u8; 32];

        assert!(verify(key, data, &wrong_tag).is_err());
    }
}
