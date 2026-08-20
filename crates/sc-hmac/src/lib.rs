//! # sc-hmac
//!
//! HMAC-SHA256 with constant-time verification.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

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

/// Compute HMAC-SHA512. Returns 64 bytes.
#[must_use]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Verify HMAC-SHA512 in constant time.
pub fn verify_sha512(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()> {
    let computed = hmac_sha512(key, data);
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

    // ─── HMAC-SHA512 (RFC 4231) ──────────────────────────────────────────────

    #[test]
    fn rfc4231_sha512_test_case_1() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        assert_eq!(hmac_sha512(&key, data), expected);
    }

    #[test]
    fn rfc4231_sha512_test_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex!(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
        assert_eq!(hmac_sha512(key, data), expected);
    }

    #[test]
    fn sha512_verify_roundtrip() {
        let key = b"secret";
        let data = b"message";
        let tag = hmac_sha512(key, data);
        assert!(verify_sha512(key, data, &tag).is_ok());
        assert!(verify_sha512(key, data, &[0u8; 64]).is_err());
    }
}
