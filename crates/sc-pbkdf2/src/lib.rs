//! # sc-pbkdf2
//!
//! PBKDF2-HMAC-SHA256 (RFC 8018) password-based key derivation.
//!
//! Derives a cryptographic key of arbitrary length from a low-entropy password
//! by applying HMAC-SHA256 many times over a salt. The iteration count is the
//! tunable work factor: higher = slower for both you and an attacker.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use thiserror::Error;

/// Errors from PBKDF2 operations.
#[derive(Debug, Error)]
pub enum Pbkdf2Error {
    /// `iterations` was zero. At least one iteration is required (and in
    /// practice you want a high count — hundreds of thousands).
    #[error("iterations must be >= 1")]
    ZeroIterations,
    /// `length` (requested output length) was zero.
    #[error("output length must be >= 1")]
    ZeroLength,
    /// `salt` was empty. A non-empty, unique, random salt is required to defend
    /// against precomputation (rainbow tables).
    #[error("salt must not be empty")]
    EmptySalt,
}

/// Result type for PBKDF2 operations.
pub type Result<T> = core::result::Result<T, Pbkdf2Error>;

/// PBKDF2-HMAC-SHA256 namespace struct.
pub struct Pbkdf2;

impl Pbkdf2 {
    /// Derive a `length`-byte key from `password` and `salt` using `iterations`
    /// rounds of PBKDF2-HMAC-SHA256.
    ///
    /// # Errors
    /// - [`Pbkdf2Error::ZeroIterations`] if `iterations == 0`
    /// - [`Pbkdf2Error::ZeroLength`] if `length == 0`
    /// - [`Pbkdf2Error::EmptySalt`] if `salt` is empty
    ///
    /// # Security
    /// Use a unique, random salt (≥16 bytes) per password, and as many
    /// iterations as your latency budget allows (OWASP suggests 600,000+ for
    /// PBKDF2-HMAC-SHA256 as of recent guidance).
    pub fn derive(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Result<Vec<u8>> {
        if iterations == 0 {
            return Err(Pbkdf2Error::ZeroIterations);
        }
        if length == 0 {
            return Err(Pbkdf2Error::ZeroLength);
        }
        if salt.is_empty() {
            return Err(Pbkdf2Error::EmptySalt);
        }

        let mut out = vec![0u8; length];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Known-answer tests for PBKDF2-HMAC-SHA256 (the SHA-256 analogues of the
    // RFC 6070 vectors, widely published and cross-checked against libc/OpenSSL).

    #[test]
    fn kat_iter_1() {
        let out = Pbkdf2::derive(b"password", b"salt", 1, 32).expect("valid");
        assert_eq!(
            out[..],
            hex!("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        );
    }

    #[test]
    fn kat_iter_2() {
        let out = Pbkdf2::derive(b"password", b"salt", 2, 32).expect("valid");
        assert_eq!(
            out[..],
            hex!("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        );
    }

    #[test]
    fn kat_iter_4096() {
        let out = Pbkdf2::derive(b"password", b"salt", 4096, 32).expect("valid");
        assert_eq!(
            out[..],
            hex!("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        );
    }

    #[test]
    fn kat_long_password_salt_dklen_40() {
        let out = Pbkdf2::derive(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40,
        )
        .expect("valid");
        assert_eq!(
            out[..],
            hex!("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")
        );
    }

    #[test]
    fn rejects_zero_iterations() {
        assert!(matches!(
            Pbkdf2::derive(b"pw", b"salt", 0, 32),
            Err(Pbkdf2Error::ZeroIterations)
        ));
    }

    #[test]
    fn rejects_zero_length() {
        assert!(matches!(
            Pbkdf2::derive(b"pw", b"salt", 1, 0),
            Err(Pbkdf2Error::ZeroLength)
        ));
    }

    #[test]
    fn rejects_empty_salt() {
        assert!(matches!(
            Pbkdf2::derive(b"pw", b"", 1, 32),
            Err(Pbkdf2Error::EmptySalt)
        ));
    }

    #[test]
    fn deterministic() {
        let a = Pbkdf2::derive(b"pw", b"salt", 1000, 32).expect("valid");
        let b = Pbkdf2::derive(b"pw", b"salt", 1000, 32).expect("valid");
        assert_eq!(a, b);
    }

    #[test]
    fn different_salt_different_output() {
        let a = Pbkdf2::derive(b"pw", b"salt1", 1000, 32).expect("valid");
        let b = Pbkdf2::derive(b"pw", b"salt2", 1000, 32).expect("valid");
        assert_ne!(a, b);
    }

    #[test]
    fn respects_output_length() {
        assert_eq!(Pbkdf2::derive(b"pw", b"salt", 10, 16).expect("valid").len(), 16);
        assert_eq!(Pbkdf2::derive(b"pw", b"salt", 10, 64).expect("valid").len(), 64);
    }
}
