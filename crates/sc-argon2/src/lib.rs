//! # sc-argon2
//!
//! Argon2id (RFC 9106) password hashing / key derivation.
//!
//! Argon2id is the current recommended password-hashing function: it is
//! *memory-hard*, which makes large-scale GPU/ASIC cracking expensive in a way
//! that iteration-only KDFs (PBKDF2) cannot match. This exposes the raw
//! key-derivation form (`derive` → raw bytes), suitable for turning a password
//! into an encryption key.
//!
//! Uses the audited RustCrypto `argon2` crate. Algorithm is fixed to
//! **Argon2id**, version **0x13** (v1.3, the RFC 9106 standard).

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use argon2::{Algorithm, Argon2, Params, Version};
use thiserror::Error;

/// Errors from Argon2id operations.
#[derive(Debug, Error)]
pub enum Argon2Error {
    /// `salt` was empty. Argon2 requires a salt of at least 8 bytes; a unique,
    /// random 16-byte salt per password is recommended.
    #[error("salt must not be empty")]
    EmptySalt,
    /// `length` (requested output length) was zero.
    #[error("output length must be >= 1")]
    ZeroLength,
    /// The cost parameters (m_cost / t_cost / p_cost) or salt/output length were
    /// rejected by the Argon2 implementation. The message carries the detail.
    #[error("invalid Argon2 parameters: {0}")]
    InvalidParams(String),
    /// Hashing itself failed (e.g. salt too short for the library's minimum).
    #[error("Argon2 hashing failed: {0}")]
    HashingFailed(String),
}

/// Result type for Argon2id operations.
pub type Result<T> = core::result::Result<T, Argon2Error>;

/// Argon2id namespace struct.
pub struct Argon2id;

impl Argon2id {
    /// Derive a `length`-byte key from `password` and `salt` using Argon2id.
    ///
    /// # Parameters
    /// - `m_cost`: memory cost in **KiB** (e.g. `19456` = 19 MiB, `65536` = 64 MiB)
    /// - `t_cost`: number of iterations (time cost)
    /// - `p_cost`: degree of parallelism (lanes)
    /// - `length`: desired output length in bytes
    ///
    /// # Errors
    /// - [`Argon2Error::EmptySalt`] if `salt` is empty
    /// - [`Argon2Error::ZeroLength`] if `length == 0`
    /// - [`Argon2Error::InvalidParams`] if the cost parameters are out of range
    ///   (e.g. `m_cost < 8 * p_cost`, `t_cost == 0`, `p_cost == 0`)
    /// - [`Argon2Error::HashingFailed`] if hashing fails (e.g. salt shorter than
    ///   the 8-byte minimum)
    ///
    /// # Security
    /// Use a unique, random salt (≥16 bytes) per password. For interactive
    /// logins, OWASP suggests m=19456 (19 MiB), t=2, p=1 as a starting point;
    /// tune upward to your latency budget.
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        length: usize,
    ) -> Result<Vec<u8>> {
        if salt.is_empty() {
            return Err(Argon2Error::EmptySalt);
        }
        if length == 0 {
            return Err(Argon2Error::ZeroLength);
        }

        let params = Params::new(m_cost, t_cost, p_cost, Some(length))
            .map_err(|e| Argon2Error::InvalidParams(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = vec![0u8; length];
        argon2
            .hash_password_into(password, salt, &mut out)
            .map_err(|e| Argon2Error::HashingFailed(e.to_string()))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Known-answer tests generated with the Argon2 reference implementation
    // (argon2-cffi / libargon2), Argon2id, version 0x13, no secret/associated data.
    const SALT: &[u8] = b"somesalt12345678"; // 16 bytes

    #[test]
    fn kat_t1_m32_p1_len32() {
        let out = Argon2id::derive(b"password", SALT, 32, 1, 1, 32).expect("valid");
        assert_eq!(
            out[..],
            hex!("d9bc939174cecff705ca7bd6e2a66c00defa130d8f978d92a3fe0ce9bbc8dc03")
        );
    }

    #[test]
    fn kat_t3_m256_p1_len32() {
        let out = Argon2id::derive(b"password", SALT, 256, 3, 1, 32).expect("valid");
        assert_eq!(
            out[..],
            hex!("11d2bf6764de12ca6e31c394416c87b2d60fc9676acb35ed2b92c15ce3c6842c")
        );
    }

    #[test]
    fn kat_t1_m32_p1_len64() {
        let out = Argon2id::derive(b"password", SALT, 32, 1, 1, 64).expect("valid");
        assert_eq!(
            out[..],
            hex!(
                "07f872346434ed9713385ee2737d533ba5a8475f0e45ec2410fd7829f645224b"
                "ef805cd9522ea9ed6bb28d907abcb41a816381a2204802beb0482dcf4918e145"
            )
        );
    }

    #[test]
    fn kat_t2_m64_p2_len32() {
        let out = Argon2id::derive(b"password", SALT, 64, 2, 2, 32).expect("valid");
        assert_eq!(
            out[..],
            hex!("bc418ea5103abc2ba7105df54a95022fd755ef3cef33bbc8c0f7a4666acaddbc")
        );
    }

    #[test]
    fn rejects_empty_salt() {
        assert!(matches!(
            Argon2id::derive(b"pw", b"", 32, 1, 1, 32),
            Err(Argon2Error::EmptySalt)
        ));
    }

    #[test]
    fn rejects_zero_length() {
        assert!(matches!(
            Argon2id::derive(b"pw", SALT, 32, 1, 1, 0),
            Err(Argon2Error::ZeroLength)
        ));
    }

    #[test]
    fn rejects_bad_params() {
        // m_cost < 8 * p_cost is invalid
        assert!(matches!(
            Argon2id::derive(b"pw", SALT, 4, 1, 4, 32),
            Err(Argon2Error::InvalidParams(_))
        ));
        // t_cost == 0 is invalid
        assert!(matches!(
            Argon2id::derive(b"pw", SALT, 32, 0, 1, 32),
            Err(Argon2Error::InvalidParams(_))
        ));
    }

    #[test]
    fn rejects_short_salt() {
        // Salt shorter than 8 bytes is rejected by the library.
        assert!(Argon2id::derive(b"pw", b"short", 32, 1, 1, 32).is_err());
    }

    #[test]
    fn deterministic() {
        let a = Argon2id::derive(b"pw", SALT, 64, 2, 1, 32).expect("valid");
        let b = Argon2id::derive(b"pw", SALT, 64, 2, 1, 32).expect("valid");
        assert_eq!(a, b);
    }

    #[test]
    fn different_salt_different_output() {
        let a = Argon2id::derive(b"pw", b"salt-aaaaaaaaaaa", 32, 1, 1, 32).expect("valid");
        let b = Argon2id::derive(b"pw", b"salt-bbbbbbbbbbb", 32, 1, 1, 32).expect("valid");
        assert_ne!(a, b);
    }
}
