//! # sc-xed25519
//!
//! XEd25519 signatures using Curve25519 keys (Signal Protocol style).
//!
//! XEd25519 allows signing messages with a Curve25519 keypair — the same
//! keypair used for ECDH key agreement. This is what the Signal Protocol
//! uses to maintain a single identity key for all purposes.
//!
//! Spec: <https://signal.org/docs/specifications/xeddsa/>

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors from XEd25519 operations.
#[derive(Debug, Error)]
pub enum XEd25519Error {
    /// Invalid byte length when constructing a key, signature, or random nonce.
    #[error("invalid byte length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length received.
        actual: usize,
    },

    /// The public key cannot be converted to an Edwards point.
    #[error("invalid public key (invalid curve point)")]
    InvalidPublicKey,

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Result type for this crate.
pub type Result<T> = core::result::Result<T, XEd25519Error>;

/// Size of an XEd25519 private key in bytes (same as Curve25519).
pub const PRIVATE_KEY_SIZE: usize = 32;

/// Size of an XEd25519 public key in bytes (same as Curve25519).
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of an XEd25519 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Size of the random nonce required for signing.
pub const RANDOM_SIZE: usize = 64;

// ─── Internal helpers ──────────────────────────────────────────────────────

/// Apply RFC 7748 clamping to a 32-byte scalar.
fn clamp(mut key: [u8; 32]) -> [u8; 32] {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

/// Convert a Curve25519 private key to an Ed25519-compatible scalar.
fn private_to_scalar(private_key: &[u8; 32]) -> Scalar {
    let clamped = clamp(*private_key);
    Scalar::from_bytes_mod_order(clamped)
}

/// Convert a Curve25519 public key (Montgomery form) to Ed25519 (Edwards form).
fn montgomery_to_edwards(public_key: &[u8; 32]) -> Result<CompressedEdwardsY> {
    let mont = MontgomeryPoint(*public_key);
    let edwards = mont.to_edwards(0).ok_or(XEd25519Error::InvalidPublicKey)?;
    Ok(edwards.compress())
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Sign a message using a Curve25519 private key, with explicit randomness.
///
/// The `random` must be exactly 64 bytes. Use this for deterministic testing
/// or when you need to control the randomness source.
pub fn sign_with_random(
    private_key: &[u8],
    message: &[u8],
    random: &[u8],
) -> Result<[u8; SIGNATURE_SIZE]> {
    if private_key.len() != PRIVATE_KEY_SIZE {
        return Err(XEd25519Error::InvalidLength {
            expected: PRIVATE_KEY_SIZE,
            actual: private_key.len(),
        });
    }
    if random.len() != RANDOM_SIZE {
        return Err(XEd25519Error::InvalidLength {
            expected: RANDOM_SIZE,
            actual: random.len(),
        });
    }

    let mut priv_arr = [0u8; PRIVATE_KEY_SIZE];
    priv_arr.copy_from_slice(private_key);
    let _zeroizer = Zeroizing::new(priv_arr);

    // Derive Ed25519 scalar `a` from clamped private key.
    let a = private_to_scalar(&priv_arr);

    // Compute Edwards public key A = a * B.
    let big_a = ED25519_BASEPOINT_POINT * a;
    let a_bytes = big_a.compress();

    // XEd25519 ensures positive sign of A.
    let sign_bit = a_bytes.as_bytes()[31] >> 7;
    let mut a_positive_bytes = *a_bytes.as_bytes();
    a_positive_bytes[31] &= 0x7F;

    let s = if sign_bit == 0 { a } else { -a };

    // Compute r = H(prefix || s || M || Z) reduced mod L.
    let mut hasher = Sha512::new();
    let mut prefix = [0xFFu8; 32];
    prefix[0] = 0xFE;
    hasher.update(prefix);
    hasher.update(s.to_bytes());
    hasher.update(message);
    hasher.update(random);
    let r_hash = hasher.finalize();

    let r_arr: [u8; 64] = r_hash.into();
    let r = Scalar::from_bytes_mod_order_wide(&r_arr);

    // R = r * B
    let big_r = ED25519_BASEPOINT_POINT * r;
    let r_bytes = big_r.compress();

    // h = H(R || A_positive || M) reduced mod L.
    let mut hasher = Sha512::new();
    hasher.update(r_bytes.as_bytes());
    hasher.update(a_positive_bytes);
    hasher.update(message);
    let h_hash = hasher.finalize();

    let h_arr: [u8; 64] = h_hash.into();
    let h = Scalar::from_bytes_mod_order_wide(&h_arr);

    // S = r + h * s
    let big_s = r + (h * s);

    // signature = R || S
    let mut sig = [0u8; SIGNATURE_SIZE];
    sig[..32].copy_from_slice(r_bytes.as_bytes());
    sig[32..].copy_from_slice(&big_s.to_bytes());

    Ok(sig)
}

/// Sign a message using a Curve25519 private key.
///
/// Uses OS RNG for randomness. Signatures are NOT deterministic — each call
/// produces a different valid signature. Use [`sign_with_random`] for
/// reproducibility.
pub fn sign(private_key: &[u8], message: &[u8]) -> Result<[u8; SIGNATURE_SIZE]> {
    let mut random = [0u8; RANDOM_SIZE];
    OsRng.fill_bytes(&mut random);
    sign_with_random(private_key, message, &random)
}

/// Verify a XEd25519 signature.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if public_key.len() != PUBLIC_KEY_SIZE {
        return Err(XEd25519Error::InvalidLength {
            expected: PUBLIC_KEY_SIZE,
            actual: public_key.len(),
        });
    }
    if signature.len() != SIGNATURE_SIZE {
        return Err(XEd25519Error::InvalidLength {
            expected: SIGNATURE_SIZE,
            actual: signature.len(),
        });
    }

    let mut pub_arr = [0u8; PUBLIC_KEY_SIZE];
    pub_arr.copy_from_slice(public_key);
    let mut sig_arr = [0u8; SIGNATURE_SIZE];
    sig_arr.copy_from_slice(signature);

    // Convert Curve25519 public key to Edwards form.
    let big_a_compressed = montgomery_to_edwards(&pub_arr)?;
    let big_a = big_a_compressed
        .decompress()
        .ok_or(XEd25519Error::InvalidPublicKey)?;

    // Parse R and S from the signature.
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_arr[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig_arr[32..]);

    let big_r_compressed = CompressedEdwardsY(r_bytes);
    let big_r = big_r_compressed
        .decompress()
        .ok_or(XEd25519Error::VerificationFailed)?;

    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or(XEd25519Error::VerificationFailed)?;

    // h = H(R || A || M)
    let mut hasher = Sha512::new();
    hasher.update(big_r_compressed.as_bytes());
    hasher.update(big_a_compressed.as_bytes());
    hasher.update(message);
    let h_hash = hasher.finalize();

    let h_arr: [u8; 64] = h_hash.into();
    let h = Scalar::from_bytes_mod_order_wide(&h_arr);

    // Verify: S * B == R + h * A
    let lhs = ED25519_BASEPOINT_POINT * s;
    let rhs = big_r + (big_a * h);

    if lhs == rhs {
        Ok(())
    } else {
        Err(XEd25519Error::VerificationFailed)
    }
}

/// Verify and return a boolean (does not throw).
#[must_use]
pub fn verify_bool(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify(public_key, message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a Curve25519 keypair manually for tests.
    fn gen_curve25519_keypair() -> ([u8; 32], [u8; 32]) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;

        let scalar = Scalar::from_bytes_mod_order(secret);
        let public = (ED25519_BASEPOINT_POINT * scalar).to_montgomery();

        (secret, public.to_bytes())
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (priv_k, pub_k) = gen_curve25519_keypair();
        let message = b"Hello XEd25519!";
        let sig = sign(&priv_k, message).expect("sign");
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        verify(&pub_k, message, &sig).expect("verify");
        assert!(verify_bool(&pub_k, message, &sig));
    }

    #[test]
    fn test_deterministic_with_same_random() {
        let (priv_k, _) = gen_curve25519_keypair();
        let random = [42u8; 64];
        let message = b"deterministic test";
        let sig1 = sign_with_random(&priv_k, message, &random).expect("sign");
        let sig2 = sign_with_random(&priv_k, message, &random).expect("sign");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_random_different_signature() {
        let (priv_k, _) = gen_curve25519_keypair();
        let sig1 = sign(&priv_k, b"msg").expect("sign");
        let sig2 = sign(&priv_k, b"msg").expect("sign");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_tampered_message_fails() {
        let (priv_k, pub_k) = gen_curve25519_keypair();
        let sig = sign(&priv_k, b"original").expect("sign");
        assert!(verify(&pub_k, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let (priv_a, _) = gen_curve25519_keypair();
        let (_, pub_b) = gen_curve25519_keypair();
        let sig = sign(&priv_a, b"msg").expect("sign");
        assert!(verify(&pub_b, b"msg", &sig).is_err());
    }

    #[test]
    fn test_invalid_sizes() {
        assert!(sign(&[0u8; 31], b"msg").is_err());
        assert!(verify(&[0u8; 31], b"msg", &[0u8; 64]).is_err());
        assert!(verify(&[0u8; 32], b"msg", &[0u8; 63]).is_err());
        assert!(sign_with_random(&[0u8; 32], b"msg", &[0u8; 63]).is_err());
    }

    #[test]
    fn test_empty_message() {
        let (priv_k, pub_k) = gen_curve25519_keypair();
        let sig = sign(&priv_k, b"").expect("sign");
        verify(&pub_k, b"", &sig).expect("verify");
    }

    #[test]
    fn test_large_message() {
        let (priv_k, pub_k) = gen_curve25519_keypair();
        let msg = vec![0xABu8; 100_000];
        let sig = sign(&priv_k, &msg).expect("sign");
        verify(&pub_k, &msg, &sig).expect("verify");
    }
}
