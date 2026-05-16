//! # sc-curve25519
//!
//! Curve25519 ECDH operations for Signalis Core.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use curve25519_dalek::montgomery::MontgomeryPoint;
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Errors that can occur in this crate.
#[derive(Debug, Error)]
pub enum Curve25519Error {
    /// Invalid byte length when constructing a key.
    #[error("invalid byte length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length received.
        actual: usize,
    },

    /// Point is not on the curve.
    #[error("invalid point: small-order or identity")]
    InvalidPoint,
}

/// Result type for this crate.
pub type Result<T> = core::result::Result<T, Curve25519Error>;

/// A Curve25519 private key (32 bytes, clamped per RFC 7748).
///
/// We store the clamped scalar as raw bytes to preserve the exact byte
/// representation expected by X25519. Using `Scalar::from_bytes_mod_order`
/// would apply modular reduction and lose the clamping invariants.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// Clamped scalar bytes (32 bytes, with bits set per RFC 7748 §5).
    bytes: [u8; 32],
}

impl PrivateKey {
    /// Generate a new random private key.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::from_bytes_clamped(&bytes)
    }

    /// Construct a private key from 32 bytes (applies RFC 7748 clamping).
    #[must_use]
    pub fn from_bytes_clamped(bytes: &[u8; 32]) -> Self {
        let mut clamped = *bytes;
        // RFC 7748 §5 clamping for X25519
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        Self { bytes: clamped }
    }

    /// Construct a private key from a byte slice.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Curve25519Error::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self::from_bytes_clamped(&arr))
    }

    /// Derive the corresponding public key.
    ///
    /// Uses `mul_base_clamped` which expects already-clamped scalar bytes.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let point = MontgomeryPoint::mul_base_clamped(self.bytes);
        PublicKey { point }
    }

    /// Get the raw bytes of this private key (clamped).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A Curve25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    point: MontgomeryPoint,
}

impl PublicKey {
    /// Construct a public key from 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            point: MontgomeryPoint(*bytes),
        }
    }

    /// Construct a public key from a byte slice.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Curve25519Error::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self::from_bytes(&arr))
    }

    /// Get the raw bytes of this public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.point.0
    }

    /// Get the raw bytes (owned copy).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.0
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey").finish()
    }
}

/// A shared secret produced by X25519 ECDH.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Convert into raw bytes (consumes the secret).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedSecret").finish()
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

/// A keypair.
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// The private key.
    pub private: PrivateKey,
    /// The public key.
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a new random keypair.
    #[must_use]
    pub fn generate() -> Self {
        let private = PrivateKey::generate();
        let public = private.public_key();
        Self { private, public }
    }

    /// Construct from a private key.
    #[must_use]
    pub fn from_private(private: PrivateKey) -> Self {
        let public = private.public_key();
        Self { private, public }
    }

    /// Perform X25519 Diffie-Hellman.
    ///
    /// Uses `mul_clamped` which is the canonical X25519 scalar multiplication
    /// expecting already-clamped scalar bytes.
    #[must_use]
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecret {
        // X25519 scalar multiplication: peer_public * private_scalar
        let shared_point = peer_public.point.mul_clamped(self.private.bytes);
        SharedSecret {
            bytes: shared_point.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public.as_bytes().len(), 32);
    }

    #[test]
    fn test_diffie_hellman_agreement() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = alice.diffie_hellman(&bob.public);
        let bob_shared = bob.diffie_hellman(&alice.public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_invalid_length_private_key() {
        let result = PrivateKey::try_from_bytes(&[0u8; 31]);
        assert!(matches!(
            result,
            Err(Curve25519Error::InvalidLength {
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        let kp = KeyPair::generate();
        let bytes = kp.public.to_bytes();
        let restored = PublicKey::from_bytes(&bytes);
        assert_eq!(kp.public.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_private_key_clamping() {
        let bytes = [0xFFu8; 32];
        let pk = PrivateKey::from_bytes_clamped(&bytes);
        let result = pk.to_bytes();
        assert_eq!(result[0] & 0b111, 0);
        assert_eq!(result[31] & 0x80, 0);
        assert_eq!(result[31] & 0x40, 0x40);
    }
}
