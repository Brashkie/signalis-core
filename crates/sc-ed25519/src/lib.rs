//! # sc-ed25519
//!
//! Ed25519 digital signatures (RFC 8032) for Signalis Core.
//!
//! Provides standard Ed25519 with deterministic signatures. Use [`KeyPair`]
//! for the high-level API or the free functions [`sign`], [`verify`],
//! [`verify_bool`] for one-shot operations.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Errors that can occur in this crate.
#[derive(Debug, Error)]
pub enum Ed25519Error {
    /// Invalid byte length when constructing a key or signature.
    #[error("invalid byte length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length received.
        actual: usize,
    },

    /// Invalid public key encoding.
    #[error("invalid public key encoding")]
    InvalidPublicKey,

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Result type for this crate.
pub type Result<T> = core::result::Result<T, Ed25519Error>;

/// Size of an Ed25519 private key in bytes.
pub const PRIVATE_KEY_SIZE: usize = 32;

/// Size of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of an Ed25519 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Size of an Ed25519 seed in bytes.
pub const SEED_SIZE: usize = 32;

/// An Ed25519 private key (32 bytes).
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// The raw 32-byte secret seed.
    bytes: [u8; PRIVATE_KEY_SIZE],
}

impl PrivateKey {
    /// Generate a new random Ed25519 private key.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; PRIVATE_KEY_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Construct a private key from a 32-byte seed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; PRIVATE_KEY_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Construct a private key from a byte slice.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PRIVATE_KEY_SIZE {
            return Err(Ed25519Error::InvalidLength {
                expected: PRIVATE_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; PRIVATE_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Derive the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let signing_key = SigningKey::from_bytes(&self.bytes);
        PublicKey {
            bytes: signing_key.verifying_key().to_bytes(),
        }
    }

    /// Sign a message. Ed25519 signatures are deterministic (RFC 8032).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        let signing_key = SigningKey::from_bytes(&self.bytes);
        let signature: Signature = signing_key.sign(message);
        signature.to_bytes()
    }

    /// Get the raw bytes of this private key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_SIZE] {
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

/// An Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    /// The compressed point bytes.
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl PublicKey {
    /// Construct a public key from 32 bytes (no validation).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Construct a public key from a byte slice.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(Ed25519Error::InvalidLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Verify a signature against this public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(Ed25519Error::InvalidLength {
                expected: SIGNATURE_SIZE,
                actual: signature.len(),
            });
        }
        let mut sig_arr = [0u8; SIGNATURE_SIZE];
        sig_arr.copy_from_slice(signature);

        let verifying_key =
            VerifyingKey::from_bytes(&self.bytes).map_err(|_| Ed25519Error::InvalidPublicKey)?;
        let sig = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| Ed25519Error::VerificationFailed)
    }

    /// Get the raw bytes of this public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Get the raw bytes (owned copy).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey").finish()
    }
}

/// An Ed25519 keypair.
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

    /// Construct a keypair from a 32-byte seed (deterministic).
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let private = PrivateKey::try_from_bytes(seed)?;
        let public = private.public_key();
        Ok(Self { private, public })
    }

    /// Construct from a private key.
    #[must_use]
    pub fn from_private(private: PrivateKey) -> Self {
        let public = private.public_key();
        Self { private, public }
    }

    /// Sign a message with this keypair.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        self.private.sign(message)
    }

    /// Verify a signature with this keypair.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.public.verify(message, signature)
    }
}

/// One-shot sign function (no keypair object needed).
pub fn sign(private_key: &[u8], message: &[u8]) -> Result<[u8; SIGNATURE_SIZE]> {
    let priv_key = PrivateKey::try_from_bytes(private_key)?;
    Ok(priv_key.sign(message))
}

/// One-shot verify function.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let pub_key = PublicKey::try_from_bytes(public_key)?;
    pub_key.verify(message, signature)
}

/// Convenience: verify and return a boolean (does not throw).
#[must_use]
pub fn verify_bool(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify(public_key, message, signature).is_ok()
}

/// Convenience: derive the public key from a private key (32-byte input).
pub fn public_from_private(private_key: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE]> {
    let priv_key = PrivateKey::try_from_bytes(private_key)?;
    Ok(priv_key.public_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public.as_bytes().len(), 32);
        assert_eq!(kp.private.to_bytes().len(), 32);
    }

    #[test]
    fn test_keypairs_are_unique() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert_ne!(a.public.to_bytes(), b.public.to_bytes());
        assert_ne!(a.private.to_bytes(), b.private.to_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let message = b"Hello, World!";
        let sig = kp.sign(message);
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        kp.verify(message, &sig).expect("valid signature");
    }

    #[test]
    fn test_signature_is_deterministic() {
        let kp = KeyPair::generate();
        let message = b"test";
        let sig1 = kp.sign(message);
        let sig2 = kp.sign(message);
        assert_eq!(sig1, sig2, "Ed25519 signatures must be deterministic");
    }

    #[test]
    fn test_tampered_message_fails() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"original");
        assert!(kp.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp_a = KeyPair::generate();
        let kp_b = KeyPair::generate();
        let sig = kp_a.sign(b"msg");
        assert!(kp_b.verify(b"msg", &sig).is_err());
    }

    #[test]
    fn test_keypair_from_seed() {
        let seed = [42u8; 32];
        let kp1 = KeyPair::from_seed(&seed).expect("valid seed");
        let kp2 = KeyPair::from_seed(&seed).expect("valid seed");
        assert_eq!(kp1.public.to_bytes(), kp2.public.to_bytes());
        assert_eq!(kp1.private.to_bytes(), kp2.private.to_bytes());
    }

    #[test]
    fn test_invalid_sizes() {
        let result = PrivateKey::try_from_bytes(&[0u8; 31]);
        assert!(matches!(
            result,
            Err(Ed25519Error::InvalidLength {
                expected: 32,
                actual: 31
            })
        ));

        let result = PublicKey::try_from_bytes(&[0u8; 33]);
        assert!(matches!(
            result,
            Err(Ed25519Error::InvalidLength {
                expected: 32,
                actual: 33
            })
        ));
    }

    #[test]
    fn test_public_from_private() {
        let kp = KeyPair::generate();
        let derived = public_from_private(&kp.private.to_bytes()).expect("valid");
        assert_eq!(derived, kp.public.to_bytes());
    }

    // RFC 8032 test vector 1 (empty message)
    #[test]
    fn test_rfc8032_vector_1() {
        let secret = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public =
            hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = hex!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );

        let derived_pub = public_from_private(&secret).expect("valid");
        assert_eq!(derived_pub, expected_public);

        let sig = sign(&secret, b"").expect("sign");
        assert_eq!(sig, expected_signature);

        verify(&expected_public, b"", &expected_signature).expect("verify");
    }
}
