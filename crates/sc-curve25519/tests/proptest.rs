//! Property-based tests for X25519.
//!
//! These verify mathematical invariants across a wide range of randomly
//! generated inputs, rather than a handful of fixed vectors. They do NOT test
//! the primitive's math (that's curve25519-dalek's job) — they test that our
//! wrapper preserves the expected algebraic properties.

use proptest::prelude::*;
use sc_curve25519::{KeyPair, PrivateKey};

proptest! {
    /// Diffie-Hellman must be commutative: DH(a, B) == DH(b, A).
    /// This is the core correctness property of any ECDH implementation.
    #[test]
    fn dh_is_commutative(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let alice = KeyPair::from_private(PrivateKey::from_bytes_clamped(&a));
        let bob = KeyPair::from_private(PrivateKey::from_bytes_clamped(&b));

        let ab = alice.diffie_hellman(&bob.public);
        let ba = bob.diffie_hellman(&alice.public);

        prop_assert_eq!(ab.as_bytes(), ba.as_bytes());
    }

    /// A shared secret is always exactly 32 bytes.
    #[test]
    fn shared_secret_is_32_bytes(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let alice = KeyPair::from_private(PrivateKey::from_bytes_clamped(&a));
        let bob = KeyPair::from_private(PrivateKey::from_bytes_clamped(&b));
        prop_assert_eq!(alice.diffie_hellman(&bob.public).as_bytes().len(), 32);
    }
}
