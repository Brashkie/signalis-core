//! Property-based tests for Ed25519 signatures.

use proptest::prelude::*;
use sc_ed25519::KeyPair;

proptest! {
    /// Any signature produced by a key verifies under that key's public key.
    #[test]
    fn sign_then_verify_succeeds(seed in any::<[u8; 32]>(), msg in any::<Vec<u8>>()) {
        let kp = KeyPair::from_seed(&seed).expect("32-byte seed is always valid");
        let sig = kp.sign(&msg);
        prop_assert!(kp.verify(&msg, &sig).is_ok());
    }

    /// Verifying a signature against a DIFFERENT message must fail.
    #[test]
    fn tampered_message_fails(
        seed in any::<[u8; 32]>(),
        m1 in any::<Vec<u8>>(),
        m2 in any::<Vec<u8>>(),
    ) {
        prop_assume!(m1 != m2);
        let kp = KeyPair::from_seed(&seed).expect("32-byte seed is always valid");
        let sig = kp.sign(&m1);
        prop_assert!(kp.verify(&m2, &sig).is_err());
    }

    /// A signature is always exactly 64 bytes.
    #[test]
    fn signature_is_64_bytes(seed in any::<[u8; 32]>(), msg in any::<Vec<u8>>()) {
        let kp = KeyPair::from_seed(&seed).expect("valid seed");
        prop_assert_eq!(kp.sign(&msg).len(), 64);
    }
}
