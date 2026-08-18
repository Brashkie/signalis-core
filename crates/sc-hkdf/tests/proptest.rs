//! Property-based tests for HKDF-SHA256.

use proptest::prelude::*;
use sc_hkdf::Hkdf;

proptest! {
    /// Derivation is deterministic: same inputs always give the same output.
    #[test]
    fn derive_is_deterministic(
        salt in any::<Vec<u8>>(),
        ikm in any::<Vec<u8>>(),
        info in any::<Vec<u8>>(),
        len in 1usize..=255,
    ) {
        let a = Hkdf::derive(&salt, &ikm, &info, len).expect("valid length");
        let b = Hkdf::derive(&salt, &ikm, &info, len).expect("valid length");
        prop_assert_eq!(a, b);
    }

    /// The output length always equals the requested length (1..=255 blocks-ish).
    #[test]
    fn derive_respects_length(
        salt in any::<Vec<u8>>(),
        ikm in any::<Vec<u8>>(),
        info in any::<Vec<u8>>(),
        len in 1usize..=1024,
    ) {
        let out = Hkdf::derive(&salt, &ikm, &info, len).expect("valid length");
        prop_assert_eq!(out.len(), len);
    }
}
