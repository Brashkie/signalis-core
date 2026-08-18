//! Property-based tests for the encoding helpers (roundtrip invariants).

use proptest::prelude::*;
use sc_encoding::{base64, hex};

proptest! {
    /// base64: decode(encode(x)) == x for all byte strings.
    #[test]
    fn base64_roundtrip(data in any::<Vec<u8>>()) {
        let encoded = base64::encode(&data);
        let decoded = base64::decode(&encoded).expect("our own output must decode");
        prop_assert_eq!(decoded, data);
    }

    /// base64 URL-safe: decode(encode(x)) == x.
    #[test]
    fn base64_url_safe_roundtrip(data in any::<Vec<u8>>()) {
        let encoded = base64::encode_url_safe(&data);
        let decoded = base64::decode_url_safe(&encoded).expect("our own output must decode");
        prop_assert_eq!(decoded, data);
    }

    /// hex (lowercase): decode(encode(x)) == x.
    #[test]
    fn hex_roundtrip(data in any::<Vec<u8>>()) {
        let encoded = hex::encode(&data);
        let decoded = hex::decode(&encoded).expect("our own output must decode");
        prop_assert_eq!(decoded, data);
    }

    /// hex (uppercase): decode(encode_upper(x)) == x (decode is case-insensitive).
    #[test]
    fn hex_upper_roundtrip(data in any::<Vec<u8>>()) {
        let encoded = hex::encode_upper(&data);
        let decoded = hex::decode(&encoded).expect("our own output must decode");
        prop_assert_eq!(decoded, data);
    }
}
