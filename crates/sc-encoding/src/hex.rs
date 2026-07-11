//! Hex (Base16) encode/decode helpers.
//!
//! - **Encoding** produces lowercase output (`a-f`, `0-9`).
//! - **Decoding** accepts both uppercase and lowercase (case-insensitive)
//!   for interoperability, matching how RFC 4648 §8 specifies Base16.
//!
//! ## Examples
//!
//! ```
//! use sc_encoding::hex;
//!
//! let encoded = hex::encode(b"\xde\xad\xbe\xef");
//! assert_eq!(encoded, "deadbeef");
//!
//! let decoded = hex::decode("DEADBEEF").unwrap();
//! assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);
//! ```

use crate::{EncodingError, Result};

/// Encode bytes to a lowercase hex string.
///
/// Each byte produces exactly 2 output characters, so `output.len() == 2 * input.len()`.
/// Never fails.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    ::hex::encode(input)
}

/// Encode bytes to an uppercase hex string.
///
/// Rare use case (some legacy protocols), but included for completeness.
#[must_use]
pub fn encode_upper(input: &[u8]) -> String {
    ::hex::encode_upper(input)
}

/// Decode a hex string back to bytes. Case-insensitive.
///
/// # Errors
///
/// - [`EncodingError::InvalidLength`] if the string has an odd number of characters.
/// - [`EncodingError::InvalidCharacter`] if any character is not `0-9`, `a-f`, or `A-F`.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    ::hex::decode(input).map_err(map_hex_error)
}

/// Cheap validation: is this a well-formed hex string?
///
/// Runs in `O(n)`. Returns `true` for an even-length string containing
/// only `0-9`, `a-f`, `A-F`. Empty string returns `true`.
#[must_use]
pub fn is_valid(input: &str) -> bool {
    if input.len() % 2 != 0 {
        return false;
    }
    input.bytes().all(|b| b.is_ascii_hexdigit())
}

fn map_hex_error(err: ::hex::FromHexError) -> EncodingError {
    use ::hex::FromHexError;
    match err {
        FromHexError::InvalidHexCharacter { index, .. } => EncodingError::InvalidCharacter {
            encoding: "hex",
            position: index,
        },
        FromHexError::OddLength => EncodingError::InvalidLength {
            encoding: "hex",
            // The hex crate doesn't expose the actual length on OddLength,
            // so we report 0 as a sentinel. The `expected` message is the
            // useful part for the caller.
            length: 0,
            expected: "even (multiple of 2)",
        },
        FromHexError::InvalidStringLength => EncodingError::InvalidLength {
            encoding: "hex",
            length: 0,
            expected: "matches expected buffer size",
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn round_trip_basic() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"\x00", "00"),
            (b"\xff", "ff"),
            (b"\xde\xad\xbe\xef", "deadbeef"),
            (b"\x00\x01\x02\x03", "00010203"),
        ];
        for (bytes, hex) in cases {
            assert_eq!(encode(bytes), *hex);
            assert_eq!(decode(hex).unwrap(), *bytes);
        }
    }

    #[test]
    fn decode_is_case_insensitive() {
        assert_eq!(decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode("DeAdBeEf").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn encode_produces_lowercase() {
        assert_eq!(encode(&[0xde, 0xad]), "dead");
        assert!(!encode(&[0xde, 0xad]).chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn encode_upper_produces_uppercase() {
        assert_eq!(encode_upper(&[0xde, 0xad]), "DEAD");
    }

    #[test]
    fn rejects_odd_length() {
        let err = decode("abc").unwrap_err();
        assert!(matches!(
            err,
            EncodingError::InvalidLength { encoding: "hex", .. }
        ));
    }

    #[test]
    fn rejects_invalid_character() {
        let err = decode("abgh").unwrap_err();
        assert!(matches!(
            err,
            EncodingError::InvalidCharacter { encoding: "hex", .. }
        ));
    }

    #[test]
    fn is_valid_various() {
        assert!(is_valid(""));
        assert!(is_valid("00"));
        assert!(is_valid("deadbeef"));
        assert!(is_valid("DEADBEEF"));
        assert!(is_valid("00112233445566778899aabbccddeeff"));

        assert!(!is_valid("a"));           // odd
        assert!(!is_valid("abc"));         // odd
        assert!(!is_valid("gg"));          // invalid character
        assert!(!is_valid("de ad"));       // space not allowed
        assert!(!is_valid("0x00"));        // "0x" prefix not stripped
    }

    #[test]
    fn empty_round_trip() {
        assert_eq!(encode(b""), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn all_bytes_round_trip() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let hex = encode(&bytes);
        assert_eq!(hex.len(), 512);
        assert_eq!(decode(&hex).unwrap(), bytes);
    }
}
