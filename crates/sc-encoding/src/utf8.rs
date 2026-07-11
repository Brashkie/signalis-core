//! UTF-8 encode/decode helpers with strict validation.
//!
//! These are thin wrappers around Rust's built-in UTF-8 handling
//! (`str::from_utf8` and friends) that expose a consistent error type
//! with the rest of `sc-encoding`.
//!
//! ## Design notes
//!
//! - **`encode`** converts a `&str` to its UTF-8 bytes. This is always
//!   valid because `&str` is guaranteed by Rust to hold valid UTF-8.
//! - **`decode`** validates the bytes strictly. Invalid sequences
//!   (lone surrogates, overlong encodings, truncated multi-byte
//!   sequences) all return an error rather than replacing with U+FFFD.
//! - **`is_valid`** is a cheap check without allocation.
//!
//! ## Examples
//!
//! ```
//! use sc_encoding::utf8;
//!
//! let bytes = utf8::encode("Hola");
//! assert_eq!(bytes, b"Hola");
//!
//! let text = utf8::decode(b"Hola").unwrap();
//! assert_eq!(text, "Hola");
//!
//! assert!(!utf8::is_valid(&[0xff, 0xfe]));
//! ```

use crate::{EncodingError, Result};

/// Encode a string to its UTF-8 byte representation.
///
/// Never fails — `&str` is always valid UTF-8 by definition.
#[must_use]
pub fn encode(input: &str) -> Vec<u8> {
    input.as_bytes().to_vec()
}

/// Decode UTF-8 bytes to a `String`.
///
/// # Errors
///
/// Returns [`EncodingError::InvalidUtf8`] if the bytes contain any
/// invalid UTF-8 sequence (truncated, overlong, lone surrogate, etc.).
pub fn decode(input: &[u8]) -> Result<String> {
    core::str::from_utf8(input)
        .map(|s| s.to_owned())
        .map_err(|e| EncodingError::InvalidUtf8 {
            reason: e.to_string(),
        })
}

/// Cheap validation: are these bytes valid UTF-8?
///
/// Runs in `O(n)`. No allocations.
#[must_use]
pub fn is_valid(input: &[u8]) -> bool {
    core::str::from_utf8(input).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn encode_ascii() {
        assert_eq!(encode("hello"), b"hello");
    }

    #[test]
    fn encode_multibyte() {
        // "ñ" is 2 bytes in UTF-8 (0xc3 0xb1)
        assert_eq!(encode("ñ"), vec![0xc3, 0xb1]);
        // "€" is 3 bytes (0xe2 0x82 0xac)
        assert_eq!(encode("€"), vec![0xe2, 0x82, 0xac]);
        // "🦀" is 4 bytes
        assert_eq!(encode("🦀"), vec![0xf0, 0x9f, 0xa6, 0x80]);
    }

    #[test]
    fn decode_ascii() {
        assert_eq!(decode(b"hello").unwrap(), "hello");
    }

    #[test]
    fn decode_multibyte() {
        assert_eq!(decode(&[0xc3, 0xb1]).unwrap(), "ñ");
        assert_eq!(decode(&[0xf0, 0x9f, 0xa6, 0x80]).unwrap(), "🦀");
    }

    #[test]
    fn round_trip() {
        let cases = [
            "",
            "hello",
            "Hola, mundo!",
            "日本語",
            "🦀 crab",
            "\u{0000}\u{0001}\u{007f}", // control chars are valid UTF-8
        ];
        for input in cases {
            let bytes = encode(input);
            let decoded = decode(&bytes).unwrap();
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        // 0xff is never valid in UTF-8
        assert!(decode(&[0xff]).is_err());
        assert!(decode(&[0xfe, 0xfe]).is_err());

        // Truncated multi-byte sequence (starts a 3-byte char but only 1 byte given)
        assert!(decode(&[0xe2]).is_err());

        // Lone continuation byte
        assert!(decode(&[0x80]).is_err());
    }

    #[test]
    fn is_valid_various() {
        assert!(is_valid(b""));
        assert!(is_valid(b"hello"));
        assert!(is_valid(&[0xc3, 0xb1]));            // ñ
        assert!(is_valid(&[0xf0, 0x9f, 0xa6, 0x80])); // 🦀

        assert!(!is_valid(&[0xff]));
        assert!(!is_valid(&[0x80]));                 // lone continuation
        assert!(!is_valid(&[0xe2]));                 // truncated
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(""), Vec::<u8>::new());
        assert_eq!(decode(b"").unwrap(), "");
    }

    #[test]
    fn invalid_utf8_error_carries_reason() {
        let err = decode(&[0xff]).unwrap_err();
        match err {
            EncodingError::InvalidUtf8 { reason } => {
                assert!(!reason.is_empty());
            }
            _ => panic!("expected InvalidUtf8"),
        }
    }
}
