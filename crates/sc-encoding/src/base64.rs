//! Base64 encode/decode helpers (RFC 4648).
//!
//! Two variants are provided:
//!
//! - **Standard** (`encode` / `decode`) — uses the alphabet
//!   `A-Za-z0-9+/` with `=` padding. Suitable for MIME, email, and
//!   most general-purpose payloads.
//! - **URL-safe** (`encode_url_safe` / `decode_url_safe`) — uses
//!   `-` and `_` instead of `+` and `/`, and omits padding. Suitable
//!   for URLs, HTTP headers, JWTs, and filenames.
//!
//! ## Examples
//!
//! ```
//! use sc_encoding::base64;
//!
//! let encoded = base64::encode(b"hello");
//! assert_eq!(encoded, "aGVsbG8=");
//!
//! let decoded = base64::decode(&encoded).unwrap();
//! assert_eq!(decoded, b"hello");
//!
//! let url_safe = base64::encode_url_safe(b"hello");
//! assert_eq!(url_safe, "aGVsbG8"); // no padding
//! ```

use crate::{EncodingError, Result};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// Encode bytes to standard Base64 (RFC 4648, with `=` padding).
///
/// Never fails — encoding cannot produce invalid output.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decode a standard Base64 string back to bytes.
///
/// Accepts input with padding (`=` characters). Rejects input with
/// invalid characters, incorrect padding, or wrong length.
///
/// # Errors
///
/// Returns [`EncodingError::InvalidCharacter`], [`EncodingError::InvalidPadding`],
/// or [`EncodingError::InvalidLength`] depending on the failure mode.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(map_base64_error)
}

/// Encode bytes to URL-safe Base64 without padding (RFC 4648 §5).
///
/// Uses `-` and `_` instead of `+` and `/`, and omits `=` padding.
/// Safe to include in URLs, filenames, and HTTP headers as-is.
#[must_use]
pub fn encode_url_safe(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Decode a URL-safe Base64 string back to bytes.
///
/// # Errors
///
/// Returns [`EncodingError::InvalidCharacter`] or
/// [`EncodingError::InvalidLength`] on malformed input.
pub fn decode_url_safe(input: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(input.as_bytes())
        .map_err(map_base64_error)
}

/// Map the underlying base64 crate's errors to our unified error type.
fn map_base64_error(err: base64::DecodeError) -> EncodingError {
    use base64::DecodeError;
    match err {
        DecodeError::InvalidByte(pos, _) => EncodingError::InvalidCharacter {
            encoding: "base64",
            position: pos,
        },
        DecodeError::InvalidLength(len) => EncodingError::InvalidLength {
            encoding: "base64",
            length: len,
            expected: "multiple of 4 (or unpadded length congruent to 0/2/3 mod 4)",
        },
        DecodeError::InvalidLastSymbol(pos, _) => EncodingError::InvalidCharacter {
            encoding: "base64",
            position: pos,
        },
        DecodeError::InvalidPadding => EncodingError::InvalidPadding,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // ─── RFC 4648 §10 test vectors ────────────────────────────────────

    #[test]
    fn rfc4648_test_vectors_standard() {
        // From RFC 4648, Section 10
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in cases {
            assert_eq!(encode(input), *expected);
            assert_eq!(decode(expected).unwrap(), *input);
        }
    }

    #[test]
    fn rfc4648_test_vectors_url_safe() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in cases {
            assert_eq!(encode_url_safe(input), *expected);
            assert_eq!(decode_url_safe(expected).unwrap(), *input);
        }
    }

    #[test]
    fn round_trip_random() {
        // Round-trip a mix of byte values to catch alphabet mismatches
        let inputs: &[&[u8]] = &[
            &[0u8; 1],
            &[0xff; 1],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            &[0xff, 0xfe, 0xfd, 0xfc],
            b"\xde\xad\xbe\xef",
        ];
        for input in inputs {
            let enc = encode(input);
            assert_eq!(decode(&enc).unwrap(), *input);

            let enc_url = encode_url_safe(input);
            assert_eq!(decode_url_safe(&enc_url).unwrap(), *input);
        }
    }

    #[test]
    fn rejects_invalid_character() {
        // "!" is not in the Base64 alphabet
        let err = decode("aGVsbG8!").unwrap_err();
        assert!(matches!(
            err,
            EncodingError::InvalidCharacter {
                encoding: "base64",
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_padding() {
        // Missing final "=" makes this malformed
        let err = decode("aGVsbG8").unwrap_err();
        assert!(matches!(
            err,
            EncodingError::InvalidPadding | EncodingError::InvalidLength { .. }
        ));
    }

    #[test]
    fn url_safe_uses_dash_and_underscore() {
        // Bytes that produce '+' and '/' in standard should produce '-' and '_' in URL-safe
        let bytes = &[0xff, 0xef, 0xff];
        let std = encode(bytes);
        let url = encode_url_safe(bytes);
        assert!(std.contains('+') || std.contains('/'));
        assert!(!url.contains('+') && !url.contains('/'));
    }

    #[test]
    fn empty_input_produces_empty_output() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode_url_safe(b""), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_url_safe("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_url_safe_input_with_standard_chars() {
        // "+" is not valid in URL-safe alphabet
        let err = decode_url_safe("a+bc").unwrap_err();
        assert!(matches!(err, EncodingError::InvalidCharacter { .. }));
    }

    #[test]
    fn standard_accepts_padded_and_rejects_unpadded() {
        assert!(decode("Zg==").is_ok());
        // Unpadded standard fails; user should use url-safe for that
        assert!(decode("Zg").is_err());
    }
}
