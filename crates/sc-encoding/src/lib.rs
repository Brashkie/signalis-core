//! # sc-encoding
//!
//! Encoding/decoding helpers for signalis-core.
//!
//! Provides constant-time-friendly (as much as possible for encodings)
//! Base64, Hex, and UTF-8 encode/decode functions. These are used both
//! by the wider signalis-core public API and by internal callers that
//! need consistent, audited encoding routines rather than ad-hoc ones.
//!
//! ## Modules
//!
//! - [`base64`] — RFC 4648 Base64 (standard + URL-safe variants)
//! - [`hex`] — RFC 4648 Base16 (lowercase output, case-insensitive input)
//! - [`utf8`] — UTF-8 encode/decode with strict validation
//!
//! ## Errors
//!
//! All decoding operations return a [`Result`] with a variant of
//! [`EncodingError`]. Failures are never silent — malformed input
//! ALWAYS produces an error rather than a lossy conversion.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(missing_docs)]

use thiserror::Error;

pub mod base64;
pub mod hex;
pub mod utf8;

// Re-exports for ergonomic external usage.
// These alias the module-level functions so callers can write
// `sc_encoding::base64_encode(...)` instead of `sc_encoding::base64::encode(...)`.
#[doc(inline)]
pub use base64::{decode as base64_decode, encode as base64_encode};
#[doc(inline)]
pub use hex::{decode as hex_decode, encode as hex_encode};
#[doc(inline)]
pub use utf8::{decode as utf8_decode, encode as utf8_encode};

/// Errors that can occur during encode/decode operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodingError {
    /// The input string contained characters that are not valid for this encoding.
    #[error("invalid character(s) in {encoding} input at position {position}")]
    InvalidCharacter {
        /// The encoding that failed (e.g. "base64", "hex").
        encoding: &'static str,
        /// Byte position of the first invalid character.
        position: usize,
    },

    /// The input length is invalid for this encoding (e.g. odd length for hex).
    #[error("invalid length for {encoding}: {length} (expected {expected})")]
    InvalidLength {
        /// The encoding that failed.
        encoding: &'static str,
        /// Actual length of the input.
        length: usize,
        /// Human-readable expected shape (e.g. "multiple of 2", "multiple of 4").
        expected: &'static str,
    },

    /// The Base64 input had incorrect or invalid padding.
    #[error("invalid Base64 padding")]
    InvalidPadding,

    /// The bytes were not valid UTF-8.
    #[error("invalid UTF-8: {reason}")]
    InvalidUtf8 {
        /// Human-readable reason from the underlying validator.
        reason: String,
    },
}

/// Result type used by every function in this crate.
pub type Result<T> = core::result::Result<T, EncodingError>;
