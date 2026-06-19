//! Cryptographic utility helpers.
//!
//! Small, audit-friendly helpers that every crypto library eventually needs
//! to expose publicly. Currently:
//!
//! - [`secure_random`] — fill a buffer with cryptographically secure random bytes
//! - [`constant_time_eq`] — compare two byte slices in constant time
//! - [`secure_zeroize`] — overwrite a buffer with zeros (compiler can't elide)
//! - [`random_bytes`] — convenience that allocates + fills
//!
//! All operations here are intentionally minimal wrappers around audited
//! crates (`rand`, `subtle`, `zeroize`). The point is to give the rest of
//! the workspace (and the NAPI layer) a single, named import.

#![deny(clippy::all)]
#![forbid(unsafe_code)]

use rand::RngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors emitted by this crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("secure_random: requested size {requested} exceeds max ({max})")]
    SizeTooLarge { requested: usize, max: usize },
    #[error("secure_random: requested zero bytes")]
    ZeroSize,
}

type Result<T> = std::result::Result<T, Error>;

/// Maximum bytes a single `secure_random` call will produce.
///
/// 16 MiB. Larger requests almost certainly indicate a bug rather than a
/// legitimate need (real entropy is typically 32-64 bytes per call).
pub const MAX_RANDOM_BYTES: usize = 16 * 1024 * 1024;

// ═══════════════════════════════════════════════════════════════════════════
// Random
// ═══════════════════════════════════════════════════════════════════════════

/// Fill `buf` with cryptographically secure random bytes from the OS RNG.
///
/// Backed by [`rand::rngs::OsRng`], which uses:
/// - `getrandom(2)` on Linux 3.17+
/// - `BCryptGenRandom` on Windows
/// - `SecRandomCopyBytes` on macOS/iOS
/// - `getentropy(2)` on FreeBSD/OpenBSD
/// - `arc4random_buf(3)` as fallback
///
/// Panics if the OS RNG is unavailable (treated as unrecoverable, which is
/// correct for a crypto library — never silently degrade).
pub fn secure_random(buf: &mut [u8]) {
    rand::rngs::OsRng.fill_bytes(buf);
}

/// Allocate and return `size` random bytes.
///
/// Convenience wrapper around [`secure_random`].
///
/// # Errors
/// - [`Error::ZeroSize`] if `size == 0`
/// - [`Error::SizeTooLarge`] if `size > MAX_RANDOM_BYTES`
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    if size == 0 {
        return Err(Error::ZeroSize);
    }
    if size > MAX_RANDOM_BYTES {
        return Err(Error::SizeTooLarge {
            requested: size,
            max: MAX_RANDOM_BYTES,
        });
    }
    let mut buf = vec![0u8; size];
    secure_random(&mut buf);
    Ok(buf)
}

// ═══════════════════════════════════════════════════════════════════════════
// Constant-time comparison
// ═══════════════════════════════════════════════════════════════════════════

/// Compare two byte slices in constant time.
///
/// Returns `true` if the slices have the same length AND contents.
/// Length-mismatched slices return `false` immediately (length is not secret).
///
/// Use this when comparing MACs, signatures, tokens, or any secret value
/// where a timing-based comparison could leak information about the secret.
///
/// **Wrong:**
/// ```ignore
/// if expected_mac == received_mac { ... }
/// // ^ early-exit on first mismatch — leaks position via timing
/// ```
///
/// **Right:**
/// ```
/// use sc_utils::constant_time_eq;
/// let expected = [0u8; 32];
/// let received = [0u8; 32];
/// if constant_time_eq(&expected, &received) { /* ok */ }
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ═══════════════════════════════════════════════════════════════════════════
// Secure zeroize
// ═══════════════════════════════════════════════════════════════════════════

/// Overwrite a buffer with zeros, guaranteed not to be elided by the compiler.
///
/// Use this when you're done with a secret (key material, plaintext after
/// encryption, etc.) and want to reduce the window during which the secret
/// could appear in a memory dump.
///
/// **Limitations** (no library can fully solve these):
/// - Doesn't help if the secret was already copied somewhere (stack, swap, GC).
/// - Doesn't prevent the OS from paging your secret to disk before zeroize ran.
/// - Doesn't help against a compromised kernel.
///
/// What it DOES guarantee: the compiler won't optimize away the zero write
/// just because the buffer is dropped immediately after.
pub fn secure_zeroize(buf: &mut [u8]) {
    buf.zeroize();
}

// ═══════════════════════════════════════════════════════════════════════════
// Version
// ═══════════════════════════════════════════════════════════════════════════

/// Crate version (compile-time constant from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─── secure_random / random_bytes ────────────────────────────────────

    #[test]
    fn fills_buffer_with_random_bytes() {
        let mut buf = [0u8; 32];
        secure_random(&mut buf);
        // Almost-zero probability that all 32 bytes are zero
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn two_calls_produce_different_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        secure_random(&mut a);
        secure_random(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn random_bytes_returns_requested_size() {
        let bytes = random_bytes(64).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn random_bytes_zero_size_errors() {
        let result = random_bytes(0);
        assert!(matches!(result, Err(Error::ZeroSize)));
    }

    #[test]
    fn random_bytes_too_large_errors() {
        let result = random_bytes(MAX_RANDOM_BYTES + 1);
        assert!(matches!(result, Err(Error::SizeTooLarge { .. })));
    }

    #[test]
    fn random_bytes_at_max_succeeds() {
        // Sanity: the boundary IS allowed (not strictly greater)
        let result = random_bytes(MAX_RANDOM_BYTES);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), MAX_RANDOM_BYTES);
    }

    #[test]
    fn fills_empty_slice_safely() {
        let mut buf: [u8; 0] = [];
        secure_random(&mut buf); // should not panic
    }

    // ─── constant_time_eq ────────────────────────────────────────────────

    #[test]
    fn eq_matching_returns_true() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn eq_mismatched_returns_false() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn eq_different_lengths_returns_false() {
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 3, 4]));
        assert!(!constant_time_eq(&[1, 2, 3, 4], &[1, 2, 3]));
    }

    #[test]
    fn eq_both_empty_returns_true() {
        assert!(constant_time_eq(&[], &[]));
    }

    #[test]
    fn eq_one_empty_returns_false() {
        assert!(!constant_time_eq(&[], &[0]));
        assert!(!constant_time_eq(&[0], &[]));
    }

    // ─── secure_zeroize ──────────────────────────────────────────────────

    #[test]
    fn zeroize_overwrites_buffer() {
        let mut buf = [0xffu8; 32];
        secure_zeroize(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroize_empty_buffer_safe() {
        let mut buf: [u8; 0] = [];
        secure_zeroize(&mut buf); // should not panic
    }

    #[test]
    fn zeroize_single_byte() {
        let mut buf = [0xff];
        secure_zeroize(&mut buf);
        assert_eq!(buf, [0]);
    }

    // ─── VERSION ─────────────────────────────────────────────────────────

    #[test]
    fn version_is_non_empty() {
        assert!(!VERSION.is_empty());
        assert!(VERSION.starts_with("0."));
    }
}
