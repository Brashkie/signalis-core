//! # sc-blake3
//!
//! BLAKE3 wrappers for the three core modes:
//! - **hash**: fast general-purpose hashing (32-byte output)
//! - **keyed_hash**: a MAC with a 32-byte key (HMAC alternative)
//! - **derive_key**: context-separated key derivation (HKDF alternative)
//!
//! Uses the official `blake3` crate (reference implementation). The XOF /
//! extendable-output mode is intentionally not exposed here.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use subtle::ConstantTimeEq;

/// Size of a BLAKE3 key / default output, in bytes.
pub const KEY_SIZE: usize = 32;
/// Default BLAKE3 output size, in bytes.
pub const OUTPUT_SIZE: usize = 32;

/// Compute a BLAKE3 hash (default 32-byte output).
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute a BLAKE3 keyed hash (MAC) with a 32-byte key.
#[must_use]
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Verify a BLAKE3 keyed-hash MAC in **constant time**.
///
/// Returns `true` iff `expected_tag` matches the computed MAC. A length
/// mismatch returns `false` without leaking timing information about content.
#[must_use]
pub fn keyed_hash_verify(key: &[u8; 32], data: &[u8], expected_tag: &[u8]) -> bool {
    let computed = keyed_hash(key, data);
    computed.ct_eq(expected_tag).into()
}

/// Derive a 32-byte subkey from key material using a context string.
///
/// The `context` string should be hardcoded, globally unique, and
/// application-specific (e.g. `"myapp 2026-01-01 session key"`). It is NOT a
/// salt and NOT secret — it provides domain separation.
#[must_use]
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, key_material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Official BLAKE3 test-vector conventions:
    //   input     = bytes [0, 1, 2, ... 250, 0, 1, ...] (i % 251)
    //   key       = b"whats the Elvish word for friend" (32 bytes)
    //   context   = "BLAKE3 2019-12-27 16:29:52 test vectors context"
    // KATs below were cross-checked against the official `blake3` reference.

    const KEY: &[u8; 32] = b"whats the Elvish word for friend";
    const CTX: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    fn make_input(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn hash_empty() {
        assert_eq!(
            hash(b""),
            hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
    }

    #[test]
    fn hash_len_1() {
        assert_eq!(
            hash(&make_input(1)),
            hex!("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213")
        );
    }

    #[test]
    fn hash_len_1024() {
        assert_eq!(
            hash(&make_input(1024)),
            hex!("42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7")
        );
    }

    #[test]
    fn keyed_hash_kats() {
        assert_eq!(
            keyed_hash(KEY, b""),
            hex!("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26")
        );
        assert_eq!(
            keyed_hash(KEY, &make_input(1024)),
            hex!("75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4")
        );
    }

    #[test]
    fn derive_key_kats() {
        assert_eq!(
            derive_key(CTX, b""),
            hex!("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d")
        );
        assert_eq!(
            derive_key(CTX, &make_input(1024)),
            hex!("7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706")
        );
    }

    #[test]
    fn keyed_hash_verify_roundtrip() {
        let tag = keyed_hash(KEY, b"message");
        assert!(keyed_hash_verify(KEY, b"message", &tag));
        assert!(!keyed_hash_verify(KEY, b"message", &[0u8; 32]));
        assert!(!keyed_hash_verify(KEY, b"message", &[0u8; 10])); // wrong length
    }

    #[test]
    fn different_modes_differ() {
        // Same input, three modes → three different outputs.
        let h = hash(b"same");
        let k = keyed_hash(KEY, b"same");
        let d = derive_key(CTX, b"same");
        assert_ne!(h, k);
        assert_ne!(h, d);
        assert_ne!(k, d);
    }
}
