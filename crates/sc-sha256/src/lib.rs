//! # sc-sha256
//!
//! SHA-256 hashing convenience wrappers.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use sha2::{Digest, Sha256};

/// Compute SHA-256 hash. Returns 32 bytes.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Streaming SHA-256 hasher.
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    /// Create a new hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feed more data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        let result = self.inner.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn nist_test_vector_empty() {
        let result = sha256(b"");
        let expected =
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(result, expected);
    }

    #[test]
    fn nist_test_vector_abc() {
        let result = sha256(b"abc");
        let expected =
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_streaming_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";

        let oneshot = sha256(data);

        let mut hasher = Sha256Hasher::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..]);
        let streamed = hasher.finalize();

        assert_eq!(oneshot, streamed);
    }
}
