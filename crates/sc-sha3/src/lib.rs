//! # sc-sha3
//!
//! SHA-3 hashing convenience wrappers (SHA3-256 and SHA3-512, FIPS 202).
//!
//! SHA-3 is the Keccak-based NIST standard, structurally different from the
//! SHA-2 family — useful when a protocol requires SHA-3 specifically or wants
//! diversity from SHA-2. Uses the audited RustCrypto `sha3` crate.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use sha3::{Digest, Sha3_256, Sha3_512};

/// Compute SHA3-256 hash. Returns 32 bytes.
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA3-512 hash. Returns 64 bytes.
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Streaming SHA3-256 hasher.
pub struct Sha3_256Hasher {
    inner: Sha3_256,
}

impl Default for Sha3_256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_256Hasher {
    /// Create a new hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha3_256::new(),
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

/// Streaming SHA3-512 hasher.
pub struct Sha3_512Hasher {
    inner: Sha3_512,
}

impl Default for Sha3_512Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_512Hasher {
    /// Create a new hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha3_512::new(),
        }
    }

    /// Feed more data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 64] {
        let result = self.inner.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // NIST FIPS 202 known-answer tests.

    #[test]
    fn sha3_256_empty() {
        let result = sha3_256(b"");
        let expected = hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(result, expected);
    }

    #[test]
    fn sha3_256_abc() {
        let result = sha3_256(b"abc");
        let expected = hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        assert_eq!(result, expected);
    }

    #[test]
    fn sha3_512_empty() {
        let result = sha3_512(b"");
        let expected = hex!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn sha3_512_abc() {
        let result = sha3_512(b"abc");
        let expected = hex!(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn sha3_256_streaming_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = sha3_256(data);
        let mut hasher = Sha3_256Hasher::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..]);
        assert_eq!(oneshot, hasher.finalize());
    }

    #[test]
    fn sha3_512_streaming_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = sha3_512(data);
        let mut hasher = Sha3_512Hasher::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..]);
        assert_eq!(oneshot, hasher.finalize());
    }
}
