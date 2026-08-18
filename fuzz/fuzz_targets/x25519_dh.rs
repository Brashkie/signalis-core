//! X25519 Diffie-Hellman must never panic for any 32-byte key material.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sc_curve25519::{KeyPair, PrivateKey, PublicKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut priv_bytes = [0u8; 32];
    let mut pub_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&data[..32]);
    pub_bytes.copy_from_slice(&data[32..64]);

    let kp = KeyPair::from_private(PrivateKey::from_bytes_clamped(&priv_bytes));
    let peer = PublicKey::from_bytes(&pub_bytes);
    let _ = kp.diffie_hellman(&peer);
});
