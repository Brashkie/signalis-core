//! Ed25519 verification must never panic on arbitrary input — it must return
//! Ok/Err for every possible (pubkey, message, signature) triple.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Layout: [32-byte pubkey][64-byte sig][rest = message]
    if data.len() < 96 {
        return;
    }
    let public_key = &data[..32];
    let signature = &data[32..96];
    let message = &data[96..];
    // Result intentionally ignored: we only care that this never panics.
    let _ = sc_ed25519::verify(public_key, message, signature);
});
