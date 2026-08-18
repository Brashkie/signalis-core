//! base64 / hex decoders must never panic on arbitrary input — malformed input
//! must return an Err, never crash.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sc_encoding::base64::decode(s);
        let _ = sc_encoding::base64::decode_url_safe(s);
        let _ = sc_encoding::hex::decode(s);
    }
});
