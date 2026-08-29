//! KDF / MAC benchmarks: HKDF (SHA-256 & SHA-512), HMAC, and BLAKE3 keyed/derive.
//!
//! Run with: `cargo bench -p sc-benches --bench kdf`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sc_hkdf::{Hkdf, HkdfSha512};

fn bench_extract(c: &mut Criterion) {
    let salt = [0x01u8; 32];
    let ikm = [0x02u8; 32];
    c.bench_function("hkdf_extract", |b| {
        b.iter(|| Hkdf::extract(black_box(&salt), black_box(&ikm)));
    });
}

fn bench_expand(c: &mut Criterion) {
    let prk = [0x03u8; 32];
    let info = b"signalis-core benchmark";
    c.bench_function("hkdf_expand_32", |b| {
        b.iter(|| Hkdf::expand(black_box(&prk), black_box(info), black_box(32usize)).unwrap());
    });
    c.bench_function("hkdf_expand_64", |b| {
        b.iter(|| Hkdf::expand(black_box(&prk), black_box(info), black_box(64usize)).unwrap());
    });
}

fn bench_derive(c: &mut Criterion) {
    let salt = [0x01u8; 32];
    let ikm = [0x02u8; 32];
    let info = b"signalis-core benchmark";
    c.bench_function("hkdf_derive_32", |b| {
        b.iter(|| {
            Hkdf::derive(black_box(&salt), black_box(&ikm), black_box(info), black_box(32usize)).unwrap()
        });
    });
}

fn bench_hkdf_sha512(c: &mut Criterion) {
    let salt = [0x01u8; 32];
    let ikm = [0x02u8; 32];
    let info = b"signalis-core benchmark";
    c.bench_function("hkdf_sha512_derive_32", |b| {
        b.iter(|| {
            HkdfSha512::derive(black_box(&salt), black_box(&ikm), black_box(info), black_box(32usize))
                .unwrap()
        });
    });
}

fn bench_hmac(c: &mut Criterion) {
    let key = [0x01u8; 32];
    let data = vec![0x61u8; 1024];
    c.bench_function("hmac_sha256_1KiB", |b| {
        b.iter(|| sc_hmac::hmac_sha256(black_box(&key), black_box(&data)));
    });
    c.bench_function("hmac_sha512_1KiB", |b| {
        b.iter(|| sc_hmac::hmac_sha512(black_box(&key), black_box(&data)));
    });
}

fn bench_blake3_modes(c: &mut Criterion) {
    let key = [0x01u8; 32];
    let data = vec![0x61u8; 1024];
    c.bench_function("blake3_keyed_hash_1KiB", |b| {
        b.iter(|| sc_blake3::keyed_hash(black_box(&key), black_box(&data)));
    });
    c.bench_function("blake3_derive_key_1KiB", |b| {
        b.iter(|| sc_blake3::derive_key(black_box("signalis-core bench context"), black_box(&data)));
    });
}

criterion_group!(
    benches,
    bench_extract,
    bench_expand,
    bench_derive,
    bench_hkdf_sha512,
    bench_hmac,
    bench_blake3_modes
);
criterion_main!(benches);
