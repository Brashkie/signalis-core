//! HKDF-SHA256 benchmarks: extract, expand, and the combined derive.
//!
//! Run with: `cargo bench -p sc-benches --bench kdf`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sc_hkdf::Hkdf;

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

criterion_group!(benches, bench_extract, bench_expand, bench_derive);
criterion_main!(benches);
