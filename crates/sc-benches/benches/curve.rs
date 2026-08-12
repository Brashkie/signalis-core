//! Curve25519 benchmarks: key generation and Diffie-Hellman.
//!
//! These are the asymmetric operations in a handshake and are far more
//! expensive than the symmetric primitives — usually the dominant cost when
//! establishing a session.
//!
//! Run with: `cargo bench -p sc-benches --bench curve`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sc_curve25519::KeyPair;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("curve25519_keygen", |b| {
        b.iter(|| black_box(KeyPair::generate()));
    });
}

fn bench_diffie_hellman(c: &mut Criterion) {
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();

    c.bench_function("curve25519_diffie_hellman", |b| {
        b.iter(|| black_box(alice.diffie_hellman(black_box(&bob.public))));
    });
}

criterion_group!(benches, bench_keygen, bench_diffie_hellman);
criterion_main!(benches);
