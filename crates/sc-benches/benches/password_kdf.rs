//! Password-KDF benchmarks: PBKDF2 and Argon2id.
//!
//! These are intentionally *slow* (that's the point of a password KDF), so the
//! parameters here are modest to keep the benchmark runnable. They measure
//! relative cost, not a recommended production work factor.
//!
//! Run with: `cargo bench -p sc-benches --bench password_kdf`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sc_argon2::Argon2id;
use sc_pbkdf2::Pbkdf2;

fn bench_pbkdf2(c: &mut Criterion) {
    let password = b"correct horse battery staple";
    let salt = [0x01u8; 16];
    let mut group = c.benchmark_group("pbkdf2");
    // A few iteration counts to show the linear scaling of the work factor.
    for &iters in &[10_000u32, 100_000] {
        group.bench_function(format!("iters_{iters}"), |b| {
            b.iter(|| {
                Pbkdf2::derive(black_box(password), black_box(&salt), black_box(iters), black_box(32usize))
                    .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_argon2id(c: &mut Criterion) {
    let password = b"correct horse battery staple";
    let salt = [0x02u8; 16];
    let mut group = c.benchmark_group("argon2id");
    // (m_cost KiB, t_cost, p_cost) combinations — modest so the bench finishes.
    for &(m, t, p) in &[(8 * 1024u32, 1u32, 1u32), (19 * 1024, 2, 1)] {
        group.bench_function(format!("m{m}_t{t}_p{p}"), |b| {
            b.iter(|| {
                Argon2id::derive(
                    black_box(password),
                    black_box(&salt),
                    black_box(m),
                    black_box(t),
                    black_box(p),
                    black_box(32usize),
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_pbkdf2, bench_argon2id);
criterion_main!(benches);
