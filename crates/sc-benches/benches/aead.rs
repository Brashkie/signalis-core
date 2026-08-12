//! AEAD benchmarks: AES-256-GCM vs ChaCha20-Poly1305.
//!
//! Benchmarking both side by side shows which cipher wins on this hardware for
//! a given message size (AES tends to win where AES-NI is available; ChaCha on
//! CPUs without it).
//!
//! Run with: `cargo bench -p sc-benches --bench aead`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sc_aes::Aes256GcmCipher;
use sc_chacha20poly1305::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher};

const SIZES: &[usize] = &[64, 1024, 16 * 1024, 256 * 1024];

fn bench_aes_gcm(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let cipher = Aes256GcmCipher::new(&key);

    let mut group = c.benchmark_group("aes256gcm_encrypt");
    for &size in SIZES {
        let pt = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &pt, |b, pt| {
            b.iter(|| cipher.encrypt(black_box(&nonce), black_box(pt)).unwrap());
        });
    }
    group.finish();
}

fn bench_chacha(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
    let aad: &[u8] = &[];

    let mut group = c.benchmark_group("chacha20poly1305_encrypt");
    for &size in SIZES {
        let pt = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &pt, |b, pt| {
            b.iter(|| {
                cipher
                    .encrypt(black_box(&nonce), black_box(pt), black_box(aad))
                    .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_xchacha(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 24];
    let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
    let aad: &[u8] = &[];

    let mut group = c.benchmark_group("xchacha20poly1305_encrypt");
    for &size in SIZES {
        let pt = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &pt, |b, pt| {
            b.iter(|| {
                cipher
                    .encrypt(black_box(&nonce), black_box(pt), black_box(aad))
                    .unwrap()
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aes_gcm, bench_chacha, bench_xchacha);
criterion_main!(benches);
