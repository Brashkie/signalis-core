//! Hashing benchmarks (SHA-256, SHA-3, BLAKE3) across a range of input sizes.
//!
//! Run with: `cargo bench -p sc-benches --bench hashing`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sc_sha256::{sha256, Sha256Hasher};

const SIZES: &[usize] = &[64, 1024, 16 * 1024, 256 * 1024];

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for &size in SIZES {
        let data = vec![0x61u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sha256(black_box(data)));
        });
    }
    group.finish();
}

fn bench_sha256_streaming(c: &mut Criterion) {
    // Streaming API in fixed-size chunks — models hashing a large buffer
    // incrementally rather than all at once.
    let data = vec![0x61u8; 256 * 1024];
    let mut group = c.benchmark_group("sha256_streaming");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("256KiB_in_16KiB_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha256Hasher::new();
            for chunk in data.chunks(16 * 1024) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        });
    });
    group.finish();
}

fn bench_sha3_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_256");
    for &size in SIZES {
        let data = vec![0x61u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sc_sha3::sha3_256(black_box(data)));
        });
    }
    group.finish();
}

fn bench_sha3_512(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_512");
    for &size in SIZES {
        let data = vec![0x61u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sc_sha3::sha3_512(black_box(data)));
        });
    }
    group.finish();
}

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");
    for &size in SIZES {
        let data = vec![0x61u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sc_blake3::hash(black_box(data)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sha256,
    bench_sha256_streaming,
    bench_sha3_256,
    bench_sha3_512,
    bench_blake3
);
criterion_main!(benches);
