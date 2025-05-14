use criterion::{criterion_group, criterion_main, Criterion};
use amulet_core::crypto::{classic::ClassicCryptoProvider, fips::FipsCryptoProvider, Hasher};
use amulet_core::types::AlgSuite;

fn hash_benchmarks(c: &mut Criterion) {
    let data = b"benchmark data for hashing";

    c.bench_function("blake3_hash", |b| {
        b.iter(|| {
            let _cid = ClassicCryptoProvider::hash(data, AlgSuite::CLASSIC);
        })
    });

    c.bench_function("sha3_hash", |b| {
        b.iter(|| {
            let _cid = FipsCryptoProvider::hash(data, AlgSuite::FIPS);
        })
    });
}

criterion_group!(benches, hash_benchmarks);
criterion_main!(benches); 