//! Microbenchmarks for the forward rate-limit primitives + bidir copy.
//!
//! Three benches:
//!
//! * `token_bucket/grant_hot`  — tight `try_acquire` loop on a bucket sized
//!   so every request succeeds (the steady-state, throttle-not-binding path).
//! * `token_bucket/refuse_hot` — tight `try_acquire` on a drained bucket
//!   so every request returns a `Some(wait)` (worst case for the gate).
//! * `bidir/copy_unthrottled`  — `copy_bidirectional_throttled` between two
//!   `tokio::io::duplex` pipes with `TokenBucket::unlimited()` on both sides;
//!   measures the raw copy-loop throughput excluding scheduler/syscall noise.
//!
//! Run explicitly with:
//!
//! `cargo bench -p spt-forward --features bench --bench token_bucket`

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use spt_forward::{bidir::copy_bidirectional_throttled, limits::TokenBucket};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;

fn bench_token_bucket(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_bucket");

    // 100 GB/s bucket — try_acquire effectively always succeeds.
    let grant_bucket = TokenBucket::new(100 * 1024 * 1024 * 1024, 1024 * 1024);
    group.bench_function("grant_hot", |b| {
        b.iter(|| {
            let r = grant_bucket.try_acquire(black_box(64));
            black_box(r);
        });
    });

    // 1 KiB/s bucket, drained — every try_acquire returns a wait.
    let refuse_bucket = TokenBucket::new(1024, 1024);
    // Drain the burst.
    let _ = refuse_bucket.try_acquire(1024);
    group.bench_function("refuse_hot", |b| {
        b.iter(|| {
            let r = refuse_bucket.try_acquire(black_box(8192));
            black_box(r);
        });
    });

    group.finish();
}

fn bench_bidir_copy(c: &mut Criterion) {
    const PAYLOAD: usize = 64 * 1024;
    let rt = Runtime::new().expect("tokio rt");
    let mut group = c.benchmark_group("bidir_copy");
    group.throughput(Throughput::Bytes((PAYLOAD as u64) * 2));
    group.bench_function("unthrottled_64k_each_way", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut a_outer, mut a_inner) = tokio::io::duplex(8 * 1024);
                let (mut b_outer, mut b_inner) = tokio::io::duplex(8 * 1024);

                let payload = vec![0xAAu8; PAYLOAD];
                let p1 = payload.clone();
                let p2 = payload.clone();
                let writer_a = tokio::spawn(async move {
                    a_outer.write_all(&p1).await.unwrap();
                    a_outer.shutdown().await.unwrap();
                });
                let writer_b = tokio::spawn(async move {
                    b_outer.write_all(&p2).await.unwrap();
                    b_outer.shutdown().await.unwrap();
                });

                let stats = copy_bidirectional_throttled(
                    &mut a_inner,
                    &mut b_inner,
                    TokenBucket::unlimited(),
                    TokenBucket::unlimited(),
                )
                .await
                .expect("copy");
                writer_a.await.unwrap();
                writer_b.await.unwrap();
                black_box(stats);
            });
        });
    });
    group.finish();
}

criterion_group!(benches, bench_token_bucket, bench_bidir_copy);
criterion_main!(benches);
