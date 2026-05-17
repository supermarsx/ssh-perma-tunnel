//! Microbenchmarks for `spt-stats` hot paths.
//!
//! Groups:
//!
//! * `sliding_window` — `SlidingWindow::{add_bytes, record_conn, record_error}`
//!   write paths at 1k / 100k samples, plus the `aggregates()` snapshot read.
//! * `ewma` — `Ewma::sample` in a tight 10k-iteration loop (the supervisor's
//!   throughput-tracking hot path).
//! * `session_table` — `SessionTable::{insert, get, remove}` at N=10 (fresh
//!   sessions) and N=1000 (busy server).
//! * `connection_table` — same shape against `ConnectionTable`.
//! * `instability` — `InstabilityDetector::{record_reconnect, record_error}`
//!   over 1k events plus a final `evaluate()`.
//!
//! Run explicitly with:
//!
//! `cargo bench -p spt-stats --features bench --bench aggregation`
//!
//! Note on API names: `SlidingWindow` exposes typed write methods
//! (`add_bytes`/`record_conn`/`record_error`) and `aggregates()` for the
//! snapshot read — these are the public hot paths. `Ewma::sample(value, dt)`
//! is the single update entry-point. `InstabilityDetector::record_reconnect`
//! / `record_error` plus `evaluate()` are the supervisor-facing trait
//! methods.

#![allow(missing_docs)]

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use spt_core::{ConnectionId, ForwardId, ProfileId, SessionId};
use spt_stats::{
    instability::{InstabilityDetector, ThresholdInstability},
    tables::{ConnectionEntry, ConnectionTable, SessionEntry, SessionTable},
    Ewma, SlidingWindow,
};

fn sample_session(i: usize) -> SessionEntry {
    let opened = chrono::DateTime::from_timestamp(0, 0).expect("epoch");
    SessionEntry {
        session_id: SessionId::new(format!("s{i}")).expect("session id"),
        profile_id: ProfileId::new("p").expect("profile id"),
        opened_at: opened,
        remote_endpoint: "host:22".into(),
        last_activity: opened,
        bytes_in: 0,
        bytes_out: 0,
    }
}

fn sample_connection(i: usize) -> ConnectionEntry {
    let opened = chrono::DateTime::from_timestamp(0, 0).expect("epoch");
    ConnectionEntry {
        connection_id: ConnectionId::new(format!("c{i}")).expect("connection id"),
        session_id: SessionId::new("s0").expect("session id"),
        forward_id: ForwardId::new(format!("f{}", i % 3)).expect("forward id"),
        opened_at: opened,
        peer: "10.0.0.1:55000".into(),
        local: "127.0.0.1:5000".into(),
        bytes_in: 0,
        bytes_out: 0,
    }
}

fn bench_sliding_window(c: &mut Criterion) {
    let mut group = c.benchmark_group("sliding_window");

    for &samples in &[1_000_usize, 100_000_usize] {
        group.throughput(Throughput::Elements(samples as u64));
        group.bench_with_input(
            BenchmarkId::new("record", samples),
            &samples,
            |b, &samples| {
                b.iter(|| {
                    let w = SlidingWindow::new(Duration::from_secs(60), 6);
                    for i in 0..samples {
                        w.add_bytes(black_box(i as u64));
                        if i % 8 == 0 {
                            w.record_conn();
                        }
                        if i % 32 == 0 {
                            w.record_error();
                        }
                    }
                    black_box(w);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("summary", samples),
            &samples,
            |b, &samples| {
                // Pre-populate once outside the hot loop; we're measuring the
                // snapshot read, not the writes.
                let w = SlidingWindow::new(Duration::from_secs(60), 6);
                for i in 0..samples {
                    w.add_bytes(i as u64);
                }
                b.iter(|| {
                    let a = w.aggregates();
                    black_box(a);
                });
            },
        );
    }

    group.finish();
}

fn bench_ewma(c: &mut Criterion) {
    const ITERS: usize = 10_000;
    let mut group = c.benchmark_group("ewma");
    group.throughput(Throughput::Elements(ITERS as u64));
    group.bench_function("sample_tight_10k", |b| {
        b.iter(|| {
            let e = Ewma::new(Duration::from_secs(1));
            for i in 0..ITERS {
                e.sample(black_box(i as f64), Duration::from_millis(1));
            }
            black_box(e.value());
        });
    });
    group.finish();
}

fn bench_session_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_table");

    for &n in &[10_usize, 1_000_usize] {
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("insert", n), &n, |b, &n| {
            b.iter(|| {
                let t = SessionTable::new();
                for i in 0..n {
                    t.insert(sample_session(i));
                }
                black_box(t.len());
            });
        });

        group.bench_with_input(BenchmarkId::new("get", n), &n, |b, &n| {
            let t = SessionTable::new();
            for i in 0..n {
                t.insert(sample_session(i));
            }
            let keys: Vec<SessionId> = (0..n)
                .map(|i| SessionId::new(format!("s{i}")).expect("session id"))
                .collect();
            b.iter(|| {
                for k in &keys {
                    black_box(t.get(black_box(k)));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("remove", n), &n, |b, &n| {
            // Re-populate every iteration so the remove loop actually has
            // work to do. The `iter_batched`-style preparation is folded into
            // the timed body — the cost is the same across the two N values
            // and dominated by `remove` at large N.
            b.iter(|| {
                let t = SessionTable::new();
                for i in 0..n {
                    t.insert(sample_session(i));
                }
                for i in 0..n {
                    let id = SessionId::new(format!("s{i}")).expect("session id");
                    black_box(t.remove(black_box(&id)));
                }
                black_box(t.len());
            });
        });
    }

    group.finish();
}

fn bench_connection_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_table");

    for &n in &[10_usize, 1_000_usize] {
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("insert", n), &n, |b, &n| {
            b.iter(|| {
                let t = ConnectionTable::new();
                for i in 0..n {
                    t.insert(sample_connection(i));
                }
                black_box(t.len());
            });
        });

        group.bench_with_input(BenchmarkId::new("get", n), &n, |b, &n| {
            let t = ConnectionTable::new();
            for i in 0..n {
                t.insert(sample_connection(i));
            }
            let keys: Vec<ConnectionId> = (0..n)
                .map(|i| ConnectionId::new(format!("c{i}")).expect("connection id"))
                .collect();
            b.iter(|| {
                for k in &keys {
                    black_box(t.get(black_box(k)));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("remove", n), &n, |b, &n| {
            b.iter(|| {
                let t = ConnectionTable::new();
                for i in 0..n {
                    t.insert(sample_connection(i));
                }
                for i in 0..n {
                    let id = ConnectionId::new(format!("c{i}")).expect("connection id");
                    black_box(t.remove(black_box(&id)));
                }
                black_box(t.len());
            });
        });
    }

    group.finish();
}

fn bench_instability(c: &mut Criterion) {
    const EVENTS: usize = 1_000;
    let mut group = c.benchmark_group("instability");
    group.throughput(Throughput::Elements(EVENTS as u64));
    group.bench_function("observe_1k_events", |b| {
        b.iter(|| {
            let d = ThresholdInstability::new(Duration::from_secs(60), 6, 10_000, 10_000);
            for i in 0..EVENTS {
                // Mix reconnects and errors so both counters get exercised.
                if i % 3 == 0 {
                    d.record_error();
                } else {
                    d.record_reconnect();
                }
            }
            let v = d.evaluate();
            black_box(v);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_sliding_window,
    bench_ewma,
    bench_session_table,
    bench_connection_table,
    bench_instability,
);
criterion_main!(benches);
