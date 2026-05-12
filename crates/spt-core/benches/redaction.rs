//! Microbenchmarks for `spt_core::redaction::redact`.
//!
//! Sizes (10 KiB / 100 KiB / 1 MiB) approximate log buffers, MCP responses,
//! and full-event JSON dumps. We bench `Standard` (default for log sinks)
//! and `Strict` (hostname/email scrub on top) on the same fixtures so the
//! cost of the strict-only IPv4/IPv6/email passes is visible.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use spt_core::redaction::{redact, RedactionMode};

const SIZES: &[usize] = &[10 * 1024, 100 * 1024, 1024 * 1024];

/// Build a payload of approximately `size` bytes that contains a representative
/// mix of secrets, IPs and emails so both Standard and Strict have real work.
fn build_payload(size: usize) -> String {
    let chunk = "GET /api HTTP/1.1\n\
        Authorization: Bearer abcdef.ghijkl.mnopqr_123\n\
        X-Other: basic dXNlcjpwYXNz\n\
        client_ip=10.0.0.1 peer=2001:db8::1 user=alice@example.com\n\
        password=\"hunter2\" api_key=sk-12345 token=opaque-token\n\
        body: lorem ipsum dolor sit amet, consectetur adipiscing elit, \
        sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
        Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.\n";
    let mut s = String::with_capacity(size + chunk.len());
    while s.len() < size {
        s.push_str(chunk);
    }
    s.truncate(size);
    s
}

fn bench_redact(c: &mut Criterion) {
    let mut group = c.benchmark_group("redact");
    for &size in SIZES {
        let payload = build_payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("standard", size), &payload, |b, p| {
            b.iter(|| {
                let out = redact(black_box(p.as_str()), RedactionMode::Standard);
                black_box(out);
            });
        });
        group.bench_with_input(BenchmarkId::new("strict", size), &payload, |b, p| {
            b.iter(|| {
                let out = redact(black_box(p.as_str()), RedactionMode::Strict);
                black_box(out);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_redact);
criterion_main!(benches);
