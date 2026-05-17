//! Microbenchmarks for `spt-observability` hot paths.
//!
//! Three Criterion groups:
//!
//! * `redaction` — the per-log-line byte rewriter wrapped around every sink
//!   ([`spt_observability::redaction::RedactingWriter`]) at realistic
//!   payload sizes (10 KiB / 100 KiB / 1 MiB).
//! * `metrics_prom` — Prometheus text-format render over a populated
//!   registry (50 counters / 50 gauges / 10 histograms) using the
//!   production [`MetricsExporter::render`] path.
//! * `syslog_framing` — RFC 6587 octet-counted frame emission for
//!   256-byte and 4-KiB syslog records. The framer itself is
//!   `pub(crate)` in `syslog_tcp.rs::write_frame` (an `AsyncWrite` of
//!   `"<len> "` + payload + flush); since we cannot expose that
//!   without taking a write lock outside this executor's scope, the
//!   bench replicates the exact three-call sequence on a reusable
//!   `Vec<u8>`. Any drift between this bench and `write_frame` should
//!   be caught in review.

use std::io::Write;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use prometheus::{Histogram, HistogramOpts, IntCounter, IntGauge, Opts};
use spt_core::RedactionMode;
use spt_observability::redaction::RedactingWriter;
use spt_observability::MetricsExporter;

// ---------------------------------------------------------------------------
// Group 1 — redaction
// ---------------------------------------------------------------------------

const REDACT_SIZES: &[usize] = &[10 * 1024, 100 * 1024, 1024 * 1024];

/// Build a payload of approximately `size` bytes mixing tokens, IPs, emails
/// and prose so the redactor has real work to do on each line.
fn build_redact_payload(size: usize) -> Vec<u8> {
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
    // Ensure the buffer ends with a newline so the writer flushes one final
    // line on every iteration rather than holding tail bytes.
    if !s.ends_with('\n') {
        // Replace the last byte with '\n' to keep the size constant.
        s.pop();
        s.push('\n');
    }
    s.into_bytes()
}

fn bench_redaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("redaction");
    for &size in REDACT_SIZES {
        let payload = build_redact_payload(size);
        group.throughput(Throughput::Bytes(payload.len() as u64));
        // Reuse a single sink Vec across iterations to avoid measuring the
        // sink's own allocator. Reset (clear) inside the iter.
        group.bench_with_input(BenchmarkId::new("standard", size), &payload, |b, p| {
            let mut sink: Vec<u8> = Vec::with_capacity(p.len() + 4096);
            b.iter(|| {
                sink.clear();
                let mut w = RedactingWriter::new(&mut sink, RedactionMode::Standard);
                w.write_all(black_box(p.as_slice())).unwrap();
                w.flush().unwrap();
                black_box(&sink);
            });
        });
        group.bench_with_input(BenchmarkId::new("strict", size), &payload, |b, p| {
            let mut sink: Vec<u8> = Vec::with_capacity(p.len() + 4096);
            b.iter(|| {
                sink.clear();
                let mut w = RedactingWriter::new(&mut sink, RedactionMode::Strict);
                w.write_all(black_box(p.as_slice())).unwrap();
                w.flush().unwrap();
                black_box(&sink);
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Group 2 — metrics_prom
// ---------------------------------------------------------------------------

const N_COUNTERS: usize = 50;
const N_GAUGES: usize = 50;
const N_HISTOGRAMS: usize = 10;
const HISTOGRAM_OBSERVATIONS: usize = 50;

/// Build a `MetricsExporter` with the standard metrics plus a populated set
/// of 50 counters / 50 gauges / 10 histograms registered on its registry.
fn populated_exporter() -> MetricsExporter {
    let me = MetricsExporter::new().expect("exporter");
    let reg = me.registry();

    for i in 0..N_COUNTERS {
        let c = IntCounter::with_opts(Opts::new(
            format!("bench_counter_{i}"),
            format!("synthetic counter {i}"),
        ))
        .expect("counter opts");
        c.inc_by((i as u64).wrapping_mul(7) + 1);
        reg.register(Box::new(c)).expect("register counter");
    }
    for i in 0..N_GAUGES {
        let g = IntGauge::with_opts(Opts::new(
            format!("bench_gauge_{i}"),
            format!("synthetic gauge {i}"),
        ))
        .expect("gauge opts");
        g.set(i as i64 * 3 - 17);
        reg.register(Box::new(g)).expect("register gauge");
    }
    for i in 0..N_HISTOGRAMS {
        let opts = HistogramOpts::new(
            format!("bench_histogram_{i}"),
            format!("synthetic histogram {i}"),
        )
        .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]);
        let h = Histogram::with_opts(opts).expect("hist opts");
        // Observe a handful of values across buckets so the encoder must
        // emit non-trivial per-bucket counts.
        for j in 0..HISTOGRAM_OBSERVATIONS {
            let v = (j as f64).mul_add(0.013, 0.001 * (i as f64 + 1.0));
            h.observe(v);
        }
        reg.register(Box::new(h)).expect("register histogram");
    }
    // Touch the standard metrics so the gathered output is non-empty there too.
    me.standard().bytes_in.with_label_values(&["fwd-1"]).inc_by(123);
    me.standard().bytes_out.with_label_values(&["fwd-1"]).inc_by(456);
    me.standard().reconnects.with_label_values(&["p1"]).inc();
    me.standard().profile_state.with_label_values(&["p1"]).set(2);
    me
}

fn bench_metrics_prom(c: &mut Criterion) {
    let me = populated_exporter();
    // Establish baseline rendered size for a Bytes throughput annotation.
    let body_len = me.render().expect("render").len();

    let mut group = c.benchmark_group("metrics_prom");
    group.throughput(Throughput::Bytes(body_len as u64));
    group.bench_function("render_populated_50c_50g_10h", |b| {
        b.iter(|| {
            let out = me.render().expect("render");
            black_box(out);
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Group 3 — syslog_framing
// ---------------------------------------------------------------------------

const FRAMING_SIZES: &[usize] = &[256, 4096];

/// Build a synthetic RFC 5424-shaped record of `size` bytes. The framing
/// path treats the payload as opaque bytes, so any UTF-8 of the right size
/// works for benchmarking.
fn build_syslog_payload(size: usize) -> Vec<u8> {
    let prefix = b"<134>1 2024-01-01T00:00:00.000Z host spt 1 - - ";
    let mut v = Vec::with_capacity(size);
    v.extend_from_slice(prefix);
    let filler = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
    while v.len() < size {
        let take = (size - v.len()).min(filler.len());
        v.extend_from_slice(&filler[..take]);
    }
    v.truncate(size);
    v
}

/// Replicates `syslog_tcp.rs::write_frame` as a synchronous `std::io::Write`
/// emission: octet-count header (`"<len> "`), payload, flush. Mirrors the
/// three syscalls the async path makes on its inner writer.
#[inline]
fn write_frame_sync<W: Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    // Reuse a small stack-friendly buffer for the header so we don't measure
    // allocation noise when comparing record sizes.
    let mut hdr = itoa_buf::U64Buf::new();
    let hdr_bytes = hdr.write_with_space(payload.len() as u64);
    w.write_all(hdr_bytes)?;
    w.write_all(payload)?;
    w.flush()
}

/// Tiny inline integer-to-ASCII helper so the framer bench doesn't measure
/// `format!`-allocator overhead (the production path uses `format!` because
/// the cost is dwarfed by the async-write context switch; we want to surface
/// the per-byte copy cost here).
mod itoa_buf {
    pub struct U64Buf {
        // Up to 20 digits for u64 + 1 trailing space.
        buf: [u8; 21],
        len: usize,
    }

    impl U64Buf {
        pub const fn new() -> Self {
            Self {
                buf: [0; 21],
                len: 0,
            }
        }

        /// Write `n` followed by a single space into the internal buffer.
        /// Returns the populated slice.
        pub fn write_with_space(&mut self, mut n: u64) -> &[u8] {
            // Emit digits right-to-left into a scratch then copy + space.
            let mut tmp = [0u8; 20];
            let mut idx = tmp.len();
            if n == 0 {
                idx -= 1;
                tmp[idx] = b'0';
            } else {
                while n > 0 {
                    idx -= 1;
                    tmp[idx] = b'0' + (n % 10) as u8;
                    n /= 10;
                }
            }
            let digits = &tmp[idx..];
            self.buf[..digits.len()].copy_from_slice(digits);
            self.buf[digits.len()] = b' ';
            self.len = digits.len() + 1;
            &self.buf[..self.len]
        }
    }
}

fn bench_syslog_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("syslog_framing");
    for &size in FRAMING_SIZES {
        let payload = build_syslog_payload(size);
        // Throughput counts the framed bytes the writer ultimately emits
        // (header + payload), giving an intuitive MB/s figure.
        let header_len = payload.len().to_string().len() + 1; // digits + space
        group.throughput(Throughput::Bytes((header_len + payload.len()) as u64));
        group.bench_with_input(BenchmarkId::new("octet_counted", size), &payload, |b, p| {
            // Reuse the output Vec to isolate the per-iteration copy cost.
            let mut sink: Vec<u8> = Vec::with_capacity(p.len() + 32);
            b.iter(|| {
                sink.clear();
                write_frame_sync(&mut sink, black_box(p.as_slice())).unwrap();
                black_box(&sink);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_redaction, bench_metrics_prom, bench_syslog_framing);
criterion_main!(benches);
