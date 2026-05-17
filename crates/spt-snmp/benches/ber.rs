//! Microbenchmarks for the BER encoder/decoder hot paths.
//!
//! The BER codec sits on every inbound and outbound SNMP datagram — every
//! request the agent parses goes through `Decoder`, every reply it sends
//! goes through `Encoder`. Two specific branches matter for performance:
//!
//! * The OID encoder's **base-128 continuation-byte** loop in
//!   `ber::encode_arc` (one branch per 7 bits of arc value).
//! * The length prefix **short/long form** branch in `ber::write_length`
//!   (`< 128` vs `>= 128` body bytes).
//!
//! ## Payload size mapping (per type)
//!
//! The task brief lists `1B / 64B / 1KB / 8KB`. The four types BER carries
//! have very different size semantics, so size is mapped per-type:
//!
//! * **OCTET STRING** — body byte length: 1, 64, 1024, 8192.
//!   Crosses the length short→long-form boundary at ≥ 128.
//! * **SEQUENCE** — number of nested `i64` elements: 1, 16, 256, 2048.
//!   Each element is ~10 bytes encoded, so 16 elements (~160 bytes body)
//!   crosses the short→long-form boundary.
//! * **OID** — arc count: 4, 16, 64, 256. Arcs alternate small (<128)
//!   and large (>16384) to exercise the base-128 continuation-byte loop
//!   in `encode_arc`.
//! * **INTEGER** — magnitude (not length): `0`, `127`, `128`, `i64::MAX`.
//!   INTEGER is size-bounded, so size sweeps would be meaningless;
//!   magnitudes are chosen to hit each branch of `encode_int`'s leading-
//!   byte trim loop and the sign-pad branch.

#![allow(clippy::many_single_char_names)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use spt_snmp::ber::{decode_oid, encode_oid, Decoder, Encoder, Tag};

// ---------- INTEGER ----------------------------------------------------------

const INT_CASES: &[(&str, i64)] = &[
    ("zero", 0),
    ("one_byte", 127),
    ("sign_pad", 128),
    ("max", i64::MAX),
];

fn bench_integer(c: &mut Criterion) {
    // Encode
    let mut g = c.benchmark_group("ber_integer_encode");
    for (name, v) in INT_CASES {
        g.bench_with_input(BenchmarkId::from_parameter(name), v, |b, &v| {
            b.iter(|| {
                let mut e = Encoder::new();
                e.write_i64(black_box(v));
                black_box(e.finish());
            });
        });
    }
    g.finish();

    // Decode
    let mut g = c.benchmark_group("ber_integer_decode");
    for (name, v) in INT_CASES {
        let mut e = Encoder::new();
        e.write_i64(*v);
        let bytes = e.finish();
        g.bench_with_input(BenchmarkId::from_parameter(name), &bytes, |b, bytes| {
            b.iter(|| {
                let mut d = Decoder::new(black_box(bytes));
                black_box(d.read_i64().expect("decode"));
            });
        });
    }
    g.finish();
}

// ---------- OCTET STRING ----------------------------------------------------

const OCTET_SIZES: &[(&str, usize)] = &[
    ("1B", 1),
    ("64B", 64),
    ("1KB", 1024),
    ("8KB", 8 * 1024),
];

fn bench_octet_string(c: &mut Criterion) {
    // Encode
    let mut g = c.benchmark_group("ber_octet_string_encode");
    for (name, n) in OCTET_SIZES {
        let payload = vec![0xA5u8; *n];
        g.throughput(Throughput::Bytes(*n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &payload, |b, p| {
            b.iter(|| {
                let mut e = Encoder::new();
                e.write_octet_string(black_box(p));
                black_box(e.finish());
            });
        });
    }
    g.finish();

    // Decode
    let mut g = c.benchmark_group("ber_octet_string_decode");
    for (name, n) in OCTET_SIZES {
        let payload = vec![0xA5u8; *n];
        let mut e = Encoder::new();
        e.write_octet_string(&payload);
        let bytes = e.finish();
        g.throughput(Throughput::Bytes(*n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &bytes, |b, bytes| {
            b.iter(|| {
                let mut d = Decoder::new(black_box(bytes));
                black_box(d.read_octet_string().expect("decode"));
            });
        });
    }
    g.finish();
}

// ---------- OID --------------------------------------------------------------

const OID_ARC_COUNTS: &[(&str, usize)] = &[
    ("4_arcs", 4),
    ("16_arcs", 16),
    ("64_arcs", 64),
    ("256_arcs", 256),
];

/// Build an OID of `n` arcs (n >= 2). First arc is `1`, second `3` (so the
/// combined first byte is `0x2B`). Remaining arcs alternate between a small
/// (single-byte) value and a large (4-byte base-128 continuation) value, to
/// exercise the `encode_arc` continuation-byte loop on every other arc.
fn build_oid(n: usize) -> Vec<u32> {
    assert!(n >= 2);
    let mut arcs = Vec::with_capacity(n);
    arcs.push(1);
    arcs.push(3);
    for i in 2..n {
        // Alternate: small under 128 vs large requiring 3 continuation bytes.
        if i % 2 == 0 {
            arcs.push((i as u32) & 0x7F);
        } else {
            // 2^21 + 7  -> needs 4 base-128 bytes.
            arcs.push(0x0020_0007 + (i as u32));
        }
    }
    arcs
}

fn bench_oid(c: &mut Criterion) {
    // Encode (covers the encode_arc base-128 continuation-byte loop).
    let mut g = c.benchmark_group("ber_oid_encode");
    for (name, n) in OID_ARC_COUNTS {
        let arcs = build_oid(*n);
        g.throughput(Throughput::Elements(*n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &arcs, |b, arcs| {
            b.iter(|| {
                let body = encode_oid(black_box(arcs)).expect("encode oid");
                black_box(body);
            });
        });
    }
    g.finish();

    // Decode
    let mut g = c.benchmark_group("ber_oid_decode");
    for (name, n) in OID_ARC_COUNTS {
        let arcs = build_oid(*n);
        let body = encode_oid(&arcs).expect("encode oid");
        g.throughput(Throughput::Elements(*n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &body, |b, body| {
            b.iter(|| {
                let arcs = decode_oid(black_box(body)).expect("decode oid");
                black_box(arcs);
            });
        });
    }
    g.finish();

    // Encode via Encoder::write_oid (full TLV path), one representative size.
    let arcs = build_oid(16);
    c.bench_function("ber_oid_encoder_write_oid_16_arcs", |b| {
        b.iter(|| {
            let mut e = Encoder::new();
            e.write_oid(black_box(&arcs)).expect("write_oid");
            black_box(e.finish());
        });
    });
}

// ---------- SEQUENCE --------------------------------------------------------

const SEQ_ELEMENT_COUNTS: &[(&str, usize)] = &[
    ("1_elem", 1),
    ("16_elems", 16),
    ("256_elems", 256),
    ("2048_elems", 2048),
];

fn bench_sequence(c: &mut Criterion) {
    // Encode — exercises both the short-form (1 elem ~3 bytes) and the
    // long-form length prefix branch (16+ elements ~160+ bytes body).
    let mut g = c.benchmark_group("ber_sequence_encode");
    for (name, n) in SEQ_ELEMENT_COUNTS {
        let n = *n;
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &n, |b, &n| {
            b.iter(|| {
                let mut e = Encoder::new();
                e.write_sequence(|inner| {
                    for i in 0..n {
                        inner.write_i64(black_box(i as i64));
                    }
                });
                black_box(e.finish());
            });
        });
    }
    g.finish();

    // Decode
    let mut g = c.benchmark_group("ber_sequence_decode");
    for (name, n) in SEQ_ELEMENT_COUNTS {
        let n = *n;
        let mut e = Encoder::new();
        e.write_sequence(|inner| {
            for i in 0..n {
                inner.write_i64(i as i64);
            }
        });
        let bytes = e.finish();
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &bytes, |b, bytes| {
            b.iter(|| {
                let mut d = Decoder::new(black_box(bytes));
                let mut seq = d.read_sequence().expect("read_sequence");
                let mut count = 0usize;
                while !seq.is_empty() {
                    let _ = black_box(seq.read_i64().expect("read i64"));
                    count += 1;
                }
                black_box(count);
            });
        });
    }
    g.finish();
}

// ---------- length-prefix short/long form -----------------------------------

/// Targets the `write_length` short/long-form branch by encoding an OCTET
/// STRING whose body crosses the 128-byte boundary in three steps.
fn bench_length_prefix_branch(c: &mut Criterion) {
    let mut g = c.benchmark_group("ber_length_prefix");
    for &(name, n) in &[
        ("short_127", 127usize),
        ("long_128", 128usize),
        ("long_300", 300usize),
        ("long_70k", 70_000usize),
    ] {
        let payload = vec![0u8; n];
        g.bench_with_input(BenchmarkId::from_parameter(name), &payload, |b, p| {
            b.iter(|| {
                let mut e = Encoder::new();
                e.write_tlv(Tag::OCTET_STRING, black_box(p));
                black_box(e.finish());
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_integer,
    bench_octet_string,
    bench_oid,
    bench_sequence,
    bench_length_prefix_branch,
);
criterion_main!(benches);
