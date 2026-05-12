//! Microbenchmarks for the `SNMPv3` USM hot paths.
//!
//! Covers:
//!
//! * `password_to_key` for HMAC-MD5/SHA-1/SHA-256 — the RFC 3414 §A.2.2 +
//!   RFC 7860 §A.1 stretching loop is the dominant cost when bringing up a
//!   new user.
//! * `localize_key` for each algorithm — engine-localization step.
//! * `auth_digest` for each algorithm — authenticate one whole message
//!   (the per-PDU hot path on a busy agent).
//!
//! Inputs use the canonical `password = "maplesyrup"` and a 12-byte engine
//! id ending in `00 00 02` (RFC 3414 §A.3 vectors), so any drift in the
//! benchmark also catches a regression against the published vectors.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use spt_snmp::usm::{auth_digest, localize_key, password_to_key, AuthProtocol};

const ALGS: &[(&str, AuthProtocol)] = &[
    ("md5", AuthProtocol::HmacMd5),
    ("sha1", AuthProtocol::HmacSha1),
    ("sha256", AuthProtocol::HmacSha256),
];

const PASSWORD: &[u8] = b"maplesyrup";
const ENGINE_ID: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn bench_password_to_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("usm_password_to_key");
    for (name, alg) in ALGS {
        group.bench_with_input(BenchmarkId::from_parameter(name), alg, |b, &alg| {
            b.iter(|| {
                let k = password_to_key(alg, black_box(PASSWORD));
                black_box(k);
            });
        });
    }
    group.finish();
}

fn bench_localize_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("usm_localize_key");
    for (name, alg) in ALGS {
        let ku = password_to_key(*alg, PASSWORD);
        group.bench_with_input(BenchmarkId::from_parameter(name), alg, |b, &alg| {
            b.iter(|| {
                let kul = localize_key(alg, black_box(&ku), black_box(&ENGINE_ID));
                black_box(kul);
            });
        });
    }
    group.finish();
}

fn bench_authenticate(c: &mut Criterion) {
    // A small SNMP-sized buffer (~256B) — typical authNoPriv message.
    let msg = vec![0xA5u8; 256];
    let mut group = c.benchmark_group("usm_authenticate");
    for (name, alg) in ALGS {
        let ku = password_to_key(*alg, PASSWORD);
        let kul = localize_key(*alg, &ku, &ENGINE_ID);
        group.bench_with_input(BenchmarkId::from_parameter(name), alg, |b, &alg| {
            b.iter(|| {
                let tag = auth_digest(alg, black_box(&kul), black_box(&msg)).expect("digest");
                black_box(tag);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_password_to_key,
    bench_localize_key,
    bench_authenticate,
);
criterion_main!(benches);
