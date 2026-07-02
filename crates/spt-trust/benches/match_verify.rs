//! Microbenchmarks for the trust hot paths.
//!
//! Two bench groups:
//!
//! * `known_hosts_match` — `KnownHosts::verify` against a populated
//!   100-entry table that mixes hashed (`|1|salt|hash`) and plaintext
//!   host fields. The hashed path runs HMAC-SHA1 per candidate, the
//!   plaintext path is a linear glob/comma scan; both are the real
//!   per-handshake cost on a busy fleet's `~/.ssh/known_hosts`.
//!     - `hit_first` — match on the first entry (best case).
//!     - `hit_last`  — match on the last entry (worst-case scan).
//!     - `miss`      — host not in the table (full scan + `NotFound`).
//!
//! * `tls_pin_verify` — `TlsPin::verify` against a real self-signed
//!   X.509 (DER) cert minted with `rcgen`. Two cases:
//!     - `match`    — the pin set contains the cert's SPKI digest.
//!     - `mismatch` — the pin set contains only a non-matching digest,
//!       so verify fails with `TrustFailed` after the SHA-256.
//!
//! Run explicitly with:
//!
//! `cargo bench -p spt-trust --features bench --bench match_verify`

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use spt_trust::known_hosts::{KnownHosts, KnownHostsResult};
use spt_trust::tls_pin::TlsPin;
use x509_parser::prelude::*;

/// Build a 100-entry [`KnownHosts`] populated with a mix of plaintext and
/// hashed entries. The fixture key is the deterministic Ed25519 fixture from
/// `spt-key::testing` so every run has stable inputs.
///
/// Layout (index → form):
///   * even indices → plaintext `host{i}.example` (port 22)
///   * odd indices  → hashed `host{i}.example`    (port 22)
///
/// The very last entry is the "target" host used by the `hit_last` bench.
fn build_known_hosts_100() -> (KnownHosts, ssh_key::PublicKey) {
    let kp = spt_key::testing::fixtures::ed25519_kp().expect("ed25519 fixture");
    let pk = kp.public_ref().clone();
    let mut kh = KnownHosts::default();
    for i in 0..100u32 {
        let host = format!("host{i}.example");
        let hashed = i % 2 == 1;
        kh.add(&host, 22, pk.clone(), hashed);
    }
    (kh, pk)
}

fn bench_known_hosts_match(c: &mut Criterion) {
    let (kh, pk) = build_known_hosts_100();
    let mut group = c.benchmark_group("known_hosts_match");

    // Hit on the first entry (even → plaintext path).
    group.bench_function("hit_first", |b| {
        b.iter(|| {
            let r = kh.verify(black_box("host0.example"), black_box(22), black_box(&pk));
            debug_assert!(matches!(r, KnownHostsResult::Match));
            black_box(r);
        });
    });

    // Hit on the last entry (odd → hashed path, full scan).
    group.bench_function("hit_last", |b| {
        b.iter(|| {
            let r = kh.verify(black_box("host99.example"), black_box(22), black_box(&pk));
            debug_assert!(matches!(r, KnownHostsResult::Match));
            black_box(r);
        });
    });

    // Miss — host is not in the table, full scan + NotFound.
    group.bench_function("miss", |b| {
        b.iter(|| {
            let r = kh.verify(black_box("nope.example"), black_box(22), black_box(&pk));
            debug_assert!(matches!(r, KnownHostsResult::NotFound));
            black_box(r);
        });
    });

    group.finish();
}

/// Mint a self-signed cert with `rcgen` and return `(DER bytes, SPKI SHA-256)`.
/// The SPKI digest is computed the same way `TlsPin::verify` does it (over
/// `tbs_certificate.subject_pki.raw`), so the resulting pin is guaranteed to
/// match the cert.
fn mint_cert_and_pin() -> (Vec<u8>, [u8; 32]) {
    let cert = rcgen::generate_simple_self_signed(vec!["bench.example".into()])
        .expect("rcgen self-signed cert");
    let der = cert.cert.der().to_vec();
    let (_, parsed) = X509Certificate::from_der(&der).expect("parse self-signed DER");
    let mut h = Sha256::new();
    h.update(parsed.tbs_certificate.subject_pki.raw);
    let pin: [u8; 32] = h.finalize().into();
    (der, pin)
}

fn bench_tls_pin_verify(c: &mut Criterion) {
    let (der, pin) = mint_cert_and_pin();
    let cert_der = CertificateDer::from(der);

    let matching = TlsPin {
        spki_sha256: vec![pin],
    };
    let mismatching = TlsPin {
        spki_sha256: vec![[0xAB; 32]],
    };

    let mut group = c.benchmark_group("tls_pin_verify");

    group.bench_function("match", |b| {
        b.iter(|| {
            let r = matching.verify(black_box(&cert_der));
            debug_assert!(r.is_ok());
            black_box(r.ok());
        });
    });

    group.bench_function("mismatch", |b| {
        b.iter(|| {
            let r = mismatching.verify(black_box(&cert_der));
            debug_assert!(r.is_err());
            black_box(r.err());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_known_hosts_match, bench_tls_pin_verify);
criterion_main!(benches);
