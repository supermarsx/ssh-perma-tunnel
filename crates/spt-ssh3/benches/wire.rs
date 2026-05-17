//! Microbenchmarks for the SSH3 wire-format hot paths.
//!
//! Two Criterion groups:
//!
//! * `frame` — encode + decode of the four [`Ssh3Frame`] payload shapes that
//!   appear on every spt↔spt SSH3 connection (control-stream `Settings`, the
//!   per-forward `DirectTcpRequest` channel open, the server-side
//!   `ForwardOpenResponse` ack, and bulk `Data` frames). Each shape is run
//!   at 64 B, 1 KiB and 16 KiB payload sizes so the throughput numbers cover
//!   both short-control and bulk-data behaviour.
//!
//! * `jwt` — verify a P-256 (ES256) JWT. The JWT is constructed **once** in
//!   the bench setup (keypair generation + signing live outside the timed
//!   closure) because verification is the actual auth-hot-loop step that
//!   runs on every SSH3 connect. The bench mirrors the server-side
//!   recipe: take the compact-serialization JWT, split on `.`, base64-decode
//!   the signature, repack the JWS `r || s` bytes into SSH-wire ECDSA
//!   format, and call [`signature::Verifier::verify`] against the public
//!   half of the keypair.
//!
//! Run explicitly with:
//!
//! `cargo bench -p spt-ssh3 --features bench --bench wire`

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use signature::Verifier;
use spt_key::algorithm::KeyAlgorithm;
use spt_key::io as key_io;
use spt_key::KeyPair;
use spt_ssh3::frame::{
    ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, Ssh3Settings,
};
use spt_ssh3::jwt::{build_jwt, fresh_claims, DEFAULT_JWT_LIFETIME_SECS};
use ssh_key::public::PublicKey;
use ssh_key::{Algorithm, EcdsaCurve, Signature};

const PAYLOAD_SIZES: &[usize] = &[64, 1024, 16 * 1024];

/// Build a `Data` frame whose payload is `len` bytes of repeating filler.
fn data_frame(len: usize) -> Ssh3Frame {
    Ssh3Frame::new(Ssh3FrameKind::Data, Bytes::from(vec![0xA5u8; len]))
}

/// Build a `DirectTcpRequest` frame with a host string sized to land the
/// total payload close to `len` bytes. The host string is repeated 'h'
/// characters; the payload header is 4 bytes (`u16` host length + `u16`
/// port), so the host body fills the rest.
fn channel_open_frame(len: usize) -> Ssh3Frame {
    let host_len = len.saturating_sub(4).clamp(1, u16::MAX as usize);
    let host: String = "h".repeat(host_len);
    let payload = ChannelOpenPayload { host, port: 22 }.encode();
    Ssh3Frame::new(Ssh3FrameKind::DirectTcpRequest, payload)
}

/// Build a `ForwardOpenResponse` (the per-forward "ack") frame. The reason
/// string fills the requested payload size minus the 3-byte header
/// (`u8` ok + `u16` reason length).
fn ack_frame(len: usize) -> Ssh3Frame {
    let reason_len = len.saturating_sub(3).clamp(0, u16::MAX as usize);
    let reason: String = "r".repeat(reason_len);
    let payload = ForwardOpenResponse { ok: true, reason }.encode();
    Ssh3Frame::new(Ssh3FrameKind::ForwardOpenResponse, payload)
}

/// Build a `Settings` frame. The Settings payload is small and fixed-shape;
/// the size argument controls the length of the `version` string so the
/// bench can compare short vs long advertised version strings at the same
/// nominal payload sizes as the other frame kinds.
fn settings_frame(len: usize) -> Ssh3Frame {
    let header = 1 + 4 + 2; // flags + max_forwards + version length
    let ver_len = len.saturating_sub(header).clamp(0, u16::MAX as usize);
    let version: String = "v".repeat(ver_len);
    let s = Ssh3Settings {
        direct_tcp: true,
        remote_tcp: true,
        udp_datagrams: true,
        agent_forwarding: false,
        max_forwards: Some(64),
        version: Some(version),
        extras: vec![],
    };
    Ssh3Frame::new(Ssh3FrameKind::Settings, s.encode_payload())
}

fn bench_frame_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame");
    for &size in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        // ---- Settings ----
        let f = settings_frame(size);
        group.bench_with_input(BenchmarkId::new("settings/encode", size), &f, |b, f| {
            b.iter(|| black_box(f.encode()));
        });
        let encoded = f.encode();
        group.bench_with_input(
            BenchmarkId::new("settings/decode", size),
            &encoded,
            |b, e| {
                b.iter(|| {
                    let mut buf = e.clone();
                    let de = Ssh3Frame::decode(&mut buf).expect("decode");
                    black_box(de);
                });
            },
        );

        // ---- ChannelOpen (DirectTcpRequest) ----
        let f = channel_open_frame(size);
        group.bench_with_input(BenchmarkId::new("channel_open/encode", size), &f, |b, f| {
            b.iter(|| black_box(f.encode()));
        });
        let encoded = f.encode();
        group.bench_with_input(
            BenchmarkId::new("channel_open/decode", size),
            &encoded,
            |b, e| {
                b.iter(|| {
                    let mut buf = e.clone();
                    let de = Ssh3Frame::decode(&mut buf).expect("decode");
                    black_box(de);
                });
            },
        );

        // ---- Data ----
        let f = data_frame(size);
        group.bench_with_input(BenchmarkId::new("data/encode", size), &f, |b, f| {
            b.iter(|| black_box(f.encode()));
        });
        let encoded = f.encode();
        group.bench_with_input(BenchmarkId::new("data/decode", size), &encoded, |b, e| {
            b.iter(|| {
                let mut buf = e.clone();
                let de = Ssh3Frame::decode(&mut buf).expect("decode");
                black_box(de);
            });
        });

        // ---- Ack (ForwardOpenResponse) ----
        let f = ack_frame(size);
        group.bench_with_input(BenchmarkId::new("ack/encode", size), &f, |b, f| {
            b.iter(|| black_box(f.encode()));
        });
        let encoded = f.encode();
        group.bench_with_input(BenchmarkId::new("ack/decode", size), &encoded, |b, e| {
            b.iter(|| {
                let mut buf = e.clone();
                let de = Ssh3Frame::decode(&mut buf).expect("decode");
                black_box(de);
            });
        });
    }
    group.finish();
}

/// Repack a JWS-format ECDSA signature (`r || s`, each `field_size` bytes
/// big-endian, zero-padded) back into SSH-wire `mpint || mpint` format so
/// `ssh-key`'s [`Signature::new`] accepts it. Mirror of the
/// `extract_ecdsa_rs` helper in `spt_ssh3::jwt`.
fn jws_rs_to_ssh_wire(rs: &[u8], field_size: usize) -> Vec<u8> {
    assert_eq!(rs.len(), field_size * 2, "JWS r||s must be 2 * field_size");
    let mut out = Vec::with_capacity(rs.len() + 16);
    for half in [&rs[..field_size], &rs[field_size..]] {
        // Strip leading zero bytes (mpint is shortest possible big-endian).
        let mut body: &[u8] = half;
        while body.len() > 1 && body[0] == 0 {
            body = &body[1..];
        }
        // Add a sign byte if the high bit is set.
        let needs_pad = body.first().copied().is_some_and(|b| b & 0x80 != 0);
        let len = body.len() + usize::from(needs_pad);
        out.extend_from_slice(&u32::try_from(len).expect("len fits in u32").to_be_bytes());
        if needs_pad {
            out.push(0);
        }
        out.extend_from_slice(body);
    }
    out
}

/// Pre-built JWT verification fixture: keypair, full compact-serialization
/// JWT string, plus the pre-decoded signing input + SSH-wire signature so
/// the timed loop does the same work as a real server-side `verify`.
struct JwtFixture {
    kp: KeyPair,
    signing_input: String,
    sig: Signature,
}

fn build_p256_jwt_fixture() -> JwtFixture {
    let kp = key_io::generate(KeyAlgorithm::EcdsaP256).expect("generate ES256 keypair");
    let claims = fresh_claims(
        &kp,
        "alice",
        "host.example",
        7443,
        "/ssh3",
        DEFAULT_JWT_LIFETIME_SECS,
    );
    let jwt = build_jwt(&kp, &claims).expect("build JWT");

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = B64URL.decode(parts[2]).expect("base64-decode signature");
    assert_eq!(sig_bytes.len(), 64, "ES256 signature must be 64 bytes");

    let wire = jws_rs_to_ssh_wire(&sig_bytes, 32);
    let sig = Signature::new(
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        wire,
    )
    .expect("ssh-key Signature::new accepts repacked r||s");

    JwtFixture {
        kp,
        signing_input,
        sig,
    }
}

fn bench_jwt_verify(c: &mut Criterion) {
    let fixture = build_p256_jwt_fixture();
    let mut group = c.benchmark_group("jwt");
    group.bench_function("verify_es256", |b| {
        b.iter(|| {
            // Hot loop: signature verification only — the rest of the JWT
            // parse pipeline (split / base64 / repack) is one-time setup
            // cost, identical across implementations. We invoke the
            // `signature::Verifier` trait method via UFCS so it doesn't
            // collide with the inherent `PublicKey::verify(namespace, msg,
            // SshSig)` on the SSH-signature-format path.
            <PublicKey as Verifier<Signature>>::verify(
                fixture.kp.public_ref(),
                black_box(fixture.signing_input.as_bytes()),
                black_box(&fixture.sig),
            )
            .expect("ES256 signature verifies against pubkey");
        });
    });
    group.finish();
}

criterion_group!(benches, bench_frame_group, bench_jwt_verify);
criterion_main!(benches);
