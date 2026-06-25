// Fuzz-harness boilerplate: the doc comments reference wire-format terms that
// read as code to clippy, the `hex` helper deliberately appends `format!` per
// byte, and `assert_no_panic` is intentionally an `if … { panic! }` (it is the
// fuzz-failure reporter, not a plain assert). These are test-only.
#![allow(
    clippy::doc_markdown,
    clippy::format_push_string,
    clippy::manual_assert
)]
//! Deterministic "fuzz"-style malformed-input safety tests for the
//! length-prefixed AEAD/frame decoders in `spt-obfs`.
//!
//! Top fuzz target #3 from the offensive audit
//! (`.orchestration/logs/sec-offensive.md`, "Top 3 fuzz harnesses"): the
//! per-byte hot-path decoders against an untrusted peer — `obfs4::open_frame`,
//! the shadowsocks AEAD open path, and `websocket::decode_binary_frame`. These
//! are correct today (per the audit's "Verified SAFE") but regressions here
//! are silent and the release profile is `panic = "abort"`, so a single
//! decode panic on peer bytes is a process-wide DoS.
//!
//! ## What these tests prove
//!
//! For each decoder, across three malformed-input distributions, the decoder
//! returns `Ok`/`Err` and NEVER panics, aborts, or allocates unbounded
//! memory:
//!
//! * (a) uniformly random byte buffers of varied lengths (0..a few KiB),
//! * (b) structurally-valid-prefix-then-garbage — a real length prefix
//!   (obfs4 2-byte obfuscated `plen`, websocket 5-byte header, shadowsocks
//!   salt) followed by random / oversized / truncated payload — exercises the
//!   length/offset arithmetic,
//! * (c) boundary lengths (0, 1, exactly the frame cap `MAX_FRAME_PT`, cap+1,
//!   and `u16`-max length fields).
//!
//! Where a decoder needs a cipher context (shadowsocks) we set up a fixed test
//! transport with a fixed direct password and fuzz the ciphertext/length
//! fields.
//!
//! ## How a regression surfaces
//!
//! Every decode runs inside [`std::panic::catch_unwind`]. In debug a panic is
//! caught and the test FAILS with the offending input dumped in hex; in
//! release (panic=abort) a genuine panic aborts the process and fails the run
//! loudly. We never silently swallow a panic.
//!
//! Determinism: a fixed-seed [`StdRng`] (rand 0.8, already in the tree).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use spt_obfs::config::{ObfsConfig, SsMethod};
use spt_obfs::obfs4::{open_frame, MAX_FRAME_PT};
use spt_obfs::shadowsocks::ShadowsocksTransport;
use spt_obfs::websocket::decode_binary_frame;
use spt_obfs::NoopAuditHook;
use spt_secrets::SecretRef;

const SEED: u64 = 0x4f42_4653_5f34_2121; // "OBFS_4!!"

const ITERS_RANDOM: usize = 40_000;
const ITERS_STRUCTURED: usize = 30_000;
/// Shadowsocks `open` runs a real BLAKE3 KDF + AES-256-GCM per call, so it is
/// ~10x heavier than the pure framing decoders; use a smaller (still large)
/// count to keep the debug run comfortably under the time budget.
const ITERS_SS: usize = 12_000;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn assert_no_panic<F, T>(label: &str, input: &[u8], decode: F)
where
    F: FnOnce() -> T,
{
    let result = catch_unwind(AssertUnwindSafe(decode));
    if result.is_err() {
        panic!(
            "PANIC in {label} on malformed input ({} bytes):\nhex: {}\n\
             This is a real fuzz finding — the decoder must never panic on \
             arbitrary peer bytes (panic=abort = process DoS in release).",
            input.len(),
            hex(input)
        );
    }
}

/// Fixed 32-byte obfs4 frame key.
const OBFS4_KEY: [u8; 32] = [0x42; 32];

/// Build a shadowsocks transport with a fixed cipher context for fuzzing the
/// AEAD `open` decoder.
fn ss_transport() -> ShadowsocksTransport {
    let cfg = ObfsConfig::Shadowsocks {
        method: SsMethod::Aead2022Blake3Aes256Gcm,
        password: SecretRef::new("fuzz", "ss").expect("static secret ref"),
    };
    ShadowsocksTransport::new(cfg, Arc::new(NoopAuditHook))
        .expect("construct shadowsocks transport")
        .with_direct_password(b"fuzz-fixed-password".to_vec())
}

// ---------------------------------------------------------------------------
// (a) uniformly random byte buffers
// ---------------------------------------------------------------------------

#[test]
fn obfs4_open_frame_survives_uniform_random() {
    let mut rng = StdRng::seed_from_u64(SEED);
    for _ in 0..ITERS_RANDOM {
        let len = rng.gen_range(0..4096usize);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        let ctr = rng.gen::<u64>();
        assert_no_panic("obfs4::open_frame/random", &buf, || {
            open_frame(&OBFS4_KEY, ctr, &buf)
        });
    }
}

#[test]
fn websocket_decode_binary_frame_survives_uniform_random() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x01);
    for _ in 0..ITERS_RANDOM {
        let len = rng.gen_range(0..4096usize);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        assert_no_panic("decode_binary_frame/random", &buf, || {
            decode_binary_frame(&buf)
        });
    }
}

#[test]
fn shadowsocks_open_survives_uniform_random() {
    let t = ss_transport();
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x02);
    for _ in 0..ITERS_SS {
        let len = rng.gen_range(0..4096usize);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        assert_no_panic("shadowsocks::open/random", &buf, || t.open(&buf));
    }
}

// ---------------------------------------------------------------------------
// (b) structurally-valid-prefix-then-garbage
// ---------------------------------------------------------------------------

#[test]
fn websocket_decode_valid_header_then_garbage() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x10);
    for _ in 0..ITERS_STRUCTURED {
        let mut buf = Vec::new();
        // Valid binary opcode byte 0x82 (the decoder checks this first).
        buf.push(0x82);
        // 4-byte big-endian declared length — sometimes mismatching the body.
        let declared: u32 = match rng.gen_range(0..4u8) {
            0 => rng.gen::<u32>(),
            1 => u32::MAX,
            2 => 0,
            _ => rng.gen_range(0..512),
        };
        buf.extend_from_slice(&declared.to_be_bytes());
        let body = rng.gen_range(0..512usize);
        let start = buf.len();
        buf.resize(start + body, 0);
        rng.fill_bytes(&mut buf[start..]);
        assert_no_panic("decode_binary_frame/header+garbage", &buf, || {
            decode_binary_frame(&buf)
        });
    }
}

#[test]
fn obfs4_open_frame_valid_prefix_then_garbage() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x11);
    for _ in 0..ITERS_STRUCTURED {
        // obfs4 frame = [obf_len:2][ciphertext+tag]. Build a 2-byte length
        // prefix (random — it is XOR-masked so any value is plausible) then a
        // body whose length usually contradicts the decoded plen.
        let mut buf = vec![rng.gen::<u8>(), rng.gen::<u8>()];
        let body = rng.gen_range(0..MAX_FRAME_PT + 64);
        let start = buf.len();
        buf.resize(start + body, 0);
        rng.fill_bytes(&mut buf[start..]);
        let ctr = rng.gen::<u64>();
        assert_no_panic("obfs4::open_frame/prefix+garbage", &buf, || {
            open_frame(&OBFS4_KEY, ctr, &buf)
        });
    }
}

#[test]
fn shadowsocks_open_valid_salt_then_garbage() {
    let t = ss_transport();
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x12);
    // salt_len for Aead2022Blake3Aes256Gcm == key_len (32). Prepend a salt of
    // varied length (sometimes short, sometimes exact, sometimes long) then a
    // random ciphertext tail that will fail AEAD verification — must Err, not
    // panic.
    for _ in 0..ITERS_SS {
        let salt_len = match rng.gen_range(0..4u8) {
            0 => rng.gen_range(0..32usize), // short (below salt_len)
            1 => 32,                        // exact
            _ => rng.gen_range(32..96usize),
        };
        let ct_len = rng.gen_range(0..512usize);
        let mut buf = vec![0u8; salt_len + ct_len];
        rng.fill_bytes(&mut buf);
        assert_no_panic("shadowsocks::open/salt+garbage", &buf, || t.open(&buf));
    }
}

// ---------------------------------------------------------------------------
// (c) boundary lengths
// ---------------------------------------------------------------------------

#[test]
fn obfs4_open_frame_boundary_lengths_never_panic() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x20);
    // Framed-buffer lengths at and around the structural minimum (2 + 16) and
    // the plaintext cap (2 + MAX_FRAME_PT + 16).
    let lens: &[usize] = &[
        0,
        1,
        2,
        17,
        18,
        2 + 16,
        2 + 16 + 1,
        2 + MAX_FRAME_PT + 16 - 1,
        2 + MAX_FRAME_PT + 16,
        2 + MAX_FRAME_PT + 16 + 1,
        u16::MAX as usize,
    ];
    for &len in lens {
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        // Drive a few nonce counters incl. boundary values.
        for &ctr in &[0u64, 1, u64::MAX] {
            assert_no_panic("obfs4::open_frame/boundary", &buf, || {
                open_frame(&OBFS4_KEY, ctr, &buf)
            });
        }
    }
}

#[test]
fn websocket_decode_boundary_lengths_never_panic() {
    // Frame lengths at/around the 5-byte header minimum, with declared
    // lengths at u32 extremes.
    let frame_lens: &[usize] = &[0, 1, 4, 5, 6, 7, 64, 1024];
    let declared: &[u32] = &[0, 1, u32::MAX, u32::MAX - 1];
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x21);
    for &flen in frame_lens {
        for &dec in declared {
            let mut buf = vec![0u8; flen];
            if !buf.is_empty() {
                buf[0] = 0x82;
            }
            if buf.len() >= 5 {
                buf[1..5].copy_from_slice(&dec.to_be_bytes());
            }
            if buf.len() > 5 {
                rng.fill_bytes(&mut buf[5..]);
            }
            assert_no_panic("decode_binary_frame/boundary", &buf, || {
                decode_binary_frame(&buf)
            });
        }
    }
}

#[test]
fn shadowsocks_open_boundary_lengths_never_panic() {
    let t = ss_transport();
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x22);
    // salt_len == 32 for the configured method. Sweep around it plus the AEAD
    // tag size (16) so the post-salt ciphertext is sometimes shorter than a
    // single tag.
    let lens: &[usize] = &[0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 1024, 65_536];
    for &len in lens {
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        assert_no_panic("shadowsocks::open/boundary", &buf, || t.open(&buf));
    }
}
