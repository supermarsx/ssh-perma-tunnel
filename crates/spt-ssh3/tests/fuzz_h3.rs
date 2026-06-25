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
//! hand-rolled HTTP/3 + QPACK wire decoders in `spt-ssh3`.
//!
//! Top fuzz target #1 from the offensive audit
//! (`.orchestration/logs/sec-offensive.md`, "Top 3 fuzz harnesses"): the
//! QPACK/h3 decode path. A crash here is a remote DoS — the release profile
//! is `panic = "abort"`, so any panic on peer bytes kills the whole process
//! (the O1 `n + len` overflow→slice-panic finding).
//!
//! ## What these tests prove
//!
//! For each decoder, across three malformed-input distributions, the decoder
//! returns `Ok` or `Err` and NEVER panics, aborts, or allocates unbounded
//! memory:
//!
//! * (a) uniformly random byte buffers of varied lengths (0..a few KiB),
//! * (b) structurally-valid-prefix-then-garbage (a real QPACK field-section
//!   prefix / field-line opcode followed by random / oversized / truncated
//!   payload — exercises the length/offset math that O1 lived in),
//! * (c) boundary lengths (0, 1, exactly a cap, cap+1, `usize::MAX`-ish length
//!   fields encoded as QPACK prefix-ints).
//!
//! ## How a regression surfaces
//!
//! Every decode call runs inside [`std::panic::catch_unwind`]. In a debug
//! build (panic=unwind) a panic is caught and the test FAILS with the
//! offending input dumped in hex so the case is reproducible. In a release
//! build (panic=abort) a genuine panic aborts the process, which also fails
//! the test run loudly — that is the DoS semantics we are guarding. We never
//! silently swallow a panic.
//!
//! Determinism: a fixed-seed [`StdRng`] (rand 0.8, already in the tree) so
//! every CI run feeds identical bytes. Tuned to stay well under ~30s
//! single-threaded.

use std::panic::{catch_unwind, AssertUnwindSafe};

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use spt_ssh3::frame::Ssh3Frame;
use spt_ssh3::testing::fuzz;

/// Fixed PRNG seed so the corpus is byte-identical across runs.
const SEED: u64 = 0x5353_4833_5f48_3321; // "SSH3_H3!"

/// Iterations per distribution per decoder. ~100k total decode calls across
/// the file; each call is tiny (<= a few KiB) so the whole file runs in a
/// couple of seconds even in debug.
const ITERS_RANDOM: usize = 40_000;
const ITERS_STRUCTURED: usize = 30_000;

/// Hex-dump helper for reproducible failure reports.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Run `decode` on `input`; turn any panic into a test failure that dumps the
/// offending bytes in hex so the case can be replayed. Returns nothing — we
/// only care that it did not panic; the Ok/Err result is intentionally
/// ignored (both are acceptable, neither is a crash).
fn assert_no_panic<F, T>(label: &str, input: &[u8], decode: F)
where
    F: FnOnce() -> T,
{
    let result = catch_unwind(AssertUnwindSafe(decode));
    if result.is_err() {
        panic!(
            "PANIC in {label} on malformed input ({} bytes):\nhex: {}\n\
             This is a real fuzz finding — the decoder must never panic on \
             arbitrary bytes (panic=abort = process DoS in release).",
            input.len(),
            hex(input)
        );
    }
}

/// Encode `value` as a QPACK/HPACK prefix-int with an `n`-bit prefix and a
/// zero top, mirroring the crate's `write_prefix_int`. Used to craft hostile
/// length fields (distribution c).
fn encode_prefix_int(top: u8, n: u8, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let max = (1u64 << n) - 1;
    if value < max {
        out.push(top | (value as u8));
    } else {
        out.push(top | (max as u8));
        let mut remaining = value - max;
        while remaining >= 128 {
            out.push(((remaining & 0x7F) as u8) | 0x80);
            remaining >>= 7;
        }
        out.push(remaining as u8);
    }
    out
}

// ---------------------------------------------------------------------------
// (a) uniformly random byte buffers
// ---------------------------------------------------------------------------

#[test]
fn qpack_decode_survives_uniform_random() {
    let mut rng = StdRng::seed_from_u64(SEED);
    for _ in 0..ITERS_RANDOM {
        let len = rng.gen_range(0..4096usize);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        assert_no_panic("qpack_decode/random", &buf, || fuzz::qpack_decode(&buf));
    }
}

#[test]
fn ssh3_frame_decode_survives_uniform_random() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x01);
    for _ in 0..ITERS_RANDOM {
        let len = rng.gen_range(0..4096usize);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        assert_no_panic("Ssh3Frame::decode/random", &buf, || {
            let mut b = bytes::Bytes::copy_from_slice(&buf);
            Ssh3Frame::decode(&mut b)
        });
    }
}

#[test]
fn read_literal_string_and_prefix_int_survive_uniform_random() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x02);
    for _ in 0..ITERS_RANDOM {
        let len = rng.gen_range(0..512usize);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        assert_no_panic("read_literal_string/random", &buf, || {
            fuzz::read_literal_string(&buf)
        });
        // read_prefix_int's `n` must be 1..=8 (a contract on the caller, not
        // wire data); fuzz every legal prefix width.
        let n = rng.gen_range(1u8..=8);
        assert_no_panic("read_prefix_int/random", &buf, || {
            fuzz::read_prefix_int(&buf, n)
        });
    }
}

// ---------------------------------------------------------------------------
// (b) structurally-valid-prefix-then-garbage
// ---------------------------------------------------------------------------

#[test]
fn qpack_decode_survives_valid_prefix_then_garbage() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x10);
    // The four QPACK field-line opcode families the decoder dispatches on
    // (RFC 9204 §4.5): indexed, literal-with-name-ref, literal-with-literal-
    // name, plus a deliberately-unsupported byte. We prepend a valid field-
    // section prefix (RIC=0, DeltaBase=0) then a chosen opcode then garbage.
    for _ in 0..ITERS_STRUCTURED {
        let mut buf = Vec::new();
        // Valid field-section prefix: 0x00 0x00.
        buf.push(0x00);
        buf.push(0x00);
        // Pick an opcode family.
        let op = match rng.gen_range(0..4u8) {
            0 => 0xC0 | rng.gen_range(0..0x3fu8), // indexed (1 T ...)
            1 => 0x50 | rng.gen_range(0..0x0fu8), // literal-name-ref (01 N T ...)
            2 => 0x20 | rng.gen_range(0..0x07u8), // literal-literal-name (001 N H ...)
            _ => rng.gen_range(0..0x20u8),        // unsupported low opcodes
        };
        buf.push(op);
        // Followed by a random-length garbage tail.
        let tail = rng.gen_range(0..256usize);
        let start = buf.len();
        buf.resize(start + tail, 0);
        rng.fill_bytes(&mut buf[start..]);
        assert_no_panic("qpack_decode/prefix+garbage", &buf, || {
            fuzz::qpack_decode(&buf)
        });
    }
}

#[test]
fn ssh3_frame_decode_survives_valid_header_then_garbage() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x11);
    for _ in 0..ITERS_STRUCTURED {
        let mut buf = Vec::new();
        // kind byte (random — exercises both known and unknown kinds).
        buf.push(rng.gen::<u8>());
        // 4-byte big-endian declared length — sometimes huge, sometimes the
        // cap, sometimes tiny — followed by a body that usually does NOT
        // match the declared length (truncation / over-declaration).
        let declared: u32 = match rng.gen_range(0..4u8) {
            0 => rng.gen::<u32>(),      // arbitrary (often > cap)
            1 => 16 * 1024 * 1024,      // exactly a plausible cap
            2 => 16 * 1024 * 1024 + 1,  // cap + 1
            _ => rng.gen_range(0..512), // small
        };
        buf.extend_from_slice(&declared.to_be_bytes());
        let body = rng.gen_range(0..512usize);
        let start = buf.len();
        buf.resize(start + body, 0);
        rng.fill_bytes(&mut buf[start..]);
        assert_no_panic("Ssh3Frame::decode/header+garbage", &buf, || {
            let mut b = bytes::Bytes::copy_from_slice(&buf);
            Ssh3Frame::decode(&mut b)
        });
    }
}

// ---------------------------------------------------------------------------
// (c) boundary lengths — the O1 `n + len` overflow class, exhaustively
// ---------------------------------------------------------------------------

#[test]
fn read_literal_string_boundary_and_overflow_lengths_never_panic() {
    // Length fields at and around every interesting boundary, with 0/1/exact/
    // over body sizes. This is the distribution that O1 (the unchecked
    // `n + len` slice) lived in.
    let lengths: &[u64] = &[
        0,
        1,
        2,
        126,
        127,
        128,
        129,
        255,
        256,
        4095,
        4096,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    let body_sizes: &[usize] = &[0, 1, 2, 16, 256];
    for &len in lengths {
        // literal-string header: top bit (Huffman) = 0, 7-bit prefix length.
        let header = encode_prefix_int(0x00, 7, len);
        for &body in body_sizes {
            let mut buf = header.clone();
            buf.resize(buf.len() + body, 0xAB);
            assert_no_panic("read_literal_string/boundary", &buf, || {
                fuzz::read_literal_string(&buf)
            });
            // Same hostile length driven end-to-end through qpack_decode via a
            // literal-name-ref field (static name idx 0 = :authority).
            let mut e2e = vec![0x00, 0x00, 0x50];
            e2e.extend_from_slice(&buf);
            assert_no_panic("qpack_decode/boundary", &e2e, || fuzz::qpack_decode(&e2e));
        }
    }
}

#[test]
fn read_prefix_int_boundary_lengths_never_panic() {
    // Every legal prefix width against truncated / maximal continuation
    // sequences. Includes a 10-byte all-continuation run (the longest a u64
    // can need) and an over-long run that must be rejected, not panic.
    let payloads: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xFF],
        vec![0xFF, 0xFF],
        // max-prefix then 9 continuation bytes with high bit set (never
        // terminates within u64) -> must Err on "continuation too long".
        {
            let mut v = vec![0xFF];
            v.extend(std::iter::repeat_n(0x80, 12));
            v
        },
        // valid long value: 0xFF then a terminating continuation.
        vec![0xFF, 0x81, 0x01],
    ];
    for n in 1u8..=8 {
        for p in &payloads {
            assert_no_panic("read_prefix_int/boundary", p, || {
                fuzz::read_prefix_int(p, n)
            });
        }
    }
}
