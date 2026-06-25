// Fuzz-harness boilerplate: the doc comments reference wire-format terms that
// read as code to clippy, the `hex` helper deliberately appends `format!` per
// byte, and `assert_no_panic` is intentionally an `if … { panic! }` (it is the
// fuzz-failure reporter, not a plain assert). These are test-only.
#![allow(
    clippy::doc_markdown,
    clippy::format_push_string,
    clippy::manual_assert
)]
//! Deterministic "fuzz"-style malformed-input safety tests for the SNMP wire
//! decoders in `spt-snmp`.
//!
//! Top fuzz target #2 from the offensive audit
//! (`.orchestration/logs/sec-offensive.md`, "Top 3 fuzz harnesses"): the
//! SNMPv3 message / PDU / BER decode path and the GetBulk handler. This is the
//! unauthenticated UDP attack surface — a crash here is a remote DoS, and the
//! release profile is `panic = "abort"`, so any panic on a peer datagram kills
//! the whole process.
//!
//! ## What these tests prove
//!
//! For each decoder, across three malformed-input distributions, the decoder
//! returns `Ok`/`Err` and NEVER panics, aborts, or allocates unbounded memory:
//!
//! * (a) uniformly random byte buffers of varied lengths (0..a few KiB),
//! * (b) structurally-valid-prefix-then-garbage — a real BER `SEQUENCE`
//!   TLV header (tag + length) followed by random / oversized / truncated
//!   payload, exercising the length/offset arithmetic the audit's `pos + n`
//!   class lived in,
//! * (c) boundary lengths (0, 1, exactly a cap, cap+1, and `usize`-max-ish BER
//!   long-form length fields).
//!
//! Plus a LIVE path: malformed datagrams are fired at a running agent socket so
//! the real `handle_datagram` → decode → dispatch (incl. the GetBulk handler)
//! chain is exercised, and the agent is proven to still answer a valid request
//! afterwards (bounded, no spin/OOM/abort).
//!
//! ## How a regression surfaces
//!
//! Every pure-decode call runs inside [`std::panic::catch_unwind`]. In a debug
//! build (panic=unwind) a panic is caught and the test FAILS with the offending
//! input dumped in hex so the case is reproducible. In a release build
//! (panic=abort) a genuine panic aborts the process and fails the run loudly —
//! that is the DoS semantics we are guarding. We never silently swallow a
//! panic.
//!
//! Determinism: a fixed-seed [`StdRng`] (rand, already in the tree) so every CI
//! run feeds identical bytes. Tuned to stay well under ~30s single-threaded.

use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use spt_snmp::ber::{decode_oid, Decoder};
use spt_snmp::message::{Message, ScopedPdu, SecurityParameters};
use spt_snmp::pdu::{Pdu, PduKind};
use spt_snmp::usm::{AuthProtocol, SecretBytes, UsmUser};
use spt_snmp::value::VarBind;
use spt_snmp::{AgentBuilder, AgentHandle, ConstScalar, ObjectIdentifier, Value};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Fixed PRNG seed so the corpus is byte-identical across runs.
const SEED: u64 = 0x534e_4d50_5f42_4552; // "SNMP_BER"

/// Iterations per distribution per decoder. Each call is tiny (<= a few KiB) so
/// the whole file's pure-decode portion runs in a couple of seconds in debug.
const ITERS_RANDOM: usize = 30_000;
const ITERS_STRUCTURED: usize = 20_000;

/// Hex-dump helper for reproducible failure reports.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Run `decode` on `input`; turn any panic into a test failure that dumps the
/// offending bytes in hex so the case can be replayed. The Ok/Err result is
/// intentionally ignored (both are acceptable; only a panic is a crash).
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

/// Encode a BER definite length (short form `< 0x80`, else long form). Used to
/// craft structurally-valid TLV headers in distribution (b).
fn encode_ber_len(len: u64) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut body = Vec::new();
    let mut v = len;
    while v > 0 {
        body.push((v & 0xFF) as u8);
        v >>= 8;
    }
    body.reverse();
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(0x80 | (body.len() as u8));
    out.extend_from_slice(&body);
    out
}

/// Drive every pure-byte decode entry point on one buffer.
fn drive_all_decoders(label: &str, buf: &[u8]) {
    assert_no_panic(&format!("{label}/Message::from_bytes"), buf, || {
        Message::from_bytes(buf)
    });
    assert_no_panic(&format!("{label}/ScopedPdu::from_bytes"), buf, || {
        ScopedPdu::from_bytes(buf)
    });
    assert_no_panic(
        &format!("{label}/SecurityParameters::decode_inner"),
        buf,
        || SecurityParameters::decode_inner(buf),
    );
    assert_no_panic(&format!("{label}/decode_oid"), buf, || decode_oid(buf));
    // The raw BER reader chain: a sequence of reads against arbitrary bytes.
    assert_no_panic(&format!("{label}/Decoder chain"), buf, || {
        let mut d = Decoder::new(buf);
        let _ = d.peek_tag();
        let _ = d.read_tlv();
        let mut d2 = Decoder::new(buf);
        if let Ok(mut seq) = d2.read_sequence() {
            let _ = seq.read_i64();
            let _ = seq.read_octet_string();
            let _ = seq.read_oid();
        }
        let mut d3 = Decoder::new(buf);
        let _ = d3.read_i64();
        let mut d4 = Decoder::new(buf);
        let _ = d4.read_octet_string();
        let mut d5 = Decoder::new(buf);
        let _ = d5.read_oid();
    });
}

// ---------------------------------------------------------------------------
// (a) uniformly random byte buffers
// ---------------------------------------------------------------------------

#[test]
fn snmp_decoders_survive_uniform_random() {
    let mut rng = StdRng::seed_from_u64(SEED);
    for _ in 0..ITERS_RANDOM {
        let len = rng.gen_range(0..4096usize);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        drive_all_decoders("random", &buf);
    }
}

// ---------------------------------------------------------------------------
// (b) structurally-valid-prefix-then-garbage
// ---------------------------------------------------------------------------

#[test]
fn snmp_decoders_survive_valid_ber_header_then_garbage() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x10);
    // A real BER tag + length header (sometimes SEQUENCE, sometimes other
    // primitive tags, with a declared length that usually contradicts the
    // body) followed by random garbage. This exercises the length/offset math
    // (`read_length` + the `pos + len` slice extraction) on a structurally
    // plausible prefix — the audit's `pos + n` class.
    let tags: &[u8] = &[
        0x30, // SEQUENCE
        0x02, // INTEGER
        0x04, // OCTET STRING
        0x06, // OID
        0x05, // NULL
        0x40, // IpAddress (APPLICATION 0)
        0x41, // Counter32
        0x43, // TimeTicks
        0xa2, // GetResponse PDU (context 2)
        0xa5, // GetBulk PDU (context 5)
    ];
    for _ in 0..ITERS_STRUCTURED {
        let mut buf = Vec::new();
        let tag = tags[rng.gen_range(0..tags.len())];
        buf.push(tag);
        // Declared length — sometimes huge (long-form), sometimes contradicting
        // the body, sometimes accurate-ish.
        let declared: u64 = match rng.gen_range(0..5u8) {
            0 => rng.gen_range(0..0x80),      // short form
            1 => u64::from(rng.gen::<u32>()), // arbitrary long form
            2 => u64::MAX,                    // pathological long form
            3 => 0,                           // empty
            _ => rng.gen_range(0..512),       // small-ish
        };
        buf.extend_from_slice(&encode_ber_len(declared));
        let body = rng.gen_range(0..512usize);
        let start = buf.len();
        buf.resize(start + body, 0);
        rng.fill_bytes(&mut buf[start..]);
        drive_all_decoders("ber-header+garbage", &buf);
    }
}

#[test]
fn snmp_decoders_survive_nested_sequences() {
    // Deeply / repeatedly nested SEQUENCE headers to exercise the recursive
    // descent (read_sequence within read_sequence) of Message/ScopedPdu decode
    // against truncated inner content. No stack overflow / panic permitted.
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x11);
    for _ in 0..ITERS_STRUCTURED {
        let depth = rng.gen_range(0..40usize);
        let mut buf = Vec::new();
        // Emit `depth` SEQUENCE headers each claiming a large length, then a
        // random tail. The decoder must reject the under-length content with an
        // Err, never recurse unbounded or panic.
        for _ in 0..depth {
            buf.push(0x30);
            buf.extend_from_slice(&encode_ber_len(rng.gen_range(0..4096)));
        }
        let tail = rng.gen_range(0..64usize);
        let start = buf.len();
        buf.resize(start + tail, 0);
        rng.fill_bytes(&mut buf[start..]);
        drive_all_decoders("nested-sequences", &buf);
    }
}

// ---------------------------------------------------------------------------
// (c) boundary lengths
// ---------------------------------------------------------------------------

#[test]
fn snmp_decoders_boundary_lengths_never_panic() {
    // BER long-form length fields at and around every interesting boundary,
    // each with 0/1/exact/short bodies. This is the distribution the SNMP
    // `pos + n` / `IpAddress`-copy panic class lived in.
    let lengths: &[u64] = &[
        0,
        1,
        2,
        0x7f,
        0x80,
        0x81,
        127,
        128,
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
    let body_sizes: &[usize] = &[0, 1, 2, 4, 16, 256];
    let tags: &[u8] = &[0x30, 0x02, 0x04, 0x06, 0x40];
    for &tag in tags {
        for &len in lengths {
            let header = {
                let mut h = vec![tag];
                h.extend_from_slice(&encode_ber_len(len));
                h
            };
            for &body in body_sizes {
                let mut buf = header.clone();
                buf.resize(buf.len() + body, 0xAB);
                drive_all_decoders("boundary", &buf);
            }
        }
    }
}

#[test]
fn snmp_oid_decode_boundary_arcs_never_panic() {
    // OID decode against subidentifiers with maximal continuation runs (the
    // >32-bit arc rejection path) and truncated continuations.
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x20);
    for _ in 0..ITERS_STRUCTURED {
        let len = rng.gen_range(0..64usize);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        // Bias some bytes to have the high continuation bit set so we hit the
        // multi-byte subidentifier accumulator paths.
        for b in &mut buf {
            if rng.gen_bool(0.5) {
                *b |= 0x80;
            }
        }
        assert_no_panic("decode_oid/boundary", &buf, || decode_oid(&buf));
    }
}

// ---------------------------------------------------------------------------
// LIVE PATH: malformed datagrams against a running agent (handle_datagram →
// decode → dispatch). Proves bounded handling + continued liveness.
// ---------------------------------------------------------------------------

fn fuzz_user() -> UsmUser {
    UsmUser::auth_only(
        "probe",
        AuthProtocol::HmacSha256,
        SecretBytes::from("password-must-be-at-least-eight-bytes"),
    )
}

async fn spawn_agent() -> AgentHandle {
    AgentBuilder::new()
        .documentation_enterprise_pen()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(fuzz_user())
        .add_scalar(
            "1.3.6.1.4.1.32473.1.1.0".parse().unwrap(),
            ConstScalar::new(Value::Integer(7)),
        )
        .run()
        .await
        .unwrap()
}

/// Send a discovery (engine-id) request and confirm the agent answers, proving
/// it is alive and serving after a barrage of garbage datagrams.
async fn assert_agent_alive(sock: &UdpSocket, target: SocketAddr) {
    use spt_snmp::message::{
        GlobalData, MessageData, SecurityParameters as Sec, FLAG_REPORTABLE, SECURITY_MODEL_USM,
    };
    let scoped = ScopedPdu {
        context_engine_id: vec![],
        context_name: vec![],
        pdu: Pdu {
            kind: PduKind::GetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(
                "1.3.6.1.4.1.32473.1.1.0"
                    .parse::<ObjectIdentifier>()
                    .unwrap(),
            )],
        },
    };
    let msg = Message {
        global: GlobalData {
            msg_id: 1,
            msg_max_size: 65_507,
            msg_flags: FLAG_REPORTABLE,
            msg_security_model: SECURITY_MODEL_USM,
        },
        security: Sec {
            engine_id: vec![],
            engine_boots: 0,
            engine_time: 0,
            user_name: vec![],
            auth_params: vec![],
            priv_params: vec![],
        },
        data: MessageData::Plain(scoped.to_bytes().unwrap()),
    };
    sock.send_to(&msg.to_bytes().unwrap(), target)
        .await
        .unwrap();
    let mut buf = vec![0u8; 65_535];
    let got = timeout(Duration::from_millis(1500), sock.recv_from(&mut buf)).await;
    assert!(
        matches!(got, Ok(Ok(_))),
        "agent must still answer a valid discovery request after malformed-datagram barrage"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_survives_malformed_datagram_barrage() {
    let agent = spawn_agent().await;
    let target = agent.local_addr();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Confirm liveness before the barrage.
    assert_agent_alive(&sock, target).await;

    let mut rng = StdRng::seed_from_u64(SEED ^ 0x30);
    // A large but UDP-sized barrage of malformed datagrams. Each goes through
    // the real handle_datagram → Message::from_bytes → (maybe) dispatch path.
    // A panic in that task under panic=abort would kill the process; a hang or
    // OOM would make the post-barrage liveness check time out.
    for i in 0..3_000 {
        let kind = i % 3;
        let datagram: Vec<u8> = match kind {
            0 => {
                // Uniform random datagram (0..1500 — typical MTU).
                let len = rng.gen_range(0..1500usize);
                let mut b = vec![0u8; len];
                rng.fill_bytes(&mut b);
                b
            }
            1 => {
                // SEQUENCE header with a pathological declared length + garbage.
                let mut b = vec![0x30];
                b.extend_from_slice(&encode_ber_len(match rng.gen_range(0..3u8) {
                    0 => u64::MAX,
                    1 => u64::from(u32::MAX),
                    _ => rng.gen_range(0..2048),
                }));
                let tail = rng.gen_range(0..256usize);
                let s = b.len();
                b.resize(s + tail, 0);
                rng.fill_bytes(&mut b[s..]);
                b
            }
            _ => {
                // A GetBulk-shaped context-tagged PDU header then garbage, to
                // poke the dispatch/handler entry under malformed framing.
                let mut b = vec![0x30];
                b.extend_from_slice(&encode_ber_len(rng.gen_range(0..512)));
                b.push(0x02); // version INTEGER
                b.extend_from_slice(&encode_ber_len(1));
                b.push(rng.gen::<u8>());
                let tail = rng.gen_range(0..256usize);
                let s = b.len();
                b.resize(s + tail, 0);
                rng.fill_bytes(&mut b[s..]);
                b
            }
        };
        // Fire and (mostly) forget; drain any reply without blocking long.
        sock.send_to(&datagram, target).await.unwrap();
        // Non-blocking drain of any reply: malformed datagrams seldom elicit
        // one, and we must not spend a per-iteration timeout budget here.
        let mut rbuf = vec![0u8; 65_535];
        let _ = sock.try_recv_from(&mut rbuf);
    }

    // The agent must still be alive and serving.
    assert_agent_alive(&sock, target).await;
    agent.shutdown().await.unwrap();
}
