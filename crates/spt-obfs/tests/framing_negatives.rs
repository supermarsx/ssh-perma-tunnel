//! Negative / edge-case framing coverage for the spt-obfs stream layers.
//!
//! The existing suites (`contract.rs`, `obfs4_vectors.rs`,
//! `shadowsocks_replay.rs`) are positive-path heavy, and `fuzz_obfs.rs`
//! asserts only *no-panic* across random/structured/boundary inputs. This
//! file asserts **exact error behaviour** on the structural negatives the
//! fuzz harness deliberately does not pin:
//!
//! * oversized frame (length field claims > the protocol cap) → clean reject
//! * replayed nonce inside a session (shadowsocks `AeadStream`) → reject
//! * nonce-counter advance / desync handling
//! * fragmented `poll_read` (a frame split across multiple 1-byte reads
//!   reassembles correctly; a partial frame yields `Pending`, not a panic
//!   or busy-loop)
//! * websocket binary-frame decoder negatives (text opcode, short header,
//!   length mismatch)
//! * meek non-2xx HTTP status surfaced as a handshake error
//! * shadowsocks bad-tag / truncated-AEAD rejected
//!
//! All stream-level tests drive the **public** `AeadStream::new` /
//! `Obfs4Stream::new` constructors over an in-memory duplex mock, so no
//! production code is touched and no network is required.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use spt_obfs::config::{ObfsConfig, SsMethod};
use spt_obfs::meek::MeekHttpTransport;
use spt_obfs::obfs4::{seal_frame, NtorKeys, Obfs4Stream, MAX_FRAME_PT};
use spt_obfs::shadowsocks::{AeadStream, ShadowsocksTransport};
use spt_obfs::transport::ObfsTransport;
use spt_obfs::NoopAuditHook;
use spt_secrets::SecretRef;

// ---------------------------------------------------------------------------
// In-memory mock duplex with a controllable per-read chunk size.
//
// `read_chunk` caps how many bytes a single `poll_read` will surface; a
// value of 1 forces maximal fragmentation so we exercise the stream layer's
// reassembly state machine across many `poll_read` calls. When the read
// buffer is empty the mock returns `Poll::Pending` (registering no fresh
// waker) so a reader that would otherwise busy-loop instead parks — the test
// uses `tokio::time::timeout` to convert "stuck Pending" into a failure.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockDuplex {
    inbound: Arc<Mutex<VecDeque<u8>>>,
    outbound: Arc<Mutex<Vec<u8>>>,
    read_chunk: usize,
    eof: Arc<Mutex<bool>>,
}

impl MockDuplex {
    fn new(inbound: Vec<u8>, read_chunk: usize) -> Self {
        Self {
            inbound: Arc::new(Mutex::new(inbound.into_iter().collect())),
            outbound: Arc::new(Mutex::new(Vec::new())),
            read_chunk: read_chunk.max(1),
            eof: Arc::new(Mutex::new(false)),
        }
    }

    /// Empty inbound, used as a write sink to capture produced wire bytes.
    fn capturing() -> Self {
        Self::new(Vec::new(), 4096)
    }

    fn captured(&self) -> Vec<u8> {
        self.outbound.lock().unwrap().clone()
    }

    fn set_eof(&self) {
        *self.eof.lock().unwrap() = true;
    }
}

impl AsyncRead for MockDuplex {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut q = self.inbound.lock().unwrap();
        if q.is_empty() {
            if *self.eof.lock().unwrap() {
                // Returning Ok with nothing filled signals EOF.
                return Poll::Ready(Ok(()));
            }
            // No data yet and not at EOF — park. We do NOT register a waker
            // here; the tests that hit this path wrap the read in a timeout
            // so a genuine stall fails loudly rather than hanging the suite.
            return Poll::Pending;
        }
        let n = self.read_chunk.min(buf.remaining()).min(q.len());
        for _ in 0..n {
            buf.put_slice(&[q.pop_front().unwrap()]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.outbound.lock().unwrap().extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// shadowsocks helpers
// ---------------------------------------------------------------------------

const SS_METHOD: SsMethod = SsMethod::Aead2022Blake3Aes256Gcm;

fn ss_transport(pw: &[u8]) -> ShadowsocksTransport {
    let cfg = ObfsConfig::Shadowsocks {
        method: SS_METHOD,
        password: SecretRef::new("ns", "ss").unwrap(),
    };
    ShadowsocksTransport::new(cfg, Arc::new(NoopAuditHook))
        .unwrap()
        .with_direct_password(pw.to_vec())
}

/// Derive the 32-byte AEAD subkey the `AeadStream` will use for a given
/// password + salt, via the public `derive_key` on the transport.
fn ss_subkey(pw: &[u8], salt: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    ss_transport(pw).derive_key(salt).unwrap()
}

/// Produce one or more on-wire shadowsocks frames for `payloads` by driving
/// a real `AeadStream` writer against a capturing mock, then return the raw
/// wire bytes. This uses only the public stream constructor — the precise
/// nonce/AEAD wire shape stays an implementation detail.
async fn ss_wire_frames(key: &[u8], payloads: &[&[u8]]) -> Vec<u8> {
    let sink = MockDuplex::capturing();
    let mut w = AeadStream::new(
        Box::new(sink.clone()),
        SS_METHOD,
        zeroize::Zeroizing::new(key.to_vec()),
    );
    for p in payloads {
        w.write_all(p).await.unwrap();
    }
    sink.captured()
}

// ---------------------------------------------------------------------------
// 1. shadowsocks: fragmented poll_read reassembles a frame split 1 byte/read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_fragmented_read_reassembles_single_byte_chunks() {
    let key = ss_subkey(b"frag-pw", &[0x11; 32]);
    let payload = b"SSH-2.0-spt fragmented across many reads\r\n".to_vec();
    let wire = ss_wire_frames(&key, &[&payload]).await;
    assert!(wire.len() > payload.len(), "framed must exceed plaintext");

    // Feed the wire one byte per poll_read.
    let inner = MockDuplex::new(wire, 1);
    inner.set_eof();
    let mut r = AeadStream::new(Box::new(inner), SS_METHOD, key.clone());

    let mut got = vec![0u8; payload.len()];
    r.read_exact(&mut got).await.expect("reassemble frame");
    assert_eq!(got, payload, "1-byte-fragmented frame must reassemble");
}

// ---------------------------------------------------------------------------
// 2. shadowsocks: a partial frame (missing the body) does not panic / busy-
//    loop. With no EOF and incomplete bytes the reader must park (Pending),
//    which the timeout surfaces as a clean WouldBlock rather than a hang.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_partial_frame_parks_not_panics() {
    let key = ss_subkey(b"partial-pw", &[0x22; 32]);
    let wire = ss_wire_frames(&key, &[b"complete-frame"]).await;
    // Deliver only the length block (2 + 16) and HALF the body block — never
    // a full body, and no EOF — so the reader can never complete a frame.
    let partial = wire[..(2 + 16) + 4].to_vec();
    let inner = MockDuplex::new(partial, 1); // no set_eof: stays pending
    let mut r = AeadStream::new(Box::new(inner), SS_METHOD, key);

    let mut buf = [0u8; 64];
    let res = tokio::time::timeout(Duration::from_millis(200), r.read(&mut buf)).await;
    assert!(
        res.is_err(),
        "an incomplete frame with no EOF must park (Pending), not resolve: {res:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. shadowsocks: a cap-sized frame (plaintext == 0x3fff, the maximum the
//    writer emits per chunk) round-trips through the stream layer without
//    mis-sizing the target buffer. The writer caps each chunk at 0x3fff, so
//    a single write of exactly the cap produces exactly one frame; the
//    reader must size its body read to that length and not over-read. The
//    *value*-overflow path (a length field decoding above 0x3fff) is
//    structurally unreachable from a well-behaved writer and is guarded in
//    source by the `plen > 0x3fff` check the fuzz harness already pounds on.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_cap_sized_frame_round_trips_without_overread() {
    let key = ss_subkey(b"oversize-pw", &[0x33; 32]);
    let payload = vec![0xAB; 0x3fff]; // exactly the per-chunk cap
    let wire = ss_wire_frames(&key, &[&payload]).await;
    let inner = MockDuplex::new(wire, 7); // odd chunk size to stress reassembly
    inner.set_eof();
    let mut r = AeadStream::new(Box::new(inner), SS_METHOD, key);
    let mut got = vec![0u8; 0x3fff];
    r.read_exact(&mut got).await.expect("cap-sized frame ok");
    assert_eq!(got, payload);
}

// ---------------------------------------------------------------------------
// 4. shadowsocks: a tampered (bad-tag) length block fails the read with
//    InvalidData, not a panic.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_bad_tag_in_length_block_rejected() {
    let key = ss_subkey(b"badtag-pw", &[0x44; 32]);
    let mut wire = ss_wire_frames(&key, &[b"hello"]).await;
    // Flip a byte inside the length block (first 18 bytes = 2 + 16-tag).
    wire[5] ^= 0xFF;
    let inner = MockDuplex::new(wire, 4096);
    inner.set_eof();
    let mut r = AeadStream::new(Box::new(inner), SS_METHOD, key);
    let mut buf = [0u8; 32];
    let err = r.read(&mut buf).await.expect_err("bad tag must error");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "got {err:?}");
}

// ---------------------------------------------------------------------------
// 5. shadowsocks: a tampered body block (valid length, bad body tag) fails
//    with InvalidData.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_bad_tag_in_body_block_rejected() {
    let key = ss_subkey(b"body-pw", &[0x55; 32]);
    let mut wire = ss_wire_frames(&key, &[b"abcdef"]).await;
    // Corrupt the final byte (inside the body block's tag).
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    let inner = MockDuplex::new(wire, 4096);
    inner.set_eof();
    let mut r = AeadStream::new(Box::new(inner), SS_METHOD, key);
    let mut buf = [0u8; 32];
    let err = r.read(&mut buf).await.expect_err("bad body tag must error");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "got {err:?}");
}

// ---------------------------------------------------------------------------
// 6. shadowsocks: replayed frame inside a session is rejected. The reader
//    advances its nonce counter per frame; re-presenting the FIRST frame's
//    bytes as the second frame decrypts under nonce(2,3) and fails the AEAD
//    tag — surfaced as InvalidData. This is the practical replay defence.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_replayed_frame_in_session_rejected() {
    let key = ss_subkey(b"replay-pw", &[0x66; 32]);
    // One genuine frame; capture its exact wire bytes.
    let frame0 = ss_wire_frames(&key, &[b"frame-zero"]).await;
    // Wire = [frame0][frame0 again]. The second copy is a replay: it will be
    // opened under the advanced nonce counter and must fail.
    let mut wire = frame0.clone();
    wire.extend_from_slice(&frame0);
    let inner = MockDuplex::new(wire, 4096);
    inner.set_eof();
    let mut r = AeadStream::new(Box::new(inner), SS_METHOD, key);

    // First frame decrypts fine.
    let mut got0 = vec![0u8; b"frame-zero".len()];
    r.read_exact(&mut got0).await.expect("first frame ok");
    assert_eq!(got0, b"frame-zero");

    // Second (replayed) frame must fail the AEAD tag under the new nonce.
    let mut buf = [0u8; 32];
    let err = r
        .read(&mut buf)
        .await
        .expect_err("replayed frame must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "got {err:?}");
}

// ---------------------------------------------------------------------------
// 7. shadowsocks: nonce counters advance across many frames without panic
//    (exercises the per-frame counter increment over a long run).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ss_many_frames_advance_nonce_without_desync() {
    let key = ss_subkey(b"manyframe-pw", &[0x77; 32]);
    let payloads: Vec<Vec<u8>> = (0u8..64).map(|i| vec![i; (i as usize % 13) + 1]).collect();
    let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
    let wire = ss_wire_frames(&key, &refs).await;

    let inner = MockDuplex::new(wire, 3);
    inner.set_eof();
    let mut r = AeadStream::new(Box::new(inner), SS_METHOD, key);
    for expect in &payloads {
        let mut got = vec![0u8; expect.len()];
        r.read_exact(&mut got).await.expect("frame decodes");
        assert_eq!(&got, expect, "frame body must round-trip in order");
    }
}

// ---------------------------------------------------------------------------
// 8. shadowsocks open(): truncated AEAD (frame minus part of its tag) errs.
// ---------------------------------------------------------------------------

#[test]
fn ss_open_truncated_aead_rejected() {
    let t = ss_transport(b"trunc-pw");
    let sealed = t.seal(b"some-bytes").unwrap();
    // Drop the last 4 tag bytes — AEAD verification must fail.
    let trunc = &sealed[..sealed.len() - 4];
    let err = t.open(trunc).unwrap_err();
    let msg = format!("{err}");
    assert!(!msg.is_empty(), "truncated AEAD must surface an error");
}

// ---------------------------------------------------------------------------
// 9. obfs4: fragmented poll_read reassembles a multi-frame stream delivered
//    one byte per read.
// ---------------------------------------------------------------------------

fn obfs4_keys() -> NtorKeys {
    // c2s == s2c so the writer (which seals under c2s) and reader (which
    // opens under s2c) share a key. Auth is irrelevant for the frame layer.
    NtorKeys {
        c2s_key: [0x42; 32],
        s2c_key: [0x42; 32],
        auth: [0u8; 32],
    }
}

#[tokio::test]
async fn obfs4_fragmented_read_reassembles() {
    let keys = obfs4_keys();
    let payloads: Vec<Vec<u8>> = (0u8..8).map(|i| vec![i; (i as usize + 1) * 5]).collect();

    // Build the wire by sealing each frame under the s2c key with the
    // counter the reader will use (0, 1, 2, ...).
    let mut wire = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        let f = seal_frame(&keys.s2c_key, i as u64, p).unwrap();
        wire.extend_from_slice(&f);
    }

    let inner = MockDuplex::new(wire, 1); // one byte per read
    inner.set_eof();
    let mut r = Obfs4Stream::new(Box::new(inner), keys, Duration::ZERO);
    for expect in &payloads {
        let mut got = vec![0u8; expect.len()];
        r.read_exact(&mut got)
            .await
            .expect("obfs4 frame reassembles");
        assert_eq!(&got, expect);
    }
}

// ---------------------------------------------------------------------------
// 10. obfs4: an oversized declared length in the (XOR-masked) prefix is
//     rejected as InvalidData. We forge a prefix that unmasks to a plen >
//     MAX_FRAME_PT for counter 0.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn obfs4_oversize_prefix_rejected() {
    use sha2::{Digest, Sha256};
    let keys = obfs4_keys();
    // Recompute the length mask exactly as obfs4.rs does for counter 0.
    let n = [0u8; 24]; // obfs4_nonce_from_ctr(0): all zero
    let mut h = Sha256::new();
    h.update(b"obfs4-len");
    h.update(keys.s2c_key);
    h.update(n);
    let d = h.finalize();
    let mask = [d[0], d[1]];
    // Choose a plaintext length above the cap, then mask it so the reader
    // unmasks back to the oversized value.
    let oversize: u16 = (MAX_FRAME_PT as u16) + 1;
    let be = oversize.to_be_bytes();
    let prefix = [be[0] ^ mask[0], be[1] ^ mask[1]];

    let inner = MockDuplex::new(prefix.to_vec(), 4096);
    inner.set_eof();
    let mut r = Obfs4Stream::new(Box::new(inner), keys, Duration::ZERO);
    let mut buf = [0u8; 32];
    let err = r
        .read(&mut buf)
        .await
        .expect_err("oversize obfs4 prefix must reject");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "got {err:?}");
}

// ---------------------------------------------------------------------------
// 11. obfs4: a tampered frame body fails decryption (InvalidData) at the
//     stream layer, not just the open_frame primitive.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn obfs4_tampered_body_rejected_at_stream() {
    let keys = obfs4_keys();
    let mut frame = seal_frame(&keys.s2c_key, 0, b"payload-bytes").unwrap();
    let last = frame.len() - 1;
    frame[last] ^= 0x80; // corrupt tag
    let inner = MockDuplex::new(frame, 4096);
    inner.set_eof();
    let mut r = Obfs4Stream::new(Box::new(inner), keys, Duration::ZERO);
    let mut buf = [0u8; 64];
    let err = r.read(&mut buf).await.expect_err("tamper must reject");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "got {err:?}");
}

// ---------------------------------------------------------------------------
// 12. obfs4: partial frame (header read, body missing) with no EOF parks
//     rather than panicking.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn obfs4_partial_frame_parks() {
    let keys = obfs4_keys();
    let frame = seal_frame(&keys.s2c_key, 0, b"abcdefghij").unwrap();
    // Provide only the 2-byte prefix + a couple of body bytes, no EOF.
    let partial = frame[..4].to_vec();
    let inner = MockDuplex::new(partial, 1);
    let mut r = Obfs4Stream::new(Box::new(inner), keys, Duration::ZERO);
    let mut buf = [0u8; 32];
    let res = tokio::time::timeout(Duration::from_millis(200), r.read(&mut buf)).await;
    assert!(res.is_err(), "partial obfs4 frame must park, got {res:?}");
}

// ---------------------------------------------------------------------------
// 13. websocket binary-frame decoder: text opcode rejected with a Handshake
//     error (not silently accepted as binary).
// ---------------------------------------------------------------------------

#[test]
fn websocket_text_opcode_rejected_when_binary_expected() {
    use bytes::{BufMut, BytesMut};
    use spt_obfs::websocket::decode_binary_frame;
    let mut buf = BytesMut::new();
    buf.put_u8(0x81); // text opcode (FIN=1, opcode=text)
    buf.put_u32(3);
    buf.put_slice(b"abc");
    let err = decode_binary_frame(&buf).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("opcode") || msg.contains("binary"),
        "got {msg}"
    );
}

// ---------------------------------------------------------------------------
// 14. websocket binary-frame decoder: short header (< 5 bytes) rejected.
// ---------------------------------------------------------------------------

#[test]
fn websocket_short_header_rejected() {
    use spt_obfs::websocket::decode_binary_frame;
    for len in 0..5usize {
        let short = vec![0x82u8; len];
        assert!(
            decode_binary_frame(&short).is_err(),
            "header of {len} bytes must reject"
        );
    }
}

// ---------------------------------------------------------------------------
// 15. websocket binary-frame decoder: declared-length / body-length mismatch
//     rejected (not truncated, not over-read).
// ---------------------------------------------------------------------------

#[test]
fn websocket_length_mismatch_rejected() {
    use bytes::{BufMut, BytesMut};
    use spt_obfs::websocket::decode_binary_frame;
    let mut buf = BytesMut::new();
    buf.put_u8(0x82);
    buf.put_u32(10); // claims 10 body bytes
    buf.put_slice(b"abc"); // only 3 present
    let err = decode_binary_frame(&buf).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("length") || msg.contains("mismatch"),
        "got {msg}"
    );
}

// ---------------------------------------------------------------------------
// 16. meek-http: a simulated non-2xx HTTP status is surfaced as a handshake
//     error containing the status code (control-frame / front error path).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meek_non_2xx_status_surfaces_handshake_error() {
    for code in [301u16, 403, 500, 503] {
        let cfg = ObfsConfig::MeekHttp {
            url: "https://front.example/p".into(),
            front_host: None,
            sni: None,
        };
        let mut t = MeekHttpTransport::new(cfg, Arc::new(NoopAuditHook)).unwrap();
        t.set_simulated_status(code);
        let err = match t.connect("ssh.example:22").await {
            Ok(_) => panic!("non-2xx status {code} must error"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains(&code.to_string()),
            "status {code} not in `{msg}`"
        );
    }
}

// ---------------------------------------------------------------------------
// 17. meek-http: a 2xx simulated status does NOT short-circuit as an error
//     (it proceeds to the live request, which fails on the bogus host — but
//     NOT with the simulated-status message). Confirms the status gate only
//     rejects non-2xx.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meek_2xx_status_does_not_trip_status_gate() {
    let cfg = ObfsConfig::MeekHttp {
        url: "https://no.such.host.invalid/p".into(),
        front_host: None,
        sni: None,
    };
    let mut t = MeekHttpTransport::new(cfg, Arc::new(NoopAuditHook)).unwrap();
    t.set_simulated_status(204); // 2xx → gate passes, live request attempted
    let res = tokio::time::timeout(Duration::from_millis(500), t.connect("x:22")).await;
    // Either it times out or it fails DNS — but it must not be the
    // "front returned HTTP 204" short-circuit message.
    if let Ok(Ok(_)) = res {
        panic!("connect to an invalid host must not succeed");
    }
    if let Ok(Err(e)) = res {
        let msg = format!("{e}");
        assert!(
            !msg.contains("returned HTTP 204"),
            "2xx must not trip the status gate: {msg}"
        );
    }
}
