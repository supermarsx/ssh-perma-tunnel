//! Cross-transport **data-plane gauntlet** for the shadowsocks + obfs4 obfs
//! stream framers.
//!
//! Companion to `framing_negatives.rs` (which pins the structural negatives)
//! and `shadowsocks_replay.rs` (replay). This suite runs both AEAD framers
//! through the SHARED [`support`] gauntlet so byte-integrity, mid-frame
//! backpressure, and half-close/EOF are asserted identically for each:
//!
//! * **byte-integrity** — the full payload table (0 B … multi-MiB) echoed
//!   through a real client<->server obfs pair over `tokio::io::duplex`,
//!   asserted byte-exact.
//! * **partial-write / backpressure** — the same payloads driven through a
//!   `FlakySink` inner: the produced wire must be byte-identical to the clean
//!   encoding (proving the AEAD nonce / obfs4 counter advances EXACTLY once per
//!   wire frame — no re-seal/desync) AND decode byte-exact on the peer.
//! * **half-close / EOF both directions** — one side closes its write half; the
//!   peer sees a clean EOF while its own write half still works.
//! * **split-frame reassembly** — a frame delivered one byte per inner read
//!   reassembles correctly.
//! * **zero-length + max-size** payloads, and an **in-session replay** guard.
//!
//! All of this drives the PUBLIC stream constructors over in-memory transports
//! — no production code is touched and no network is required.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use spt_obfs::config::{ObfsConfig, SsMethod};
use spt_obfs::obfs4::{NtorKeys, Obfs4Stream, MAX_FRAME_PT};
use spt_obfs::shadowsocks::{direction_keys, AeadStream, ShadowsocksTransport, SsRole};
use spt_obfs::NoopAuditHook;
use spt_secrets::SecretRef;
use zeroize::Zeroizing;

use support::{
    byte_integrity_gauntlet, gauntlet_payloads, half_close_client_then_server,
    half_close_server_then_client, make_payload, BoxedStream, FlakySink, MockDuplex,
};

// ===========================================================================
// shadowsocks helpers
// ===========================================================================

const SS_FRAME: usize = 0x3fff; // per-chunk plaintext cap the writer emits

fn ss_transport(method: SsMethod, pw: &[u8]) -> ShadowsocksTransport {
    let cfg = ObfsConfig::Shadowsocks {
        method,
        password: SecretRef::new("ns", "ss").unwrap(),
    };
    ShadowsocksTransport::new(cfg, Arc::new(NoopAuditHook))
        .unwrap()
        .with_direct_password(pw.to_vec())
}

fn ss_session_key(method: SsMethod, pw: &[u8], salt: &[u8]) -> Zeroizing<Vec<u8>> {
    ss_transport(method, pw).derive_key(salt).unwrap()
}

/// A connected client<->server shadowsocks `AeadStream` pair over an in-memory
/// duplex. Each side uses the mirrored per-direction subkeys, so both
/// directions decrypt.
fn ss_pair(method: SsMethod, key: &[u8]) -> (BoxedStream, BoxedStream) {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (c_tx, c_rx) = direction_keys(key, method, SsRole::Client);
    let (s_tx, s_rx) = direction_keys(key, method, SsRole::Server);
    let client = AeadStream::new(Box::new(a), method, c_tx, c_rx);
    let server = AeadStream::new(Box::new(b), method, s_tx, s_rx);
    (Box::new(client), Box::new(server))
}

/// Produce the clean on-wire bytes a client-role writer emits for `payload`.
async fn ss_clean_wire(method: SsMethod, key: &[u8], payload: &[u8]) -> Vec<u8> {
    let sink = MockDuplex::capturing();
    let (tx, rx) = direction_keys(key, method, SsRole::Client);
    let mut w = AeadStream::new(Box::new(sink.clone()), method, tx, rx);
    w.write_all(payload).await.unwrap();
    w.flush().await.unwrap();
    sink.captured()
}

/// A server-role reader over `wire`, EOF-terminated.
fn ss_reader(method: SsMethod, key: &[u8], wire: Vec<u8>, chunk: usize) -> AeadStream {
    let inner = MockDuplex::new(wire, chunk);
    inner.set_eof();
    let (tx, rx) = direction_keys(key, method, SsRole::Server);
    AeadStream::new(Box::new(inner), method, tx, rx)
}

// ===========================================================================
// obfs4 helpers
// ===========================================================================

/// Distinct per-direction keys so the duplex pair genuinely exercises both
/// directions (client seals under c2s / opens under s2c; the server mirror
/// swaps them).
fn obfs4_keys() -> NtorKeys {
    NtorKeys {
        c2s_key: [0x11; 32],
        s2c_key: [0x22; 32],
        auth: [0u8; 32],
    }
}

/// Symmetric keys (c2s == s2c) for the single-ended wire/replay cells where a
/// lone writer's frames must be re-opened by a lone reader.
fn obfs4_sym_keys() -> NtorKeys {
    NtorKeys {
        c2s_key: [0x42; 32],
        s2c_key: [0x42; 32],
        auth: [0u8; 32],
    }
}

fn obfs4_pair(keys: NtorKeys) -> (BoxedStream, BoxedStream) {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let client = Obfs4Stream::new(Box::new(a), keys, Duration::ZERO);
    // Server mirror: its tx (c2s slot) must be the client's rx key and vice
    // versa, so the two directions decrypt against each other.
    let server_keys = NtorKeys {
        c2s_key: keys.s2c_key,
        s2c_key: keys.c2s_key,
        auth: keys.auth,
    };
    let server = Obfs4Stream::new(Box::new(b), server_keys, Duration::ZERO);
    (Box::new(client), Box::new(server))
}

async fn obfs4_clean_wire(keys: NtorKeys, payload: &[u8]) -> Vec<u8> {
    let sink = MockDuplex::capturing();
    let mut w = Obfs4Stream::new(Box::new(sink.clone()), keys, Duration::ZERO);
    w.write_all(payload).await.unwrap();
    w.flush().await.unwrap();
    sink.captured()
}

fn obfs4_reader(keys: NtorKeys, wire: Vec<u8>, chunk: usize) -> Obfs4Stream {
    let inner = MockDuplex::new(wire, chunk);
    inner.set_eof();
    Obfs4Stream::new(Box::new(inner), keys, Duration::ZERO)
}

// ===========================================================================
// shadowsocks gauntlet cells
// ===========================================================================

#[tokio::test]
async fn ss_byte_integrity_gauntlet_aes256() {
    let method = SsMethod::Aead2022Blake3Aes256Gcm;
    let key = ss_session_key(method, b"integrity-pw", &[0x01; 32]);
    let (client, server) = ss_pair(method, &key);
    byte_integrity_gauntlet(client, server, gauntlet_payloads(SS_FRAME)).await;
}

#[tokio::test]
async fn ss_byte_integrity_gauntlet_chacha() {
    let method = SsMethod::Aead2022Blake3ChaCha20Poly1305;
    let key = ss_session_key(method, b"integrity-cc", &[0x02; 32]);
    let (client, server) = ss_pair(method, &key);
    byte_integrity_gauntlet(client, server, gauntlet_payloads(SS_FRAME)).await;
}

#[tokio::test]
async fn ss_half_close_client_then_server() {
    let method = SsMethod::Aead2022Blake3Aes256Gcm;
    let key = ss_session_key(method, b"hc1-pw", &[0x03; 32]);
    let (client, server) = ss_pair(method, &key);
    half_close_client_then_server(client, server).await;
}

#[tokio::test]
async fn ss_half_close_server_then_client() {
    let method = SsMethod::Aead2022Blake3Aes256Gcm;
    let key = ss_session_key(method, b"hc2-pw", &[0x04; 32]);
    let (client, server) = ss_pair(method, &key);
    half_close_server_then_client(client, server).await;
}

/// Every payload driven through a `FlakySink` (accepts 1023 B then Pending
/// mid-frame) must produce wire byte-identical to the clean encoding — the
/// definitive "nonce advances exactly once per wire frame, no re-seal" check —
/// and decode byte-exact on the peer.
#[tokio::test]
async fn ss_backpressure_gauntlet_no_nonce_desync() {
    let method = SsMethod::Aead2022Blake3Aes256Gcm;
    let key = ss_session_key(method, b"backpressure-pw", &[0x05; 32]);

    for (name, payload) in gauntlet_payloads(SS_FRAME) {
        let clean = ss_clean_wire(method, &key, &payload).await;

        let sink = FlakySink::new(1023);
        let (tx, rx) = direction_keys(&key, method, SsRole::Client);
        let mut w = AeadStream::new(Box::new(sink.clone()), method, tx, rx);
        tokio::time::timeout(Duration::from_secs(30), async {
            w.write_all(&payload).await.expect("write_all backpressure");
            w.flush().await.expect("flush");
        })
        .await
        .unwrap_or_else(|_| panic!("`{name}` writer stalled under backpressure (re-seal loop?)"));
        let wire = sink.captured();

        assert_eq!(
            wire, clean,
            "`{name}`: backpressured wire must be byte-identical to the clean \
             encoding (a nonce-skip re-seal would diverge)"
        );

        // Peer decodes byte-exact.
        let mut r = ss_reader(method, &key, wire, 7);
        let mut got = vec![0u8; payload.len()];
        if !payload.is_empty() {
            r.read_exact(&mut got).await.unwrap_or_else(|e| {
                panic!("`{name}`: peer failed to decode backpressured wire: {e}")
            });
        }
        assert_eq!(got, payload, "`{name}`: round-trip must be byte-exact");
    }
}

/// A frame split one byte per inner read reassembles correctly for a curated
/// set spanning the frame boundary.
#[tokio::test]
async fn ss_split_frame_reassembly_single_byte_reads() {
    let method = SsMethod::Aead2022Blake3Aes256Gcm;
    let key = ss_session_key(method, b"split-pw", &[0x06; 32]);
    for n in [
        1usize,
        7,
        SS_FRAME - 1,
        SS_FRAME,
        SS_FRAME + 1,
        SS_FRAME * 2 + 3,
    ] {
        let payload = make_payload(n);
        let wire = ss_clean_wire(method, &key, &payload).await;
        // 1 byte per read for the small ones; a small odd chunk for the larger
        // multi-frame case to keep the read count (and the test) fast.
        let chunk = if n <= SS_FRAME { 1 } else { 5 };
        let mut r = ss_reader(method, &key, wire, chunk);
        let mut got = vec![0u8; n];
        r.read_exact(&mut got)
            .await
            .unwrap_or_else(|e| panic!("split reassembly n={n} failed: {e}"));
        assert_eq!(got, payload, "split reassembly n={n} corrupted");
    }
}

/// Zero-length write emits NO frame; a cap-sized (0x3fff) write emits EXACTLY
/// one frame of the expected wire length.
#[tokio::test]
async fn ss_zero_and_max_payload_wire_shape() {
    let method = SsMethod::Aead2022Blake3Aes256Gcm;
    let key = ss_session_key(method, b"minmax-pw", &[0x07; 32]);

    // Zero-length: no bytes on the wire, reader sees clean EOF.
    let empty_wire = ss_clean_wire(method, &key, &[]).await;
    assert!(
        empty_wire.is_empty(),
        "a zero-length write must not emit a frame"
    );
    let mut r = ss_reader(method, &key, empty_wire, 4096);
    let mut buf = [0u8; 8];
    assert_eq!(r.read(&mut buf).await.unwrap(), 0, "empty wire => EOF");

    // Max single-frame: exactly one length block + one body block.
    let payload = make_payload(SS_FRAME);
    let wire = ss_clean_wire(method, &key, &payload).await;
    let expected_len = (2 + 16) + (SS_FRAME + 16);
    assert_eq!(
        wire.len(),
        expected_len,
        "a cap-sized write must be exactly one frame on the wire"
    );
    let mut r = ss_reader(method, &key, wire, 4096);
    let mut got = vec![0u8; SS_FRAME];
    r.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);
}

/// In-session replay: re-injecting an already-consumed frame at a later
/// position fails the AEAD tag (the monotonic counter nonce IS the replay
/// defence). Reaffirms `shadowsocks_replay.rs` through the gauntlet path.
#[tokio::test]
async fn ss_in_session_replay_rejected() {
    let method = SsMethod::Aead2022Blake3Aes256Gcm;
    let key = ss_session_key(method, b"replay-pw", &[0x08; 32]);
    let frame0 = ss_clean_wire(method, &key, b"frame-zero").await;
    let mut wire = frame0.clone();
    wire.extend_from_slice(&frame0); // [A][A]

    let mut r = ss_reader(method, &key, wire, 4096);
    let mut got = vec![0u8; b"frame-zero".len()];
    r.read_exact(&mut got).await.expect("first frame ok");
    assert_eq!(got, b"frame-zero");

    let mut buf = [0u8; 32];
    let err = r
        .read(&mut buf)
        .await
        .expect_err("replayed frame must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "got {err:?}");
}

// ===========================================================================
// obfs4 gauntlet cells
// ===========================================================================

#[tokio::test]
async fn obfs4_byte_integrity_gauntlet() {
    let (client, server) = obfs4_pair(obfs4_keys());
    byte_integrity_gauntlet(client, server, gauntlet_payloads(MAX_FRAME_PT)).await;
}

#[tokio::test]
async fn obfs4_half_close_client_then_server() {
    let (client, server) = obfs4_pair(obfs4_keys());
    half_close_client_then_server(client, server).await;
}

#[tokio::test]
async fn obfs4_half_close_server_then_client() {
    let (client, server) = obfs4_pair(obfs4_keys());
    half_close_server_then_client(client, server).await;
}

/// obfs4 counterpart of the shadowsocks backpressure gauntlet: the per-
/// direction counter must advance exactly once per wire frame under mid-frame
/// backpressure, so the produced wire is byte-identical to the clean encoding
/// and decodes byte-exact.
#[tokio::test]
async fn obfs4_backpressure_gauntlet_no_counter_desync() {
    let keys = obfs4_sym_keys();
    for (name, payload) in gauntlet_payloads(MAX_FRAME_PT) {
        let clean = obfs4_clean_wire(keys, &payload).await;

        let sink = FlakySink::new(1023);
        let mut w = Obfs4Stream::new(Box::new(sink.clone()), keys, Duration::ZERO);
        tokio::time::timeout(Duration::from_secs(30), async {
            w.write_all(&payload).await.expect("obfs4 write_all");
            w.flush().await.expect("obfs4 flush");
        })
        .await
        .unwrap_or_else(|_| panic!("`{name}` obfs4 writer stalled under backpressure"));
        let wire = sink.captured();

        assert_eq!(
            wire, clean,
            "`{name}`: obfs4 backpressured wire must be byte-identical to clean"
        );

        let mut r = obfs4_reader(keys, wire, 5);
        let mut got = vec![0u8; payload.len()];
        if !payload.is_empty() {
            r.read_exact(&mut got)
                .await
                .unwrap_or_else(|e| panic!("`{name}`: obfs4 peer decode failed: {e}"));
        }
        assert_eq!(
            got, payload,
            "`{name}`: obfs4 round-trip must be byte-exact"
        );
    }
}

#[tokio::test]
async fn obfs4_split_frame_reassembly_single_byte_reads() {
    let keys = obfs4_sym_keys();
    for n in [
        1usize,
        7,
        MAX_FRAME_PT - 1,
        MAX_FRAME_PT,
        MAX_FRAME_PT + 1,
        MAX_FRAME_PT * 2 + 3,
    ] {
        let payload = make_payload(n);
        let wire = obfs4_clean_wire(keys, &payload).await;
        let chunk = if n <= MAX_FRAME_PT { 1 } else { 3 };
        let mut r = obfs4_reader(keys, wire, chunk);
        let mut got = vec![0u8; n];
        r.read_exact(&mut got)
            .await
            .unwrap_or_else(|e| panic!("obfs4 split reassembly n={n} failed: {e}"));
        assert_eq!(got, payload, "obfs4 split reassembly n={n} corrupted");
    }
}

#[tokio::test]
async fn obfs4_zero_and_max_payload_wire_shape() {
    let keys = obfs4_sym_keys();

    // Zero-length write emits nothing.
    let empty = obfs4_clean_wire(keys, &[]).await;
    assert!(
        empty.is_empty(),
        "zero-length obfs4 write must emit no frame"
    );

    // Max single frame: 2-byte obf-len prefix + secretbox(pt + 16-byte tag).
    let payload = make_payload(MAX_FRAME_PT);
    let wire = obfs4_clean_wire(keys, &payload).await;
    assert_eq!(
        wire.len(),
        2 + MAX_FRAME_PT + 16,
        "cap-sized obfs4 write must be exactly one frame"
    );
    let mut r = obfs4_reader(keys, wire, 4096);
    let mut got = vec![0u8; MAX_FRAME_PT];
    r.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);
}
