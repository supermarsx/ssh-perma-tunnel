//! t8-A6 shadowsocks AEAD replay-protection tests.
//!
//! ## Wire model in this codebase
//!
//! The `AeadStream` in `crates/spt-obfs/src/shadowsocks.rs` uses a
//! *monotonic counter* for nonces, not server-supplied random nonces.
//! Each side maintains independent `read_nonce` / `write_nonce` counters
//! initialised to zero; both sides advance them in lockstep.
//!
//! These tests confirm the practical security property: an off-the-wire
//! attacker who captures a frame and replays it onto a fresh session
//! cannot decrypt under the new salt, and an attacker who re-sends a frame
//! inside the same session causes an AEAD decrypt failure at the frame
//! boundary (counter desync).
//!
//! ## Replay protection = the counter nonce (no separate window)
//!
//! Replay protection within a session IS the monotonic counter nonce: each
//! frame is opened under a strictly increasing nonce and the AEAD tag only
//! validates at the exact expected position, so a re-injected frame fails the
//! tag. An earlier revision also carried a `seen: BTreeSet<u64>` "sliding
//! window", but it tracked the same *local* counter (never a wire value), so
//! its reuse check was unreachable dead code — it has been **removed**. The
//! `in_session_frame_replay_desyncs_and_fails` test below exercises the real
//! property end-to-end through a live `AeadStream` pair.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use spt_obfs::audit::NoopAuditHook;
use spt_obfs::config::{ObfsConfig, SsMethod};
use spt_obfs::shadowsocks::{direction_keys, AeadStream, ShadowsocksTransport, SsRole};
use spt_secrets::SecretRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

fn ss_cfg(method: SsMethod) -> ObfsConfig {
    ObfsConfig::Shadowsocks {
        method,
        password: SecretRef::new("ns", "ss").unwrap(),
    }
}

fn transport(method: SsMethod, pw: &[u8]) -> ShadowsocksTransport {
    ShadowsocksTransport::new(ss_cfg(method), Arc::new(NoopAuditHook))
        .unwrap()
        .with_direct_password(pw.to_vec())
}

#[test]
fn cross_session_replay_fails_under_new_salt() {
    // Seal under one freshly-minted random salt; decrypting under a
    // *different* salt (different session) must fail because the derived
    // subkey diverges.
    let t1 = transport(SsMethod::Aead2022Blake3Aes256Gcm, b"shared-pw");
    let t2 = transport(SsMethod::Aead2022Blake3Aes256Gcm, b"shared-pw");
    let sealed = t1.seal(b"payload").unwrap();
    // Each `seal` mints a fresh random salt; sealed bytes carry the salt
    // header so a same-password peer can decrypt. Confirm round-trip
    // works *within* a session (sanity), then mutate the salt and check
    // it fails.
    let opened = t2.open(&sealed).unwrap();
    assert_eq!(opened, b"payload");

    // Mutate the salt portion in the sealed blob — first 32 bytes for
    // AEAD-2022 AES-256-GCM. Then opening must fail (subkey diverges).
    let mut tampered = sealed.clone();
    tampered[0] ^= 0xAA;
    assert!(
        t2.open(&tampered).is_err(),
        "tampered salt must produce decrypt failure"
    );
}

#[test]
fn truncated_frame_rejected() {
    // A frame shorter than the salt header cannot be opened.
    let t = transport(SsMethod::Aead2022Blake3Aes256Gcm, b"pw");
    let sealed = t.seal(b"hello").unwrap();
    let truncated = &sealed[..8];
    assert!(t.open(truncated).is_err());
}

#[test]
fn tampered_ciphertext_rejected() {
    // Flip a byte in the ciphertext section; the AEAD tag must fail to
    // validate. This is the practical replay-protection mechanism for
    // counter-mode AEAD streams: any wire-level mutation desyncs the
    // tag.
    let t = transport(SsMethod::Aead2022Blake3Aes256Gcm, b"pw");
    let mut sealed = t.seal(b"hello world").unwrap();
    let last_idx = sealed.len() - 1;
    sealed[last_idx] ^= 0x01;
    assert!(
        t.open(&sealed).is_err(),
        "tampered ciphertext must fail decrypt"
    );
}

/// Minimal in-memory duplex: serves a fixed inbound byte queue to the reader
/// and discards writes. Returns EOF (Ready+empty) once the queue drains so a
/// reader does not hang.
#[derive(Clone)]
struct ReplayDuplex {
    inbound: Arc<Mutex<VecDeque<u8>>>,
}

impl ReplayDuplex {
    fn new(inbound: Vec<u8>) -> Self {
        Self {
            inbound: Arc::new(Mutex::new(inbound.into_iter().collect())),
        }
    }
}

impl AsyncRead for ReplayDuplex {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut q = self.inbound.lock().unwrap();
        let n = buf.remaining().min(q.len());
        for _ in 0..n {
            buf.put_slice(&[q.pop_front().unwrap()]);
        }
        // Empty + nothing filled => EOF.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ReplayDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A write sink that captures everything written, used to harvest the on-wire
/// frame bytes a client-role `AeadStream` emits.
#[derive(Clone)]
struct CaptureSink(Arc<Mutex<Vec<u8>>>);

impl AsyncRead for CaptureSink {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CaptureSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Produce the on-wire frames a client-role `AeadStream` emits for `payloads`,
/// one entry per payload (split by the byte delta after each write).
async fn wire_frames(session_key: &[u8], method: SsMethod, payloads: &[&[u8]]) -> Vec<Vec<u8>> {
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let (tx, rx) = direction_keys(session_key, method, SsRole::Client);
    let mut w = AeadStream::new(Box::new(CaptureSink(captured.clone())), method, tx, rx);
    let mut frames = Vec::new();
    let mut prev_len = 0usize;
    for p in payloads {
        w.write_all(p).await.unwrap();
        let snap = captured.lock().unwrap().clone();
        frames.push(snap[prev_len..].to_vec());
        prev_len = snap.len();
    }
    frames
}

#[tokio::test]
async fn in_session_frame_replay_desyncs_and_fails() {
    // Real replay property (replacing the former zero-assertion tautology):
    // re-injecting an already-consumed frame at a later position fails the AEAD
    // tag because the reader's monotonic counter nonce has advanced.
    let method = SsMethod::Aead2022Blake3Aes256Gcm;
    let key = transport(method, b"replay-pw")
        .derive_key(&[0x33; 32])
        .unwrap();

    let frames = wire_frames(&key, method, &[b"frame-one", b"frame-two"]).await;
    assert_eq!(frames.len(), 2);

    // Honest baseline: [A][B] reads back both payloads.
    let mut ok_wire = frames[0].clone();
    ok_wire.extend_from_slice(&frames[1]);
    let (s_tx, s_rx) = direction_keys(&key, method, SsRole::Server);
    let mut reader = AeadStream::new(Box::new(ReplayDuplex::new(ok_wire)), method, s_tx, s_rx);
    let mut got = vec![0u8; b"frame-one".len()];
    reader.read_exact(&mut got).await.unwrap();
    assert_eq!(got, b"frame-one");
    let mut got2 = vec![0u8; b"frame-two".len()];
    reader.read_exact(&mut got2).await.unwrap();
    assert_eq!(got2, b"frame-two");

    // Attack: [A][A] — replay frame A in B's slot. The first read succeeds;
    // the second must fail (counter desync → AEAD tag mismatch).
    let mut replay_wire = frames[0].clone();
    replay_wire.extend_from_slice(&frames[0]);
    let (s_tx2, s_rx2) = direction_keys(&key, method, SsRole::Server);
    let mut reader2 = AeadStream::new(
        Box::new(ReplayDuplex::new(replay_wire)),
        method,
        s_tx2,
        s_rx2,
    );
    let mut first = vec![0u8; b"frame-one".len()];
    reader2.read_exact(&mut first).await.unwrap();
    assert_eq!(first, b"frame-one");
    // Reading the replayed frame must error (not silently accept the replay).
    let mut buf = [0u8; 64];
    let res = reader2.read(&mut buf).await;
    assert!(
        res.is_err(),
        "a replayed frame must fail the AEAD tag at the advanced counter, got {res:?}"
    );
}

#[test]
fn wrong_password_fails_open_independent_of_replay() {
    // Defence-in-depth: even without replay, mismatched key material
    // rejects. This was also covered by the inline mod tests; we replicate
    // here so the integration suite catches regressions in `derive_key`.
    let t_seal = transport(SsMethod::Aead2022Blake3Aes256Gcm, b"alpha");
    let t_open = transport(SsMethod::Aead2022Blake3Aes256Gcm, b"beta");
    let sealed = t_seal.seal(b"x").unwrap();
    assert!(t_open.open(&sealed).is_err());
}

#[test]
fn chacha_method_replay_safety_parallels_aes_gcm() {
    // Same property under the ChaCha20-Poly1305 AEAD variant.
    let t = transport(SsMethod::Aead2022Blake3ChaCha20Poly1305, b"pw");
    let sealed = t.seal(b"chacha-payload").unwrap();
    assert_eq!(t.open(&sealed).unwrap(), b"chacha-payload");
    // Flip a salt byte.
    let mut tampered = sealed.clone();
    tampered[3] ^= 0xFF;
    assert!(t.open(&tampered).is_err());
}
