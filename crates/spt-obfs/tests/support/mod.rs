//! Shared data-plane test harness for the spt-obfs `*Stream` framing layers.
//!
//! This module is the reusable **obfs gauntlet**: a single, transport-agnostic
//! set of driver helpers that every obfs stream wrapper
//! (`AsyncRead + AsyncWrite`) is run through so the same byte-integrity /
//! backpressure / half-close invariants are asserted identically for every
//! transport instead of being hand-rolled per transport.
//!
//! It is consumed by the integration test binaries via `mod support;` (the
//! standard `tests/<name>/mod.rs` shared-code pattern). Because each test
//! binary uses a different subset of the helpers, the module is
//! `#![allow(dead_code)]`.
//!
//! ## What the gauntlet exercises
//!
//! * [`byte_integrity_gauntlet`] — a table of payloads (0 B, 1 B, tiny, one
//!   frame-boundary, just-over-boundary, multi-frame, 64 KiB, multi-MiB)
//!   echoed through a client<->server obfs pair over `tokio::io::duplex` and
//!   asserted **byte-exact**.
//! * [`half_close_client_then_server`] / [`half_close_server_then_client`] —
//!   one side closes its write half; the peer must observe a clean EOF while
//!   its own write half still works (no premature close, no hang).
//! * [`FlakySink`] + [`MockDuplex`] — a partial-accepting sink and a
//!   fragmented-read mock used by the per-transport backpressure cells (the
//!   AEAD/counter must advance EXACTLY once per wire frame under mid-frame
//!   backpressure).

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use spt_obfs::transport::AsyncReadWrite;

/// One end of a connected obfs stream pair (boxed as the trait object the
/// production framers already accept as their inner transport).
pub type BoxedStream = Box<dyn AsyncReadWrite>;

// ---------------------------------------------------------------------------
// Deterministic payload table.
// ---------------------------------------------------------------------------

/// Deterministic filler byte for index `i` — a simple, seed-free PRNG-ish
/// pattern so payloads are reproducible across runs (no wall-clock / RNG
/// flakiness) yet varied enough that an off-by-one / reorder corrupts them.
#[must_use]
pub fn fill_byte(i: usize) -> u8 {
    // Multiply-xor mix; the modulus keeps it inside a byte with a long period.
    ((i.wrapping_mul(1_103_515_245).wrapping_add(12_345) >> 3) & 0xff) as u8
}

/// Build a deterministic payload of `n` bytes.
#[must_use]
pub fn make_payload(n: usize) -> Vec<u8> {
    (0..n).map(fill_byte).collect()
}

/// A "multi-MiB" payload size used by the large-transfer cells (>= 4 MiB, plus
/// a prime-ish tail so it never lands on a frame boundary).
pub const MULTI_MIB: usize = 4 * 1024 * 1024 + 123;

/// The gauntlet payload table for a transport whose per-frame plaintext cap is
/// `frame_size`. Each entry is `(name, bytes)`; names appear in assert messages
/// so a failing cell is identifiable.
///
/// Covers: empty, single byte, tiny, one-below / exactly / one-above the frame
/// boundary, several frames, 64 KiB, and a multi-MiB payload.
#[must_use]
pub fn gauntlet_payloads(frame_size: usize) -> Vec<(String, Vec<u8>)> {
    let mut sizes = vec![
        ("zero".to_string(), 0usize),
        ("one".to_string(), 1),
        ("tiny".to_string(), 7),
        ("frame_minus_one".to_string(), frame_size.saturating_sub(1)),
        ("frame_exact".to_string(), frame_size),
        ("frame_plus_one".to_string(), frame_size + 1),
        ("multi_frame".to_string(), frame_size * 3 + 7),
        ("k64".to_string(), 64 * 1024),
        ("multi_mib".to_string(), MULTI_MIB),
    ];
    // De-dup by size (e.g. frame_size==1 would collide) while keeping names.
    sizes.dedup_by_key(|(_, n)| *n);
    sizes
        .into_iter()
        .map(|(name, n)| (name, make_payload(n)))
        .collect()
}

// ---------------------------------------------------------------------------
// byte-integrity gauntlet: echo every payload through a client<->server pair.
// ---------------------------------------------------------------------------

/// Drive `payloads` through a connected obfs `client`<->`server` pair and
/// assert the client reads back **byte-exact** what it wrote, in order, with a
/// clean EOF and nothing extra.
///
/// The server side is a pure echo (`tokio::io::copy` from its read half to its
/// write half), so the assertion fails if the transport corrupts, loses,
/// duplicates, or reorders any byte. Writer and reader run concurrently so a
/// multi-MiB payload cannot deadlock on a full duplex buffer.
pub async fn byte_integrity_gauntlet(
    client: BoxedStream,
    server: BoxedStream,
    payloads: Vec<(String, Vec<u8>)>,
) {
    let (mut s_rd, mut s_wr) = tokio::io::split(server);
    let echo = tokio::spawn(async move {
        // Echo every byte back until the client half-closes, then FIN.
        tokio::io::copy(&mut s_rd, &mut s_wr).await?;
        s_wr.shutdown().await?;
        io::Result::Ok(())
    });

    let (mut c_rd, mut c_wr) = tokio::io::split(client);
    let expected: Vec<u8> = payloads.iter().flat_map(|(_, p)| p.clone()).collect();
    let names: Vec<(String, usize)> = payloads.iter().map(|(n, p)| (n.clone(), p.len())).collect();

    let writer = tokio::spawn(async move {
        for (_name, p) in &payloads {
            c_wr.write_all(p).await.expect("write_all payload");
        }
        c_wr.flush().await.expect("flush");
        c_wr.shutdown().await.expect("shutdown write half");
    });

    // Read back the concatenation, checking each payload's slice as it arrives
    // so a failing cell names the offending payload.
    let mut got = vec![0u8; expected.len()];
    let read = tokio::time::timeout(Duration::from_secs(60), c_rd.read_exact(&mut got));
    read.await
        .expect("echo round-trip must not hang")
        .expect("read_exact the full echo");

    let mut off = 0usize;
    for (name, len) in &names {
        let slice = &got[off..off + len];
        assert_eq!(
            slice,
            &expected[off..off + len],
            "payload `{name}` ({len} B) corrupted on round-trip"
        );
        off += len;
    }

    // Clean EOF: after the echoed bytes the next read is 0, not extra bytes.
    let mut tail = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(10), c_rd.read(&mut tail))
        .await
        .expect("EOF read must not hang")
        .expect("EOF read");
    assert_eq!(n, 0, "expected clean EOF after the echo, got extra bytes");

    writer.await.expect("writer task");
    echo.await
        .expect("echo task join")
        .expect("echo copy result");
}

// ---------------------------------------------------------------------------
// half-close / EOF both directions.
// ---------------------------------------------------------------------------

const HC_C2S: &[u8] = b"client->server before half-close";
const HC_S2C: &[u8] = b"server->client after peer half-close";

/// Client closes its write half after sending one message; the server must see
/// a clean EOF (read returns 0) and its OWN write half must still deliver a
/// message to the still-open client read half. Asserts no premature close and
/// no hang in either leg.
pub async fn half_close_client_then_server(client: BoxedStream, server: BoxedStream) {
    let (mut c_rd, mut c_wr) = tokio::io::split(client);
    let (mut s_rd, mut s_wr) = tokio::io::split(server);

    c_wr.write_all(HC_C2S).await.unwrap();
    c_wr.flush().await.unwrap();

    let mut buf = vec![0u8; HC_C2S.len()];
    with_timeout(s_rd.read_exact(&mut buf), "server read pre-EOF msg").await;
    assert_eq!(buf, HC_C2S);

    // Client half-closes.
    c_wr.shutdown().await.unwrap();

    // Server observes a clean EOF (0 bytes), not an error, not a hang.
    let mut junk = [0u8; 32];
    let n = with_timeout(s_rd.read(&mut junk), "server EOF read").await;
    assert_eq!(n, 0, "server must see clean EOF after client half-close");

    // Server's write half still works; client's read half still receives it.
    s_wr.write_all(HC_S2C).await.unwrap();
    s_wr.flush().await.unwrap();
    let mut back = vec![0u8; HC_S2C.len()];
    with_timeout(c_rd.read_exact(&mut back), "client read post-EOF msg").await;
    assert_eq!(back, HC_S2C, "server->client leg must survive client EOF");

    // Full close is then clean on the client side too.
    s_wr.shutdown().await.unwrap();
    let n2 = with_timeout(c_rd.read(&mut junk), "client final EOF read").await;
    assert_eq!(n2, 0, "client must see clean EOF after server shutdown");
}

/// Mirror of [`half_close_client_then_server`]: the SERVER closes its write
/// half first; the client must see a clean EOF while its own write half still
/// reaches the server.
pub async fn half_close_server_then_client(client: BoxedStream, server: BoxedStream) {
    let (mut c_rd, mut c_wr) = tokio::io::split(client);
    let (mut s_rd, mut s_wr) = tokio::io::split(server);

    s_wr.write_all(HC_S2C).await.unwrap();
    s_wr.flush().await.unwrap();

    let mut buf = vec![0u8; HC_S2C.len()];
    with_timeout(c_rd.read_exact(&mut buf), "client read pre-EOF msg").await;
    assert_eq!(buf, HC_S2C);

    // Server half-closes.
    s_wr.shutdown().await.unwrap();

    let mut junk = [0u8; 32];
    let n = with_timeout(c_rd.read(&mut junk), "client EOF read").await;
    assert_eq!(n, 0, "client must see clean EOF after server half-close");

    // Client's write half still reaches the server.
    c_wr.write_all(HC_C2S).await.unwrap();
    c_wr.flush().await.unwrap();
    let mut back = vec![0u8; HC_C2S.len()];
    with_timeout(s_rd.read_exact(&mut back), "server read post-EOF msg").await;
    assert_eq!(back, HC_C2S, "client->server leg must survive server EOF");

    c_wr.shutdown().await.unwrap();
    let n2 = with_timeout(s_rd.read(&mut junk), "server final EOF read").await;
    assert_eq!(n2, 0, "server must see clean EOF after client shutdown");
}

/// Await `fut` under a generous deadline so a genuine stall fails loudly with
/// `label` rather than hanging the whole suite.
async fn with_timeout<F, T>(fut: F, label: &str) -> T
where
    F: std::future::Future<Output = io::Result<T>>,
{
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .unwrap_or_else(|_| panic!("`{label}` timed out (transport stalled)"))
        .unwrap_or_else(|e| panic!("`{label}` errored: {e}"))
}

// ---------------------------------------------------------------------------
// In-memory mock duplex with a controllable per-read chunk size (fragmented
// reads) and a settable EOF. Mirrors the one in `framing_negatives.rs`.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MockDuplex {
    inbound: Arc<Mutex<VecDeque<u8>>>,
    outbound: Arc<Mutex<Vec<u8>>>,
    read_chunk: usize,
    eof: Arc<Mutex<bool>>,
}

impl MockDuplex {
    #[must_use]
    pub fn new(inbound: Vec<u8>, read_chunk: usize) -> Self {
        Self {
            inbound: Arc::new(Mutex::new(inbound.into_iter().collect())),
            outbound: Arc::new(Mutex::new(Vec::new())),
            read_chunk: read_chunk.max(1),
            eof: Arc::new(Mutex::new(false)),
        }
    }

    /// Empty inbound, used purely as a write sink to capture produced wire
    /// bytes.
    #[must_use]
    pub fn capturing() -> Self {
        Self::new(Vec::new(), 4096)
    }

    #[must_use]
    pub fn captured(&self) -> Vec<u8> {
        self.outbound.lock().unwrap().clone()
    }

    pub fn set_eof(&self) {
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
                return Poll::Ready(Ok(())); // EOF: Ready with nothing filled.
            }
            // No data and not at EOF — park. Tests that hit this wrap the read
            // in a timeout so a genuine stall fails loudly instead of hanging.
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
// Backpressure sink: accepts at most `chunk` bytes per successful poll_write,
// then returns `Pending` on the very next poll (waking itself so the runtime
// re-polls). Reproduces real TCP backpressure: a partial write (`n > 0`)
// followed by a mid-frame `Pending` — the HIGH-1 AEAD/counter desync trigger.
// Everything accepted is captured so the produced wire can be replayed.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FlakySink {
    out: Arc<Mutex<Vec<u8>>>,
    chunk: usize,
    pending_next: Arc<Mutex<bool>>,
}

impl FlakySink {
    #[must_use]
    pub fn new(chunk: usize) -> Self {
        Self {
            out: Arc::new(Mutex::new(Vec::new())),
            chunk: chunk.max(1),
            pending_next: Arc::new(Mutex::new(false)),
        }
    }

    #[must_use]
    pub fn captured(&self) -> Vec<u8> {
        self.out.lock().unwrap().clone()
    }
}

impl AsyncRead for FlakySink {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Never used as a reader.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FlakySink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut pend = self.pending_next.lock().unwrap();
        if *pend {
            *pend = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = self.chunk.min(data.len());
        self.out.lock().unwrap().extend_from_slice(&data[..n]);
        *pend = true;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
