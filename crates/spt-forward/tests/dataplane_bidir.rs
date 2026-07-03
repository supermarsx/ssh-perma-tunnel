//! Data-plane regression tests for the generic bidirectional copy/forward
//! layer (`spt_forward::bidir`).
//!
//! These are *class* tests (not instance pins) for the four data-plane bug
//! families the coverage audit (`cov-dataplane.md`) flagged as unguarded at the
//! shared copy core:
//!
//! * **P2 — half-close / EOF propagation both directions**: closing one write
//!   half must EOF only that direction; the reverse direction stays open until
//!   it closes too. No premature full-close, no hang when one side lingers.
//! * **P4 — mid-stream error surfacing**: a read/write error mid-transfer must
//!   surface as `Err`, never be swallowed into `Ok(CopyStats::default())` (the
//!   silent-truncation-reported-as-success class).
//! * **byte-integrity + backpressure gauntlet**: table of payloads
//!   {0, tiny, 64 KiB, >= 1 MiB} pushed through a partial-accepting sink;
//!   byte-exact both directions, no loss under partial writes.
//! * **throttle + idle boundary**: rate-limited transfers run to completion
//!   without idle-close (even where per-chunk drain time straddles the idle
//!   window); a genuinely idle connection still closes after the timeout.
//!
//! All timing tests use `tokio`'s paused clock where the outcome depends only
//! on the throttle math (no wall-clock flakiness). Error/half-close tests that
//! must *not* be perturbed by an auto-advancing idle timer use the real clock
//! with a very large idle timeout that cannot fire inside a sub-second test.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{
    duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
};
use tokio::time::Instant;

use spt_forward::{
    copy_bidirectional_throttled, copy_bidirectional_throttled_idle, CopyStats, TokenBucket,
};

// ---------------------------------------------------------------------------
// Test mocks
// ---------------------------------------------------------------------------

/// Wraps a real [`DuplexStream`] but caps every `poll_write` to at most `chunk`
/// bytes, forcing the `write_all` loop in `copy_one` to make partial-write
/// progress. Reads pass straight through. This reproduces a sink that only ever
/// accepts a fragment per syscall (TCP send-buffer pressure) without needing an
/// external waker — the underlying duplex still drives readiness.
struct PartialWriteStream {
    inner: DuplexStream,
    chunk: usize,
}

impl PartialWriteStream {
    fn new(inner: DuplexStream, chunk: usize) -> Self {
        Self { inner, chunk }
    }
}

impl AsyncRead for PartialWriteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PartialWriteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let cap = buf.len().min(this.chunk.max(1));
        Pin::new(&mut this.inner).poll_write(cx, &buf[..cap])
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// A stream whose read side serves `read_data` (then EOF) and whose write side
/// accepts bytes until `err_after` total have been written, after which every
/// `poll_write` returns an error. Used to inject a mid-transfer *write* error
/// and prove the copy surfaces it rather than swallowing it.
struct ErrWriteAfterN {
    read_data: Vec<u8>,
    read_pos: usize,
    written: usize,
    err_after: usize,
}

impl ErrWriteAfterN {
    fn new(read_data: Vec<u8>, err_after: usize) -> Self {
        Self {
            read_data,
            read_pos: 0,
            written: 0,
            err_after,
        }
    }
}

impl AsyncRead for ErrWriteAfterN {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let remaining = &this.read_data[this.read_pos..];
        let n = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..n]);
        this.read_pos += n;
        // n == 0 once drained => clean EOF.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ErrWriteAfterN {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.written >= this.err_after {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected mid-stream write error",
            )));
        }
        let allowed = (this.err_after - this.written).min(buf.len());
        this.written += allowed;
        Poll::Ready(Ok(allowed))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A stream whose read side yields `err_after` bytes and then returns an error
/// (rather than EOF), and whose write side is an infinite sink. Used to inject a
/// mid-transfer *read* error.
struct ErrReadAfterN {
    served: usize,
    err_after: usize,
}

impl ErrReadAfterN {
    fn new(err_after: usize) -> Self {
        Self {
            served: 0,
            err_after,
        }
    }
}

impl AsyncRead for ErrReadAfterN {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.served >= this.err_after {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected mid-stream read error",
            )));
        }
        let remaining = this.err_after - this.served;
        let n = remaining.min(buf.remaining());
        // Fill with a recognisable byte; content is irrelevant to the test.
        for _ in 0..n {
            buf.put_slice(&[0xA5]);
        }
        this.served += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ErrReadAfterN {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A stream whose read side is at EOF from the start and whose write side is an
/// infinite sink. Used as the *other* end of a copy when we only care about the
/// direction being tested — its read EOF lets that leg finish `Ok(0)` so
/// `tokio::join!` can complete instead of blocking forever on an open peer.
struct NullStream;

impl AsyncRead for NullStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Leave the buffer empty => immediate EOF.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for NullStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Deterministic pseudo-random payload (LCG, Numerical-Recipes constants) so
/// byte-exactness assertions are meaningful and reproducible without a new dep.
fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed;
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        v.push((s >> 33) as u8);
    }
    v
}

// ---------------------------------------------------------------------------
// P2 — half-close / EOF propagation, both directions
// ---------------------------------------------------------------------------

// After A half-closes its write, B must still see EOF on A->B, yet B->A must
// stay open and deliver until B also closes. Then both close cleanly with the
// full per-direction byte counts.
#[tokio::test]
async fn half_close_a_first_keeps_reverse_open() {
    let (mut left_app, mut left_tun) = duplex(4096);
    let (mut right_tun, mut right_app) = duplex(4096);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
        )
        .await
    });

    // A sends then half-closes its WRITE half.
    left_app.write_all(b"a-payload").await.unwrap();
    left_app.shutdown().await.unwrap();

    // B receives A's bytes and the EOF on that direction...
    let mut got_ab = vec![0u8; 9];
    right_app.read_exact(&mut got_ab).await.unwrap();
    assert_eq!(&got_ab, b"a-payload");

    // ...but the REVERSE direction must remain fully open. This is the exact
    // premature-full-close regression: pre-fix this read would hang or EOF.
    right_app.write_all(b"b-reply").await.unwrap();
    let mut got_ba = vec![0u8; 7];
    left_app.read_exact(&mut got_ba).await.unwrap();
    assert_eq!(&got_ba, b"b-reply");

    // Now B closes; A observes a clean FIN and the bridge finishes.
    right_app.shutdown().await.unwrap();
    let mut trailing = Vec::new();
    left_app.read_to_end(&mut trailing).await.unwrap();
    assert!(
        trailing.is_empty(),
        "unexpected trailing bytes: {trailing:?}"
    );

    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(stats.a_to_b, 9, "A->B byte count");
    assert_eq!(stats.b_to_a, 7, "B->A byte count");
}

// Symmetric ordering: B half-closes first; A->B must stay open afterward.
#[tokio::test]
async fn half_close_b_first_keeps_forward_open() {
    let (mut left_app, mut left_tun) = duplex(4096);
    let (mut right_tun, mut right_app) = duplex(4096);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
        )
        .await
    });

    right_app.write_all(b"from-b").await.unwrap();
    right_app.shutdown().await.unwrap();

    let mut got_ba = vec![0u8; 6];
    left_app.read_exact(&mut got_ba).await.unwrap();
    assert_eq!(&got_ba, b"from-b");

    // Forward direction still open after B's half-close.
    left_app.write_all(b"from-a-later").await.unwrap();
    let mut got_ab = vec![0u8; 12];
    right_app.read_exact(&mut got_ab).await.unwrap();
    assert_eq!(&got_ab, b"from-a-later");

    left_app.shutdown().await.unwrap();
    let mut trailing = Vec::new();
    right_app.read_to_end(&mut trailing).await.unwrap();
    assert!(trailing.is_empty());

    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(stats.a_to_b, 12);
    assert_eq!(stats.b_to_a, 6);
}

// Both sides send then half-close (near-simultaneous). Both payloads must be
// delivered and both counts correct — no direction is truncated by the other's
// close.
#[tokio::test]
async fn half_close_simultaneous_both_deliver() {
    let (mut left_app, mut left_tun) = duplex(4096);
    let (mut right_tun, mut right_app) = duplex(4096);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
        )
        .await
    });

    left_app.write_all(b"AAAA").await.unwrap();
    right_app.write_all(b"BBBBBB").await.unwrap();
    left_app.shutdown().await.unwrap();
    right_app.shutdown().await.unwrap();

    let mut got_ab = Vec::new();
    right_app.read_to_end(&mut got_ab).await.unwrap();
    let mut got_ba = Vec::new();
    left_app.read_to_end(&mut got_ba).await.unwrap();
    assert_eq!(got_ab, b"AAAA");
    assert_eq!(got_ba, b"BBBBBB");

    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(stats.a_to_b, 4);
    assert_eq!(stats.b_to_a, 6);
}

// The same half-close invariant must hold on the idle-timeout code path (the
// watchdog select loop), not only the plain copy. A very large real-clock idle
// timeout cannot fire inside this sub-second test, so any early close would be a
// genuine premature-close bug, not the idle watchdog.
#[tokio::test]
async fn half_close_reverse_open_on_idle_path() {
    let (mut left_app, mut left_tun) = duplex(4096);
    let (mut right_tun, mut right_app) = duplex(4096);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled_idle(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
            Some(Duration::from_secs(3600)),
        )
        .await
    });

    left_app.write_all(b"early").await.unwrap();
    left_app.shutdown().await.unwrap();
    let mut got_ab = vec![0u8; 5];
    right_app.read_exact(&mut got_ab).await.unwrap();
    assert_eq!(&got_ab, b"early");

    // Reverse direction still usable after the forward half-close.
    right_app.write_all(b"late-reply").await.unwrap();
    let mut got_ba = vec![0u8; 10];
    left_app.read_exact(&mut got_ba).await.unwrap();
    assert_eq!(&got_ba, b"late-reply");

    right_app.shutdown().await.unwrap();
    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(stats.a_to_b, 5);
    assert_eq!(stats.b_to_a, 10);
}

// One side lingers (sends nothing, never closes) after the other half-closes.
// The copy must NOT hang forever: the idle watchdog eventually closes the
// quiescent connection. Guards the "no hang when one side lingers" clause.
#[tokio::test(start_paused = true)]
async fn lingering_half_open_side_is_idle_closed() {
    let (mut left_app, mut left_tun) = duplex(4096);
    // right_app is held open (never written, never closed) to simulate a
    // lingering peer.
    let (mut right_tun, _right_app) = duplex(4096);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled_idle(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
            Some(Duration::from_secs(2)),
        )
        .await
    });

    left_app.write_all(b"bye").await.unwrap();
    left_app.shutdown().await.unwrap();

    // Advance well past two idle windows; the lingering reverse half must not
    // wedge the copy open forever.
    tokio::time::advance(Duration::from_secs(10)).await;
    let stats = bridge.await.unwrap().unwrap();
    // Idle close returns the zeroed default (documented behaviour).
    assert_eq!(stats, CopyStats::default());
}

// ---------------------------------------------------------------------------
// P4 — mid-stream error must NOT become silent Ok(default)
// ---------------------------------------------------------------------------

// A sink that errors after N accepted bytes: the plain copy must return Err,
// never Ok(CopyStats::default()) hiding the truncation.
#[tokio::test]
async fn mid_stream_write_error_surfaced_plain() {
    let (mut a_app, mut a) = duplex(256 * 1024);
    // b accepts 4 KiB then errors; its read side is empty (immediate EOF).
    let mut b = ErrWriteAfterN::new(Vec::new(), 4096);

    let payload = vec![0x5A_u8; 64 * 1024];
    a_app.write_all(&payload).await.unwrap();
    a_app.shutdown().await.unwrap();

    let res = copy_bidirectional_throttled(
        &mut a,
        &mut b,
        TokenBucket::unlimited(),
        TokenBucket::unlimited(),
    )
    .await;

    assert!(
        res.is_err(),
        "mid-stream write error must surface as Err, got Ok({:?})",
        res.ok()
    );
}

// Same guard on the idle-timeout path. A large real-clock idle timeout ensures
// the watchdog cannot masquerade the error as an idle Ok(default).
#[tokio::test]
async fn mid_stream_write_error_surfaced_idle_path() {
    let (mut a_app, mut a) = duplex(256 * 1024);
    let mut b = ErrWriteAfterN::new(Vec::new(), 8192);

    let payload = vec![0x33_u8; 128 * 1024];
    a_app.write_all(&payload).await.unwrap();
    a_app.shutdown().await.unwrap();

    let res = copy_bidirectional_throttled_idle(
        &mut a,
        &mut b,
        TokenBucket::unlimited(),
        TokenBucket::unlimited(),
        Some(Duration::from_secs(3600)),
    )
    .await;

    assert!(
        res.is_err(),
        "mid-stream write error on idle path must surface as Err, got Ok({:?})",
        res.ok()
    );
}

// A source that errors mid-read must likewise surface as Err (the read `?` in
// copy_one), not a silent success.
#[tokio::test]
async fn mid_stream_read_error_surfaced_plain() {
    // a serves 4 KiB then errors on read; its write side is an infinite sink.
    let mut a = ErrReadAfterN::new(4096);
    // b's read side is at EOF (so the b->a leg finishes cleanly) and its write
    // side drains whatever a produces before a's read errors.
    let mut b = NullStream;

    let res = copy_bidirectional_throttled(
        &mut a,
        &mut b,
        TokenBucket::unlimited(),
        TokenBucket::unlimited(),
    )
    .await;

    assert!(
        res.is_err(),
        "mid-stream read error must surface as Err, got Ok({:?})",
        res.ok()
    );
}

// ---------------------------------------------------------------------------
// byte-integrity + backpressure gauntlet
// ---------------------------------------------------------------------------

/// Push `payload_ab` (A->B) and `payload_ba` (B->A) simultaneously through
/// `copy_bidirectional_throttled_idle`, with BOTH tunnel ends wrapped in a
/// [`PartialWriteStream`] capped at `chunk` bytes/write. Returns the received
/// bytes for each direction plus the reported stats.
async fn run_copy_gauntlet(
    payload_ab: Vec<u8>,
    payload_ba: Vec<u8>,
    chunk: usize,
) -> (Vec<u8>, Vec<u8>, CopyStats) {
    // Modest duplex buffers force streaming/backpressure rather than one-shot
    // buffering, so the partial-write path is genuinely exercised.
    let (left_app, left_tun) = duplex(16 * 1024);
    let (right_tun, right_app) = duplex(16 * 1024);
    let mut a = PartialWriteStream::new(left_tun, chunk);
    let mut b = PartialWriteStream::new(right_tun, chunk);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled_idle(
            &mut a,
            &mut b,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
            None,
        )
        .await
    });

    let (mut la_r, mut la_w) = tokio::io::split(left_app);
    let (mut ra_r, mut ra_w) = tokio::io::split(right_app);

    let p_ab = payload_ab.clone();
    let w_ab = tokio::spawn(async move {
        la_w.write_all(&p_ab).await.unwrap();
        la_w.shutdown().await.unwrap();
    });
    let p_ba = payload_ba.clone();
    let w_ba = tokio::spawn(async move {
        ra_w.write_all(&p_ba).await.unwrap();
        ra_w.shutdown().await.unwrap();
    });

    let r_ab = tokio::spawn(async move {
        let mut v = Vec::new();
        ra_r.read_to_end(&mut v).await.unwrap();
        v
    });
    let r_ba = tokio::spawn(async move {
        let mut v = Vec::new();
        la_r.read_to_end(&mut v).await.unwrap();
        v
    });

    w_ab.await.unwrap();
    w_ba.await.unwrap();
    let got_ab = r_ab.await.unwrap();
    let got_ba = r_ba.await.unwrap();
    let stats = bridge.await.unwrap().unwrap();
    (got_ab, got_ba, stats)
}

#[tokio::test]
async fn byte_integrity_partial_write_gauntlet() {
    // (payload length, per-write chunk cap). Zero-length, tiny, one full buffer,
    // >64 KiB, and a >1 MiB prime-sized payload — each byte-exact under a
    // fragmenting sink in BOTH directions at once.
    let cases: &[(usize, usize)] = &[
        (0, 1),
        (1, 1),
        (100, 7),
        (64 * 1024, 1000),
        (1_048_576 + 4099, 8191),
    ];

    for &(len, chunk) in cases {
        let payload_ab = lcg_bytes(0xA11C_E5EE_D000_0001 ^ len as u64, len);
        // Distinct payload for the reverse direction to catch any cross-wiring.
        let payload_ba = lcg_bytes(0xB0B0_5EED_0000_0002 ^ len as u64, len);

        let (got_ab, got_ba, stats) =
            run_copy_gauntlet(payload_ab.clone(), payload_ba.clone(), chunk).await;

        assert_eq!(
            got_ab, payload_ab,
            "A->B not byte-exact for len={len} chunk={chunk}"
        );
        assert_eq!(
            got_ba, payload_ba,
            "B->A not byte-exact for len={len} chunk={chunk}"
        );
        assert_eq!(stats.a_to_b as usize, len, "A->B stats for len={len}");
        assert_eq!(stats.b_to_a as usize, len, "B->A stats for len={len}");
    }
}

// ---------------------------------------------------------------------------
// throttle + idle boundary
// ---------------------------------------------------------------------------

/// Run a one-directional rate-limited (A->B) transfer under an idle timeout and
/// assert the ENTIRE payload is delivered byte-exact and reported — i.e. the
/// throttle drain must never be mistaken for idleness and truncated.
async fn assert_throttled_completes(rate: u64, burst: u64, idle: Duration, payload_len: usize) {
    let (mut left_app, mut left_tun) = duplex(64 * 1024);
    let (mut right_tun, right_app) = duplex(64 * 1024);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled_idle(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::new(rate, burst),
            TokenBucket::unlimited(),
            Some(idle),
        )
        .await
    });

    let payload = lcg_bytes(0xDEAD_BEEF_0000_0000 ^ payload_len as u64, payload_len);
    let (mut ra_r, mut ra_w) = tokio::io::split(right_app);
    let p = payload.clone();
    let writer = tokio::spawn(async move {
        left_app.write_all(&p).await.unwrap();
        left_app.shutdown().await.unwrap();
    });
    // Close the quiescent reverse direction so B->A EOFs cleanly.
    let closer = tokio::spawn(async move {
        ra_w.shutdown().await.unwrap();
    });
    let reader = tokio::spawn(async move {
        let mut v = vec![0u8; payload_len];
        ra_r.read_exact(&mut v).await.unwrap();
        v
    });

    writer.await.unwrap();
    closer.await.unwrap();
    let got = reader.await.unwrap();
    assert_eq!(
        got, payload,
        "throttled transfer truncated (rate={rate} burst={burst} idle={idle:?} len={payload_len})"
    );

    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(
        stats.a_to_b as usize, payload_len,
        "throttled transfer under-reported (rate={rate} burst={burst} idle={idle:?})"
    );
}

// A rate-limited transfer whose per-chunk drain vastly exceeds the idle window
// must still complete (in-flight beacon keeps it "busy").
#[tokio::test(start_paused = true)]
async fn throttle_drain_far_exceeds_idle_completes() {
    // 1 KiB/s, 1 KiB burst => ~16 s to drain 16 KiB; idle 2 s.
    assert_throttled_completes(1024, 1024, Duration::from_secs(2), 16 * 1024).await;
}

// Boundary: a single per-token acquire (~1 s at 1 KiB/s) is on the same order as
// the idle window (1 s). Straddling the boundary must not trip a false close.
#[tokio::test(start_paused = true)]
async fn throttle_acquire_near_idle_boundary_completes() {
    assert_throttled_completes(1024, 1024, Duration::from_secs(1), 8 * 1024).await;
}

// A different (rate, burst, idle) combo, larger burst so the drain proceeds in
// bigger steps but still crosses several idle windows.
#[tokio::test(start_paused = true)]
async fn throttle_larger_burst_multi_window_completes() {
    // 8 KiB/s, 4 KiB burst, idle 500 ms, 32 KiB payload.
    assert_throttled_completes(8 * 1024, 4 * 1024, Duration::from_millis(500), 32 * 1024).await;
}

// The counterpart invariant: with a throttle bucket configured but NO bytes ever
// flowing, the watchdog must STILL fire (the in-flight fix must not wedge it on).
#[tokio::test(start_paused = true)]
async fn throttled_but_idle_still_closes() {
    let (_left_app, mut left_tun) = duplex(4096);
    let (mut right_tun, _right_app) = duplex(4096);

    let start = Instant::now();
    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled_idle(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::new(1024, 1024),
            TokenBucket::new(1024, 1024),
            Some(Duration::from_secs(1)),
        )
        .await
    });

    tokio::time::advance(Duration::from_secs(5)).await;
    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(stats, CopyStats::default());
    // Sanity: it did wait for at least one idle window, not close instantly.
    assert!(start.elapsed() >= Duration::from_secs(1));
}
