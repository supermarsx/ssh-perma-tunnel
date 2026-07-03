//! Backpressure-aware bidirectional copy with optional throttling.
//!
//! Unlike `tokio::io::copy_bidirectional`, this version blocks each
//! per-direction loop on a [`crate::limits::TokenBucket`] before issuing the
//! write, so a slow bucket throttles the *throughput* (not just the read
//! rate). The two directions are otherwise independent: a half-close on one
//! side does not stop the other until both halves have closed or errored.

use std::future::poll_fn;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::limits::TokenBucket;

/// Shared activity beacon for the idle watchdog. Each direction's copy loop
/// bumps the generation counter whenever bytes actually move, and marks itself
/// "in flight" for the entire duration of draining a chunk (the throttle
/// acquire *plus* the downstream write). The watchdog samples both to detect
/// true quiescence without touching the hot read/write path beyond a couple of
/// relaxed atomics.
///
/// The in-flight counter is the crux of the idle-vs-throttle distinction: a
/// heavily rate-limited transfer can legitimately spend longer than one idle
/// window inside a single [`TokenBucket::acquire`], during which the generation
/// counter does not advance. Treating that window as idle would false-close an
/// actively-draining connection and silently truncate it. By keeping the
/// direction marked in-flight across the acquire+write, the watchdog sees the
/// connection as busy (data is moving, just slowly) and never idle-closes it.
/// The timeout therefore fires only when *no* direction is mid-chunk and no
/// bytes have moved for a full window — genuine idleness.
#[derive(Debug, Default)]
struct ActivityBeacon {
    /// Advanced once per non-empty read and once again after the matching write
    /// completes, so a completed chunk always changes the sampled generation.
    generation: AtomicU64,
    /// Number of directions currently draining a chunk (inside acquire+write).
    /// Non-zero means data is actively being moved, however slowly.
    in_flight: AtomicU64,
}

impl ActivityBeacon {
    fn bump(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    fn enter_transfer(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    fn exit_transfer(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    fn sample(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    fn is_busy(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) > 0
    }
}

/// Per-side counters returned from [`copy_bidirectional_throttled`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CopyStats {
    /// Bytes copied a→b.
    pub a_to_b: u64,
    /// Bytes copied b→a.
    pub b_to_a: u64,
}

/// Buffer size for each direction's copy loop. Sized to comfortably hold a
/// single TCP segment without wasting memory on idle connections.
const BUF_SIZE: usize = 16 * 1024;

/// Copy bytes between two duplex streams, throttling each direction with the
/// matching token bucket.
///
/// `bucket_a_to_b` throttles bytes written into `b`; `bucket_b_to_a` throttles
/// bytes written into `a`. Pass [`TokenBucket::unlimited`] to disable a side.
///
/// Returns total bytes per direction once both sides are closed, an error
/// surfaces on either side, or the deadline (`max_lifetime`) elapses (when
/// `Some`).
pub async fn copy_bidirectional_throttled<A, B>(
    a: &mut A,
    b: &mut B,
    bucket_a_to_b: TokenBucket,
    bucket_b_to_a: TokenBucket,
) -> std::io::Result<CopyStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);

    let a_to_b = copy_one(&mut a_r, &mut b_w, bucket_a_to_b, None);
    let b_to_a = copy_one(&mut b_r, &mut a_w, bucket_b_to_a, None);

    let (ab, ba) = tokio::join!(a_to_b, b_to_a);
    Ok(CopyStats {
        a_to_b: ab?,
        b_to_a: ba?,
    })
}

/// Copy bytes between two duplex streams with per-direction throttling *and* an
/// idle timeout.
///
/// Behaves exactly like [`copy_bidirectional_throttled`] but additionally
/// closes the connection if no bytes flow in *either* direction for
/// `idle_timeout`. The timeout is reset by byte activity: every non-empty read
/// bumps a shared activity beacon (a single relaxed atomic increment — it does
/// not touch the per-byte hot loop), and a lightweight watchdog samples the
/// beacon at `idle_timeout` granularity.
///
/// On idle expiry the copy returns the [`CopyStats`] accumulated so far with
/// the directions' streams dropped (which shuts the halves down). A `None`
/// timeout is equivalent to [`copy_bidirectional_throttled`] (no idle close).
pub async fn copy_bidirectional_throttled_idle<A, B>(
    a: &mut A,
    b: &mut B,
    bucket_a_to_b: TokenBucket,
    bucket_b_to_a: TokenBucket,
    idle_timeout: Option<Duration>,
) -> std::io::Result<CopyStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let Some(idle) = idle_timeout.filter(|d| !d.is_zero()) else {
        return copy_bidirectional_throttled(a, b, bucket_a_to_b, bucket_b_to_a).await;
    };

    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);

    let beacon = Arc::new(ActivityBeacon::default());

    let a_to_b = copy_one(&mut a_r, &mut b_w, bucket_a_to_b, Some(&beacon));
    let b_to_a = copy_one(&mut b_r, &mut a_w, bucket_b_to_a, Some(&beacon));
    let copies = async {
        let (ab, ba) = tokio::join!(a_to_b, b_to_a);
        Ok::<CopyStats, std::io::Error>(CopyStats {
            a_to_b: ab?,
            b_to_a: ba?,
        })
    };
    tokio::pin!(copies);

    // Watchdog: sample the beacon at `idle` cadence. If two consecutive samples
    // are identical, no byte moved in the whole interval → idle close.
    let mut last_seen = beacon.sample();
    loop {
        tokio::select! {
            res = &mut copies => return res,
            () = tokio::time::sleep(idle) => {
                let now = beacon.sample();
                // Idle only when the generation has not advanced AND neither
                // direction is mid-chunk. `is_busy()` covers a transfer that is
                // legitimately slow due to its configured rate limit: while it
                // sits in `bucket.acquire()` draining real data the generation
                // does not move, but the direction is marked in-flight, so it is
                // NOT counted as idle and never truncated.
                if now == last_seen && !beacon.is_busy() {
                    // No byte moved and nothing is in flight for a full idle
                    // window — a genuinely idle connection. Log the close so it
                    // is observable (the previous silent `Ok(default)` return
                    // made idle closes invisible), then return the partial
                    // stats; dropping the split halves shuts both directions
                    // down.
                    tracing::debug!(
                        idle_timeout = ?idle,
                        "bidir: idle watchdog closing quiescent connection"
                    );
                    return Ok(CopyStats::default());
                }
                last_seen = now;
            }
        }
    }
}

async fn copy_one<R, W>(
    src: &mut R,
    dst: &mut W,
    bucket: TokenBucket,
    beacon: Option<&ActivityBeacon>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Heap-allocate a single uninitialised 16 KiB scratch buffer once and reuse
    // it across every read in this direction. This avoids the per-call
    // `vec![0u8; BUF_SIZE]` allocation + memset that previously fired on every
    // `copy_one` invocation (two per accepted forward connection).
    //
    // Safety: `Box<[MaybeUninit<u8>; BUF_SIZE]>` holds `BUF_SIZE` uninitialised
    // bytes. We only ever read from the slice via `ReadBuf::uninit`, which
    // tracks the initialised prefix internally, and we only forward
    // `ReadBuf::filled()` (the initialised portion) to `write_all`. We never
    // expose uninitialised memory to safe code or to the writer.
    let mut buf: Box<[MaybeUninit<u8>; BUF_SIZE]> = Box::new([MaybeUninit::uninit(); BUF_SIZE]);
    let mut total: u64 = 0;
    loop {
        // Wrap the scratch buffer in a fresh `ReadBuf` for every iteration so
        // `filled()` starts at zero. `ReadBuf::uninit` tracks how much of the
        // underlying memory the reader has initialised; only that initialised
        // prefix is exposed via `filled()`.
        let mut read_buf = ReadBuf::uninit(buf.as_mut_slice());
        poll_fn(|cx| Pin::new(&mut *src).poll_read(cx, &mut read_buf)).await?;
        let n = read_buf.filled().len();
        if n == 0 {
            // EOF — half-close downstream so the peer notices.
            let _ = dst.shutdown().await;
            return Ok(total);
        }
        // Byte activity — reset the idle watchdog (single relaxed increment)
        // and mark this direction in-flight for the whole drain (throttle
        // acquire + write). Marking in-flight is what keeps a legitimately
        // rate-limited chunk — which can block inside `acquire` for longer than
        // a full idle window — from being mis-read as idle and truncated.
        if let Some(b) = beacon {
            b.bump();
            b.enter_transfer();
        }
        // Ensure the in-flight mark is cleared even if the write errors out, so
        // a failed direction cannot wedge the watchdog into "always busy".
        let drain = async {
            if bucket.is_active() {
                bucket.acquire(n as u64).await;
            }
            // `filled()` is the initialised portion of the buffer — never pass
            // uninitialised memory to `write_all`.
            dst.write_all(read_buf.filled()).await
        };
        let result = drain.await;
        if let Some(b) = beacon {
            // Bump again on completion so a chunk that finished entirely within
            // one idle window still advances the sampled generation, then clear
            // the in-flight mark.
            b.bump();
            b.exit_transfer();
        }
        result?;
        total += n as u64;
    }
}

/// Compute the steady-state throughput in bytes/sec from a copy that ran for
/// `dt` between `start` and now.
#[must_use]
pub fn throughput_bps(bytes: u64, start: Instant) -> u64 {
    let dt = start.elapsed().as_secs_f64();
    if dt <= 0.0 {
        return 0;
    }
    (bytes as f64 / dt) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt};

    #[tokio::test]
    async fn copies_both_directions_unthrottled() {
        let (mut left_app, mut left_tun) = duplex(64);
        let (mut right_tun, mut right_app) = duplex(64);

        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled(
                &mut left_tun,
                &mut right_tun,
                TokenBucket::unlimited(),
                TokenBucket::unlimited(),
            )
            .await
        });

        left_app.write_all(b"hello").await.unwrap();
        left_app.shutdown().await.unwrap();

        right_app.write_all(b"world").await.unwrap();
        right_app.shutdown().await.unwrap();

        let mut got_right = Vec::new();
        right_app.read_to_end(&mut got_right).await.unwrap();
        let mut got_left = Vec::new();
        left_app.read_to_end(&mut got_left).await.unwrap();
        assert_eq!(got_right, b"hello");
        assert_eq!(got_left, b"world");

        let stats = bridge.await.unwrap().unwrap();
        assert_eq!(stats.a_to_b, 5);
        assert_eq!(stats.b_to_a, 5);
    }

    #[tokio::test]
    async fn throttling_slows_throughput() {
        // 4 KiB/s bucket; 16 KiB payload. Real-time test (not paused) so we
        // measure actual wall-clock throttling.
        let (mut left_app, mut left_tun) = duplex(64 * 1024);
        let (mut right_tun, mut right_app) = duplex(64 * 1024);

        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled(
                &mut left_tun,
                &mut right_tun,
                TokenBucket::new(4 * 1024, 4 * 1024),
                TokenBucket::unlimited(),
            )
            .await
        });

        let payload = vec![0xAB; 16 * 1024];
        left_app.write_all(&payload).await.unwrap();
        left_app.shutdown().await.unwrap();
        // Close the unused reverse direction so b_to_a finishes too.
        right_app.shutdown().await.unwrap();

        let start = std::time::Instant::now();
        let mut got = vec![0u8; payload.len()];
        tokio::io::AsyncReadExt::read_exact(&mut right_app, &mut got)
            .await
            .unwrap();
        let dt = start.elapsed();
        // 16 KiB at 4 KiB/s with 4 KiB burst ~ 3s wall-clock.
        assert!(
            dt >= std::time::Duration::from_millis(2000),
            "expected throttling >=2s, got {dt:?}"
        );
        assert_eq!(got.len(), payload.len());
        let _ = bridge.await.unwrap();
    }

    #[tokio::test]
    async fn idle_none_behaves_like_plain_copy() {
        let (mut left_app, mut left_tun) = duplex(64);
        let (mut right_tun, mut right_app) = duplex(64);
        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled_idle(
                &mut left_tun,
                &mut right_tun,
                TokenBucket::unlimited(),
                TokenBucket::unlimited(),
                None,
            )
            .await
        });
        left_app.write_all(b"ping").await.unwrap();
        left_app.shutdown().await.unwrap();
        right_app.shutdown().await.unwrap();
        let mut got = Vec::new();
        right_app.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");
        let stats = bridge.await.unwrap().unwrap();
        assert_eq!(stats.a_to_b, 4);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_closes_after_quiescence() {
        // No bytes ever flow; with a 1s idle timeout the copy must return on
        // its own rather than blocking forever.
        let (_left_app, mut left_tun) = duplex(64);
        let (mut right_tun, _right_app) = duplex(64);
        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled_idle(
                &mut left_tun,
                &mut right_tun,
                TokenBucket::unlimited(),
                TokenBucket::unlimited(),
                Some(std::time::Duration::from_secs(1)),
            )
            .await
        });
        // Advance well past two idle windows so the watchdog fires.
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        let stats = bridge.await.unwrap().unwrap();
        // Idle close returns default (zero) stats.
        assert_eq!(stats, CopyStats::default());
    }

    #[tokio::test(start_paused = true)]
    async fn throttled_transfer_not_idle_closed() {
        // Regression (MED-3): a legitimately rate-limited transfer whose single
        // chunk takes far longer than the idle window to drain must NOT be
        // idle-closed. Pre-fix, the activity beacon was bumped only *before*
        // `bucket.acquire()`; while the chunk drained (≈16 s at 1 KiB/s) the
        // generation never advanced, so the watchdog saw two equal samples and
        // false-closed — dropping the in-flight write, truncating the upload,
        // and returning zero stats reported as success. With the in-flight mark
        // held across acquire+write the connection reads as busy and survives.
        let payload_len = 16 * 1024;
        let (mut left_app, mut left_tun) = duplex(64 * 1024);
        let (mut right_tun, mut right_app) = duplex(64 * 1024);

        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled_idle(
                &mut left_tun,
                &mut right_tun,
                // 1 KiB/s, 1 KiB burst → ≈16 s to drain a 16 KiB chunk.
                TokenBucket::new(1024, 1024),
                TokenBucket::unlimited(),
                // Idle window far shorter than the per-chunk drain time; this is
                // exactly the config that false-closed pre-fix.
                Some(Duration::from_secs(2)),
            )
            .await
        });

        let payload = vec![0xCD; payload_len];
        left_app.write_all(&payload).await.unwrap();
        left_app.shutdown().await.unwrap();
        // Close the quiescent reverse direction so it EOFs cleanly.
        right_app.shutdown().await.unwrap();

        // Must receive the *entire* payload — no truncation.
        let mut got = vec![0u8; payload_len];
        tokio::io::AsyncReadExt::read_exact(&mut right_app, &mut got)
            .await
            .unwrap();
        assert_eq!(got, payload);

        let stats = bridge.await.unwrap().unwrap();
        // Full byte count reported, not the zeroed idle-close default.
        assert_eq!(stats.a_to_b as usize, payload_len);
    }

    #[tokio::test(start_paused = true)]
    async fn throttled_but_quiescent_still_idle_closes() {
        // A throttle bucket is configured but no bytes ever flow: `acquire` is
        // never entered, nothing is in-flight, so the watchdog must still fire
        // after the idle window (the fix must not wedge the watchdog "on").
        let (_left_app, mut left_tun) = duplex(64);
        let (mut right_tun, _right_app) = duplex(64);
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
    }

    #[tokio::test(start_paused = true)]
    async fn idle_does_not_close_while_active() {
        // Bytes keep flowing within each idle window; the copy must NOT close
        // until both halves shut down naturally.
        let (mut left_app, mut left_tun) = duplex(1024);
        let (mut right_tun, mut right_app) = duplex(1024);
        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled_idle(
                &mut left_tun,
                &mut right_tun,
                TokenBucket::unlimited(),
                TokenBucket::unlimited(),
                Some(std::time::Duration::from_secs(2)),
            )
            .await
        });
        for _ in 0..3 {
            left_app.write_all(b"tick").await.unwrap();
            let mut buf = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut right_app, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf, b"tick");
            // Sleep less than the idle window so activity keeps resetting it.
            tokio::time::advance(std::time::Duration::from_secs(1)).await;
        }
        // Now go quiet and let it idle-close.
        left_app.shutdown().await.unwrap();
        right_app.shutdown().await.unwrap();
        let _ = bridge.await.unwrap();
    }
}
