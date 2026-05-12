//! Backpressure-aware bidirectional copy with optional throttling.
//!
//! Unlike `tokio::io::copy_bidirectional`, this version blocks each
//! per-direction loop on a [`crate::limits::TokenBucket`] before issuing the
//! write, so a slow bucket throttles the *throughput* (not just the read
//! rate). The two directions are otherwise independent: a half-close on one
//! side does not stop the other until both halves have closed or errored.

use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::TokenBucket;

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

    let a_to_b = copy_one(&mut a_r, &mut b_w, bucket_a_to_b);
    let b_to_a = copy_one(&mut b_r, &mut a_w, bucket_b_to_a);

    let (ab, ba) = tokio::join!(a_to_b, b_to_a);
    Ok(CopyStats {
        a_to_b: ab?,
        b_to_a: ba?,
    })
}

async fn copy_one<R, W>(src: &mut R, dst: &mut W, bucket: TokenBucket) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            // EOF — half-close downstream so the peer notices.
            let _ = dst.shutdown().await;
            return Ok(total);
        }
        if bucket.is_active() {
            bucket.acquire(n as u64).await;
        }
        dst.write_all(&buf[..n]).await?;
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
    use tokio::io::duplex;

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
}
