//! Token-bucket rate limiter and connection-cap gate.
//!
//! Two primitives:
//!
//! * [`TokenBucket`] — classic byte-rate token bucket with configurable burst.
//!   Used by [`crate::bidir::copy_bidirectional_throttled`] to throttle per
//!   direction (per-connection / per-forward / per-profile by composition).
//! * [`ConnectionGate`] — semaphore-style cap on concurrent connections.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;

// --------------------------------------------------------------------------
// TokenBucket
// --------------------------------------------------------------------------

/// A simple async token bucket measured in bytes.
///
/// `rate_bps` tokens are added per second up to `burst`. Calls to
/// [`TokenBucket::acquire`] block until enough tokens are available.
///
/// Internals are guarded by a [`parking_lot::Mutex`]; awaits never hold the
/// mutex.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    inner: Arc<TokenBucketInner>,
}

#[derive(Debug)]
struct TokenBucketInner {
    rate_bps: u64,
    burst: u64,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// New bucket producing `rate_bps` bytes per second with capacity `burst`.
    ///
    /// `rate_bps == 0` disables throttling — [`acquire`](Self::acquire) becomes
    /// a no-op.
    #[must_use]
    pub fn new(rate_bps: u64, burst: u64) -> Self {
        let burst = burst.max(rate_bps.max(1));
        Self {
            inner: Arc::new(TokenBucketInner {
                rate_bps,
                burst,
                state: Mutex::new(State {
                    tokens: burst as f64,
                    last: Instant::now(),
                }),
            }),
        }
    }

    /// Disabled bucket — `acquire` is always immediate. Equivalent to
    /// `TokenBucket::new(0, 0)`.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(0, 0)
    }

    /// Whether this bucket actually throttles. `false` when `rate_bps == 0`.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.inner.rate_bps > 0
    }

    /// Configured rate, in bytes/second.
    #[must_use]
    pub fn rate_bps(&self) -> u64 {
        self.inner.rate_bps
    }

    /// Configured burst, in bytes.
    #[must_use]
    pub fn burst(&self) -> u64 {
        self.inner.burst
    }

    /// Try to consume `n` tokens without blocking.
    ///
    /// Returns the [`Duration`] the caller must wait if there aren't enough,
    /// or `None` if the request was satisfied.
    pub fn try_acquire(&self, n: u64) -> Option<Duration> {
        if !self.is_active() {
            return None;
        }
        let mut s = self.inner.state.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(s.last).as_secs_f64();
        s.last = now;
        s.tokens = (s.tokens + elapsed * self.inner.rate_bps as f64).min(self.inner.burst as f64);
        let need = n as f64;
        if s.tokens >= need {
            s.tokens -= need;
            None
        } else {
            let deficit = need - s.tokens;
            let wait_secs = deficit / self.inner.rate_bps as f64;
            Some(Duration::from_secs_f64(wait_secs.max(0.0)))
        }
    }

    /// Block until `n` tokens are available, then consume them.
    ///
    /// Requests larger than `burst` are split into chunks of `burst` to keep
    /// progress; the cumulative wait still reflects the full byte count.
    pub async fn acquire(&self, n: u64) {
        if !self.is_active() || n == 0 {
            return;
        }
        let mut remaining = n;
        while remaining > 0 {
            let take = remaining.min(self.inner.burst);
            loop {
                match self.try_acquire(take) {
                    None => break,
                    Some(wait) => tokio::time::sleep(wait).await,
                }
            }
            remaining -= take;
        }
    }
}

// --------------------------------------------------------------------------
// ConnectionGate
// --------------------------------------------------------------------------

/// A simple semaphore counting active connections, with a hard cap.
#[derive(Debug, Clone)]
pub struct ConnectionGate {
    sem: Arc<tokio::sync::Semaphore>,
    cap: u32,
}

impl ConnectionGate {
    /// New gate with `cap` permits. `cap == 0` means "unlimited" (always
    /// returns a permit).
    #[must_use]
    pub fn new(cap: u32) -> Self {
        // Tokio Semaphore caps at MAX_PERMITS; when 0 we still want a
        // semaphore so the API is uniform — store cap=0 separately.
        let permits = if cap == 0 {
            tokio::sync::Semaphore::MAX_PERMITS
        } else {
            cap as usize
        };
        Self {
            sem: Arc::new(tokio::sync::Semaphore::new(permits)),
            cap,
        }
    }

    /// Try to acquire a permit without waiting. Returns `None` if exhausted.
    pub fn try_acquire(&self) -> Option<ConnectionPermit> {
        self.sem
            .clone()
            .try_acquire_owned()
            .ok()
            .map(|p| ConnectionPermit { _permit: p })
    }

    /// Acquire a permit, awaiting if necessary.
    pub async fn acquire(&self) -> ConnectionPermit {
        // Semaphore::acquire_owned only fails if the semaphore is closed;
        // we never close it.
        let p = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .expect("connection gate semaphore must remain open");
        ConnectionPermit { _permit: p }
    }

    /// Configured cap (`0` = unlimited).
    #[must_use]
    pub fn cap(&self) -> u32 {
        self.cap
    }

    /// Number of currently-held permits.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        if self.cap == 0 {
            0
        } else {
            (self.cap as usize - self.sem.available_permits()) as u32
        }
    }
}

/// RAII permit for a slot held in a [`ConnectionGate`]. Drop releases the slot.
#[derive(Debug)]
pub struct ConnectionPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn unlimited_bucket_is_immediate() {
        let b = TokenBucket::unlimited();
        let start = Instant::now();
        b.acquire(1_000_000).await;
        assert!(start.elapsed() < Duration::from_millis(1));
    }

    #[tokio::test(start_paused = true)]
    async fn bucket_enforces_rate() {
        // 1 KiB/s, burst 1 KiB. Drain burst, then a second 1 KiB takes ~1s.
        let b = TokenBucket::new(1024, 1024);
        b.acquire(1024).await; // burst
        let start = Instant::now();
        b.acquire(1024).await;
        let dt = start.elapsed();
        assert!(
            dt >= Duration::from_millis(900),
            "expected >=900ms, got {dt:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn bucket_burst_is_immediate() {
        let b = TokenBucket::new(1024, 4096);
        let start = Instant::now();
        b.acquire(4096).await;
        assert!(start.elapsed() < Duration::from_millis(1));
    }

    #[test]
    fn try_acquire_reports_wait() {
        let b = TokenBucket::new(1000, 1000);
        // Drain
        assert!(b.try_acquire(1000).is_none());
        // Next one needs to wait
        let w = b.try_acquire(500).unwrap();
        assert!(w > Duration::ZERO);
    }

    #[tokio::test]
    async fn gate_limits_to_cap() {
        let g = ConnectionGate::new(2);
        let p1 = g.try_acquire().unwrap();
        let p2 = g.try_acquire().unwrap();
        assert!(g.try_acquire().is_none());
        assert_eq!(g.in_flight(), 2);
        drop(p1);
        let _p3 = g.try_acquire().unwrap();
        assert_eq!(g.in_flight(), 2);
        drop(p2);
    }

    #[tokio::test]
    async fn gate_unlimited_never_blocks() {
        let g = ConnectionGate::new(0);
        let _permits: Vec<_> = (0..1000).map(|_| g.try_acquire().unwrap()).collect();
        assert_eq!(g.in_flight(), 0); // unlimited reports 0
    }
}
