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

/// Scaling factor: 1 second expressed in nanoseconds. Internal token
/// accounting is in units of `bytes * NANOS_PER_SEC` so refill (which is
/// `elapsed_nanos * rate_bps`) and drain (`n * NANOS_PER_SEC`) both land in
/// the same unit using pure integer math.
const NANOS_PER_SEC: u128 = 1_000_000_000;

#[derive(Debug)]
struct TokenBucketInner {
    rate_bps: u64,
    burst: u64,
    /// Bucket capacity in scaled units (`burst * NANOS_PER_SEC`). Precomputed
    /// so the per-acquire path never recomputes it.
    capacity_scaled: u128,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Available tokens in scaled units: bytes × NANOS_PER_SEC.
    tokens_scaled: u128,
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
        let capacity_scaled = (burst as u128).saturating_mul(NANOS_PER_SEC);
        Self {
            inner: Arc::new(TokenBucketInner {
                rate_bps,
                burst,
                capacity_scaled,
                state: Mutex::new(State {
                    tokens_scaled: capacity_scaled,
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
        let rate = self.inner.rate_bps as u128;
        let cap = self.inner.capacity_scaled;
        let need_scaled = (n as u128).saturating_mul(NANOS_PER_SEC);

        let mut s = self.inner.state.lock();
        let now = Instant::now();
        let elapsed_nanos = now.duration_since(s.last).as_nanos();
        s.last = now;
        // Refill: tokens += elapsed_nanos * rate_bps (scaled units), cap at
        // capacity. Saturating math keeps long idle periods from overflowing.
        let refill = elapsed_nanos.saturating_mul(rate);
        s.tokens_scaled = s.tokens_scaled.saturating_add(refill).min(cap);

        if s.tokens_scaled >= need_scaled {
            s.tokens_scaled -= need_scaled;
            None
        } else {
            let deficit = need_scaled - s.tokens_scaled;
            // wait_nanos = floor(deficit / rate) + 1. The `+1` guarantees
            // the caller, on retry after `sleep(wait)`, will find enough
            // tokens — without it, integer-floor division can leave the
            // bucket still 1 scaled-unit short and produce a busy spin.
            // This is the precise edge case the previous f64-based path
            // could hit (f64 underestimates wait by <1 ULP). rate is
            // non-zero by virtue of `is_active()` above.
            let wait_nanos = deficit / rate + 1;
            // u128 -> u64 saturate: anything beyond u64::MAX nanos
            // (~584 years) is clamped — Duration::from_nanos takes u64.
            let wait_nanos = u64::try_from(wait_nanos).unwrap_or(u64::MAX);
            Some(Duration::from_nanos(wait_nanos))
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

    /// Reference token bucket implemented in pure `f64` (the pre-rewrite
    /// behavior). Used by `prop_u128_matches_f64_reference` to assert the
    /// new integer-nanos implementation agrees on accept/reject within a
    /// 1-byte tolerance across 1000 random `(elapsed_nanos, drain_bytes)`
    /// sequences.
    struct RefBucketF64 {
        rate_bps: u64,
        burst: u64,
        tokens: f64,
    }

    impl RefBucketF64 {
        fn new(rate_bps: u64, burst: u64) -> Self {
            let burst = burst.max(rate_bps.max(1));
            Self {
                rate_bps,
                burst,
                tokens: burst as f64,
            }
        }

        /// Pure step: advance by `elapsed_nanos` and attempt to drain `n`.
        /// Returns `true` on accept, `false` on reject (mirrors the
        /// `Option<Duration>::is_none()` semantics of `try_acquire`).
        fn step(&mut self, elapsed_nanos: u128, n: u64) -> bool {
            if self.rate_bps == 0 {
                return true;
            }
            let elapsed_secs = (elapsed_nanos as f64) / 1.0e9;
            self.tokens = (self.tokens + elapsed_secs * self.rate_bps as f64)
                .min(self.burst as f64);
            let need = n as f64;
            if self.tokens >= need {
                self.tokens -= need;
                true
            } else {
                false
            }
        }
    }

    /// Drive the new u128 path manually so we can inject a controlled
    /// elapsed-nanos value (mirrors `try_acquire` but uses an externally
    /// supplied "now offset" instead of `Instant::now()`). Returns
    /// `Some(())` on accept, `None` on reject — matches reference semantics.
    fn step_u128(
        rate_bps: u64,
        capacity_scaled: u128,
        tokens_scaled: &mut u128,
        elapsed_nanos: u128,
        n: u64,
    ) -> bool {
        if rate_bps == 0 {
            return true;
        }
        let rate = rate_bps as u128;
        let need_scaled = (n as u128).saturating_mul(NANOS_PER_SEC);
        let refill = elapsed_nanos.saturating_mul(rate);
        *tokens_scaled = tokens_scaled.saturating_add(refill).min(capacity_scaled);
        if *tokens_scaled >= need_scaled {
            *tokens_scaled -= need_scaled;
            true
        } else {
            false
        }
    }

    #[test]
    fn prop_u128_matches_f64_reference() {
        // Deterministic LCG keeps the test reproducible without a new
        // dev-dep. Constants from Numerical Recipes.
        let mut rng: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let mut next = || {
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            rng
        };

        // Realistic-ish bucket: 1 MiB/s, 4 MiB burst.
        let rate_bps: u64 = 1024 * 1024;
        let burst: u64 = 4 * 1024 * 1024;
        let capacity_scaled = (burst as u128).saturating_mul(NANOS_PER_SEC);

        let mut tokens_scaled: u128 = capacity_scaled;
        let mut reference = RefBucketF64::new(rate_bps, burst);
        // Re-sync reference to capacity (mirror initial state).
        reference.tokens = burst as f64;

        let mut disagreements = 0u32;
        let mut net_drift_bytes: i128 = 0;

        for _ in 0..1000 {
            // Elapsed in the range [0, 100ms) nanos. Wide enough to exercise
            // refill saturation against capacity occasionally.
            let elapsed_nanos = (next() % 100_000_000) as u128;
            // Drain size in the range [1, 2 * burst). > burst triggers reject.
            let n = (next() % (2 * burst)) + 1;

            let got = step_u128(rate_bps, capacity_scaled, &mut tokens_scaled, elapsed_nanos, n);
            let want = reference.step(elapsed_nanos, n);

            if got != want {
                // Tolerance: only count it as a disagreement if the f64
                // reference is within 1 byte of the u128 decision point.
                // That is: |ref.tokens - need| <= 1 byte (in real bytes).
                let need = n as f64;
                let diff = (reference.tokens - need).abs();
                if diff > 1.0 {
                    disagreements += 1;
                }
                // Re-sync the f64 tokens to the u128 view (in bytes) so a
                // single rounding glitch doesn't snowball through 1000 iter.
                reference.tokens = (tokens_scaled / NANOS_PER_SEC) as f64;
                // Track net drift (signed) to assert global behavior.
                net_drift_bytes += if got { 0 } else { n as i128 };
            }
        }

        assert_eq!(
            disagreements, 0,
            "u128 and f64 reference disagreed on accept/reject outside the 1-byte tolerance band; net drift = {net_drift_bytes} bytes"
        );
    }

    #[test]
    fn invariant_cumulative_consumption_under_rate_plus_burst() {
        // Drive the real bucket with `try_acquire` (zero-wait acquires only)
        // and assert: consumed_bytes <= rate_bps * elapsed + burst at all times.
        // This is the bucket invariant; the u128 rewrite must preserve it.
        let rate_bps: u64 = 4096;
        let burst: u64 = 4096;
        let b = TokenBucket::new(rate_bps, burst);
        let mut rng: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = || {
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            rng
        };

        let start = std::time::Instant::now();
        let mut consumed: u128 = 0;
        for _ in 0..1000 {
            let n = (next() % 512) + 1;
            if b.try_acquire(n).is_none() {
                consumed += n as u128;
            }
            let elapsed_nanos = start.elapsed().as_nanos();
            // Allowed = rate * elapsed_secs + burst, computed in scaled units
            // to avoid f64.
            let allowed = elapsed_nanos
                .saturating_mul(rate_bps as u128)
                / NANOS_PER_SEC
                + burst as u128;
            assert!(
                consumed <= allowed,
                "consumed {consumed} > allowed {allowed} after {elapsed_nanos}ns"
            );
        }
    }
}
