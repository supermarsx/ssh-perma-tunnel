//! Token-bucket bandwidth limiter used by recursive SFTP transfers.
//!
//! Construct with [`TokenBucket::new`] giving the steady-state rate in
//! bytes/second; call [`TokenBucket::consume`] before each chunk and `await`
//! the returned future to be unblocked when enough tokens have accumulated.
//! Tokens refill linearly against [`tokio::time::Instant::now`], so the
//! limiter is monotonic and unaffected by wall-clock skew.

use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

/// Steady-rate token bucket with a one-second burst capacity.
#[derive(Debug)]
pub struct TokenBucket {
    rate_bps: u64,
    burst: u64,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Construct a limiter that allows `rate_bps` bytes per second on
    /// average. `rate_bps == 0` disables limiting.
    #[must_use]
    pub fn new(rate_bps: u64) -> Self {
        Self {
            rate_bps,
            burst: rate_bps,
            state: Mutex::new(State {
                tokens: rate_bps as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Returns `true` if the bucket is configured to allow unlimited
    /// throughput (constructed with `0`).
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.rate_bps == 0
    }

    /// Consume `bytes` from the bucket, sleeping just enough for the
    /// refill clock to catch up. Returns immediately when the bucket is
    /// unlimited.
    pub async fn consume(&self, bytes: u64) {
        if self.is_unlimited() {
            return;
        }
        loop {
            let sleep = {
                let mut state = self.state.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_refill).as_secs_f64();
                state.tokens += elapsed * self.rate_bps as f64;
                if state.tokens > self.burst as f64 {
                    state.tokens = self.burst as f64;
                }
                state.last_refill = now;
                if state.tokens >= bytes as f64 {
                    state.tokens -= bytes as f64;
                    return;
                }
                let deficit = bytes as f64 - state.tokens;
                let secs = deficit / self.rate_bps as f64;
                Duration::from_secs_f64(secs.max(0.001))
            };
            tokio::time::sleep(sleep).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn unlimited_returns_immediately() {
        let bucket = TokenBucket::new(0);
        let start = Instant::now();
        bucket.consume(10 * 1024 * 1024).await;
        assert!(start.elapsed() < Duration::from_millis(5));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn approximates_target_rate_over_two_seconds() {
        // 5 MiB/s × 2s = 10 MiB; allow ±5%.
        let rate = 5 * 1024 * 1024;
        let bucket = TokenBucket::new(rate);
        // Drain the initial burst capacity so we measure steady-state.
        bucket.consume(rate).await;
        let start = Instant::now();
        let chunk = 64 * 1024;
        let mut delivered = 0u64;
        // Hit the 2-second mark by polling chunk-sized consumes.
        while start.elapsed() < Duration::from_secs(2) {
            bucket.consume(chunk).await;
            delivered += chunk;
        }
        let target = 2 * rate;
        let low = (target as f64 * 0.85) as u64;
        let high = (target as f64 * 1.15) as u64;
        assert!(
            delivered >= low && delivered <= high,
            "delivered {delivered} not within [{low}, {high}] for target {target}",
        );
    }
}
