//! Reconnect backoff per spec §11.2.
//!
//! Algorithm: **full-jitter exponential backoff**:
//!
//! ```text
//! delay_n = uniform(0, min(max_delay, initial_delay * 2^n))
//! ```
//!
//! After a stable connection holds for `reset_after`, the attempt counter is
//! reset to zero on the next failure.

use std::time::Duration;

use rand::Rng;

/// Backoff configuration. Mirrors `[profiles.reconnect]`.
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    /// First retry delay (ceiling).
    pub initial_delay: Duration,
    /// Cap on the exponentially-increasing delay.
    pub max_delay: Duration,
    /// Reset attempt counter after this much continuous uptime.
    pub reset_after: Duration,
    /// Jitter ratio (informational; full-jitter implementation always
    /// samples in `[0, ceiling)` regardless of this value).
    pub jitter: f32,
    /// Maximum attempts (`0` = unlimited).
    pub max_attempts: u32,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            reset_after: Duration::from_secs(120),
            jitter: 1.0,
            max_attempts: 0,
        }
    }
}

/// Stateful backoff calculator.
#[derive(Debug, Clone)]
pub struct Backoff {
    cfg: BackoffConfig,
    attempt: u32,
}

impl Backoff {
    /// New backoff at attempt 0.
    #[must_use]
    pub fn new(cfg: BackoffConfig) -> Self {
        Self { cfg, attempt: 0 }
    }

    /// Current attempt count (number of failures so far).
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Whether further attempts are allowed under `max_attempts`.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.cfg.max_attempts != 0 && self.attempt >= self.cfg.max_attempts
    }

    /// Reset attempt counter (call on stable uptime).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Compute the next-attempt delay and bump the attempt counter.
    ///
    /// `rng` is taken explicitly so tests are deterministic.
    pub fn next_delay<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Duration {
        let n = self.attempt;
        self.attempt = self.attempt.saturating_add(1);
        ceiling_for_attempt(self.cfg.initial_delay, self.cfg.max_delay, n)
            .map(|c| sample_jitter(c, rng))
            .unwrap_or(Duration::ZERO)
    }

    /// Compute the next-attempt delay using thread-local rng.
    pub fn next_delay_default(&mut self) -> Duration {
        let mut r = rand::thread_rng();
        self.next_delay(&mut r)
    }
}

fn ceiling_for_attempt(initial: Duration, max: Duration, n: u32) -> Option<Duration> {
    let initial_ms = initial.as_millis() as u64;
    let max_ms = max.as_millis() as u64;
    if initial_ms == 0 {
        return Some(Duration::ZERO);
    }
    let factor: u64 = 1_u64.checked_shl(n.min(31))?;
    let ceiling_ms = initial_ms
        .saturating_mul(factor)
        .min(max_ms.max(initial_ms));
    Some(Duration::from_millis(ceiling_ms))
}

fn sample_jitter<R: Rng + ?Sized>(ceiling: Duration, rng: &mut R) -> Duration {
    let max_ms = ceiling.as_millis() as u64;
    if max_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rng.gen_range(0..=max_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn ceiling_doubles_until_cap() {
        let init = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        let cs: Vec<u64> = (0..10)
            .map(|n| ceiling_for_attempt(init, max, n).unwrap().as_secs())
            .collect();
        // 1, 2, 4, 8, 16, 32, then capped at 60.
        assert_eq!(cs[0], 1);
        assert_eq!(cs[1], 2);
        assert_eq!(cs[5], 32);
        assert!(cs.iter().skip(6).all(|&v| v == 60));
    }

    #[test]
    fn full_jitter_within_ceiling() {
        let mut rng = StdRng::seed_from_u64(42);
        let mut b = Backoff::new(BackoffConfig {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(8),
            ..Default::default()
        });
        for n in 0..20 {
            let d = b.next_delay(&mut rng);
            let cap =
                ceiling_for_attempt(Duration::from_secs(1), Duration::from_secs(8), n).unwrap();
            assert!(d <= cap, "attempt {n}: {d:?} > ceiling {cap:?}");
        }
    }

    #[test]
    fn reset_clears_attempt_counter() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut b = Backoff::new(BackoffConfig::default());
        for _ in 0..5 {
            let _ = b.next_delay(&mut rng);
        }
        assert_eq!(b.attempt(), 5);
        b.reset();
        assert_eq!(b.attempt(), 0);
    }

    #[test]
    fn max_attempts_exhausts() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut b = Backoff::new(BackoffConfig {
            max_attempts: 3,
            ..Default::default()
        });
        for _ in 0..3 {
            assert!(!b.exhausted());
            let _ = b.next_delay(&mut rng);
        }
        assert!(b.exhausted());
    }

    #[test]
    fn unlimited_max_attempts_never_exhausts() {
        let b = Backoff::new(BackoffConfig {
            max_attempts: 0,
            ..Default::default()
        });
        assert!(!b.exhausted());
    }
}
