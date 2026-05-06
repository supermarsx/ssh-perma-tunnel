//! Exponentially-weighted moving average for throughput.
//!
//! `Ewma::sample(value, dt)` updates the average with `value` observed over
//! the elapsed `dt`. The smoothing factor is computed as
//! `alpha = 1 - exp(-dt / tau)` so that the EWMA's response to a step input
//! depends on real elapsed time, not call frequency.

use std::time::Duration;

use parking_lot::Mutex;

/// EWMA filter parameterized by a time constant.
#[derive(Debug)]
pub struct Ewma {
    inner: Mutex<EwmaInner>,
    tau_seconds: f64,
}

#[derive(Debug, Clone, Copy)]
struct EwmaInner {
    /// Current EWMA value, or `None` if no samples yet.
    value: Option<f64>,
}

impl Ewma {
    /// New EWMA with time-constant `tau`. Larger `tau` = slower response.
    ///
    /// # Panics
    /// Panics if `tau` is zero.
    #[must_use]
    pub fn new(tau: Duration) -> Self {
        assert!(!tau.is_zero(), "tau must be > 0");
        Self {
            inner: Mutex::new(EwmaInner { value: None }),
            tau_seconds: tau.as_secs_f64(),
        }
    }

    /// Feed a new sample observed over the elapsed `dt`.
    pub fn sample(&self, value: f64, dt: Duration) {
        let dts = dt.as_secs_f64().max(0.0);
        let alpha = if dts <= 0.0 {
            // No time elapsed; treat as no decay. First sample still primes.
            0.0
        } else {
            1.0 - (-dts / self.tau_seconds).exp()
        };
        let mut g = self.inner.lock();
        g.value = Some(match g.value {
            None => value,
            Some(prev) => prev + alpha * (value - prev),
        });
    }

    /// Current EWMA value, or `None` if no samples have been observed yet.
    #[must_use]
    pub fn value(&self) -> Option<f64> {
        self.inner.lock().value
    }

    /// Reset to the unprimed state.
    pub fn reset(&self) {
        self.inner.lock().value = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_primes_value() {
        let e = Ewma::new(Duration::from_secs(10));
        assert!(e.value().is_none());
        e.sample(100.0, Duration::from_secs(1));
        assert_eq!(e.value(), Some(100.0));
    }

    #[test]
    fn convergence_to_constant_input() {
        let e = Ewma::new(Duration::from_secs(1));
        e.sample(0.0, Duration::from_secs(1));
        for _ in 0..200 {
            e.sample(50.0, Duration::from_secs(1));
        }
        let v = e.value().unwrap();
        assert!((v - 50.0).abs() < 0.001, "v={v}");
    }

    #[test]
    fn longer_tau_responds_more_slowly() {
        let fast = Ewma::new(Duration::from_secs(1));
        let slow = Ewma::new(Duration::from_secs(60));
        fast.sample(0.0, Duration::from_secs(1));
        slow.sample(0.0, Duration::from_secs(1));
        for _ in 0..3 {
            fast.sample(100.0, Duration::from_secs(1));
            slow.sample(100.0, Duration::from_secs(1));
        }
        assert!(fast.value().unwrap() > slow.value().unwrap());
    }

    #[test]
    fn reset_clears_value() {
        let e = Ewma::new(Duration::from_secs(1));
        e.sample(7.0, Duration::from_secs(1));
        assert!(e.value().is_some());
        e.reset();
        assert!(e.value().is_none());
    }

    #[test]
    fn zero_dt_does_not_explode() {
        let e = Ewma::new(Duration::from_secs(1));
        e.sample(10.0, Duration::ZERO);
        assert_eq!(e.value(), Some(10.0));
        e.sample(20.0, Duration::ZERO);
        // Second zero-dt sample should not change value.
        assert_eq!(e.value(), Some(10.0));
    }
}
