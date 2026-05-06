//! Instability detection trait + a simple default implementation.
//!
//! `spt-supervisor` consumes the [`InstabilityDetector`] trait so it doesn't
//! pull in the implementation directly — this avoids the otherwise-circular
//! dep between the supervisor and the stats crate.

use std::sync::Arc;
use std::time::Duration;

use crate::clock::{Clock, SystemClock};
use crate::counters::RollingCounter;

/// Verdict reported by [`InstabilityDetector::evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstabilityVerdict {
    /// Within configured thresholds.
    Stable,
    /// Threshold breached; supervisor SHOULD apply backoff/penalty.
    Unstable {
        /// Reconnects observed in window.
        reconnects: u64,
        /// Errors observed in window.
        errors: u64,
    },
}

/// Trait the supervisor consumes; implementations decide what "unstable" means.
pub trait InstabilityDetector: Send + Sync {
    /// Record one reconnect event (e.g. transport drop + retry).
    fn record_reconnect(&self);
    /// Record one error event.
    fn record_error(&self);
    /// Evaluate the current state.
    fn evaluate(&self) -> InstabilityVerdict;
}

/// Threshold-based detector backed by two rolling counters.
pub struct ThresholdInstability {
    reconnects: RollingCounter,
    errors: RollingCounter,
    /// Maximum reconnects in window before flagging as unstable.
    max_reconnects: u64,
    /// Maximum errors in window before flagging as unstable.
    max_errors: u64,
}

impl ThresholdInstability {
    /// Create a detector with `window`, divided into `buckets`.
    ///
    /// # Panics
    /// Panics if `buckets == 0` or `window` is zero.
    #[must_use]
    pub fn new(window: Duration, buckets: u32, max_reconnects: u64, max_errors: u64) -> Self {
        Self::with_clock(
            window,
            buckets,
            max_reconnects,
            max_errors,
            Arc::new(SystemClock),
        )
    }

    /// Create a detector with an injected clock.
    ///
    /// # Panics
    /// Panics if `buckets == 0` or `window` is zero.
    #[must_use]
    pub fn with_clock(
        window: Duration,
        buckets: u32,
        max_reconnects: u64,
        max_errors: u64,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            reconnects: RollingCounter::with_clock(window, buckets, clock.clone()),
            errors: RollingCounter::with_clock(window, buckets, clock),
            max_reconnects,
            max_errors,
        }
    }
}

impl InstabilityDetector for ThresholdInstability {
    fn record_reconnect(&self) {
        self.reconnects.tick();
    }

    fn record_error(&self) {
        self.errors.tick();
    }

    fn evaluate(&self) -> InstabilityVerdict {
        let r = self.reconnects.sum_over_window();
        let e = self.errors.sum_over_window();
        if r > self.max_reconnects || e > self.max_errors {
            InstabilityVerdict::Unstable {
                reconnects: r,
                errors: e,
            }
        } else {
            InstabilityVerdict::Stable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    #[test]
    fn stable_until_threshold_crossed() {
        let clock = Arc::new(TestClock::at_now());
        let d = ThresholdInstability::with_clock(Duration::from_secs(60), 6, 3, 5, clock.clone());
        for _ in 0..3 {
            d.record_reconnect();
        }
        assert!(matches!(d.evaluate(), InstabilityVerdict::Stable));
        d.record_reconnect();
        assert!(matches!(
            d.evaluate(),
            InstabilityVerdict::Unstable { reconnects: 4, .. }
        ));
    }

    #[test]
    fn instability_recovers_after_window() {
        let clock = Arc::new(TestClock::at_now());
        let d = ThresholdInstability::with_clock(Duration::from_secs(10), 10, 1, 100, clock.clone());
        d.record_reconnect();
        d.record_reconnect();
        assert!(matches!(d.evaluate(), InstabilityVerdict::Unstable { .. }));
        clock.advance(Duration::from_secs(11));
        assert!(matches!(d.evaluate(), InstabilityVerdict::Stable));
    }
}
