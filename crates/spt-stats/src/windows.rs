//! Sliding-window aggregates: bytes/conns/errors over a configurable window.

use std::sync::Arc;
use std::time::Duration;

use crate::clock::{Clock, SystemClock};
use crate::counters::RollingCounter;

/// Aggregate sample exported from [`SlidingWindow::aggregates`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowAggregates {
    /// Bytes transferred in the window (in + out, caller's choice of direction).
    pub bytes: u64,
    /// Connections opened in the window.
    pub conns: u64,
    /// Errors observed in the window.
    pub errors: u64,
}

/// Three rolling counters sharing a window — bytes / connections / errors.
#[derive(Clone)]
pub struct SlidingWindow {
    bytes: RollingCounter,
    conns: RollingCounter,
    errors: RollingCounter,
}

impl SlidingWindow {
    /// New window of `window` width split into `buckets`. Uses real time.
    #[must_use]
    pub fn new(window: Duration, buckets: u32) -> Self {
        Self::with_clock(window, buckets, Arc::new(SystemClock))
    }

    /// New window with an injected clock.
    #[must_use]
    pub fn with_clock(window: Duration, buckets: u32, clock: Arc<dyn Clock>) -> Self {
        Self {
            bytes: RollingCounter::with_clock(window, buckets, clock.clone()),
            conns: RollingCounter::with_clock(window, buckets, clock.clone()),
            errors: RollingCounter::with_clock(window, buckets, clock),
        }
    }

    /// Record `n` bytes of throughput.
    pub fn add_bytes(&self, n: u64) {
        self.bytes.add(n);
    }

    /// Record an opened connection.
    pub fn record_conn(&self) {
        self.conns.tick();
    }

    /// Record an error.
    pub fn record_error(&self) {
        self.errors.tick();
    }

    /// Snapshot the three counters.
    #[must_use]
    pub fn aggregates(&self) -> WindowAggregates {
        WindowAggregates {
            bytes: self.bytes.sum_over_window(),
            conns: self.conns.sum_over_window(),
            errors: self.errors.sum_over_window(),
        }
    }

    /// Borrow the bytes counter (e.g. for direct queries).
    #[must_use]
    pub fn bytes_counter(&self) -> &RollingCounter {
        &self.bytes
    }

    /// Borrow the conns counter.
    #[must_use]
    pub fn conns_counter(&self) -> &RollingCounter {
        &self.conns
    }

    /// Borrow the errors counter.
    #[must_use]
    pub fn errors_counter(&self) -> &RollingCounter {
        &self.errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    #[test]
    fn aggregates_snapshot() {
        let clock = Arc::new(TestClock::at_now());
        let w = SlidingWindow::with_clock(Duration::from_secs(60), 6, clock);
        w.add_bytes(100);
        w.add_bytes(50);
        w.record_conn();
        w.record_conn();
        w.record_error();
        let a = w.aggregates();
        assert_eq!(a.bytes, 150);
        assert_eq!(a.conns, 2);
        assert_eq!(a.errors, 1);
    }

    #[test]
    fn aggregates_decay_with_window() {
        let clock = Arc::new(TestClock::at_now());
        let w = SlidingWindow::with_clock(Duration::from_secs(10), 10, clock.clone());
        w.add_bytes(1000);
        w.record_conn();
        clock.advance(Duration::from_secs(11));
        let a = w.aggregates();
        assert_eq!(a.bytes, 0);
        assert_eq!(a.conns, 0);
    }

    #[test]
    fn fresh_window_is_zero() {
        let clock = Arc::new(TestClock::at_now());
        let w = SlidingWindow::with_clock(Duration::from_secs(60), 6, clock);
        let a = w.aggregates();
        assert_eq!(a.bytes, 0);
        assert_eq!(a.conns, 0);
        assert_eq!(a.errors, 0);
        assert_eq!(a, WindowAggregates::default());
    }

    #[test]
    fn counter_borrows_expose_query_path() {
        let clock = Arc::new(TestClock::at_now());
        let w = SlidingWindow::with_clock(Duration::from_secs(60), 6, clock);
        w.add_bytes(7);
        w.record_conn();
        w.record_conn();
        w.record_error();
        assert_eq!(w.bytes_counter().sum_over_window(), 7);
        assert_eq!(w.conns_counter().sum_over_window(), 2);
        assert_eq!(w.errors_counter().sum_over_window(), 1);
    }

    #[test]
    fn window_clone_shares_underlying_counters() {
        let clock = Arc::new(TestClock::at_now());
        let w = SlidingWindow::with_clock(Duration::from_secs(60), 6, clock);
        let w2 = w.clone();
        w.add_bytes(50);
        assert_eq!(w2.aggregates().bytes, 50);
    }

    #[test]
    fn window_aggregates_debug_and_equal() {
        let a = WindowAggregates {
            bytes: 1,
            conns: 2,
            errors: 3,
        };
        let b = a;
        assert_eq!(a, b);
        let s = format!("{a:?}");
        assert!(s.contains("WindowAggregates"));
    }

    #[test]
    fn system_clock_constructor_smoke() {
        let w = SlidingWindow::new(Duration::from_secs(60), 6);
        w.add_bytes(123);
        assert_eq!(w.aggregates().bytes, 123);
    }
}
