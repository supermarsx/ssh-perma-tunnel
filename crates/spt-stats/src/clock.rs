//! Monotonic clock abstraction used across stats structures.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Source of monotonic instants. Tests substitute [`TestClock`] for
/// deterministic time.
pub trait Clock: Send + Sync + 'static {
    /// Current monotonic instant.
    fn now(&self) -> Instant;
}

/// Default real-time clock backed by `std::time::Instant`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Manually-advanced clock for tests.
#[derive(Debug, Clone)]
pub struct TestClock {
    inner: Arc<Mutex<Instant>>,
}

impl TestClock {
    /// Construct a clock anchored to `start`.
    #[must_use]
    pub fn new(start: Instant) -> Self {
        Self {
            inner: Arc::new(Mutex::new(start)),
        }
    }

    /// Construct a clock anchored to `Instant::now()`.
    #[must_use]
    pub fn at_now() -> Self {
        Self::new(Instant::now())
    }

    /// Advance the clock by `delta`.
    pub fn advance(&self, delta: Duration) {
        let mut t = self.inner.lock();
        *t += delta;
    }

    /// Set the clock to `t` (must be >= current value).
    pub fn set(&self, t: Instant) {
        let mut g = self.inner.lock();
        *g = t;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        *self.inner.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_advances() {
        let c = TestClock::at_now();
        let t0 = c.now();
        c.advance(Duration::from_secs(5));
        let t1 = c.now();
        assert!(t1 - t0 >= Duration::from_secs(5));
    }

    #[test]
    fn system_clock_monotonic() {
        let c = SystemClock;
        let a = c.now();
        let b = c.now();
        assert!(b >= a);
    }
}
