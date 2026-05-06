//! Clock abstraction for testable time-driven components.
//!
//! Tasks that depend on wall-clock time (event-log rotation at midnight,
//! status-snapshot timestamps, ringed snapshot filenames) take a
//! [`Clock`] trait object so tests can inject a fake clock.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

/// A source of UTC wall-clock time.
pub trait Clock: Send + Sync + 'static {
    /// Current UTC instant.
    fn now(&self) -> DateTime<Utc>;
}

/// The real system clock — uses [`chrono::Utc::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A controllable clock for tests.
#[derive(Debug, Clone)]
pub struct TestClock {
    inner: Arc<Mutex<DateTime<Utc>>>,
}

impl TestClock {
    /// New test clock pinned at `start`.
    #[must_use]
    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(start)),
        }
    }

    /// Set the current time.
    pub fn set(&self, t: DateTime<Utc>) {
        *self.inner.lock().expect("test-clock mutex poisoned") = t;
    }

    /// Advance the clock by `delta`.
    pub fn advance(&self, delta: chrono::Duration) {
        let mut g = self.inner.lock().expect("test-clock mutex poisoned");
        *g += delta;
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.inner.lock().expect("test-clock mutex poisoned")
    }
}
