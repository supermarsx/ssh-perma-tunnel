//! Sliding-window instability detector.
//!
//! Per spec §11.4: count disconnect events within a sliding `window`. When
//! more than `max_disconnects` happen inside the window, the profile is
//! considered *unstable* — the supervisor moves it to the `Unstable` state and
//! escalates backoff. Once a configurable healthy uptime is observed without
//! further events, the flag is cleared.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

/// Configuration for [`InstabilityDetector`].
#[derive(Debug, Clone, Copy)]
pub struct InstabilityWindow {
    /// Duration over which disconnects are counted.
    pub window: Duration,
    /// Threshold — strictly more than this many events triggers instability.
    pub max_disconnects: u32,
    /// Continuous healthy time required before the unstable flag is cleared.
    pub clear_after: Duration,
}

impl Default for InstabilityWindow {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            max_disconnects: 3,
            clear_after: Duration::from_secs(120),
        }
    }
}

/// Sliding-window detector.
#[derive(Debug, Clone)]
pub struct InstabilityDetector {
    cfg: InstabilityWindow,
    events: VecDeque<Instant>,
    triggered: bool,
    last_clean: Option<Instant>,
}

impl InstabilityDetector {
    /// New detector.
    #[must_use]
    pub fn new(cfg: InstabilityWindow) -> Self {
        Self {
            cfg,
            events: VecDeque::new(),
            triggered: false,
            last_clean: None,
        }
    }

    /// Whether the detector currently considers the profile unstable.
    #[must_use]
    pub fn is_unstable(&self) -> bool {
        self.triggered
    }

    /// Record a disconnect at `now`.
    ///
    /// Returns `true` if the recording newly triggered instability.
    pub fn record_disconnect(&mut self, now: Instant) -> bool {
        let cutoff = now.checked_sub(self.cfg.window).unwrap_or(now);
        while self
            .events
            .front()
            .copied()
            .map(|t| t < cutoff)
            .unwrap_or(false)
        {
            self.events.pop_front();
        }
        self.events.push_back(now);
        self.last_clean = None;
        let count = self.events.len() as u32;
        let newly = !self.triggered && count > self.cfg.max_disconnects;
        if newly {
            self.triggered = true;
        }
        newly
    }

    /// Tick a heartbeat at `now` indicating the session is healthy. Clears
    /// the unstable flag once enough continuous health has accrued.
    ///
    /// Returns `true` if this call cleared the flag.
    pub fn tick_healthy(&mut self, now: Instant) -> bool {
        let started = match self.last_clean {
            Some(t) => t,
            None => {
                self.last_clean = Some(now);
                return false;
            }
        };
        if !self.triggered {
            return false;
        }
        if now.duration_since(started) >= self.cfg.clear_after {
            self.triggered = false;
            self.events.clear();
            true
        } else {
            false
        }
    }

    /// Number of events in the current window.
    pub fn count(&self) -> usize {
        self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn does_not_trigger_below_threshold() {
        let mut d = InstabilityDetector::new(InstabilityWindow {
            window: Duration::from_secs(60),
            max_disconnects: 3,
            clear_after: Duration::from_secs(60),
        });
        let now = Instant::now();
        for i in 0..3 {
            d.record_disconnect(now + Duration::from_secs(i));
        }
        assert!(!d.is_unstable());
    }

    #[tokio::test(start_paused = true)]
    async fn triggers_above_threshold() {
        let mut d = InstabilityDetector::new(InstabilityWindow {
            window: Duration::from_secs(60),
            max_disconnects: 3,
            clear_after: Duration::from_secs(60),
        });
        let now = Instant::now();
        for i in 0..4 {
            d.record_disconnect(now + Duration::from_secs(i));
        }
        assert!(d.is_unstable());
    }

    #[tokio::test(start_paused = true)]
    async fn old_events_age_out() {
        let mut d = InstabilityDetector::new(InstabilityWindow {
            window: Duration::from_secs(10),
            max_disconnects: 2,
            clear_after: Duration::from_secs(60),
        });
        let t0 = Instant::now();
        for i in 0..3 {
            d.record_disconnect(t0 + Duration::from_secs(i));
        }
        // Now jump past the window — only the last record should remain when we
        // record fresh events.
        let later = t0 + Duration::from_secs(60);
        d.record_disconnect(later);
        assert_eq!(d.count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn clear_after_continuous_health() {
        let mut d = InstabilityDetector::new(InstabilityWindow {
            window: Duration::from_secs(10),
            max_disconnects: 1,
            clear_after: Duration::from_secs(30),
        });
        let t0 = Instant::now();
        d.record_disconnect(t0);
        d.record_disconnect(t0 + Duration::from_secs(1));
        assert!(d.is_unstable());
        d.tick_healthy(t0 + Duration::from_secs(2)); // start clean window
        assert!(d.is_unstable());
        let cleared = d.tick_healthy(t0 + Duration::from_secs(40));
        assert!(cleared);
        assert!(!d.is_unstable());
    }
}
