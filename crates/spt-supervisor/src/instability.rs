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

/// Response action selected when the instability detector trips.
///
/// Mirrors `[profiles.instability].action`. The default
/// ([`InstabilityAction::MarkDegraded`]) reproduces today's *fixed* behavior:
/// on trip the supervisor moves the profile to the `Unstable`/degraded state
/// and escalates backoff — it does not currently *select* among alternative
/// responses.
///
/// CONSUMER (Wave C): `profile.rs::ProfileTask::handle_session_failure` (the
/// `self.instability.record_disconnect(...)` arm that fires
/// `ProfileEvent::InstabilityHit` / `SmEvent::InstabilityHit`) will branch on
/// `self.cfg.instability.action` to choose the response. `MarkDegraded` keeps
/// the current path; the other variants are wired there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstabilityAction {
    /// Move the profile to the degraded/`Unstable` state and escalate backoff
    /// (today's fixed behavior — the default).
    MarkDegraded,
    /// Trigger a failover to another endpoint.
    Failover,
    /// Increase the keepalive cadence to probe the link more aggressively.
    IncreaseKeepalive,
    /// Increase the reconnect backoff ceiling.
    IncreaseBackoff,
    /// Emit an instability event only (observe, do not change behavior).
    EmitEvent,
    /// Tear down and restart the current session immediately.
    RestartSession,
}

impl Default for InstabilityAction {
    fn default() -> Self {
        // Matches today's fixed behavior: trip → degraded + backoff escalation.
        Self::MarkDegraded
    }
}

/// Configuration for [`InstabilityDetector`].
#[derive(Debug, Clone, Copy)]
pub struct InstabilityWindow {
    /// Whether the detector is active. When `false`, [`InstabilityDetector`]
    /// never trips (see [`InstabilityDetector::record_disconnect`]). Mirrors
    /// `[profiles.instability].enabled`.
    ///
    /// Default `true`: today the detector is always wired whenever the
    /// instability config exists, so `true` preserves current behavior.
    pub enabled: bool,
    /// Duration over which disconnects are counted.
    pub window: Duration,
    /// Threshold — strictly more than this many events triggers instability.
    pub max_disconnects: u32,
    /// Continuous healthy time required before the unstable flag is cleared.
    pub clear_after: Duration,
    /// Optional secondary trip condition: keepalive misses within the window.
    ///
    /// Mirrors `[profiles.instability].max_keepalive_misses`. `None` (default)
    /// disables this condition — today only disconnect *count* trips the
    /// detector, so `None` preserves current behavior.
    ///
    /// CONSUMER (Wave C): a keepalive-miss feeder in
    /// `profile.rs::ProfileTask::run_active` (the keepalive `Err`/timeout arm)
    /// that accrues misses and trips the detector when the count exceeds this
    /// threshold.
    pub max_keepalive_misses: Option<u32>,
    /// Optional secondary trip condition: p95 latency ceiling.
    ///
    /// Mirrors `[profiles.instability].max_latency_p95`. `None` (default)
    /// disables this condition. NOTE: there is no latency sampling source in
    /// the supervisor today — Wave C must flag/provide a latency source before
    /// this can trip.
    ///
    /// CONSUMER (Wave C): a latency feeder (source TBD) in `profile.rs` that
    /// trips the detector when observed p95 exceeds this duration.
    pub max_latency_p95: Option<Duration>,
    /// Response action taken when the detector trips. See [`InstabilityAction`].
    ///
    /// Mirrors `[profiles.instability].action`. Default
    /// [`InstabilityAction::MarkDegraded`] = today's fixed behavior.
    pub action: InstabilityAction,
}

impl Default for InstabilityWindow {
    fn default() -> Self {
        Self {
            enabled: true,
            window: Duration::from_secs(60),
            max_disconnects: 3,
            clear_after: Duration::from_secs(120),
            max_keepalive_misses: None,
            max_latency_p95: None,
            action: InstabilityAction::default(),
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
    ///
    /// When the detector is disabled (`InstabilityWindow::enabled == false`)
    /// this is a no-op that never trips: no event is recorded and the unstable
    /// flag stays clear. This is the contained `enabled` gate (TW-A3); the
    /// other config knobs are consumed in Wave C.
    pub fn record_disconnect(&mut self, now: Instant) -> bool {
        if !self.cfg.enabled {
            return false;
        }
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

    #[test]
    fn defaults_preserve_current_behavior() {
        // TW-A3: new knobs default so today's behavior is unchanged.
        let w = InstabilityWindow::default();
        assert!(w.enabled, "detector is on by default");
        assert_eq!(w.max_keepalive_misses, None);
        assert_eq!(w.max_latency_p95, None);
        assert_eq!(w.action, InstabilityAction::MarkDegraded);
        assert_eq!(
            InstabilityAction::default(),
            InstabilityAction::MarkDegraded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_detector_never_trips() {
        // TW-A3: with enabled=false the detector is inert — even well above the
        // disconnect threshold it never trips and records nothing.
        let mut d = InstabilityDetector::new(InstabilityWindow {
            enabled: false,
            window: Duration::from_secs(60),
            max_disconnects: 1,
            clear_after: Duration::from_secs(60),
            ..Default::default()
        });
        let now = Instant::now();
        for i in 0..10 {
            let newly = d.record_disconnect(now + Duration::from_secs(i));
            assert!(!newly, "disabled detector must never newly-trip");
        }
        assert!(!d.is_unstable());
        assert_eq!(d.count(), 0, "disabled detector records no events");
    }

    #[tokio::test(start_paused = true)]
    async fn enabled_true_matches_legacy_trip() {
        // Sanity: the default enabled=true reproduces the pre-TW-A3 trip path.
        let mut d = InstabilityDetector::new(InstabilityWindow {
            max_disconnects: 3,
            ..Default::default()
        });
        let now = Instant::now();
        for i in 0..4 {
            d.record_disconnect(now + Duration::from_secs(i));
        }
        assert!(d.is_unstable());
    }
}
