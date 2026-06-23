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
    /// Optional secondary trip condition: consecutive keepalive misses.
    ///
    /// Mirrors `[profiles.instability].max_keepalive_misses`. `None` (default)
    /// disables this condition — only disconnect *count* trips the detector, so
    /// `None` preserves current behavior.
    ///
    /// CONSUMER: the health-probe feeder in
    /// `profile.rs::ProfileTask::run_active` calls
    /// [`InstabilityDetector::record_probe`] on every probe; a failed probe
    /// (`rtt == None`) increments a consecutive-miss counter and trips the
    /// detector when the count reaches this threshold. A successful probe resets
    /// the counter.
    pub max_keepalive_misses: Option<u32>,
    /// Optional secondary trip condition: p95 latency ceiling.
    ///
    /// Mirrors `[profiles.instability].max_latency_p95`. `None` (default)
    /// disables this condition.
    ///
    /// CONSUMER: the health-probe feeder in `profile.rs::ProfileTask::run_active`
    /// captures a coarse round-trip-time sample around each *successful* probe
    /// (`Instant::now()` before/after `session.keepalive()` /
    /// `preflight_connect()` / `probe_tcp_connect`) and feeds it via
    /// [`InstabilityDetector::record_probe`]. The detector keeps a bounded
    /// rolling window (the last [`LATENCY_WINDOW`] samples), computes p95, and
    /// trips when the rolling p95 exceeds this duration. The RTT is COARSE: it
    /// includes tokio scheduler jitter and the timeout-future wrapping overhead,
    /// so it is a relative health signal, not a precise network measurement.
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

/// Number of most-recent round-trip-time samples retained by the rolling
/// latency estimator. A small bounded window keeps the per-probe sort cheap and
/// makes the p95 reflect *recent* link behavior rather than the whole session.
pub const LATENCY_WINDOW: usize = 64;

/// Bounded rolling latency estimator.
///
/// Keeps the last [`LATENCY_WINDOW`] round-trip-time samples in insertion order
/// and computes the p95 by sorting a copy on demand. The sorted-window approach
/// is O(N log N) per query over a tiny fixed N (64), which is deterministic and
/// trivial to reason about — preferred here over a streaming P² estimator.
#[derive(Debug, Clone, Default)]
struct LatencyEstimator {
    samples: VecDeque<Duration>,
}

impl LatencyEstimator {
    /// Record one RTT sample, evicting the oldest if the window is full.
    fn record(&mut self, rtt: Duration) {
        if self.samples.len() == LATENCY_WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(rtt);
    }

    /// Current p95 over the rolling window, or `None` if no samples yet.
    ///
    /// Uses the nearest-rank method: index `ceil(0.95 * n) - 1` into the sorted
    /// samples (clamped to the last element). For small windows this is the
    /// pragmatic, fully-deterministic choice.
    fn p95(&self) -> Option<Duration> {
        let n = self.samples.len();
        if n == 0 {
            return None;
        }
        let mut sorted: Vec<Duration> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        // Nearest-rank: smallest index whose sample is >= 95% of the data.
        let rank = ((0.95_f64 * n as f64).ceil() as usize).max(1);
        let idx = rank.min(n) - 1;
        Some(sorted[idx])
    }
}

/// Sliding-window detector.
#[derive(Debug, Clone)]
pub struct InstabilityDetector {
    cfg: InstabilityWindow,
    events: VecDeque<Instant>,
    triggered: bool,
    last_clean: Option<Instant>,
    /// Rolling RTT estimator feeding the `max_latency_p95` trip condition.
    latency: LatencyEstimator,
    /// Consecutive failed-probe count feeding the `max_keepalive_misses` trip
    /// condition. Reset to 0 on any successful probe.
    consecutive_misses: u32,
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
            latency: LatencyEstimator::default(),
            consecutive_misses: 0,
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

    /// Record the outcome of one health probe.
    ///
    /// `rtt` carries the coarse round-trip-time of a *successful* probe
    /// (captured as `Instant::now()` before/after the probe future at the
    /// `profile.rs` health-probe site); `None` signals a FAILED/timed-out probe
    /// (a "keepalive miss").
    ///
    /// Feeds the two secondary trip conditions:
    /// * `max_latency_p95` — a successful probe pushes its RTT into the rolling
    ///   window; if the configured ceiling is `Some` and the rolling p95 now
    ///   exceeds it, the detector trips.
    /// * `max_keepalive_misses` — a failed probe increments the consecutive-miss
    ///   counter; if the configured threshold is `Some` and the counter reaches
    ///   it, the detector trips. A successful probe resets the counter to 0.
    ///
    /// Returns `true` if this call NEWLY tripped the detector. When the detector
    /// is disabled (`enabled == false`) this is an inert no-op that never trips
    /// and records nothing — mirroring [`Self::record_disconnect`]. With both
    /// thresholds `None` (the default) no probe outcome can trip, preserving
    /// today's behavior.
    pub fn record_probe(&mut self, rtt: Option<Duration>) -> bool {
        if !self.cfg.enabled {
            return false;
        }
        let mut newly = false;
        match rtt {
            Some(sample) => {
                // Successful probe: reset the miss streak, fold the RTT into the
                // rolling p95 window, and check the latency ceiling.
                self.consecutive_misses = 0;
                self.latency.record(sample);
                if let Some(ceiling) = self.cfg.max_latency_p95 {
                    if let Some(p95) = self.latency.p95() {
                        if p95 > ceiling && !self.triggered {
                            self.triggered = true;
                            newly = true;
                        }
                    }
                }
            }
            None => {
                // Failed/timed-out probe: count it against the consecutive-miss
                // ceiling.
                self.consecutive_misses = self.consecutive_misses.saturating_add(1);
                if let Some(threshold) = self.cfg.max_keepalive_misses {
                    if threshold > 0 && self.consecutive_misses >= threshold && !self.triggered {
                        self.triggered = true;
                        newly = true;
                    }
                }
            }
        }
        newly
    }

    /// Current rolling p95 latency, if any samples have been recorded. Exposed
    /// for diagnostics/tests.
    #[must_use]
    pub fn latency_p95(&self) -> Option<Duration> {
        self.latency.p95()
    }

    /// Current consecutive failed-probe count. Exposed for diagnostics/tests.
    #[must_use]
    pub fn consecutive_misses(&self) -> u32 {
        self.consecutive_misses
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
            // Start the secondary trip conditions fresh once health is restored
            // so a stale latency window / miss streak can't immediately re-trip.
            self.latency = LatencyEstimator::default();
            self.consecutive_misses = 0;
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

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn p95_estimator_nearest_rank() {
        // 100 samples 1..=100 ms → p95 (nearest-rank, ceil(0.95*100)=95th value).
        let mut est = LatencyEstimator::default();
        // Window holds only the last LATENCY_WINDOW=64; feed exactly 64 known
        // samples 1..=64 so the math is fully deterministic.
        for v in 1..=64u64 {
            est.record(ms(v));
        }
        // ceil(0.95 * 64) = ceil(60.8) = 61 → index 60 (0-based) → value 61ms.
        assert_eq!(est.p95(), Some(ms(61)));
        assert_eq!(est.samples.len(), LATENCY_WINDOW);
    }

    #[test]
    fn p95_estimator_evicts_oldest() {
        let mut est = LatencyEstimator::default();
        // Overflow the window: feed 1..=128. Only the last 64 (65..=128) remain.
        for v in 1..=128u64 {
            est.record(ms(v));
        }
        assert_eq!(est.samples.len(), LATENCY_WINDOW);
        // Smallest retained sample is 65ms (older ones evicted).
        assert_eq!(est.samples.iter().copied().min(), Some(ms(65)));
        // p95 over 65..=128: ceil(0.95*64)=61 → 61st of sorted 65..=128 = 125ms.
        assert_eq!(est.p95(), Some(ms(125)));
    }

    #[test]
    fn p95_estimator_empty_is_none() {
        let est = LatencyEstimator::default();
        assert_eq!(est.p95(), None);
    }

    #[test]
    fn latency_p95_trips_at_threshold() {
        // Ceiling 100ms. Below-ceiling samples must NOT trip; an above-ceiling
        // p95 must trip exactly once.
        let mut d = InstabilityDetector::new(InstabilityWindow {
            max_latency_p95: Some(ms(100)),
            ..Default::default()
        });
        // Feed 64 samples all at 50ms → p95 = 50ms < 100ms → no trip.
        for _ in 0..LATENCY_WINDOW {
            assert!(!d.record_probe(Some(ms(50))));
        }
        assert!(!d.is_unstable());
        assert_eq!(d.latency_p95(), Some(ms(50)));

        // Now flood with 200ms samples; once enough of the window is high the
        // p95 crosses 100ms and the detector newly trips. Track that exactly one
        // call reports the new trip.
        let mut newly_count = 0;
        for _ in 0..LATENCY_WINDOW {
            if d.record_probe(Some(ms(200))) {
                newly_count += 1;
            }
        }
        assert_eq!(newly_count, 1, "latency trip fires exactly once");
        assert!(d.is_unstable());
    }

    #[test]
    fn latency_p95_none_never_trips() {
        // Default max_latency_p95 = None → no latency trip regardless of RTT.
        let mut d = InstabilityDetector::new(InstabilityWindow::default());
        for _ in 0..LATENCY_WINDOW {
            assert!(!d.record_probe(Some(ms(10_000))));
        }
        assert!(!d.is_unstable());
    }

    #[test]
    fn keepalive_misses_trip_at_threshold_and_reset_on_success() {
        // Trip after 3 consecutive misses.
        let mut d = InstabilityDetector::new(InstabilityWindow {
            max_keepalive_misses: Some(3),
            ..Default::default()
        });
        assert!(!d.record_probe(None)); // 1
        assert!(!d.record_probe(None)); // 2
        assert_eq!(d.consecutive_misses(), 2);
        // A success resets the streak before we reach the threshold.
        assert!(!d.record_probe(Some(ms(5))));
        assert_eq!(d.consecutive_misses(), 0);
        assert!(!d.is_unstable());

        // Three fresh consecutive misses now trip, exactly once.
        assert!(!d.record_probe(None)); // 1
        assert!(!d.record_probe(None)); // 2
        assert!(d.record_probe(None)); // 3 → trip
        assert!(d.is_unstable());
        assert_eq!(d.consecutive_misses(), 3);
        // Further misses do not re-report a new trip.
        assert!(!d.record_probe(None));
    }

    #[test]
    fn keepalive_misses_none_never_trips() {
        // Default max_keepalive_misses = None → misses accrue but never trip.
        let mut d = InstabilityDetector::new(InstabilityWindow::default());
        for _ in 0..50 {
            assert!(!d.record_probe(None));
        }
        assert!(!d.is_unstable());
        assert_eq!(d.consecutive_misses(), 50);
    }

    #[test]
    fn disabled_detector_ignores_probes() {
        let mut d = InstabilityDetector::new(InstabilityWindow {
            enabled: false,
            max_keepalive_misses: Some(1),
            max_latency_p95: Some(ms(1)),
            ..Default::default()
        });
        assert!(!d.record_probe(None));
        assert!(!d.record_probe(Some(ms(10_000))));
        assert!(!d.is_unstable());
        assert_eq!(d.consecutive_misses(), 0);
        assert_eq!(d.latency_p95(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn tick_healthy_clears_secondary_state() {
        // After a keepalive-miss trip, sustained health clears the flag AND
        // resets the miss streak / latency window.
        let mut d = InstabilityDetector::new(InstabilityWindow {
            max_keepalive_misses: Some(1),
            clear_after: Duration::from_secs(30),
            ..Default::default()
        });
        assert!(d.record_probe(None)); // trips immediately (threshold 1)
        assert!(d.is_unstable());
        let t0 = Instant::now();
        d.tick_healthy(t0); // start clean window
        let cleared = d.tick_healthy(t0 + Duration::from_secs(40));
        assert!(cleared);
        assert!(!d.is_unstable());
        assert_eq!(d.consecutive_misses(), 0);
        assert_eq!(d.latency_p95(), None);
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
