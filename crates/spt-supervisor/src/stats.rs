//! Live stats streaming for the [`crate::Orchestrator`].
//!
//! [`StatsTick`] is a periodic snapshot broadcast over a
//! [`tokio::sync::broadcast`] channel. Subscribers (the CLI's `stats live`
//! sub-command, MCP, etc.) consume the stream lock-free; the orchestrator
//! aggregates the per-profile / per-forward counters from its
//! [`crate::session::SessionRegistry`].

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use spt_core::ProfileId;
use spt_events::{Event, EventBus, Severity};
use spt_observability::metrics::StandardMetrics;
use spt_stats::Ewma;

use crate::session::SessionRow;
use crate::state_machine::ProfileStateName;

/// Per-profile slice inside a [`StatsTick`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProfileStats {
    /// Profile name.
    pub profile: String,
    /// Number of live sessions.
    pub sessions: u64,
    /// Open connection count across all forwards.
    pub conns_open: u64,
    /// Total bytes received.
    pub bytes_in: u64,
    /// Total bytes sent.
    pub bytes_out: u64,
    /// EWMA throughput (bytes/sec, in + out summed).
    pub throughput_bps_ewma: f64,
}

/// One tick of live stats.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct StatsTick {
    /// Wall-clock timestamp of the tick.
    pub at: DateTime<Utc>,
    /// Number of live sessions across every profile.
    pub total_sessions: u64,
    /// Open connection count across every forward.
    pub total_conns_open: u64,
    /// Total bytes received this run.
    pub total_bytes_in: u64,
    /// Total bytes sent this run.
    pub total_bytes_out: u64,
    /// Per-profile breakdown.
    pub profiles: Vec<ProfileStats>,
}

impl StatsTick {
    /// Aggregate `rows` into a tick.
    #[must_use]
    pub fn from_rows(rows: &[SessionRow]) -> Self {
        let mut by_profile: std::collections::BTreeMap<String, ProfileStats> =
            std::collections::BTreeMap::new();
        let mut total_sessions: u64 = 0;
        let mut total_conns_open: u64 = 0;
        let mut total_bytes_in: u64 = 0;
        let mut total_bytes_out: u64 = 0;
        for row in rows {
            total_sessions += 1;
            total_conns_open += row.conns_open;
            total_bytes_in += row.bytes_in;
            total_bytes_out += row.bytes_out;
            let entry = by_profile
                .entry(row.profile.clone())
                .or_insert_with(|| ProfileStats {
                    profile: row.profile.clone(),
                    ..Default::default()
                });
            entry.sessions += 1;
            entry.conns_open += row.conns_open;
            entry.bytes_in += row.bytes_in;
            entry.bytes_out += row.bytes_out;
        }
        Self {
            at: Utc::now(),
            total_sessions,
            total_conns_open,
            total_bytes_in,
            total_bytes_out,
            profiles: by_profile.into_values().collect(),
        }
    }
}

/// Configuration for the orchestrator stats-tick task.
#[derive(Debug, Clone)]
pub struct StatsTickConfig {
    /// How often to publish.
    pub interval: Duration,
    /// Broadcast channel capacity.
    pub channel_capacity: usize,
    /// EWMA half-life (seconds) for throughput.
    pub ewma_half_life_secs: f64,
}

impl Default for StatsTickConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            channel_capacity: 256,
            ewma_half_life_secs: 5.0,
        }
    }
}

/// Compute throughput EWMA between two ticks. `prev` and `cur` are total byte
/// counts; `dt` is the interval between samples. Returns the new EWMA value.
pub fn update_throughput_ewma(state: &Ewma, prev_bytes: u64, cur_bytes: u64, dt: Duration) -> f64 {
    let dt_secs = dt.as_secs_f64().max(1e-3);
    let delta = cur_bytes.saturating_sub(prev_bytes) as f64;
    let bps = delta / dt_secs;
    state.sample(bps, dt);
    state.value().unwrap_or(0.0)
}

// ---------------------------------------------------------------------------
// Observability seam (E6-F1 supervisor side + E1-F13 completion)
// ---------------------------------------------------------------------------

/// Optional observability sinks injected into a [`crate::ProfileSupervisor`] /
/// [`crate::Orchestrator`] by `p4-dispatch-wire` (the wiring lives in
/// `spt-bin`'s `cli_dispatch`). Both handles are **optional**: when `None`
/// every method is a no-op, so the non-wired path and existing tests keep
/// working unchanged.
///
/// * `event_bus` — every `ProfileEvent`-driving transition is re-emitted as a
///   canonical [`spt_events::Event`] so configured `[[events.bindings]]`/sinks
///   actually fire (closing the E6-F1 gap).
/// * `metrics` — the standard Prometheus counter/gauge handles. The supervisor
///   increments `reconnects` at the reconnect site and the orchestrator's stats
///   flush populates `bytes_in/out`, `forward_active`, and `profile_state`
///   from the now-populated [`SessionRegistry`] rows (closing E1-F13 / E6-F4).
///
/// Cheaply cloneable: `EventBus` is a broadcast sender clone, `StandardMetrics`
/// holds `prometheus` `*Vec` handles which are `Arc`-backed.
#[derive(Clone, Default)]
pub struct SupervisorObservers {
    /// Canonical event bus to re-emit transitions onto, if wired.
    pub event_bus: Option<EventBus>,
    /// Standard metric handles to increment, if wired.
    pub metrics: Option<StandardMetrics>,
}

impl std::fmt::Debug for SupervisorObservers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisorObservers")
            .field("event_bus", &self.event_bus.is_some())
            .field("metrics", &self.metrics.is_some())
            .finish()
    }
}

impl SupervisorObservers {
    /// Whether either sink is wired (used to skip work cheaply).
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.event_bus.is_none() && self.metrics.is_none()
    }

    /// Emit a canonical [`Event`] for a state transition. No-op when no bus is
    /// wired. The event carries enough context to alert on: the profile id, the
    /// from/to state names, and the bound endpoint (when known).
    pub fn emit_state_change(
        &self,
        profile: &str,
        from: ProfileStateName,
        to: ProfileStateName,
        endpoint: Option<&str>,
    ) {
        let Some(bus) = &self.event_bus else { return };
        let kind = state_change_kind(to);
        let mut b = Event::builder(kind, severity_for_state(to))
            .field("from", from.to_string())
            .field("to", to.to_string())
            .message(format!("profile `{profile}` {from} → {to}"));
        if let Some(pid) = make_profile_id(profile) {
            b = b.profile(pid);
        }
        if let Some(ep) = endpoint {
            b = b.field("endpoint", ep.to_owned());
        }
        bus.emit(b.build());
    }

    /// Emit a canonical event for a non-state-transition lifecycle signal
    /// (failover request, reconnect scheduled, instability, backoff exhausted).
    /// `kind` is the canonical event kind; extra context is attached via
    /// `fields`. No-op when no bus is wired.
    pub fn emit_lifecycle(
        &self,
        kind: &str,
        severity: Severity,
        profile: &str,
        message: impl Into<String>,
        fields: &[(&str, serde_json::Value)],
    ) {
        let Some(bus) = &self.event_bus else { return };
        let mut b = Event::builder(kind.to_owned(), severity).message(message.into());
        if let Some(pid) = make_profile_id(profile) {
            b = b.profile(pid);
        }
        for (k, v) in fields {
            b = b.field((*k).to_owned(), v.clone());
        }
        bus.emit(b.build());
    }

    /// Increment the `reconnects` counter for `profile`. No-op when no metrics
    /// handle is wired.
    pub fn inc_reconnect(&self, profile: &str) {
        if let Some(m) = &self.metrics {
            m.reconnects.with_label_values(&[profile]).inc();
        }
    }

    /// Set the `profile_state` gauge for `profile`. No-op when no metrics
    /// handle is wired.
    pub fn set_profile_state(&self, profile: &str, state: ProfileStateName) {
        if let Some(m) = &self.metrics {
            m.profile_state
                .with_label_values(&[profile])
                .set(profile_state_code(state));
        }
    }
}

/// Map a [`ProfileStateName`] to the canonical event kind emitted when the
/// profile *enters* it. Mirrors `docs/events.md` (`profile.connected`,
/// `profile.degraded`, `profile.reconnecting`, …).
#[must_use]
pub fn state_change_kind(to: ProfileStateName) -> &'static str {
    match to {
        ProfileStateName::Active => "profile.connected",
        ProfileStateName::Degraded => "profile.degraded",
        ProfileStateName::Reconnecting => "profile.reconnecting",
        ProfileStateName::FailingOver => "profile.failing_over",
        ProfileStateName::Unstable => "profile.unstable",
        ProfileStateName::Disabled => "profile.disabled",
        ProfileStateName::Stopped | ProfileStateName::Stopping => "profile.disconnected",
        ProfileStateName::Resolving => "profile.resolving",
        ProfileStateName::Connecting => "profile.connecting",
        ProfileStateName::Authenticating => "profile.authenticating",
        ProfileStateName::EstablishingForwards => "profile.establishing_forwards",
        ProfileStateName::Idle => "profile.idle",
    }
}

/// Severity assigned to a profile entering `to`. Alertable states (degraded,
/// reconnecting, failing over, unstable) are `Warn`; everything else `Info`.
#[must_use]
pub fn severity_for_state(to: ProfileStateName) -> Severity {
    match to {
        ProfileStateName::Degraded
        | ProfileStateName::Reconnecting
        | ProfileStateName::FailingOver
        | ProfileStateName::Unstable => Severity::Warn,
        _ => Severity::Info,
    }
}

/// Numeric code published to the `spt_profile_state` gauge. Stable mapping so
/// dashboards can alert on `spt_profile_state{profile=…} >= 7` etc.
#[must_use]
pub fn profile_state_code(state: ProfileStateName) -> i64 {
    match state {
        ProfileStateName::Disabled => 0,
        ProfileStateName::Idle => 1,
        ProfileStateName::Resolving => 2,
        ProfileStateName::Connecting => 3,
        ProfileStateName::Authenticating => 4,
        ProfileStateName::EstablishingForwards => 5,
        ProfileStateName::Active => 6,
        ProfileStateName::Degraded => 7,
        ProfileStateName::Reconnecting => 8,
        ProfileStateName::FailingOver => 9,
        ProfileStateName::Unstable => 10,
        ProfileStateName::Stopping => 11,
        ProfileStateName::Stopped => 12,
    }
}

/// Build a [`ProfileId`] from a profile name, tolerating the (rare) case where
/// a name is empty / contains control characters by dropping the typed id (the
/// event still carries the name in `fields`/`message`).
fn make_profile_id(profile: &str) -> Option<ProfileId> {
    ProfileId::new(profile.to_owned()).ok()
}

/// Apply one stats flush to the standard metrics: set the per-forward byte
/// counters and per-profile active-connection / state gauges from a freshly
/// computed [`StatsTick`]. Called from the orchestrator's stats-tick task once
/// per interval (E1-F13 / E6-F4). No-op when no metrics handle is wired.
///
/// Byte counters are monotonic, so we feed the *delta* since the previous flush
/// (`prev` keyed by profile) via `inc_by`; gauges are absolute `set`s. The
/// caller owns `prev` across ticks.
pub fn flush_metrics(
    metrics: Option<&StandardMetrics>,
    tick: &StatsTick,
    prev: &mut std::collections::BTreeMap<String, (u64, u64)>,
) {
    let Some(m) = metrics else { return };
    for ps in &tick.profiles {
        let (pin, pout) = prev.get(&ps.profile).copied().unwrap_or((0, 0));
        let din = ps.bytes_in.saturating_sub(pin);
        let dout = ps.bytes_out.saturating_sub(pout);
        if din > 0 {
            m.bytes_in.with_label_values(&[&ps.profile]).inc_by(din);
        }
        if dout > 0 {
            m.bytes_out.with_label_values(&[&ps.profile]).inc_by(dout);
        }
        m.forward_active
            .with_label_values(&[&ps.profile])
            .set(ps.conns_open as i64);
        prev.insert(ps.profile.clone(), (ps.bytes_in, ps.bytes_out));
    }
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    use spt_observability::metrics::MetricsExporter;

    fn standard() -> StandardMetrics {
        MetricsExporter::new().unwrap().standard().clone()
    }

    fn profile_stats(name: &str, bin: u64, bout: u64, conns: u64) -> ProfileStats {
        ProfileStats {
            profile: name.to_string(),
            sessions: 1,
            conns_open: conns,
            bytes_in: bin,
            bytes_out: bout,
            throughput_bps_ewma: 0.0,
        }
    }

    #[test]
    fn flush_metrics_is_noop_without_handle() {
        // No metrics handle → must not panic and must not touch `prev`.
        let tick = StatsTick {
            profiles: vec![profile_stats("p", 10, 20, 1)],
            ..Default::default()
        };
        let mut prev = std::collections::BTreeMap::new();
        flush_metrics(None, &tick, &mut prev);
        assert!(prev.is_empty(), "no-op flush must not record state");
    }

    #[test]
    fn flush_metrics_increments_counters_by_delta() {
        let m = standard();
        let mut prev = std::collections::BTreeMap::new();

        // First flush: 100/200 bytes, 2 conns.
        let tick = StatsTick {
            profiles: vec![profile_stats("p", 100, 200, 2)],
            ..Default::default()
        };
        flush_metrics(Some(&m), &tick, &mut prev);
        assert_eq!(m.bytes_in.with_label_values(&["p"]).get(), 100);
        assert_eq!(m.bytes_out.with_label_values(&["p"]).get(), 200);
        assert_eq!(m.forward_active.with_label_values(&["p"]).get(), 2);

        // Second flush: cumulative 150/260 → counters advance by the *delta*
        // (50/60), gauge tracks the absolute conn count.
        let tick = StatsTick {
            profiles: vec![profile_stats("p", 150, 260, 0)],
            ..Default::default()
        };
        flush_metrics(Some(&m), &tick, &mut prev);
        assert_eq!(m.bytes_in.with_label_values(&["p"]).get(), 150);
        assert_eq!(m.bytes_out.with_label_values(&["p"]).get(), 260);
        assert_eq!(m.forward_active.with_label_values(&["p"]).get(), 0);
    }

    #[test]
    fn inc_reconnect_and_profile_state_respect_wiring() {
        // No metrics → no-op (no panic).
        let none = SupervisorObservers::default();
        none.inc_reconnect("p");
        none.set_profile_state("p", ProfileStateName::Active);

        // Wired → counter + gauge move.
        let m = standard();
        let obs = SupervisorObservers {
            event_bus: None,
            metrics: Some(m.clone()),
        };
        obs.inc_reconnect("p");
        obs.inc_reconnect("p");
        assert_eq!(m.reconnects.with_label_values(&["p"]).get(), 2);
        obs.set_profile_state("p", ProfileStateName::Degraded);
        assert_eq!(
            m.profile_state.with_label_values(&["p"]).get(),
            profile_state_code(ProfileStateName::Degraded)
        );
    }

    #[test]
    fn state_change_kind_maps_alertable_states() {
        assert_eq!(
            state_change_kind(ProfileStateName::Active),
            "profile.connected"
        );
        assert_eq!(
            state_change_kind(ProfileStateName::Degraded),
            "profile.degraded"
        );
        assert_eq!(
            state_change_kind(ProfileStateName::Reconnecting),
            "profile.reconnecting"
        );
        assert_eq!(severity_for_state(ProfileStateName::Active), Severity::Info);
        assert_eq!(
            severity_for_state(ProfileStateName::Degraded),
            Severity::Warn
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_state_change_publishes_canonical_event() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe();
        let obs = SupervisorObservers {
            event_bus: Some(bus),
            metrics: None,
        };
        obs.emit_state_change(
            "myprofile",
            ProfileStateName::EstablishingForwards,
            ProfileStateName::Active,
            Some("host:22"),
        );
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.kind.as_str(), "profile.connected");
        assert_eq!(ev.severity, Severity::Info);
        assert_eq!(ev.profile_id.as_ref().unwrap().as_str(), "myprofile");
        assert_eq!(
            ev.fields.get("endpoint").and_then(|v| v.as_str()),
            Some("host:22")
        );
        assert_eq!(ev.fields.get("to").and_then(|v| v.as_str()), Some("active"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_state_change_is_noop_without_bus() {
        // No bus wired → no panic, nothing to assert beyond "does not hang".
        let obs = SupervisorObservers::default();
        obs.emit_state_change("p", ProfileStateName::Idle, ProfileStateName::Active, None);
    }
}
