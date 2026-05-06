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
use spt_stats::Ewma;

use crate::session::SessionRow;

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
            let entry = by_profile.entry(row.profile.clone()).or_insert_with(|| {
                ProfileStats {
                    profile: row.profile.clone(),
                    ..Default::default()
                }
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
pub fn update_throughput_ewma(
    state: &Ewma,
    prev_bytes: u64,
    cur_bytes: u64,
    dt: Duration,
) -> f64 {
    let dt_secs = dt.as_secs_f64().max(1e-3);
    let delta = cur_bytes.saturating_sub(prev_bytes) as f64;
    let bps = delta / dt_secs;
    state.sample(bps, dt);
    state.value().unwrap_or(0.0)
}
