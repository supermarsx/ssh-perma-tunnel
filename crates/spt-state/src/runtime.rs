//! Daemon runtime-status writer (`spt status` app-overview model).
//!
//! ## Why a sibling file
//!
//! The supervisor's [`StatusWriter`](crate::status::StatusWriter) owns
//! `<state_dir>/status.json` and rewrites it on a periodic tick from the
//! supervisor task. The daemon-identity + subsystem layer (which control
//! surfaces the `tunnel run` daemon brought up: status-api, MCP loopback, DNS
//! server, metrics exporter, remote-config poller, events dispatcher) is known
//! to a *different* writer — `tunnel_run` itself — and is populated
//! incrementally as each subsystem starts.
//!
//! Sharing one file between two writers would race (two atomic-rename writers
//! clobbering each other's view). To keep the write path single-writer-per-file
//! we put the daemon/subsystem layer in a **separate sibling file**,
//! `<state_dir>/runtime.json` (see [`crate::paths::runtime_path`]), written only
//! by `tunnel_run` via [`write_runtime`]. The `spt status` command reads BOTH
//! `status.json` (profiles/forwards, via `StatusSnapshot`) and `runtime.json`
//! (daemon + subsystems, via [`RuntimeStatus`]) and merges them for display.
//!
//! A missing `runtime.json` cleanly means "no daemon running": [`read_runtime`]
//! returns `Ok(None)` rather than erroring.

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::paths;
use spt_core::{Error, Result};

// -- Schema ----------------------------------------------------------------

/// Top-level daemon runtime status, written by `tunnel run` to
/// `<state_dir>/runtime.json` and read by `spt status`.
///
/// Carries the daemon's identity plus a typed snapshot of every subsystem the
/// daemon may run. Companion to [`StatusSnapshot`](crate::status::StatusSnapshot)
/// (which carries per-profile/per-forward state); the two files are read
/// together by the `status` command.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeStatus {
    /// OS process id of the running daemon. `0` only on a defaulted value.
    pub pid: u32,
    /// Daemon binary version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Instant the daemon process started.
    pub started_at: Option<DateTime<Utc>>,
    /// Absolute path to the config file the daemon loaded.
    pub config_path: String,
    /// Absolute path to the state directory the daemon is using.
    pub state_dir: String,
    /// Wall-clock instant at which this runtime status was last flushed to
    /// disk. Stamped by [`write_runtime`]. Used for staleness detection
    /// (mirrors [`StatusSnapshot::written_at`](crate::status::StatusSnapshot)).
    /// `None` only on values that were never flushed.
    pub written_at: Option<DateTime<Utc>>,
    /// Typed per-subsystem state. Each entry is `None` when that subsystem is
    /// not running for this daemon.
    pub subsystems: Subsystems,
}

/// Typed snapshot of every subsystem the daemon may bring up.
///
/// Every field is `Option`: `None` means "this subsystem is not running".
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Subsystems {
    /// Read-only HTTP/JSON status API server.
    pub status_api: Option<StatusApiStatus>,
    /// MCP loopback control surface.
    pub mcp: Option<McpStatus>,
    /// Embedded DNS resolver/server.
    pub dns: Option<DnsStatus>,
    /// Prometheus metrics text-file exporter.
    pub metrics: Option<MetricsStatus>,
    /// Remote-config background poller.
    pub remote_config_poller: Option<RemoteConfigPollerStatus>,
    /// Events dispatcher + sinks.
    pub events: Option<EventsStatus>,
    /// Memory-monitor (RSS sampling + leak-suspected heuristic).
    pub memory_monitor: Option<MemoryMonitorStatus>,
}

/// Status-API server subsystem.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusApiStatus {
    /// Whether the server is enabled/running.
    pub enabled: bool,
    /// Bound socket address (e.g. `127.0.0.1:7878`), if listening.
    pub bind: Option<String>,
    /// Auth mode as a serde-friendly string (e.g. `"none"`, `"token"`).
    pub auth_mode: Option<String>,
    /// Whether TLS is enabled on the listener.
    pub tls: bool,
}

/// MCP loopback subsystem.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct McpStatus {
    /// Bound socket address of the loopback control surface, if listening.
    pub bind: Option<String>,
}

/// Embedded DNS server subsystem.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsStatus {
    /// Bound socket address of the DNS listener, if listening.
    pub bind: Option<String>,
    /// Listener mode as a serde-friendly string (e.g. `"udp"`, `"tcp"`).
    pub mode: Option<String>,
}

/// Prometheus metrics exporter subsystem.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsStatus {
    /// Path the exporter writes its text-exposition file to.
    pub path: Option<String>,
}

/// Remote-config background poller subsystem.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteConfigPollerStatus {
    /// Whether the poller is enabled/running.
    pub enabled: bool,
    /// Poll interval, serialized as whole seconds.
    #[serde(rename = "interval_secs")]
    pub interval_secs: Option<u64>,
}

/// Events dispatcher subsystem.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsStatus {
    /// Number of configured sinks.
    pub sink_count: u32,
    /// Event kinds being dispatched (serde-friendly strings).
    pub kinds: Vec<String>,
}

/// Memory-monitor subsystem.
///
/// Samples the daemon process's resident-set size on a fixed interval and emits
/// a `memory.leak_suspected` event when a sustained-growth heuristic trips. A
/// missing `memory_monitor` entry (or a deserialized value with all fields at
/// their defaults) means the monitor is not running — fully backward compatible
/// with `runtime.json` files written before this subsystem existed.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoryMonitorStatus {
    /// Whether the monitor is enabled/running.
    pub enabled: bool,
    /// Sampling interval, serialized as whole seconds. `None` when not sampling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u64>,
    /// Most recent resident-set-size sample, in bytes. `None` before the first
    /// sample is taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rss_bytes: Option<u64>,
    /// Number of RSS samples taken so far this run.
    pub samples: u32,
    /// Instant the monitor last flagged a suspected leak. `None` when it has
    /// never flagged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_flagged: Option<DateTime<Utc>>,
}

impl RuntimeStatus {
    /// Multiplier applied to the writer flush interval to decide staleness.
    ///
    /// Mirrors [`StatusSnapshot::STALE_INTERVAL_MULTIPLIER`](crate::status::StatusSnapshot::STALE_INTERVAL_MULTIPLIER).
    pub const STALE_INTERVAL_MULTIPLIER: u32 = 3;

    /// The daemon's process id (for a pid-liveness check by the caller).
    ///
    /// The actual OS liveness probe lives in `spt-bin`; this just exposes the
    /// recorded pid so the reader can perform it.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// True if this runtime status is stale relative to the writer's flush
    /// `interval`.
    ///
    /// Stale when [`written_at`](Self::written_at) is more than
    /// [`STALE_INTERVAL_MULTIPLIER`](Self::STALE_INTERVAL_MULTIPLIER) times
    /// `interval` in the past. A value with no `written_at` is treated as stale.
    #[must_use]
    pub fn is_stale(&self, interval: Duration) -> bool {
        self.is_stale_at(interval, Utc::now())
    }

    /// As [`Self::is_stale`], but compares against an explicit `now` instant.
    #[must_use]
    pub fn is_stale_at(&self, interval: Duration, now: DateTime<Utc>) -> bool {
        let Some(written_at) = self.written_at else {
            return true;
        };
        let max_age = interval.saturating_mul(Self::STALE_INTERVAL_MULTIPLIER);
        match now.signed_duration_since(written_at).to_std() {
            Ok(age) => age > max_age,
            Err(_) => false,
        }
    }

    // -- Builder / setters --------------------------------------------------
    //
    // `tunnel_run` constructs a `RuntimeStatus` for the daemon's identity, then
    // populates each subsystem entry as it spawns it. These consuming builders
    // and `&mut` setters support both styles.

    /// Builder: set the daemon identity fields in one call.
    #[must_use]
    pub fn with_identity(
        mut self,
        pid: u32,
        version: impl Into<String>,
        started_at: DateTime<Utc>,
        config_path: impl Into<String>,
        state_dir: impl Into<String>,
    ) -> Self {
        self.pid = pid;
        self.version = version.into();
        self.started_at = Some(started_at);
        self.config_path = config_path.into();
        self.state_dir = state_dir.into();
        self
    }

    /// Builder: attach the status-API subsystem entry.
    #[must_use]
    pub fn with_status_api(mut self, s: StatusApiStatus) -> Self {
        self.subsystems.status_api = Some(s);
        self
    }

    /// Builder: attach the MCP subsystem entry.
    #[must_use]
    pub fn with_mcp(mut self, s: McpStatus) -> Self {
        self.subsystems.mcp = Some(s);
        self
    }

    /// Builder: attach the DNS subsystem entry.
    #[must_use]
    pub fn with_dns(mut self, s: DnsStatus) -> Self {
        self.subsystems.dns = Some(s);
        self
    }

    /// Builder: attach the metrics subsystem entry.
    #[must_use]
    pub fn with_metrics(mut self, s: MetricsStatus) -> Self {
        self.subsystems.metrics = Some(s);
        self
    }

    /// Builder: attach the remote-config-poller subsystem entry.
    #[must_use]
    pub fn with_remote_config_poller(mut self, s: RemoteConfigPollerStatus) -> Self {
        self.subsystems.remote_config_poller = Some(s);
        self
    }

    /// Builder: attach the events subsystem entry.
    #[must_use]
    pub fn with_events(mut self, s: EventsStatus) -> Self {
        self.subsystems.events = Some(s);
        self
    }

    /// Builder: attach the memory-monitor subsystem entry.
    #[must_use]
    pub fn with_memory_monitor(mut self, s: MemoryMonitorStatus) -> Self {
        self.subsystems.memory_monitor = Some(s);
        self
    }

    /// Setter: record the status-API subsystem entry in place.
    pub fn set_status_api(&mut self, s: StatusApiStatus) {
        self.subsystems.status_api = Some(s);
    }

    /// Setter: record the MCP subsystem entry in place.
    pub fn set_mcp(&mut self, s: McpStatus) {
        self.subsystems.mcp = Some(s);
    }

    /// Setter: record the DNS subsystem entry in place.
    pub fn set_dns(&mut self, s: DnsStatus) {
        self.subsystems.dns = Some(s);
    }

    /// Setter: record the metrics subsystem entry in place.
    pub fn set_metrics(&mut self, s: MetricsStatus) {
        self.subsystems.metrics = Some(s);
    }

    /// Setter: record the remote-config-poller subsystem entry in place.
    pub fn set_remote_config_poller(&mut self, s: RemoteConfigPollerStatus) {
        self.subsystems.remote_config_poller = Some(s);
    }

    /// Setter: record the events subsystem entry in place.
    pub fn set_events(&mut self, s: EventsStatus) {
        self.subsystems.events = Some(s);
    }

    /// Setter: record the memory-monitor subsystem entry in place.
    pub fn set_memory_monitor(&mut self, s: MemoryMonitorStatus) {
        self.subsystems.memory_monitor = Some(s);
    }
}

// -- Writer / Reader -------------------------------------------------------

/// Atomically write `status` to `<dir>/runtime.json`, stamping `written_at`.
///
/// Mirrors the supervisor's `write_snapshot`: serialize a `written_at`-stamped
/// clone, then atomic write-then-rename. The caller's value is never mutated.
pub fn write_runtime(dir: &Path, status: &RuntimeStatus) -> Result<()> {
    write_runtime_at(dir, status, Utc::now())
}

/// As [`write_runtime`], with an explicit `now` for the `written_at` stamp.
///
/// Exposed for tests and callers that already hold a clock reading.
pub fn write_runtime_at(dir: &Path, status: &RuntimeStatus, now: DateTime<Utc>) -> Result<()> {
    let stamped = RuntimeStatus {
        written_at: Some(now),
        ..status.clone()
    };
    let bytes = serde_json::to_vec_pretty(&stamped)
        .map_err(|e| Error::RuntimeFailure(format!("serialize runtime status: {e}")))?;
    atomic::write_atomic(&paths::runtime_path(dir), &bytes)
}

/// Read `<dir>/runtime.json`.
///
/// Returns `Ok(None)` when the file does not exist (the daemon is not running,
/// or predates this feature) — a clean, backward-compatible signal rather than
/// an error. Returns `Err` only on I/O or deserialization failure.
pub fn read_runtime(dir: &Path) -> Result<Option<RuntimeStatus>> {
    let path = paths::runtime_path(dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let status: RuntimeStatus = serde_json::from_slice(&bytes)
                .map_err(|e| Error::RuntimeFailure(format!("parse runtime status: {e}")))?;
            Ok(Some(status))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::RuntimeFailure(format!(
            "read runtime status {}: {e}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn sample() -> RuntimeStatus {
        RuntimeStatus::default()
            .with_identity(
                4242,
                "0.0.1-test",
                Utc.with_ymd_and_hms(2026, 6, 11, 12, 0, 0).unwrap(),
                "/etc/spt/config.toml",
                "/var/state/spt",
            )
            .with_status_api(StatusApiStatus {
                enabled: true,
                bind: Some("127.0.0.1:7878".into()),
                auth_mode: Some("token".into()),
                tls: false,
            })
            .with_mcp(McpStatus {
                bind: Some("127.0.0.1:9000".into()),
            })
            .with_dns(DnsStatus {
                bind: Some("127.0.0.1:53".into()),
                mode: Some("udp".into()),
            })
            .with_metrics(MetricsStatus {
                path: Some("/var/state/spt/metrics.prom".into()),
            })
            .with_remote_config_poller(RemoteConfigPollerStatus {
                enabled: true,
                interval_secs: Some(60),
            })
            .with_events(EventsStatus {
                sink_count: 2,
                kinds: vec!["session".into(), "connection".into()],
            })
            .with_memory_monitor(MemoryMonitorStatus {
                enabled: true,
                interval_secs: Some(60),
                last_rss_bytes: Some(123_456_789),
                samples: 17,
                last_flagged: Some(Utc.with_ymd_and_hms(2026, 6, 11, 11, 30, 0).unwrap()),
            })
    }

    #[test]
    fn builder_populates_identity_and_subsystems() {
        let r = sample();
        assert_eq!(r.pid(), 4242);
        assert_eq!(r.version, "0.0.1-test");
        assert_eq!(r.config_path, "/etc/spt/config.toml");
        assert_eq!(r.state_dir, "/var/state/spt");
        assert!(r.started_at.is_some());

        let s = &r.subsystems;
        assert_eq!(
            s.status_api.as_ref().unwrap().bind.as_deref(),
            Some("127.0.0.1:7878")
        );
        assert_eq!(
            s.mcp.as_ref().unwrap().bind.as_deref(),
            Some("127.0.0.1:9000")
        );
        assert_eq!(s.dns.as_ref().unwrap().mode.as_deref(), Some("udp"));
        assert_eq!(
            s.metrics.as_ref().unwrap().path.as_deref(),
            Some("/var/state/spt/metrics.prom")
        );
        assert_eq!(
            s.remote_config_poller.as_ref().unwrap().interval_secs,
            Some(60)
        );
        assert_eq!(s.events.as_ref().unwrap().sink_count, 2);
        assert_eq!(s.events.as_ref().unwrap().kinds.len(), 2);

        let mm = s.memory_monitor.as_ref().unwrap();
        assert!(mm.enabled);
        assert_eq!(mm.interval_secs, Some(60));
        assert_eq!(mm.last_rss_bytes, Some(123_456_789));
        assert_eq!(mm.samples, 17);
        assert!(mm.last_flagged.is_some());
    }

    #[test]
    fn setters_populate_subsystems_in_place() {
        let mut r = RuntimeStatus::default();
        assert!(r.subsystems.status_api.is_none());
        r.set_status_api(StatusApiStatus {
            enabled: true,
            ..Default::default()
        });
        r.set_dns(DnsStatus {
            mode: Some("tcp".into()),
            ..Default::default()
        });
        assert!(r.subsystems.status_api.as_ref().unwrap().enabled);
        assert_eq!(
            r.subsystems.dns.as_ref().unwrap().mode.as_deref(),
            Some("tcp")
        );
        r.set_memory_monitor(MemoryMonitorStatus {
            enabled: true,
            interval_secs: Some(30),
            last_rss_bytes: Some(2048),
            samples: 3,
            ..Default::default()
        });
        let mm = r.subsystems.memory_monitor.as_ref().unwrap();
        assert!(mm.enabled);
        assert_eq!(mm.interval_secs, Some(30));
        assert_eq!(mm.last_rss_bytes, Some(2048));
        assert_eq!(mm.samples, 3);
        assert!(mm.last_flagged.is_none());
        // Untouched subsystems remain absent.
        assert!(r.subsystems.mcp.is_none());
        assert!(r.subsystems.metrics.is_none());
    }

    #[test]
    fn json_round_trip_preserves_all_fields() {
        let r = sample();
        let raw = serde_json::to_string(&r).unwrap();
        let back: RuntimeStatus = serde_json::from_str(&raw).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn deserializes_with_defaults_for_missing_fields() {
        // Empty object => daemon-not-running-shaped default; absent subsystems.
        let r: RuntimeStatus = serde_json::from_str("{}").unwrap();
        assert_eq!(r.pid, 0);
        assert!(r.version.is_empty());
        assert!(r.written_at.is_none());
        assert!(r.subsystems.status_api.is_none());
        assert!(r.subsystems.events.is_none());
        assert!(r.subsystems.memory_monitor.is_none());
    }

    #[test]
    fn legacy_runtime_json_without_memory_monitor_parses() {
        // A runtime.json written before the memory-monitor subsystem existed:
        // it carries other subsystems but no `memory_monitor` key. It must
        // parse cleanly with the monitor reported as not running.
        let raw = r#"{
            "pid": 4242,
            "version": "0.0.1-test",
            "subsystems": {
                "events": { "sink_count": 1, "kinds": ["session"] }
            }
        }"#;
        let r: RuntimeStatus = serde_json::from_str(raw).unwrap();
        assert_eq!(r.pid, 4242);
        assert_eq!(r.subsystems.events.as_ref().unwrap().sink_count, 1);
        assert!(r.subsystems.memory_monitor.is_none());
    }

    #[test]
    fn is_stale_uses_written_at_and_interval() {
        let interval = Duration::from_secs(5);
        let now = Utc.with_ymd_and_hms(2026, 6, 11, 12, 0, 0).unwrap();

        // None => always stale (never flushed).
        let r = RuntimeStatus::default();
        assert!(r.is_stale_at(interval, now));

        // Fresh.
        let r = RuntimeStatus {
            written_at: Some(now),
            ..Default::default()
        };
        assert!(!r.is_stale_at(interval, now));

        // Within the 3x window (10s < 15s).
        let r = RuntimeStatus {
            written_at: Some(now - chrono::Duration::seconds(10)),
            ..Default::default()
        };
        assert!(!r.is_stale_at(interval, now));

        // Past the 3x window (20s > 15s).
        let r = RuntimeStatus {
            written_at: Some(now - chrono::Duration::seconds(20)),
            ..Default::default()
        };
        assert!(r.is_stale_at(interval, now));

        // Future timestamp (clock skew) => not stale.
        let r = RuntimeStatus {
            written_at: Some(now + chrono::Duration::seconds(60)),
            ..Default::default()
        };
        assert!(!r.is_stale_at(interval, now));
    }

    #[test]
    fn write_then_read_round_trips_and_stamps_written_at() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let when = Utc.with_ymd_and_hms(2026, 6, 11, 12, 0, 0).unwrap();

        let r = sample();
        assert!(
            r.written_at.is_none(),
            "in-memory value carries no stamp yet"
        );

        write_runtime_at(&dir, &r, when).unwrap();
        // Writer must not mutate the caller's value.
        assert!(r.written_at.is_none());

        let back = read_runtime(&dir).unwrap().expect("runtime.json present");
        assert_eq!(back.written_at, Some(when));
        assert_eq!(back.pid, 4242);
        assert_eq!(back.subsystems.events.as_ref().unwrap().sink_count, 2);
    }

    #[test]
    fn read_missing_file_returns_none() {
        let tmp = tempdir().unwrap();
        // No runtime.json written => daemon-not-running.
        assert!(read_runtime(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn read_corrupt_file_returns_err() {
        let tmp = tempdir().unwrap();
        atomic::write_atomic(&paths::runtime_path(tmp.path()), b"{not json").unwrap();
        assert!(read_runtime(tmp.path()).is_err());
    }
}
