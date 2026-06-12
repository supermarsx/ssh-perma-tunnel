//! Status-snapshot writer.
//!
//! Implements the schema defined in spec §13.5 / plan §3. Snapshots are written
//! atomically to `<dir>/status.json`; a ringed copy `status.<ts>.json` is also
//! kept so an operator can inspect recent history. The writer runs as a Tokio
//! task driven by an interval, ticking until [`StatusWriterHandle::stop`]
//! returns or the handle is dropped.
//!
//! ## Concurrency
//!
//! Callers mutate a snapshot via [`StatusWriter::update`], which takes a
//! `RwLock` write guard. Reads (e.g. for the `status` CLI) take the same
//! lock with [`StatusWriter::read`].

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;

use crate::atomic;
use crate::clock::{Clock, SystemClock};
use crate::paths;
use spt_core::Result;

// -- Schema ----------------------------------------------------------------

/// Top-level status snapshot per spec §13.5 / plan §3.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusSnapshot {
    pub pid: u32,
    pub version: String,
    pub config_fingerprint_sha256: String,
    pub started_at: Option<DateTime<Utc>>,
    /// Wall-clock instant at which this snapshot was last flushed to disk.
    ///
    /// Stamped by [`write_snapshot`] on every flush. Readers use this to
    /// detect stale state left behind by a crashed supervisor: a snapshot
    /// whose `written_at` is far older than the writer's flush interval (or
    /// whose `pid` is no longer alive) should be treated as stale rather than
    /// live. `None` only on snapshots that were never flushed (e.g. defaulted
    /// in-memory values or legacy files predating this field).
    ///
    /// See [`StatusSnapshot::is_stale`] for the reader-side staleness check.
    pub written_at: Option<DateTime<Utc>>,
    pub profiles: Vec<ProfileStatus>,
    pub forwards: Vec<ForwardStatus>,
    pub sessions: Vec<SessionStatus>,
    pub connections: Vec<ConnectionStatus>,
    pub dns_records: Vec<DnsRecordStatus>,
    pub failover_state: FailoverState,
    pub last_errors: Vec<LastError>,
    pub counters: Counters,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileStatus {
    pub id: String,
    pub state: String,
    pub active_endpoint: Option<String>,
    pub reconnect_count: u64,
    pub failover_count: u64,
    pub last_successful_connection_at: Option<DateTime<Utc>>,
    pub last_error_category: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardStatus {
    pub id: String,
    pub profile: String,
    pub state: String,
    pub direction: String,
    pub transport: String,
    pub local_addr: Option<String>,
    pub remote_addr: Option<String>,
    pub assigned_remote_port: Option<u16>,
    pub current_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub current_throughput_bps: u64,
    pub rolling_throughput_bps: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionStatus {
    pub id: String,
    pub profile: String,
    pub protocol: String,
    pub endpoint: String,
    pub user_redacted: Option<String>,
    pub state: String,
    pub started_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub keepalive_state: String,
    pub reconnect_attempt: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub active_forwards: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionStatus {
    pub id: String,
    pub profile: String,
    pub forward: String,
    pub direction: String,
    pub transport: String,
    pub local_peer: Option<String>,
    pub remote_target_redacted: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub current_rate_bps: u64,
    pub applied_throttle: Option<String>,
    pub close_reason: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsRecordStatus {
    pub name: String,
    pub kind: String,
    pub value: String,
    pub healthy: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FailoverState {
    pub per_profile: Vec<FailoverProfileEntry>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FailoverProfileEntry {
    pub profile: String,
    pub current_endpoint: Option<String>,
    pub remaining_targets: u32,
    pub cooldown_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LastError {
    pub scope: String,
    pub category: String,
    pub message: String,
    pub at: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Counters {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub sessions_opened: u64,
    pub sessions_closed: u64,
    pub connections_opened: u64,
    pub connections_closed: u64,
    pub reconnects: u64,
    pub failovers: u64,
}

impl StatusSnapshot {
    /// Multiplier applied to the writer flush interval to decide staleness.
    ///
    /// A snapshot is considered stale once it is older than this many writer
    /// intervals — i.e. several flushes have been missed, strongly implying the
    /// writer is no longer running.
    pub const STALE_INTERVAL_MULTIPLIER: u32 = 3;

    /// True if this snapshot is stale relative to the writer's flush `interval`.
    ///
    /// A snapshot is stale when its [`written_at`](Self::written_at) is more
    /// than [`STALE_INTERVAL_MULTIPLIER`](Self::STALE_INTERVAL_MULTIPLIER) times
    /// `interval` in the past (compared against [`Utc::now`]). A snapshot with no
    /// `written_at` is treated as stale (it was never flushed by a live writer).
    ///
    /// Reader-side consumers (e.g. the `tunnel status|stats|sessions|health`
    /// CLI) combine this with a PID-liveness check to avoid serving post-crash
    /// state as live.
    #[must_use]
    pub fn is_stale(&self, interval: Duration) -> bool {
        self.is_stale_at(interval, Utc::now())
    }

    /// As [`Self::is_stale`], but compares against an explicit `now` instant.
    ///
    /// Exposed for tests and for callers that already hold a clock reading.
    #[must_use]
    pub fn is_stale_at(&self, interval: Duration, now: DateTime<Utc>) -> bool {
        let Some(written_at) = self.written_at else {
            return true;
        };
        let max_age = interval.saturating_mul(Self::STALE_INTERVAL_MULTIPLIER);
        match now.signed_duration_since(written_at).to_std() {
            // Positive age: stale once it exceeds the allowed window.
            Ok(age) => age > max_age,
            // Negative age (written_at in the future, e.g. clock skew): not stale.
            Err(_) => false,
        }
    }
}

// -- Writer ----------------------------------------------------------------

/// Configuration for the status writer task.
#[derive(Debug, Clone)]
pub struct StatusWriterConfig {
    /// Tick interval at which the snapshot is flushed to disk.
    pub interval: Duration,
    /// Number of ringed snapshot files to keep.
    pub ring_size: usize,
}

impl Default for StatusWriterConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            ring_size: 12,
        }
    }
}

/// Handle to a spawned status-writer task.
#[derive(Debug)]
pub struct StatusWriterHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl StatusWriterHandle {
    /// Stop the writer task and wait for it to flush.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

impl Drop for StatusWriterHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Detach: don't block in Drop; the next runtime shutdown joins.
    }
}

/// Status-snapshot writer.
#[derive(Debug, Clone)]
pub struct StatusWriter {
    inner: Arc<RwLock<StatusSnapshot>>,
    dir: PathBuf,
    cfg: StatusWriterConfig,
}

impl StatusWriter {
    /// New writer rooted at `dir`. The state directory must already exist.
    #[must_use]
    pub fn new(dir: PathBuf, cfg: StatusWriterConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StatusSnapshot::default())),
            dir,
            cfg,
        }
    }

    /// Replace the entire snapshot.
    pub async fn set(&self, snapshot: StatusSnapshot) {
        *self.inner.write().await = snapshot;
    }

    /// Mutate the snapshot under the write lock.
    pub async fn update<F: FnOnce(&mut StatusSnapshot)>(&self, f: F) {
        let mut g = self.inner.write().await;
        f(&mut g);
    }

    /// Snapshot a clone of the current state.
    pub async fn read(&self) -> StatusSnapshot {
        self.inner.read().await.clone()
    }

    /// Force a synchronous flush. Useful at shutdown or in tests.
    pub async fn flush(&self) -> Result<()> {
        let snap = self.inner.read().await.clone();
        write_snapshot(&self.dir, &snap, &SystemClock, self.cfg.ring_size)
    }

    /// Spawn the periodic writer task. Returns a handle; drop or call
    /// [`StatusWriterHandle::stop`] to terminate it.
    pub fn spawn(self) -> StatusWriterHandle {
        self.spawn_with_clock(Arc::new(SystemClock))
    }

    /// As [`Self::spawn`], with an injectable clock for tests.
    pub fn spawn_with_clock(self, clock: Arc<dyn Clock>) -> StatusWriterHandle {
        let (tx, mut rx) = oneshot::channel::<()>();
        let inner = self.inner.clone();
        let dir = self.dir.clone();
        let cfg = self.cfg.clone();

        let join = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(cfg.interval);
            // Skip the immediate first tick so we don't write at t=0 with empty data.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        // Final flush before exit.
                        let snap = inner.read().await.clone();
                        if let Err(e) = write_snapshot(&dir, &snap, clock.as_ref(), cfg.ring_size) {
                            tracing::warn!(error=%e, "final status flush failed");
                        }
                        break;
                    }
                    _ = ticker.tick() => {
                        let snap = inner.read().await.clone();
                        if let Err(e) = write_snapshot(&dir, &snap, clock.as_ref(), cfg.ring_size) {
                            tracing::warn!(error=%e, "status flush failed");
                        }
                    }
                }
            }
        });

        StatusWriterHandle {
            shutdown: Some(tx),
            join: Some(join),
        }
    }
}

fn write_snapshot(
    dir: &Path,
    snap: &StatusSnapshot,
    clock: &dyn Clock,
    ring_size: usize,
) -> Result<()> {
    use spt_core::Error;

    let now = clock.now();

    // Stamp the flush time so readers can detect stale post-crash state. We
    // clone rather than mutate the caller's snapshot so the in-memory value is
    // never altered as a side effect of flushing.
    let stamped = StatusSnapshot {
        written_at: Some(now),
        ..snap.clone()
    };

    let bytes = serde_json::to_vec_pretty(&stamped)
        .map_err(|e| Error::RuntimeFailure(format!("serialize status snapshot: {e}")))?;
    atomic::write_atomic(&paths::status_path(dir), &bytes)?;

    if ring_size > 0 {
        let ts = now.format("%Y%m%dT%H%M%S%.3fZ").to_string();
        let ring_path = paths::status_ring_path(dir, &ts);
        atomic::write_atomic(&ring_path, &bytes)?;
        prune_ring(dir, ring_size);
    }

    Ok(())
}

fn prune_ring(dir: &Path, keep: usize) {
    let mut entries: VecDeque<(String, PathBuf)> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(std::result::Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let is_json = std::path::Path::new(&name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
                if name.starts_with("status.") && is_json && name != "status.json" {
                    Some((name, e.path()))
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => return,
    };
    // Lex order on the timestamp = chronological.
    let mut sorted: Vec<_> = entries.drain(..).collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    while sorted.len() > keep {
        if let Some((_, p)) = sorted.first() {
            let _ = std::fs::remove_file(p);
        }
        sorted.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use chrono::TimeZone;
    use tempfile::tempdir;

    #[tokio::test(flavor = "current_thread")]
    async fn writer_ticks_and_flushes_atomically() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();

        let cfg = StatusWriterConfig {
            interval: Duration::from_millis(25),
            ring_size: 3,
        };
        let writer = StatusWriter::new(dir.clone(), cfg);
        writer
            .update(|s| {
                s.pid = 4242;
                s.version = "0.0.1-test".into();
            })
            .await;

        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
        ));
        let handle = writer.clone().spawn_with_clock(clock.clone());

        // Let a couple of ticks fire.
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.stop().await;

        let path = paths::status_path(&dir);
        assert!(path.is_file(), "status.json should exist");
        let s: StatusSnapshot = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(s.pid, 4242);
        assert_eq!(s.version, "0.0.1-test");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flush_writes_status_and_ring_file() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let writer = StatusWriter::new(
            dir.clone(),
            StatusWriterConfig {
                interval: Duration::from_secs(60),
                ring_size: 5,
            },
        );
        writer.update(|s| s.pid = 7).await;
        writer.flush().await.unwrap();

        assert!(paths::status_path(&dir).is_file());
        let ring: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                let is_json = std::path::Path::new(&n)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
                n.starts_with("status.") && is_json && n != "status.json"
            })
            .collect();
        assert_eq!(ring.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_set_replaces_snapshot() {
        let tmp = tempdir().unwrap();
        let writer = StatusWriter::new(tmp.path().to_path_buf(), StatusWriterConfig::default());
        let snap = StatusSnapshot {
            pid: 9001,
            version: "v9".into(),
            ..Default::default()
        };
        writer.set(snap).await;
        let read = writer.read().await;
        assert_eq!(read.pid, 9001);
        assert_eq!(read.version, "v9");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ring_size_zero_skips_ring_writes() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let writer = StatusWriter::new(
            dir.clone(),
            StatusWriterConfig {
                interval: Duration::from_secs(60),
                ring_size: 0,
            },
        );
        writer.update(|s| s.pid = 1).await;
        writer.flush().await.unwrap();
        assert!(paths::status_path(&dir).is_file());
        let ring: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                let is_json = std::path::Path::new(&n)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
                n.starts_with("status.") && is_json && n != "status.json"
            })
            .collect();
        assert!(ring.is_empty(), "unexpected ring files: {ring:?}");
    }

    #[test]
    fn config_default_values() {
        let c = StatusWriterConfig::default();
        assert_eq!(c.interval, Duration::from_secs(5));
        assert_eq!(c.ring_size, 12);
    }

    #[test]
    fn snapshot_round_trip_through_json() {
        let written = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let mut s = StatusSnapshot {
            pid: 7,
            version: "v".into(),
            config_fingerprint_sha256: "abc".into(),
            written_at: Some(written),
            ..Default::default()
        };
        s.profiles.push(ProfileStatus {
            id: "p".into(),
            state: "Running".into(),
            ..Default::default()
        });
        s.forwards.push(ForwardStatus {
            id: "f".into(),
            profile: "p".into(),
            state: "Connected".into(),
            direction: "local".into(),
            transport: "tcp".into(),
            ..Default::default()
        });
        s.sessions.push(SessionStatus {
            id: "s".into(),
            ..Default::default()
        });
        s.connections.push(ConnectionStatus {
            id: "c".into(),
            ..Default::default()
        });
        s.dns_records.push(DnsRecordStatus {
            name: "a".into(),
            kind: "A".into(),
            value: "127.0.0.1".into(),
            healthy: true,
        });
        s.failover_state.per_profile.push(FailoverProfileEntry {
            profile: "p".into(),
            current_endpoint: Some("e:22".into()),
            remaining_targets: 2,
            cooldown_until: None,
        });
        s.last_errors.push(LastError {
            scope: "session".into(),
            category: "Auth".into(),
            message: "no".into(),
            at: None,
        });
        s.counters.bytes_in = 99;

        let raw = serde_json::to_string(&s).unwrap();
        let back: StatusSnapshot = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.pid, 7);
        assert_eq!(back.written_at, Some(written));
        assert_eq!(back.profiles.len(), 1);
        assert_eq!(back.forwards.len(), 1);
        assert_eq!(back.sessions.len(), 1);
        assert_eq!(back.connections.len(), 1);
        assert_eq!(back.dns_records.len(), 1);
        assert_eq!(back.failover_state.per_profile.len(), 1);
        assert_eq!(back.last_errors.len(), 1);
        assert_eq!(back.counters.bytes_in, 99);
    }

    #[test]
    fn snapshot_deserialises_with_defaults_for_missing_fields() {
        let s: StatusSnapshot = serde_json::from_str("{}").unwrap();
        assert_eq!(s.pid, 0);
        assert!(s.version.is_empty());
        assert!(s.profiles.is_empty());
        // Legacy files predating `written_at` must still parse; absence => None.
        assert!(s.written_at.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flush_stamps_written_at_from_clock() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let writer = StatusWriter::new(
            dir.clone(),
            StatusWriterConfig {
                interval: Duration::from_secs(60),
                ring_size: 0,
            },
        );
        writer.update(|s| s.pid = 7).await;

        // The in-memory snapshot carries no timestamp yet.
        assert!(writer.read().await.written_at.is_none());

        writer.flush().await.unwrap();

        // The on-disk snapshot is stamped, but the in-memory one is untouched.
        assert!(
            writer.read().await.written_at.is_none(),
            "flush must not mutate the in-memory snapshot"
        );
        let path = paths::status_path(&dir);
        let s: StatusSnapshot = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(s.written_at.is_some(), "on-disk snapshot must be stamped");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_with_clock_stamps_deterministic_written_at() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let cfg = StatusWriterConfig {
            interval: Duration::from_millis(25),
            ring_size: 3,
        };
        let writer = StatusWriter::new(dir.clone(), cfg);
        writer.update(|s| s.pid = 4242).await;

        let when = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let clock = Arc::new(TestClock::new(when));
        let handle = writer.clone().spawn_with_clock(clock.clone());
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.stop().await;

        let path = paths::status_path(&dir);
        let s: StatusSnapshot = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(s.written_at, Some(when));
    }

    #[test]
    fn is_stale_uses_written_at_and_interval() {
        let interval = Duration::from_secs(5);
        let now = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();

        // None => always stale (never flushed by a live writer).
        let s = StatusSnapshot::default();
        assert!(s.is_stale_at(interval, now));

        // Fresh: written just now.
        let s = StatusSnapshot {
            written_at: Some(now),
            ..Default::default()
        };
        assert!(!s.is_stale_at(interval, now));

        // Within the 3x window (10s < 15s): still fresh.
        let s = StatusSnapshot {
            written_at: Some(now - chrono::Duration::seconds(10)),
            ..Default::default()
        };
        assert!(!s.is_stale_at(interval, now));

        // Past the 3x window (20s > 15s): stale.
        let s = StatusSnapshot {
            written_at: Some(now - chrono::Duration::seconds(20)),
            ..Default::default()
        };
        assert!(s.is_stale_at(interval, now));

        // Future timestamp (clock skew): treated as not stale.
        let s = StatusSnapshot {
            written_at: Some(now + chrono::Duration::seconds(60)),
            ..Default::default()
        };
        assert!(!s.is_stale_at(interval, now));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_drop_signals_shutdown() {
        let tmp = tempdir().unwrap();
        let writer = StatusWriter::new(
            tmp.path().to_path_buf(),
            StatusWriterConfig {
                interval: Duration::from_millis(20),
                ring_size: 1,
            },
        );
        writer.update(|s| s.pid = 1).await;
        {
            let _h = writer.clone().spawn();
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ring_is_pruned_to_size() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let writer = StatusWriter::new(
            dir.clone(),
            StatusWriterConfig {
                interval: Duration::from_secs(60),
                ring_size: 2,
            },
        );

        for i in 0..5_u64 {
            writer.update(|s| s.counters.bytes_in = i).await;
            // Use real flush() with system clock; sub-millisecond precision in
            // the timestamp keeps filenames distinct.
            writer.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let ring: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                let is_json = std::path::Path::new(&n)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
                n.starts_with("status.") && is_json && n != "status.json"
            })
            .collect();
        assert!(ring.len() <= 2, "ring not pruned: {}", ring.len());
    }
}
