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

    /// As [`spawn`], with an injectable clock for tests.
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

    let bytes = serde_json::to_vec_pretty(snap)
        .map_err(|e| Error::RuntimeFailure(format!("serialize status snapshot: {e}")))?;
    atomic::write_atomic(&paths::status_path(dir), &bytes)?;

    if ring_size > 0 {
        let now = clock.now();
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
