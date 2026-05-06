//! Event ring: bounded JSONL event log with daily rotation.
//!
//! Events are submitted via [`EventRing::append`] which is non-blocking — the
//! event is dropped onto a bounded `mpsc` channel and a background writer task
//! flushes them to `<dir>/events/<YYYY-MM-DD>.jsonl`. The current day's file is
//! rolled over when the wall-clock day changes (per [`Clock`]).

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::clock::{Clock, SystemClock};
use crate::paths;
use spt_core::{Error, Result};

/// One event written to the JSONL ring.
///
/// `kind` and `severity` are well-known short strings; everything else lives
/// in `extra`. The full record serialised to disk is the merge of the named
/// fields and `extra`'s top-level map keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// ISO-8601 UTC timestamp.
    pub ts: DateTime<Utc>,
    /// Event kind (e.g. `"profile.state"`, `"forward.connected"`).
    pub kind: String,
    /// Severity (e.g. `"info"`, `"warn"`, `"error"`).
    pub severity: String,
    /// Free-form additional fields. MUST be a JSON object.
    #[serde(default, flatten, skip_serializing_if = "is_null")]
    pub extra: serde_json::Value,
}

impl Event {
    /// Build a new event at `ts` with no extra fields.
    #[must_use]
    pub fn new(ts: DateTime<Utc>, kind: impl Into<String>, severity: impl Into<String>) -> Self {
        Self {
            ts,
            kind: kind.into(),
            severity: severity.into(),
            extra: serde_json::Value::Null,
        }
    }
}

fn is_null(v: &serde_json::Value) -> bool {
    v.is_null()
}

/// Configuration for [`EventRing`].
#[derive(Debug, Clone)]
pub struct EventRingConfig {
    /// Channel buffer size. When full, new events are dropped (with a warning).
    pub channel_capacity: usize,
    /// Number of daily files to retain. Older files are pruned on rotation.
    pub retain_days: usize,
}

impl Default for EventRingConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 1024,
            retain_days: 14,
        }
    }
}

/// Non-blocking event ring writer.
pub struct EventRing {
    tx: mpsc::Sender<Msg>,
    join: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

enum Msg {
    Event(Event),
}

impl EventRing {
    /// Create a new ring rooted at `state_dir`. Spawns the writer task.
    pub fn spawn(state_dir: PathBuf, cfg: EventRingConfig) -> Result<Self> {
        Self::spawn_with_clock(state_dir, cfg, Arc::new(SystemClock))
    }

    /// As [`spawn`], with a test-controllable clock.
    pub fn spawn_with_clock(
        state_dir: PathBuf,
        cfg: EventRingConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        std::fs::create_dir_all(paths::events_dir(&state_dir)).map_err(|e| {
            Error::StateLockFailed {
                path: paths::events_dir(&state_dir),
                reason: format!("create events dir: {e}"),
            }
        })?;

        let (tx, rx) = mpsc::channel::<Msg>(cfg.channel_capacity);
        let (sd_tx, sd_rx) = oneshot::channel::<()>();
        let dir = state_dir;
        let join = tokio::spawn(async move {
            run_writer(dir, cfg, clock, rx, sd_rx).await;
        });

        Ok(Self {
            tx,
            join: Some(join),
            shutdown: Some(sd_tx),
        })
    }

    /// Append an event. Returns immediately. If the writer is overloaded the
    /// event is dropped and a warning is logged.
    pub fn append(&self, ev: Event) {
        match self.tx.try_send(Msg::Event(ev)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("event ring channel full; dropping event");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("event ring writer is shut down; dropping event");
            }
        }
    }

    /// Stop the writer and wait for it to flush.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

impl Drop for EventRing {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Detach; runtime shutdown will join.
    }
}

#[allow(clippy::needless_pass_by_value)] // owned by the spawned task
async fn run_writer(
    dir: PathBuf,
    cfg: EventRingConfig,
    clock: Arc<dyn Clock>,
    mut rx: mpsc::Receiver<Msg>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut current: Option<(DayKey, File)> = None;

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                drain(&mut rx, &dir, &cfg, clock.as_ref(), &mut current);
                break;
            }
            msg = rx.recv() => {
                match msg {
                    Some(Msg::Event(ev)) => {
                        if let Err(e) = write_one(&dir, &cfg, clock.as_ref(), &mut current, &ev) {
                            tracing::warn!(error=%e, "event write failed");
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

fn drain(
    rx: &mut mpsc::Receiver<Msg>,
    dir: &Path,
    cfg: &EventRingConfig,
    clock: &dyn Clock,
    current: &mut Option<(DayKey, File)>,
) {
    while let Ok(msg) = rx.try_recv() {
        match msg {
            Msg::Event(ev) => {
                if let Err(e) = write_one(dir, cfg, clock, current, &ev) {
                    tracing::warn!(error=%e, "event write failed during drain");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DayKey(i32, u32, u32);

impl DayKey {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt.year(), dt.month(), dt.day())
    }
    fn to_string_iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.0, self.1, self.2)
    }
}

fn write_one(
    dir: &Path,
    cfg: &EventRingConfig,
    clock: &dyn Clock,
    current: &mut Option<(DayKey, File)>,
    ev: &Event,
) -> Result<()> {
    // Day key follows the event's ts so events log in the day they happened.
    let day = DayKey::from(ev.ts);

    let need_open = match current {
        Some((cur_day, _)) => *cur_day != day,
        None => true,
    };
    if need_open {
        let path = paths::events_file(dir, &day.to_string_iso());
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Error::StateLockFailed {
                path,
                reason: format!("open event file: {e}"),
            })?;
        *current = Some((day, f));
        prune_old(dir, cfg.retain_days, clock.now());
    }

    let mut line = serde_json::to_vec(ev)
        .map_err(|e| Error::RuntimeFailure(format!("serialize event: {e}")))?;
    line.push(b'\n');

    let f = &mut current.as_mut().expect("current set above").1;
    f.write_all(&line).map_err(|e| Error::StateLockFailed {
        path: paths::events_file(dir, &day.to_string_iso()),
        reason: format!("event append: {e}"),
    })?;
    Ok(())
}

fn prune_old(dir: &Path, retain_days: usize, now: DateTime<Utc>) {
    if retain_days == 0 {
        return;
    }
    let edir = paths::events_dir(dir);
    let mut files: VecDeque<(String, PathBuf)> = match std::fs::read_dir(&edir) {
        Ok(rd) => rd
            .filter_map(std::result::Result::ok)
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                if Path::new(&n)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
                {
                    Some((n, e.path()))
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => return,
    };
    if files.len() <= retain_days {
        return;
    }
    let mut sorted: Vec<_> = files.drain(..).collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let _ = now; // currently we keep the youngest N regardless of `now`.
    while sorted.len() > retain_days {
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
    async fn append_writes_jsonl_line_for_event_day() {
        let tmp = tempdir().unwrap();
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
        ));
        let ring = EventRing::spawn_with_clock(
            tmp.path().to_path_buf(),
            EventRingConfig {
                channel_capacity: 16,
                retain_days: 7,
            },
            clock.clone(),
        )
        .unwrap();

        let ev = Event::new(clock.now(), "test.kind", "info");
        ring.append(ev);
        ring.stop().await;

        let f = paths::events_file(tmp.path(), "2026-05-05");
        let body = std::fs::read_to_string(&f).unwrap();
        assert!(body.lines().count() == 1, "body: {body}");
        let parsed: Event = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(parsed.kind, "test.kind");
        assert_eq!(parsed.severity, "info");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rotation_creates_new_file_at_day_boundary() {
        let tmp = tempdir().unwrap();
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 23, 59, 59).unwrap(),
        ));
        let ring = EventRing::spawn_with_clock(
            tmp.path().to_path_buf(),
            EventRingConfig {
                channel_capacity: 16,
                retain_days: 7,
            },
            clock.clone(),
        )
        .unwrap();

        // Day 1
        ring.append(Event::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 23, 59, 59).unwrap(),
            "k1",
            "info",
        ));
        // Day 2
        clock.set(Utc.with_ymd_and_hms(2026, 5, 6, 0, 0, 1).unwrap());
        ring.append(Event::new(
            Utc.with_ymd_and_hms(2026, 5, 6, 0, 0, 1).unwrap(),
            "k2",
            "info",
        ));
        ring.stop().await;

        assert!(paths::events_file(tmp.path(), "2026-05-05").is_file());
        assert!(paths::events_file(tmp.path(), "2026-05-06").is_file());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retention_prunes_oldest_files() {
        let tmp = tempdir().unwrap();
        // Pre-create 5 historical files.
        let edir = paths::events_dir(tmp.path());
        std::fs::create_dir_all(&edir).unwrap();
        for d in &["2026-05-01", "2026-05-02", "2026-05-03", "2026-05-04"] {
            std::fs::write(edir.join(format!("{d}.jsonl")), "").unwrap();
        }
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
        ));
        let ring = EventRing::spawn_with_clock(
            tmp.path().to_path_buf(),
            EventRingConfig {
                channel_capacity: 16,
                retain_days: 2, // keep 2 newest after rotation
            },
            clock.clone(),
        )
        .unwrap();

        // Trigger an open of 2026-05-05 → prune fires and trims to 2 files.
        ring.append(Event::new(clock.now(), "k", "info"));
        ring.stop().await;

        let kept: Vec<_> = std::fs::read_dir(&edir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(kept.len(), 2, "kept: {kept:?}");
        assert!(kept.iter().any(|n| n == "2026-05-05.jsonl"));
    }
}
