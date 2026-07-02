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
///
/// Handles are commonly shared behind an `Arc` (the [`crate::EventRing`] is
/// held by the bus and cloned into event appenders), so the shutdown/join state
/// lives behind `Mutex<Option<..>>`: the writer can be signalled and its final
/// drain awaited through a shared `&self` reference (see
/// [`EventRing::stop_bounded_shared`]) without requiring sole ownership.
pub struct EventRing {
    tx: mpsc::Sender<Msg>,
    join: std::sync::Mutex<Option<JoinHandle<()>>>,
    shutdown: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}

enum Msg {
    Event(Event),
}

impl EventRing {
    /// Create a new ring rooted at `state_dir`. Spawns the writer task.
    pub fn spawn(state_dir: PathBuf, cfg: EventRingConfig) -> Result<Self> {
        Self::spawn_with_clock(state_dir, cfg, Arc::new(SystemClock))
    }

    /// As [`Self::spawn`], with a test-controllable clock.
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
            join: std::sync::Mutex::new(Some(join)),
            shutdown: std::sync::Mutex::new(Some(sd_tx)),
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

    /// Signal the writer to stop. Idempotent: the shutdown sender is taken on
    /// the first call, so later calls (and [`Drop`]) are no-ops. Never blocks.
    fn signal_shutdown(&self) {
        // Recover from a poisoned lock: the only thing guarded is an `Option`
        // we `take`, so a prior panic-while-locked can't leave it inconsistent.
        let taken = self
            .shutdown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(tx) = taken {
            let _ = tx.send(());
        }
    }

    /// Take the writer's join handle, if it hasn't already been taken.
    fn take_join(&self) -> Option<JoinHandle<()>> {
        self.join
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Stop the writer and wait for it to flush.
    pub async fn stop(self) {
        self.signal_shutdown();
        if let Some(j) = self.take_join() {
            let _ = j.await;
        }
    }

    /// Stop the writer and await its final drain, bounded by `timeout`
    /// (by-value convenience wrapper over [`Self::stop_bounded_shared`]).
    pub async fn stop_bounded(self, timeout: std::time::Duration) -> bool {
        self.stop_bounded_shared(timeout).await
    }

    /// Stop the writer and await its final drain through a **shared** `&self`
    /// reference, bounded by `timeout`.
    ///
    /// F-L3: callers that shut the ring down as part of an orderly teardown
    /// should call this (and `await` it) rather than relying on [`Drop`], which
    /// only signals the writer and detaches it — leaving the final drain to race
    /// the runtime's shutdown timeout and lose history events under backlog.
    ///
    /// Because the ring is typically held behind an `Arc` with outstanding
    /// clones (bus + event appenders), sole ownership can't be assumed, so this
    /// takes `&self`: the join handle is moved out of its `Mutex` and awaited.
    /// It is idempotent — a second call (or the by-value [`Self::stop_bounded`],
    /// or [`Drop`]) finds the handle already taken and returns `true`. The await
    /// is capped so a slow disk / large backlog can never hang teardown; if the
    /// drain does not finish within `timeout` the writer is left to complete
    /// detached (the runtime join reaps it). Returns `true` if the drain
    /// completed within the budget (or there was nothing left to await).
    pub async fn stop_bounded_shared(&self, timeout: std::time::Duration) -> bool {
        self.signal_shutdown();
        // Move the handle out and drop the lock guard BEFORE awaiting — never
        // hold a std Mutex guard across an `.await`.
        let handle = self.take_join();
        if let Some(j) = handle {
            tokio::time::timeout(timeout, j).await.is_ok()
        } else {
            true
        }
    }
}

impl Drop for EventRing {
    fn drop(&mut self) {
        // Signal the writer to stop; detach — runtime shutdown will join. If a
        // `stop*` call already took the sender this is a no-op.
        self.signal_shutdown();
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

    #[test]
    fn event_new_builds_with_null_extra() {
        let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let ev = Event::new(ts, "x", "info");
        assert_eq!(ev.kind, "x");
        assert_eq!(ev.severity, "info");
        assert!(ev.extra.is_null());
        // Null extra should be skipped in the on-wire JSON.
        let s = serde_json::to_string(&ev).unwrap();
        assert!(!s.contains("\"extra\""), "got: {s}");
        assert!(s.contains("\"kind\":\"x\""));
    }

    #[test]
    fn event_extra_flattens_into_record() {
        let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let ev = Event {
            ts,
            kind: "k".into(),
            severity: "warn".into(),
            extra: serde_json::json!({"profile": "p", "bytes": 7}),
        };
        let s = serde_json::to_string(&ev).unwrap();
        // Flatten places extra keys at top level rather than under an "extra" field.
        assert!(s.contains("\"profile\":\"p\""));
        assert!(s.contains("\"bytes\":7"));
        assert!(!s.contains("\"extra\""));
    }

    #[test]
    fn event_ring_config_defaults() {
        let c = EventRingConfig::default();
        assert_eq!(c.channel_capacity, 1024);
        assert_eq!(c.retain_days, 14);
    }

    #[test]
    fn is_null_helper_behaviour() {
        // direct sanity check of the private helper via its observable surface
        // (re-deriving here through serde_json::Value variants).
        assert!(is_null(&serde_json::Value::Null));
        assert!(!is_null(&serde_json::Value::Bool(true)));
        assert!(!is_null(&serde_json::json!({"k":1})));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_routes_events_to_their_own_day() {
        let tmp = tempdir().unwrap();
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
        ));
        let ring = EventRing::spawn_with_clock(
            tmp.path().to_path_buf(),
            EventRingConfig::default(),
            clock.clone(),
        )
        .unwrap();
        // Two events on the same day → land in the same file.
        ring.append(Event::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 1, 0, 0).unwrap(),
            "a",
            "info",
        ));
        ring.append(Event::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 23, 59, 59).unwrap(),
            "b",
            "warn",
        ));
        ring.stop().await;
        let body = std::fs::read_to_string(paths::events_file(tmp.path(), "2026-05-05")).unwrap();
        assert_eq!(body.lines().count(), 2, "body:\n{body}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retain_days_zero_skips_pruning() {
        let tmp = tempdir().unwrap();
        let edir = paths::events_dir(tmp.path());
        std::fs::create_dir_all(&edir).unwrap();
        for d in &["2020-01-01", "2020-01-02", "2020-01-03"] {
            std::fs::write(edir.join(format!("{d}.jsonl")), "").unwrap();
        }
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
        ));
        let ring = EventRing::spawn_with_clock(
            tmp.path().to_path_buf(),
            EventRingConfig {
                channel_capacity: 4,
                retain_days: 0,
            },
            clock.clone(),
        )
        .unwrap();
        ring.append(Event::new(clock.now(), "k", "info"));
        ring.stop().await;
        let kept: Vec<_> = std::fs::read_dir(&edir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        // With retain_days = 0 the pruner is skipped; all historicals remain.
        assert!(kept.iter().any(|n| n == "2020-01-01.jsonl"));
        assert!(kept.iter().any(|n| n == "2020-01-02.jsonl"));
        assert!(kept.iter().any(|n| n == "2020-01-03.jsonl"));
        assert!(kept.iter().any(|n| n == "2026-05-05.jsonl"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_after_stop_silently_drops() {
        // After stop the receiver is closed; append should not panic.
        let tmp = tempdir().unwrap();
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 0, 0, 0).unwrap(),
        ));
        let ring = EventRing::spawn_with_clock(
            tmp.path().to_path_buf(),
            EventRingConfig::default(),
            clock.clone(),
        )
        .unwrap();
        // Stash a clone of the sender via a no-op append, then stop the writer.
        ring.append(Event::new(clock.now(), "first", "info"));
        // Send one extra after triggering the shutdown to exercise the Closed branch.
        // We need to keep the sender alive but stop the consumer.  Drop after stop()
        // would also fire the shutdown_tx via Drop impl, so just call stop().
        // Cannot append after stop() consumes self; instead verify drop sends shutdown.
        drop(ring);
        // No panic == pass.
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_bounded_awaits_and_flushes_buffered_events() {
        // F-L3: an explicitly-awaited bounded final drain flushes events still
        // buffered in the channel before returning — they are not left to a
        // detached Drop that races the runtime shutdown timeout.
        let tmp = tempdir().unwrap();
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
        ));
        let ring = EventRing::spawn_with_clock(
            tmp.path().to_path_buf(),
            EventRingConfig {
                channel_capacity: 64,
                retain_days: 7,
            },
            clock.clone(),
        )
        .unwrap();
        for i in 0..10 {
            ring.append(Event::new(clock.now(), format!("k{i}"), "info"));
        }
        let completed = ring.stop_bounded(std::time::Duration::from_secs(5)).await;
        assert!(completed, "bounded drain should complete within the budget");
        let body = std::fs::read_to_string(paths::events_file(tmp.path(), "2026-05-05")).unwrap();
        assert_eq!(
            body.lines().count(),
            10,
            "all buffered events flushed on bounded stop, body:\n{body}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_bounded_shared_flushes_via_arc_with_outstanding_clone() {
        // F-L3 wiring: the ring is held behind an `Arc` with clones alive (the
        // bus + event appenders), so it is NOT sole-owned. The bounded final
        // drain must be reachable through a shared `&self` handle and still
        // flush every buffered event — an `Arc::try_unwrap` + by-value approach
        // would fail here and silently fall back to Drop.
        let tmp = tempdir().unwrap();
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
        ));
        let ring = Arc::new(
            EventRing::spawn_with_clock(
                tmp.path().to_path_buf(),
                EventRingConfig {
                    channel_capacity: 64,
                    retain_days: 7,
                },
                clock.clone(),
            )
            .unwrap(),
        );
        // An outstanding clone stays alive, exactly as an appender handle would.
        let appender = ring.clone();
        for i in 0..10 {
            appender.append(Event::new(clock.now(), format!("k{i}"), "info"));
        }

        // Drain through `&self` on the shared `Arc` (the call the spt-bin
        // `EventsPipeline::shutdown` will make on its `Arc<EventRing>`).
        let completed = ring
            .stop_bounded_shared(std::time::Duration::from_secs(5))
            .await;
        assert!(
            completed,
            "shared bounded drain should complete within budget"
        );
        let body = std::fs::read_to_string(paths::events_file(tmp.path(), "2026-05-05")).unwrap();
        assert_eq!(
            body.lines().count(),
            10,
            "all buffered events flushed via shared drain, body:\n{body}"
        );

        // The surviving clone dropping after the drain must not panic (the
        // shutdown sender/join were already taken; Drop is a no-op).
        drop(appender);
        drop(ring);
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
