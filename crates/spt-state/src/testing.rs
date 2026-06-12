//! Test facilities for `spt-state`.
//!
//! Behind the `testing` feature flag (and automatically under `cfg(test)`).
//! Provides:
//!
//! * [`TempStateDir`] — RAII handle that wraps a [`tempfile::TempDir`] and
//!   pre-creates the on-disk layout (`events/`, `sessions/`, `benchmarks/`,
//!   `diagnostics/`, `dns/`, `hosts/`, `remote-log-spool/`).
//! * [`FakeClock`] — re-export of the existing [`crate::clock::TestClock`]
//!   under a friendlier name, plus helpers (`set`, `advance`, `freeze`).
//! * [`StatusSnapshotBuilder`] — fluent builder for [`StatusSnapshot`].
//! * [`event_corpus`] — a representative slate of [`Event`]s for tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use tempfile::TempDir;

use crate::clock::{Clock, TestClock};
use crate::events::Event;
use crate::status::{
    ConnectionStatus, Counters, FailoverState, ForwardStatus, LastError, ProfileStatus,
    SessionStatus, StatusSnapshot,
};

// ---------------------------------------------------------------------------
// TempStateDir
// ---------------------------------------------------------------------------

/// A self-cleaning state directory pre-populated with the spt layout.
///
/// The temporary directory is removed when the handle drops. Subdirectories
/// `events/`, `sessions/`, `benchmarks/`, `diagnostics/`, `dns/`, `hosts/`,
/// and `remote-log-spool/` are created up front so callers can immediately
/// write into them without surprises.
pub struct TempStateDir {
    _dir: TempDir,
    /// Absolute path to the state directory root.
    pub path: PathBuf,
}

impl std::fmt::Debug for TempStateDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempStateDir")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl TempStateDir {
    /// Create a new temp state dir with the layout pre-populated.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::TempStateDir;
    /// let d = TempStateDir::new();
    /// assert!(d.path.join("events").is_dir());
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if a tempdir cannot be created or any subdirectory creation
    /// fails — both unrecoverable in tests.
    #[must_use]
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().to_path_buf();
        for sub in [
            "events",
            "sessions",
            "benchmarks",
            "diagnostics",
            "dns",
            "hosts",
        ] {
            std::fs::create_dir_all(path.join(sub)).unwrap_or_else(|e| panic!("create {sub}: {e}"));
        }
        std::fs::create_dir_all(path.join("remote-log-spool")).expect("create remote-log-spool");
        Self { _dir: dir, path }
    }

    /// Borrow the state directory path.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::TempStateDir;
    /// let d = TempStateDir::new();
    /// let _: &std::path::Path = d.as_path();
    /// ```
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// Write an initial `status.json` snapshot built by `f`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::TempStateDir;
    /// let d = TempStateDir::new().with_status(|s| { s.pid = 99; });
    /// assert!(d.path.join("status.json").is_file());
    /// ```
    #[must_use]
    pub fn with_status<F: FnOnce(&mut StatusSnapshot)>(self, f: F) -> Self {
        let mut snap = StatusSnapshot::default();
        f(&mut snap);
        let bytes = serde_json::to_vec_pretty(&snap).expect("serialize StatusSnapshot");
        std::fs::write(self.path.join("status.json"), bytes).expect("write status.json");
        self
    }
}

impl Default for TempStateDir {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FakeClock
// ---------------------------------------------------------------------------

/// A controllable clock for tests. Wraps the existing [`TestClock`] with a
/// few extra ergonomic methods (`freeze`, `into_arc`).
///
/// # Examples
///
/// ```
/// use spt_state::testing::FakeClock;
/// use chrono::{TimeZone, Utc};
/// let c = FakeClock::new(Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap());
/// assert_eq!(c.now().date_naive().to_string(), "2026-05-05");
/// ```
#[derive(Debug, Clone)]
pub struct FakeClock {
    inner: TestClock,
}

impl FakeClock {
    /// Construct a fake clock pinned at `start`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::FakeClock;
    /// use chrono::{TimeZone, Utc};
    /// let _ = FakeClock::new(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    /// ```
    #[must_use]
    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            inner: TestClock::new(start),
        }
    }

    /// Construct a clock pinned at the canonical project test instant
    /// (`2026-05-05T12:00:00Z`).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::FakeClock;
    /// let c = FakeClock::frozen();
    /// // Two reads return the same value — the clock is frozen.
    /// assert_eq!(c.now(), c.now());
    /// ```
    #[must_use]
    pub fn frozen() -> Self {
        Self::new(Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap())
    }

    /// Pin the clock at `t`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::FakeClock;
    /// use chrono::{TimeZone, Utc};
    /// let c = FakeClock::frozen();
    /// c.set(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap());
    /// ```
    pub fn set(&self, t: DateTime<Utc>) {
        self.inner.set(t);
    }

    /// Advance the clock.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::FakeClock;
    /// use chrono::Duration;
    /// let c = FakeClock::frozen();
    /// let before = c.now();
    /// c.advance(Duration::seconds(5));
    /// assert!(c.now() > before);
    /// ```
    pub fn advance(&self, delta: ChronoDuration) {
        self.inner.advance(delta);
    }

    /// Read the current time.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::FakeClock;
    /// let _ = FakeClock::frozen().now();
    /// ```
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        self.inner.now()
    }

    /// "Freeze" — alias of [`Self::set`] for readability.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::FakeClock;
    /// use chrono::{TimeZone, Utc};
    /// let c = FakeClock::frozen();
    /// c.freeze(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap());
    /// ```
    pub fn freeze(&self, t: DateTime<Utc>) {
        self.inner.set(t);
    }

    /// Box this clock as an `Arc<dyn Clock>` for injection into spawned tasks.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::FakeClock;
    /// use spt_state::Clock;
    /// let c: std::sync::Arc<dyn Clock> = FakeClock::frozen().into_arc();
    /// let _ = c.now();
    /// ```
    #[must_use]
    pub fn into_arc(self) -> Arc<dyn Clock> {
        Arc::new(self.inner)
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::frozen()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        self.inner.now()
    }
}

// ---------------------------------------------------------------------------
// StatusSnapshotBuilder
// ---------------------------------------------------------------------------

/// Fluent builder for [`StatusSnapshot`].
///
/// # Examples
///
/// ```
/// use spt_state::testing::StatusSnapshotBuilder;
/// let s = StatusSnapshotBuilder::new()
///     .pid(123)
///     .version("0.1.0")
///     .build();
/// assert_eq!(s.pid, 123);
/// ```
#[derive(Debug, Default, Clone)]
pub struct StatusSnapshotBuilder {
    inner: StatusSnapshot,
}

impl StatusSnapshotBuilder {
    /// New empty builder.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// let _ = StatusSnapshotBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `pid`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// let s = StatusSnapshotBuilder::new().pid(42).build();
    /// assert_eq!(s.pid, 42);
    /// ```
    #[must_use]
    pub fn pid(mut self, pid: u32) -> Self {
        self.inner.pid = pid;
        self
    }

    /// Set `version`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// let s = StatusSnapshotBuilder::new().version("0.1.0").build();
    /// assert_eq!(s.version, "0.1.0");
    /// ```
    #[must_use]
    pub fn version(mut self, v: &str) -> Self {
        v.clone_into(&mut self.inner.version);
        self
    }

    /// Set `config_fingerprint_sha256`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// let s = StatusSnapshotBuilder::new().fingerprint("deadbeef").build();
    /// assert_eq!(s.config_fingerprint_sha256, "deadbeef");
    /// ```
    #[must_use]
    pub fn fingerprint(mut self, fp: &str) -> Self {
        fp.clone_into(&mut self.inner.config_fingerprint_sha256);
        self
    }

    /// Pin `started_at`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use chrono::{TimeZone, Utc};
    /// let s = StatusSnapshotBuilder::new()
    ///     .started_at(Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap())
    ///     .build();
    /// assert!(s.started_at.is_some());
    /// ```
    #[must_use]
    pub fn started_at(mut self, t: DateTime<Utc>) -> Self {
        self.inner.started_at = Some(t);
        self
    }

    /// Pin `written_at` (the last-flush timestamp).
    ///
    /// Useful for building stale-snapshot fixtures that exercise
    /// [`StatusSnapshot::is_stale`](crate::status::StatusSnapshot::is_stale).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use chrono::{TimeZone, Utc};
    /// let s = StatusSnapshotBuilder::new()
    ///     .written_at(Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap())
    ///     .build();
    /// assert!(s.written_at.is_some());
    /// ```
    #[must_use]
    pub fn written_at(mut self, t: DateTime<Utc>) -> Self {
        self.inner.written_at = Some(t);
        self
    }

    /// Append a [`ProfileStatus`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use spt_state::status::ProfileStatus;
    /// let mut p = ProfileStatus::default();
    /// p.id = "p1".into();
    /// p.state = "running".into();
    /// let s = StatusSnapshotBuilder::new().add_profile(p).build();
    /// assert_eq!(s.profiles.len(), 1);
    /// ```
    #[must_use]
    pub fn add_profile(mut self, p: ProfileStatus) -> Self {
        self.inner.profiles.push(p);
        self
    }

    /// Append a [`ForwardStatus`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use spt_state::status::ForwardStatus;
    /// let mut f = ForwardStatus::default();
    /// f.id = "f1".into();
    /// let s = StatusSnapshotBuilder::new().add_forward(f).build();
    /// assert_eq!(s.forwards.len(), 1);
    /// ```
    #[must_use]
    pub fn add_forward(mut self, f: ForwardStatus) -> Self {
        self.inner.forwards.push(f);
        self
    }

    /// Append a [`SessionStatus`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use spt_state::status::SessionStatus;
    /// let s = StatusSnapshotBuilder::new()
    ///     .add_session(SessionStatus::default())
    ///     .build();
    /// assert_eq!(s.sessions.len(), 1);
    /// ```
    #[must_use]
    pub fn add_session(mut self, s: SessionStatus) -> Self {
        self.inner.sessions.push(s);
        self
    }

    /// Append a [`ConnectionStatus`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use spt_state::status::ConnectionStatus;
    /// let s = StatusSnapshotBuilder::new()
    ///     .add_connection(ConnectionStatus::default())
    ///     .build();
    /// assert_eq!(s.connections.len(), 1);
    /// ```
    #[must_use]
    pub fn add_connection(mut self, c: ConnectionStatus) -> Self {
        self.inner.connections.push(c);
        self
    }

    /// Append a [`LastError`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use spt_state::status::LastError;
    /// let mut e = LastError::default();
    /// e.scope = "profile".into();
    /// let s = StatusSnapshotBuilder::new().add_last_error(e).build();
    /// assert_eq!(s.last_errors.len(), 1);
    /// ```
    #[must_use]
    pub fn add_last_error(mut self, e: LastError) -> Self {
        self.inner.last_errors.push(e);
        self
    }

    /// Replace `counters`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use spt_state::status::Counters;
    /// let mut c = Counters::default();
    /// c.bytes_in = 1000;
    /// let s = StatusSnapshotBuilder::new().counters(c).build();
    /// assert_eq!(s.counters.bytes_in, 1000);
    /// ```
    #[must_use]
    pub fn counters(mut self, c: Counters) -> Self {
        self.inner.counters = c;
        self
    }

    /// Replace `failover_state`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// use spt_state::status::{FailoverProfileEntry, FailoverState};
    /// let mut entry = FailoverProfileEntry::default();
    /// entry.profile = "p".into();
    /// let fo = FailoverState { per_profile: vec![entry] };
    /// let s = StatusSnapshotBuilder::new().failover(fo).build();
    /// assert_eq!(s.failover_state.per_profile.len(), 1);
    /// ```
    #[must_use]
    pub fn failover(mut self, f: FailoverState) -> Self {
        self.inner.failover_state = f;
        self
    }

    /// Finalise.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_state::testing::StatusSnapshotBuilder;
    /// let _ = StatusSnapshotBuilder::new().build();
    /// ```
    #[must_use]
    pub fn build(self) -> StatusSnapshot {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// Event corpus
// ---------------------------------------------------------------------------

/// Representative [`Event`] values for tests. Timestamps are pinned at
/// `2026-05-05T12:00:00Z` plus a small per-event offset so ordering tests
/// have something stable to assert against.
///
/// # Examples
///
/// ```
/// use spt_state::testing::event_corpus;
/// let evs = event_corpus();
/// assert!(!evs.is_empty());
/// assert!(evs.iter().any(|e| e.kind == "profile.state"));
/// ```
#[must_use]
pub fn event_corpus() -> Vec<Event> {
    let base = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();

    let mk = |off_secs: i64, kind: &str, sev: &str, extra: serde_json::Value| -> Event {
        let mut ev = Event::new(base + ChronoDuration::seconds(off_secs), kind, sev);
        ev.extra = extra;
        ev
    };

    vec![
        mk(
            0,
            "process.started",
            "info",
            serde_json::json!({ "pid": 1234, "version": "0.1.0" }),
        ),
        mk(
            1,
            "profile.state",
            "info",
            serde_json::json!({ "profile": "smtp-relay", "state": "connecting" }),
        ),
        mk(
            2,
            "profile.state",
            "info",
            serde_json::json!({ "profile": "smtp-relay", "state": "running" }),
        ),
        mk(
            3,
            "forward.connected",
            "info",
            serde_json::json!({ "forward": "smtp-relay/smtp", "local": "127.0.0.1:2525" }),
        ),
        mk(
            5,
            "session.keepalive_missed",
            "warn",
            serde_json::json!({ "session": "s-1", "missed": 1 }),
        ),
        mk(
            7,
            "profile.failed",
            "error",
            serde_json::json!({ "profile": "smtp-relay", "reason": "auth_failed" }),
        ),
        mk(
            10,
            "failover.triggered",
            "warn",
            serde_json::json!({ "profile": "smtp-relay", "from": "primary", "to": "secondary" }),
        ),
        mk(
            12,
            "config.reloaded",
            "info",
            serde_json::json!({ "fingerprint": "deadbeef" }),
        ),
        mk(15, "process.shutdown", "info", serde_json::Value::Null),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_state_dir_creates_layout() {
        let d = TempStateDir::new();
        for sub in [
            "events",
            "sessions",
            "benchmarks",
            "diagnostics",
            "dns",
            "hosts",
        ] {
            assert!(d.path.join(sub).is_dir(), "missing {sub}");
        }
        assert!(d.path.join("remote-log-spool").is_dir());
    }

    #[test]
    fn temp_state_dir_with_status_writes_file() {
        let d = TempStateDir::new().with_status(|s| {
            s.pid = 7;
            s.version = "v".into();
        });
        let bytes = std::fs::read(d.path.join("status.json")).unwrap();
        let s: StatusSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s.pid, 7);
    }

    #[test]
    fn fake_clock_set_advance_freeze() {
        let c = FakeClock::frozen();
        let t0 = c.now();
        c.advance(ChronoDuration::seconds(60));
        assert_eq!(c.now() - t0, ChronoDuration::seconds(60));
        let t = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        c.freeze(t);
        assert_eq!(c.now(), t);
    }

    #[test]
    fn fake_clock_into_arc_is_clock() {
        let arc: Arc<dyn Clock> = FakeClock::frozen().into_arc();
        let _ = arc.now();
    }

    #[test]
    fn status_builder_fluent() {
        let s = StatusSnapshotBuilder::new()
            .pid(1)
            .version("0.0.1")
            .fingerprint("ab")
            .add_profile(ProfileStatus::default())
            .add_forward(ForwardStatus::default())
            .add_session(SessionStatus::default())
            .add_connection(ConnectionStatus::default())
            .add_last_error(LastError::default())
            .counters(Counters::default())
            .failover(FailoverState::default())
            .build();
        assert_eq!(s.pid, 1);
        assert_eq!(s.profiles.len(), 1);
        assert_eq!(s.forwards.len(), 1);
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.connections.len(), 1);
        assert_eq!(s.last_errors.len(), 1);
    }

    #[test]
    fn event_corpus_is_chronological() {
        let evs = event_corpus();
        assert!(evs.len() >= 5);
        for w in evs.windows(2) {
            assert!(w[0].ts <= w[1].ts);
        }
    }

    #[test]
    fn event_corpus_serializes_jsonl_friendly() {
        for ev in event_corpus() {
            let s = serde_json::to_string(&ev).expect("serialize event");
            assert!(s.starts_with('{') && s.ends_with('}'));
            assert!(!s.contains('\n'), "single-line jsonl invariant");
        }
    }
}
