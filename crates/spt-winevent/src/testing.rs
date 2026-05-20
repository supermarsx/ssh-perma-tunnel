//! Public test facilities for `spt-winevent` (gated behind `feature = "testing"`).
//!
//! Two complementary abstractions live here:
//!
//! 1. [`MockEventLogBackend`] — implements the **crate-internal**
//!    `EventLogBackend` trait. Install it via [`set_test_backend`] to capture
//!    every call routed through the public [`crate::register_source`] /
//!    [`crate::unregister_source`] / [`crate::report_event`] free functions.
//!    The backend slot is a process-global [`std::sync::OnceLock`]: install
//!    **exactly once per test binary**, before any other call into this
//!    crate. Subsequent installs return `Err`.
//!
//! 2. [`EventReporter`] / [`RecordingEventLog`] — a separate, per-consumer
//!    trait-object abstraction for code that wants to be testable without
//!    reaching for the global dispatch. Identical behavior on every OS;
//!    never touches the real Event Log.
//!
//! The two abstractions are intentionally distinct: `EventReporter` is for
//! application code that wants to pass an `Arc<dyn EventReporter>` around;
//! `MockEventLogBackend` is for asserting against this crate's public API
//! itself.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use spt_core::error::{Error, Result};

use crate::{EventLogBackend, Level};

/// One captured call into a [`MockEventLogBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedCall {
    /// [`crate::register_source`] was invoked.
    RegisterSource {
        /// Source name.
        name: String,
        /// Resolved channel name (already defaulted to `"Application"` if
        /// the caller passed `None`).
        channel: String,
        /// Path to the message-table DLL, if supplied.
        message_dll: Option<PathBuf>,
    },
    /// [`crate::unregister_source`] was invoked.
    UnregisterSource {
        /// Source name.
        name: String,
        /// Resolved channel name.
        channel: String,
    },
    /// [`crate::report_event`] was invoked.
    ReportEvent {
        /// Source name passed to `RegisterEventSourceW`.
        name: String,
        /// Severity.
        level: Level,
        /// Event ID.
        event_id: u32,
        /// Message body.
        message: String,
    },
}

#[derive(Default)]
struct MockState {
    calls: Vec<RecordedCall>,
    register_err: Option<String>,
    unregister_err: Option<String>,
    report_err: Option<String>,
}

/// In-memory [`EventLogBackend`] that records every call.
///
/// Identical behaviour on every OS. Suitable for installing as the
/// process-global backend via [`set_test_backend`], or for direct use behind
/// a `&dyn EventLogBackend` in unit tests.
///
/// Errored calls (when one of the `set_*_error` injections is configured)
/// are **not** recorded — only successful operations land in [`calls`].
///
/// [`calls`]: MockEventLogBackend::calls
#[derive(Default, Clone)]
pub struct MockEventLogBackend {
    inner: Arc<Mutex<MockState>>,
}

impl std::fmt::Debug for MockEventLogBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.lock();
        f.debug_struct("MockEventLogBackend")
            .field("calls", &state.calls.len())
            .field("register_err", &state.register_err)
            .field("unregister_err", &state.unregister_err)
            .field("report_err", &state.report_err)
            .finish()
    }
}

impl MockEventLogBackend {
    /// New empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every recorded call, in insertion order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.inner.lock().calls.clone()
    }

    /// Total number of recorded calls.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().calls.len()
    }

    /// `true` iff no calls have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().calls.is_empty()
    }

    /// Drop every recorded call (but keep error-injection state).
    pub fn clear(&self) {
        self.inner.lock().calls.clear();
    }

    /// Convenience: only the `RegisterSource` entries.
    #[must_use]
    pub fn register_calls(&self) -> Vec<RecordedCall> {
        self.calls()
            .into_iter()
            .filter(|c| matches!(c, RecordedCall::RegisterSource { .. }))
            .collect()
    }

    /// Convenience: only the `UnregisterSource` entries.
    #[must_use]
    pub fn unregister_calls(&self) -> Vec<RecordedCall> {
        self.calls()
            .into_iter()
            .filter(|c| matches!(c, RecordedCall::UnregisterSource { .. }))
            .collect()
    }

    /// Convenience: only the `ReportEvent` entries.
    #[must_use]
    pub fn report_calls(&self) -> Vec<RecordedCall> {
        self.calls()
            .into_iter()
            .filter(|c| matches!(c, RecordedCall::ReportEvent { .. }))
            .collect()
    }

    /// Make subsequent `register_source` calls return
    /// `Error::WindowsEventLogFailed(msg)`. Pass `None` to clear.
    pub fn set_register_error(&self, msg: Option<&str>) {
        self.inner.lock().register_err = msg.map(str::to_owned);
    }

    /// Make subsequent `unregister_source` calls return
    /// `Error::WindowsEventLogFailed(msg)`. Pass `None` to clear.
    pub fn set_unregister_error(&self, msg: Option<&str>) {
        self.inner.lock().unregister_err = msg.map(str::to_owned);
    }

    /// Make subsequent `report_event` calls return
    /// `Error::WindowsEventLogFailed(msg)`. Pass `None` to clear.
    pub fn set_report_error(&self, msg: Option<&str>) {
        self.inner.lock().report_err = msg.map(str::to_owned);
    }
}

impl EventLogBackend for MockEventLogBackend {
    fn register_source(&self, name: &str, channel: &str, message_dll: Option<&Path>) -> Result<()> {
        let mut state = self.inner.lock();
        if let Some(msg) = state.register_err.clone() {
            return Err(Error::WindowsEventLogFailed(msg));
        }
        state.calls.push(RecordedCall::RegisterSource {
            name: name.to_owned(),
            channel: channel.to_owned(),
            message_dll: message_dll.map(Path::to_path_buf),
        });
        Ok(())
    }

    fn unregister_source(&self, name: &str, channel: &str) -> Result<()> {
        let mut state = self.inner.lock();
        if let Some(msg) = state.unregister_err.clone() {
            return Err(Error::WindowsEventLogFailed(msg));
        }
        state.calls.push(RecordedCall::UnregisterSource {
            name: name.to_owned(),
            channel: channel.to_owned(),
        });
        Ok(())
    }

    fn report_event(&self, name: &str, level: Level, event_id: u32, message: &str) -> Result<()> {
        let mut state = self.inner.lock();
        if let Some(msg) = state.report_err.clone() {
            return Err(Error::WindowsEventLogFailed(msg));
        }
        state.calls.push(RecordedCall::ReportEvent {
            name: name.to_owned(),
            level,
            event_id,
            message: message.to_owned(),
        });
        Ok(())
    }
}

/// Install `backend` as the process-global Event Log backend.
///
/// The slot is a `OnceLock` — this function succeeds **only** if no prior
/// call into [`crate::register_source`] / [`crate::unregister_source`] /
/// [`crate::report_event`] (or to this function) has already initialised it.
/// Returns `Err(backend)` (the original `Box`) on collision.
///
/// Intended use: at the very top of a test binary, before any other crate
/// API call. Per-test swapping is **not** supported by this primitive; if
/// you need that, build your own [`EventLogBackend`]-impl on top of a
/// `Mutex`/`RwLock` of swappable inner mocks.
///
/// # Errors
///
/// Returns `Err` (handing the boxed backend back) if a backend has already
/// been installed in this process — either explicitly via a prior call to
/// this function, or implicitly by the first call to the public free
/// functions (which lazy-init the platform default).
#[cfg(any(test, feature = "testing"))]
pub fn set_test_backend(
    backend: Box<dyn EventLogBackend + 'static>,
) -> std::result::Result<(), Box<dyn EventLogBackend + 'static>> {
    crate::BACKEND.set(backend)
}

// ---------------------------------------------------------------------------
// Legacy per-consumer abstraction (kept verbatim from the pre-refactor file).
// ---------------------------------------------------------------------------

/// One captured event (legacy [`EventReporter`] abstraction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEntry {
    /// Severity.
    pub level: Level,
    /// Event ID.
    pub event_id: u32,
    /// Rendered message body.
    pub message: String,
}

/// Trait abstracting "emit one Event Log entry".
///
/// Implementors can capture (in tests) or forward to [`crate::report_event`]
/// (in production). Distinct from the crate-internal [`EventLogBackend`]:
/// this is intended for **consumer code** that wants to be testable via DI
/// of an `Arc<dyn EventReporter>`, whereas `EventLogBackend` covers the
/// crate's own public free-function dispatch.
pub trait EventReporter: Send + Sync {
    /// Emit one event.
    fn report(&self, level: Level, event_id: u32, message: &str);
}

/// In-memory [`EventReporter`] that captures every emit into a `Vec`.
///
/// Identical behavior on Windows and non-Windows targets — never touches the
/// real Event Log.
///
/// ```
/// use spt_winevent::testing::{RecordingEventLog, EventReporter};
/// use spt_winevent::Level;
///
/// let log = RecordingEventLog::new();
/// log.report(Level::Info, 1, "hello");
/// log.report(Level::Warning, 2, "careful");
/// let events = log.events();
/// assert_eq!(events.len(), 2);
/// assert_eq!(events[0].event_id, 1);
/// assert_eq!(events[1].level, Level::Warning);
/// ```
#[derive(Debug, Default, Clone)]
pub struct RecordingEventLog {
    inner: Arc<Mutex<Vec<EventEntry>>>,
}

impl RecordingEventLog {
    /// New empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every captured event, in insertion order.
    #[must_use]
    pub fn events(&self) -> Vec<EventEntry> {
        self.inner.lock().clone()
    }

    /// Number of captured events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// True iff no events have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Drop every captured event.
    pub fn clear(&self) {
        self.inner.lock().clear();
    }
}

impl EventReporter for RecordingEventLog {
    fn report(&self, level: Level, event_id: u32, message: &str) {
        self.inner.lock().push(EventEntry {
            level,
            event_id,
            message: message.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_events_in_order() {
        let log = RecordingEventLog::new();
        log.report(Level::Info, 10, "first");
        log.report(Level::Error, 20, "second");
        let evs = log.events();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].event_id, 10);
        assert_eq!(evs[0].level, Level::Info);
        assert_eq!(evs[0].message, "first");
        assert_eq!(evs[1].event_id, 20);
        assert_eq!(evs[1].level, Level::Error);
        assert_eq!(evs[1].message, "second");
    }

    #[test]
    fn clear_resets() {
        let log = RecordingEventLog::new();
        log.report(Level::Info, 1, "hi");
        assert_eq!(log.len(), 1);
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn through_trait_object() {
        let log = RecordingEventLog::new();
        let r: &dyn EventReporter = &log;
        r.report(Level::Warning, 7, "hello");
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn event_entry_equality() {
        let a = EventEntry {
            level: Level::Info,
            event_id: 1,
            message: "x".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn recording_event_log_default_is_empty() {
        let log = RecordingEventLog::default();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn recording_event_log_clone_shares_buffer() {
        let log = RecordingEventLog::new();
        let twin = log.clone();
        log.report(Level::Info, 1, "hi");
        assert_eq!(twin.len(), 1, "Arc-backed buffer must be shared");
    }

    #[test]
    fn recorded_call_equality() {
        let a = RecordedCall::ReportEvent {
            name: "s".into(),
            level: Level::Info,
            event_id: 1,
            message: "x".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn mock_debug_renders_call_count() {
        let mock = MockEventLogBackend::new();
        let s = format!("{mock:?}");
        assert!(s.contains("MockEventLogBackend"));
        assert!(s.contains("calls"));
    }
}
