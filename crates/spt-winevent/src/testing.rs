//! Public test facilities for `spt-winevent` (gated behind `feature = "testing"`).
//!
//! `spt-winevent` exposes free functions ([`crate::report_event`] and friends)
//! rather than a trait, so this module introduces a thin local
//! [`EventReporter`] trait whose only job is to be implementable by an
//! in-memory recorder. Code that wants to be testable can take an
//! `Arc<dyn EventReporter>` and substitute [`RecordingEventLog`] in tests
//! while wiring [`crate::report_event`] in production.
//!
//! **Cross-platform behavior**: this module is identical on every OS. On
//! Windows it does **not** call into `ReportEventW` — it captures events into
//! an in-memory `Vec`. Tests using `RecordingEventLog` are therefore
//! portable.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::Level;

/// One captured event.
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
/// (in production).
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
}
