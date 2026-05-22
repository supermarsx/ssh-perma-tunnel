//! Windows Event Log integration for spt.
//!
//! Provides three operations per spec §13.10:
//!
//! - [`register_source`] — write the registry entries that declare an
//!   Event Log source under
//!   `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<channel>\<name>`.
//! - [`unregister_source`] — remove the same key.
//! - [`report_event`] — emit a single event using `ReportEventW`.
//!
//! On non-Windows targets every entry point returns
//! [`spt_core::error::Error::UnsupportedPlatform`]. The Windows-side
//! implementations live in `imp.rs`. Tests on non-Windows assert the stub
//! behaviour; on Windows a `--ignored` test exercises a registry round-trip
//! against `HKCU` (test-safe) to keep CI from needing admin.
//!
//! # Internal dispatch
//!
//! The three free functions delegate to an [`EventLogBackend`] trait object
//! held inside a process-global [`OnceLock`]. The default backend is the
//! platform-appropriate real impl (Win32 on Windows, no-op stub elsewhere);
//! tests (or downstream callers using `feature = "testing"`) may install a
//! [`testing::MockEventLogBackend`] **before any other call into this crate
//! occurs** via [`testing::set_test_backend`]. Once the `OnceLock` is
//! initialized it cannot be replaced; `set_test_backend` returns `Err` if a
//! backend is already installed (real or mock). This is by design and
//! documented on that function.

#![warn(missing_docs)]
// t8-D2: harden the unsafe boundary. Any `unsafe fn` body that calls another
// unsafe operation without its own `unsafe { … }` block is a compile error.
// All FFI in `imp.rs` is wrapped in explicit blocks with adjacent SAFETY
// comments documented per `clippy::undocumented_unsafe_blocks`.
#![deny(unsafe_op_in_unsafe_fn)]

use std::path::Path;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use spt_core::error::Result;

#[cfg(windows)]
mod imp;
#[cfg(not(windows))]
mod stub;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Severity for `report_event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// `EVENTLOG_INFORMATION_TYPE`.
    Info,
    /// `EVENTLOG_WARNING_TYPE`.
    Warning,
    /// `EVENTLOG_ERROR_TYPE`.
    Error,
}

/// Channel that receives the source registration.
///
/// Defaults to `Application`. Custom channels (e.g. `spt`) require a manifest
/// install which is out of scope for this crate.
pub const DEFAULT_CHANNEL: &str = "Application";

/// Internal trait abstracting the three Event Log operations.
///
/// Implementors:
///
/// - [`imp::WindowsEventLogBackend`] (Windows only) — calls real Win32.
/// - [`stub::StubEventLogBackend`] (non-Windows) — returns
///   `Error::UnsupportedPlatform`.
/// - [`testing::MockEventLogBackend`] (when `feature = "testing"` or under
///   `cfg(test)`) — records every call into an in-memory `Vec`.
///
/// `channel` is the **resolved** channel name (the free functions apply the
/// `Option<&str> -> DEFAULT_CHANNEL` fallback before dispatching).
///
/// This trait is `pub` so [`testing::set_test_backend`] can take a
/// `Box<dyn EventLogBackend>` parameter when the `testing` feature is
/// enabled. The default trait impls (`WindowsEventLogBackend` /
/// `StubEventLogBackend`) remain crate-private; only
/// `testing::MockEventLogBackend` is exposed for external installation.
pub trait EventLogBackend: Send + Sync {
    /// Register an Event Log source under `channel` (already resolved).
    fn register_source(&self, name: &str, channel: &str, message_dll: Option<&Path>) -> Result<()>;
    /// Unregister an Event Log source from `channel` (already resolved).
    fn unregister_source(&self, name: &str, channel: &str) -> Result<()>;
    /// Emit a single event against an already-registered source.
    fn report_event(&self, name: &str, level: Level, event_id: u32, message: &str) -> Result<()>;
}

static BACKEND: OnceLock<Box<dyn EventLogBackend>> = OnceLock::new();

#[cfg(windows)]
fn default_backend() -> Box<dyn EventLogBackend> {
    Box::new(imp::WindowsEventLogBackend)
}

#[cfg(not(windows))]
fn default_backend() -> Box<dyn EventLogBackend> {
    Box::new(stub::StubEventLogBackend)
}

/// Resolve the active backend, initialising the default on first call.
pub(crate) fn backend() -> &'static dyn EventLogBackend {
    BACKEND.get_or_init(default_backend).as_ref()
}

/// Register an Event Log source.
///
/// `name` is the source name; `channel` defaults to `Application` if `None`.
/// `message_dll` is the path to a message-table DLL — most installs pass the
/// spt binary itself (which embeds the message table) or `None` to skip
/// (events still fire but Event Viewer renders the description as raw text).
pub fn register_source(
    name: &str,
    channel: Option<&str>,
    message_dll: Option<&Path>,
) -> Result<()> {
    let ch = channel.unwrap_or(DEFAULT_CHANNEL);
    backend().register_source(name, ch, message_dll)
}

/// Unregister an Event Log source.
pub fn unregister_source(name: &str, channel: Option<&str>) -> Result<()> {
    let ch = channel.unwrap_or(DEFAULT_CHANNEL);
    backend().unregister_source(name, ch)
}

/// Emit a single event.
pub fn report_event(name: &str, level: Level, event_id: u32, message: &str) -> Result<()> {
    backend().report_event(name, level, event_id, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn non_windows_returns_unsupported() {
        // NOTE: this test relies on the default stub backend being installed.
        // It must run before any other test in this binary installs a mock,
        // or the `OnceLock` will have been claimed.
        //
        // We accept the side-effect of initialising `BACKEND` with the stub;
        // subsequent `set_test_backend` calls in this binary will fail, so
        // every other inline test in `lib.rs` must avoid the global dispatch
        // entirely and operate on `MockEventLogBackend` directly.
        let err = register_source("spt-test", None, None).unwrap_err();
        assert!(matches!(
            err,
            spt_core::error::Error::UnsupportedPlatform(_)
        ));
        let err = unregister_source("spt-test", None).unwrap_err();
        assert!(matches!(
            err,
            spt_core::error::Error::UnsupportedPlatform(_)
        ));
        let err = report_event("spt-test", Level::Info, 1, "hi").unwrap_err();
        assert!(matches!(
            err,
            spt_core::error::Error::UnsupportedPlatform(_)
        ));
    }

    #[test]
    fn level_round_trip() {
        let lv = Level::Warning;
        let s = serde_json::to_string(&lv).unwrap();
        let back: Level = serde_json::from_str(&s).unwrap();
        assert_eq!(lv, back);
    }

    #[test]
    fn level_variants_serialize_lowercase() {
        assert_eq!(serde_json::to_string(&Level::Info).unwrap(), "\"info\"");
        assert_eq!(
            serde_json::to_string(&Level::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(serde_json::to_string(&Level::Error).unwrap(), "\"error\"");
    }

    #[test]
    fn level_is_copy_and_eq() {
        let a = Level::Info;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(Level::Info, Level::Warning);
        assert_ne!(Level::Warning, Level::Error);
    }

    #[test]
    fn default_channel_constant() {
        assert_eq!(DEFAULT_CHANNEL, "Application");
    }

    // ---- MockEventLogBackend unit tests (do NOT route through global) -----
    //
    // The advisor flagged the OnceLock-vs-swap hazard: we cannot reinstall a
    // mock between tests if `BACKEND` has been claimed. So we exercise the
    // mock implementation directly here, and reserve the global dispatch path
    // for the dedicated `tests/mock_backend.rs` IT binary.

    use crate::testing::{MockEventLogBackend, RecordedCall};
    use std::path::PathBuf;

    #[test]
    fn mock_records_register_source_with_dll() {
        let mock = MockEventLogBackend::new();
        let dll = PathBuf::from(r"C:\Program Files\spt\spt.exe");
        mock.register_source("src", "Application", Some(&dll))
            .unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            RecordedCall::RegisterSource {
                name,
                channel,
                message_dll,
            } => {
                assert_eq!(name, "src");
                assert_eq!(channel, "Application");
                assert_eq!(message_dll.as_deref(), Some(dll.as_path()));
            }
            other => panic!("unexpected call: {other:?}"),
        }
    }

    #[test]
    fn mock_records_register_source_without_dll() {
        let mock = MockEventLogBackend::new();
        mock.register_source("src", "Application", None).unwrap();
        let calls = mock.calls();
        assert!(matches!(
            calls[0],
            RecordedCall::RegisterSource {
                ref message_dll,
                ..
            } if message_dll.is_none()
        ));
    }

    #[test]
    fn mock_records_unregister_source() {
        let mock = MockEventLogBackend::new();
        mock.unregister_source("src", "Application").unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            RecordedCall::UnregisterSource { name, channel } => {
                assert_eq!(name, "src");
                assert_eq!(channel, "Application");
            }
            other => panic!("unexpected call: {other:?}"),
        }
    }

    #[test]
    fn mock_records_report_event() {
        let mock = MockEventLogBackend::new();
        mock.report_event("src", Level::Warning, 42, "hello")
            .unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            RecordedCall::ReportEvent {
                name,
                level,
                event_id,
                message,
            } => {
                assert_eq!(name, "src");
                assert_eq!(*level, Level::Warning);
                assert_eq!(*event_id, 42);
                assert_eq!(message, "hello");
            }
            other => panic!("unexpected call: {other:?}"),
        }
    }

    #[test]
    fn mock_records_calls_in_order() {
        let mock = MockEventLogBackend::new();
        mock.register_source("s", "Application", None).unwrap();
        mock.report_event("s", Level::Info, 1, "a").unwrap();
        mock.report_event("s", Level::Error, 2, "b").unwrap();
        mock.unregister_source("s", "Application").unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 4);
        assert!(matches!(calls[0], RecordedCall::RegisterSource { .. }));
        assert!(matches!(
            calls[1],
            RecordedCall::ReportEvent { event_id: 1, .. }
        ));
        assert!(matches!(
            calls[2],
            RecordedCall::ReportEvent { event_id: 2, .. }
        ));
        assert!(matches!(calls[3], RecordedCall::UnregisterSource { .. }));
    }

    #[test]
    fn mock_len_and_is_empty() {
        let mock = MockEventLogBackend::new();
        assert!(mock.is_empty());
        assert_eq!(mock.len(), 0);
        mock.report_event("s", Level::Info, 1, "x").unwrap();
        assert!(!mock.is_empty());
        assert_eq!(mock.len(), 1);
    }

    #[test]
    fn mock_clear_resets() {
        let mock = MockEventLogBackend::new();
        mock.report_event("s", Level::Info, 1, "x").unwrap();
        mock.report_event("s", Level::Info, 2, "y").unwrap();
        assert_eq!(mock.len(), 2);
        mock.clear();
        assert!(mock.is_empty());
    }

    #[test]
    fn mock_default_matches_new() {
        let a = MockEventLogBackend::new();
        let b = MockEventLogBackend::default();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn mock_through_trait_object() {
        let mock = MockEventLogBackend::new();
        let b: &dyn EventLogBackend = &mock;
        b.report_event("s", Level::Info, 99, "via dyn").unwrap();
        b.register_source("s", "Application", None).unwrap();
        b.unregister_source("s", "Application").unwrap();
        assert_eq!(mock.len(), 3);
    }

    #[test]
    fn mock_filter_helpers() {
        let mock = MockEventLogBackend::new();
        mock.register_source("a", "Application", None).unwrap();
        mock.report_event("a", Level::Info, 1, "x").unwrap();
        mock.report_event("a", Level::Error, 2, "y").unwrap();
        mock.unregister_source("a", "Application").unwrap();
        assert_eq!(mock.register_calls().len(), 1);
        assert_eq!(mock.unregister_calls().len(), 1);
        assert_eq!(mock.report_calls().len(), 2);
    }

    #[test]
    fn mock_error_injection_register() {
        let mock = MockEventLogBackend::new();
        mock.set_register_error(Some("boom"));
        let err = mock.register_source("s", "Application", None).unwrap_err();
        assert!(matches!(
            err,
            spt_core::error::Error::WindowsEventLogFailed(_)
        ));
        assert_eq!(mock.len(), 0, "errored calls must NOT be recorded");
    }

    #[test]
    fn mock_error_injection_unregister() {
        let mock = MockEventLogBackend::new();
        mock.set_unregister_error(Some("boom"));
        let err = mock.unregister_source("s", "Application").unwrap_err();
        assert!(matches!(
            err,
            spt_core::error::Error::WindowsEventLogFailed(_)
        ));
        assert_eq!(mock.len(), 0);
    }

    #[test]
    fn mock_error_injection_report() {
        let mock = MockEventLogBackend::new();
        mock.set_report_error(Some("boom"));
        let err = mock.report_event("s", Level::Info, 1, "x").unwrap_err();
        assert!(matches!(
            err,
            spt_core::error::Error::WindowsEventLogFailed(_)
        ));
        assert_eq!(mock.len(), 0);
    }

    #[test]
    fn mock_clear_errors_restores_success() {
        let mock = MockEventLogBackend::new();
        mock.set_report_error(Some("boom"));
        assert!(mock.report_event("s", Level::Info, 1, "x").is_err());
        mock.set_report_error(None);
        mock.report_event("s", Level::Info, 1, "x").unwrap();
        assert_eq!(mock.len(), 1);
    }

    #[test]
    fn mock_shared_across_threads() {
        use std::sync::Arc;
        use std::thread;

        let mock = Arc::new(MockEventLogBackend::new());
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let m = Arc::clone(&mock);
            handles.push(thread::spawn(move || {
                m.report_event("s", Level::Info, i, "x").unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(mock.len(), 8);
    }
}
