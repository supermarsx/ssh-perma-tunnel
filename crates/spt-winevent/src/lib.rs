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

#![warn(missing_docs)]

use std::path::Path;

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
    #[cfg(windows)]
    {
        imp::register_source(name, ch, message_dll)
    }
    #[cfg(not(windows))]
    {
        let _ = (name, ch, message_dll);
        stub::unsupported("register_source")
    }
}

/// Unregister an Event Log source.
pub fn unregister_source(name: &str, channel: Option<&str>) -> Result<()> {
    let ch = channel.unwrap_or(DEFAULT_CHANNEL);
    #[cfg(windows)]
    {
        imp::unregister_source(name, ch)
    }
    #[cfg(not(windows))]
    {
        let _ = (name, ch);
        stub::unsupported("unregister_source")
    }
}

/// Emit a single event.
pub fn report_event(name: &str, level: Level, event_id: u32, message: &str) -> Result<()> {
    #[cfg(windows)]
    {
        imp::report_event(name, level, event_id, message)
    }
    #[cfg(not(windows))]
    {
        let _ = (name, level, event_id, message);
        stub::unsupported("report_event")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn non_windows_returns_unsupported() {
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
}
