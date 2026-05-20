//! Non-Windows stub: every operation returns
//! [`spt_core::error::Error::UnsupportedPlatform`].

use std::path::Path;

use spt_core::error::{Error, Result};

use crate::{EventLogBackend, Level};

pub(crate) fn unsupported(op: &str) -> Result<()> {
    Err(Error::UnsupportedPlatform(format!(
        "spt-winevent::{op} requires Windows"
    )))
}

/// No-op backend used on every non-Windows target.
///
/// Each method returns `Error::UnsupportedPlatform`. Default backend off
/// Windows; holds no state.
pub(crate) struct StubEventLogBackend;

impl EventLogBackend for StubEventLogBackend {
    fn register_source(
        &self,
        _name: &str,
        _channel: &str,
        _message_dll: Option<&Path>,
    ) -> Result<()> {
        unsupported("register_source")
    }

    fn unregister_source(&self, _name: &str, _channel: &str) -> Result<()> {
        unsupported("unregister_source")
    }

    fn report_event(
        &self,
        _name: &str,
        _level: Level,
        _event_id: u32,
        _message: &str,
    ) -> Result<()> {
        unsupported("report_event")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_message_names_op() {
        let err = unsupported("foo").unwrap_err();
        match err {
            Error::UnsupportedPlatform(msg) => {
                assert!(msg.contains("foo"), "{msg}");
                assert!(msg.contains("Windows"), "{msg}");
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[test]
    fn stub_register_returns_unsupported() {
        let b = StubEventLogBackend;
        let err = b.register_source("s", "Application", None).unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[test]
    fn stub_register_with_dll_returns_unsupported() {
        let b = StubEventLogBackend;
        let p = std::path::PathBuf::from("/tmp/spt");
        let err = b.register_source("s", "Application", Some(&p)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[test]
    fn stub_unregister_returns_unsupported() {
        let b = StubEventLogBackend;
        let err = b.unregister_source("s", "Application").unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[test]
    fn stub_report_returns_unsupported() {
        let b = StubEventLogBackend;
        for lv in [Level::Info, Level::Warning, Level::Error] {
            let err = b.report_event("s", lv, 1, "msg").unwrap_err();
            assert!(matches!(err, Error::UnsupportedPlatform(_)));
        }
    }

    #[test]
    fn stub_through_dyn_trait() {
        let b: Box<dyn EventLogBackend> = Box::new(StubEventLogBackend);
        assert!(b.register_source("s", "Application", None).is_err());
        assert!(b.unregister_source("s", "Application").is_err());
        assert!(b.report_event("s", Level::Info, 1, "x").is_err());
    }
}
