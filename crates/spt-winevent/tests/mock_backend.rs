//! Integration tests for the global `EventLogBackend` dispatch.
//!
//! `OnceLock`-backed dispatch means this whole binary shares a single mock
//! installed at the top of [`install_once`]. Every test must:
//!
//! - Use a **unique** source name (typically the test fn name) so parallel
//!   tests don't bleed entries into each other's filter results.
//! - Read back via [`crate::filter_by_name`] rather than expecting a fixed
//!   call count.
//!
//! Error-injection is **not** exercised here (it would race across tests
//! sharing the same mock). The inline `lib.rs` unit tests cover error
//! injection against a fresh `MockEventLogBackend` directly.

#![cfg(feature = "testing")]

use std::path::PathBuf;
use std::sync::OnceLock;

use spt_winevent::testing::{set_test_backend, MockEventLogBackend, RecordedCall};
use spt_winevent::{register_source, report_event, unregister_source, Level, DEFAULT_CHANNEL};

static MOCK: OnceLock<MockEventLogBackend> = OnceLock::new();

fn install_once() -> &'static MockEventLogBackend {
    MOCK.get_or_init(|| {
        let mock = MockEventLogBackend::new();
        // First test to call this wins; subsequent tests reuse the install.
        // We install a *clone* so the caller can hold their own handle for
        // assertions while the global dispatch holds another.
        assert!(
            set_test_backend(Box::new(mock.clone())).is_ok(),
            "backend slot must be virgin at IT-binary startup"
        );
        mock
    })
}

fn filter_by_name(mock: &MockEventLogBackend, needle: &str) -> Vec<RecordedCall> {
    mock.calls()
        .into_iter()
        .filter(|c| match c {
            RecordedCall::RegisterSource { name, .. }
            | RecordedCall::UnregisterSource { name, .. }
            | RecordedCall::ReportEvent { name, .. } => name == needle,
        })
        .collect()
}

#[test]
fn register_source_routes_through_mock() {
    let mock = install_once();
    let name = "it-register-source-routes";
    register_source(name, None, None).unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    match &mine[0] {
        RecordedCall::RegisterSource {
            channel,
            message_dll,
            ..
        } => {
            assert_eq!(channel, DEFAULT_CHANNEL);
            assert!(message_dll.is_none());
        }
        other => panic!("expected RegisterSource, got {other:?}"),
    }
}

#[test]
fn register_source_with_custom_channel() {
    let mock = install_once();
    let name = "it-register-custom-channel";
    register_source(name, Some("CustomChannel"), None).unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    match &mine[0] {
        RecordedCall::RegisterSource { channel, .. } => {
            assert_eq!(channel, "CustomChannel");
        }
        other => panic!("expected RegisterSource, got {other:?}"),
    }
}

#[test]
fn register_source_with_message_dll() {
    let mock = install_once();
    let name = "it-register-with-dll";
    let dll = PathBuf::from("/opt/spt/spt.exe");
    register_source(name, None, Some(&dll)).unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    match &mine[0] {
        RecordedCall::RegisterSource { message_dll, .. } => {
            assert_eq!(message_dll.as_deref(), Some(dll.as_path()));
        }
        other => panic!("expected RegisterSource, got {other:?}"),
    }
}

#[test]
fn unregister_source_routes_through_mock() {
    let mock = install_once();
    let name = "it-unregister-source";
    unregister_source(name, None).unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    match &mine[0] {
        RecordedCall::UnregisterSource { channel, .. } => {
            assert_eq!(channel, DEFAULT_CHANNEL);
        }
        other => panic!("expected UnregisterSource, got {other:?}"),
    }
}

#[test]
fn unregister_source_with_custom_channel() {
    let mock = install_once();
    let name = "it-unregister-custom-channel";
    unregister_source(name, Some("OperationalChannel")).unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    match &mine[0] {
        RecordedCall::UnregisterSource { channel, .. } => {
            assert_eq!(channel, "OperationalChannel");
        }
        other => panic!("expected UnregisterSource, got {other:?}"),
    }
}

#[test]
fn report_event_routes_info() {
    let mock = install_once();
    let name = "it-report-info";
    report_event(name, Level::Info, 100, "info message").unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    match &mine[0] {
        RecordedCall::ReportEvent {
            level,
            event_id,
            message,
            ..
        } => {
            assert_eq!(*level, Level::Info);
            assert_eq!(*event_id, 100);
            assert_eq!(message, "info message");
        }
        other => panic!("expected ReportEvent, got {other:?}"),
    }
}

#[test]
fn report_event_routes_warning() {
    let mock = install_once();
    let name = "it-report-warning";
    report_event(name, Level::Warning, 200, "warn message").unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    assert!(matches!(
        mine[0],
        RecordedCall::ReportEvent {
            level: Level::Warning,
            event_id: 200,
            ..
        }
    ));
}

#[test]
fn report_event_routes_error() {
    let mock = install_once();
    let name = "it-report-error";
    report_event(name, Level::Error, 300, "err message").unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    assert!(matches!(
        mine[0],
        RecordedCall::ReportEvent {
            level: Level::Error,
            event_id: 300,
            ..
        }
    ));
}

#[test]
fn lifecycle_register_report_unregister() {
    let mock = install_once();
    let name = "it-lifecycle";
    register_source(name, None, None).unwrap();
    report_event(name, Level::Info, 1, "alive").unwrap();
    report_event(name, Level::Warning, 2, "wobble").unwrap();
    unregister_source(name, None).unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 4);
    assert!(matches!(mine[0], RecordedCall::RegisterSource { .. }));
    assert!(matches!(
        mine[1],
        RecordedCall::ReportEvent { event_id: 1, .. }
    ));
    assert!(matches!(
        mine[2],
        RecordedCall::ReportEvent { event_id: 2, .. }
    ));
    assert!(matches!(mine[3], RecordedCall::UnregisterSource { .. }));
}

#[test]
fn empty_message_body_is_preserved() {
    let mock = install_once();
    let name = "it-empty-message";
    report_event(name, Level::Info, 1, "").unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    match &mine[0] {
        RecordedCall::ReportEvent { message, .. } => assert_eq!(message, ""),
        other => panic!("expected ReportEvent, got {other:?}"),
    }
}

#[test]
fn unicode_message_round_trips() {
    let mock = install_once();
    let name = "it-unicode";
    let msg = "héllo 世界 🎉";
    report_event(name, Level::Info, 1, msg).unwrap();
    let mine = filter_by_name(mock, name);
    assert_eq!(mine.len(), 1);
    match &mine[0] {
        RecordedCall::ReportEvent { message, .. } => assert_eq!(message, msg),
        other => panic!("expected ReportEvent, got {other:?}"),
    }
}

#[test]
fn second_set_test_backend_returns_err() {
    install_once();
    // Slot is now claimed; trying again must fail.
    let result = set_test_backend(Box::new(MockEventLogBackend::new()));
    assert!(
        result.is_err(),
        "set_test_backend must reject a second install"
    );
}
