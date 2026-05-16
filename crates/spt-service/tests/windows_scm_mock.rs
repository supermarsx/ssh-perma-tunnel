//! Integration tests for the [`ScmBackend`] refactor inside
//! `windows_scm.rs`.
//!
//! Drives [`ScmManagerImpl`] against a recording [`MockScmBackend`] —
//! exercises every public lifecycle method without touching real Windows
//! SCM. Runs on every host; requires the `testing` feature.

#![cfg(feature = "testing")]

use std::sync::Arc;

use spt_service::testing::{BackendStatus, MockScmBackend, ScmAccess, ScmCall};
use spt_service::windows_scm::{ScmManagerImpl, WindowsScmManager};
use spt_service::{ServiceManager, ServiceSpec, ServiceState};

fn spec(name: &str) -> ServiceSpec {
    ServiceSpec {
        name: name.to_string(),
        description: format!("spt — IT mock svc {name}"),
        ..Default::default()
    }
}

#[test]
fn public_windows_scm_manager_capabilities_unchanged() {
    // Catches accidental signature changes to the public surface.
    let m = WindowsScmManager::new();
    assert_eq!(m.name(), "windows-scm");
    let caps = m.capabilities();
    assert!(caps.supports_install);
    assert!(caps.supports_reload);
    assert!(!caps.supports_user_scope);
}

#[test]
fn install_full_sequence_recorded() {
    let mock = MockScmBackend::new();
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    mgr.install(&spec("alpha")).unwrap();
    let calls = mock.calls();
    assert_eq!(calls.len(), 3);
    assert!(matches!(calls[0], ScmCall::OpenScm));
    assert!(matches!(&calls[1], ScmCall::CreateService(s) if s.name == "alpha"));
    assert!(matches!(&calls[2], ScmCall::StartService(n) if n == "alpha"));
}

#[test]
fn install_open_scm_failure_aborts_before_create() {
    let mock = MockScmBackend::new();
    mock.set_open_scm_error("simulated access denied");
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    let err = mgr.install(&spec("beta")).unwrap_err();
    assert!(format!("{err}").contains("simulated access denied"));
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert!(matches!(calls[0], ScmCall::OpenScm));
}

#[test]
fn install_post_install_start_failure_is_warning_not_error() {
    let mock = MockScmBackend::new();
    mock.set_start_service_error("simulated start failure");
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    // Install still succeeds — matches original behaviour where start
    // failure is logged but install reports success.
    mgr.install(&spec("gamma")).unwrap();
    let calls = mock.calls();
    assert!(calls.iter().any(|c| matches!(c, ScmCall::StartService(_))));
}

#[test]
fn uninstall_idempotent_on_unknown() {
    let mock = MockScmBackend::new();
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    mgr.uninstall("phantom").unwrap();
    // Only one call: the existence probe.
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        matches!(&calls[0], ScmCall::OpenServiceFor(n, ScmAccess::StopAndDelete) if n == "phantom")
    );
}

#[test]
fn uninstall_existing_stops_then_deletes() {
    let mock = MockScmBackend::new();
    mock.set_service_exists("delta", true);
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    mgr.uninstall("delta").unwrap();
    let stops = mock
        .calls()
        .iter()
        .filter(|c| matches!(c, ScmCall::StopService(_)))
        .count();
    let dels = mock
        .calls()
        .iter()
        .filter(|c| matches!(c, ScmCall::DeleteService(_)))
        .count();
    assert_eq!(stops, 1);
    assert_eq!(dels, 1);
}

#[test]
fn status_not_installed_when_backend_returns_none() {
    let mock = MockScmBackend::new();
    let mgr = ScmManagerImpl::new(Arc::new(mock));
    let st = mgr.status("nope").unwrap();
    assert_eq!(st.state, ServiceState::NotInstalled);
}

#[test]
fn status_running_with_pid_propagates() {
    let mock = MockScmBackend::new();
    mock.set_query_status(
        "svc",
        Some(BackendStatus {
            state: ServiceState::Running,
            pid: Some(99),
            exit_code: None,
        }),
    );
    let mgr = ScmManagerImpl::new(Arc::new(mock));
    let st = mgr.status("svc").unwrap();
    assert_eq!(st.state, ServiceState::Running);
    assert_eq!(st.pid, Some(99));
    assert!(st.exit_code.is_none());
}

#[test]
fn status_stopped_with_exit_code_propagates() {
    let mock = MockScmBackend::new();
    mock.set_query_status(
        "svc",
        Some(BackendStatus {
            state: ServiceState::Stopped,
            pid: None,
            exit_code: Some(7),
        }),
    );
    let mgr = ScmManagerImpl::new(Arc::new(mock));
    let st = mgr.status("svc").unwrap();
    assert_eq!(st.state, ServiceState::Stopped);
    assert_eq!(st.exit_code, Some(7));
}

#[test]
fn reload_running_dispatches_paramchange() {
    let mock = MockScmBackend::new();
    mock.set_query_status(
        "svc",
        Some(BackendStatus {
            state: ServiceState::Running,
            pid: Some(1),
            exit_code: None,
        }),
    );
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    mgr.reload("svc").unwrap();
    assert!(mock
        .calls()
        .iter()
        .any(|c| matches!(c, ScmCall::SendParamchange(_))));
}

#[test]
fn reload_stopped_returns_typed_error() {
    let mock = MockScmBackend::new();
    mock.set_query_status(
        "svc",
        Some(BackendStatus {
            state: ServiceState::Stopped,
            pid: None,
            exit_code: None,
        }),
    );
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    let err = mgr.reload("svc").unwrap_err();
    assert!(format!("{err}").contains("not running"));
    assert!(!mock
        .calls()
        .iter()
        .any(|c| matches!(c, ScmCall::SendParamchange(_))));
}

#[test]
fn reload_missing_service_returns_not_installed_error() {
    let mock = MockScmBackend::new();
    let mgr = ScmManagerImpl::new(Arc::new(mock));
    let err = mgr.reload("ghost").unwrap_err();
    assert!(format!("{err}").contains("not installed"));
}

#[test]
fn start_passes_name_to_backend() {
    let mock = MockScmBackend::new();
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    mgr.start("svc").unwrap();
    assert!(matches!(&mock.calls()[0], ScmCall::StartService(n) if n == "svc"));
}

#[test]
fn stop_passes_name_to_backend() {
    let mock = MockScmBackend::new();
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    mgr.stop("svc").unwrap();
    assert!(matches!(&mock.calls()[0], ScmCall::StopService(n) if n == "svc"));
}

#[test]
fn call_count_matches_calls_vec_len() {
    let mock = MockScmBackend::new();
    let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
    mgr.start("a").unwrap();
    mgr.stop("b").unwrap();
    let _ = mgr.status("c").unwrap();
    assert_eq!(mock.call_count(), mock.calls().len());
    assert_eq!(mock.call_count(), 3);
}
