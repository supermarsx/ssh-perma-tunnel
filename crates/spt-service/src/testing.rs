//! Public test facilities for `spt-service` (gated behind `feature = "testing"`).
//!
//! Re-exports the existing in-process [`MockRunner`] / [`RunOutput`] from
//! [`crate::runner`] for parity with sibling crates' `testing` modules, and
//! adds a [`MockServiceManager`] that records every [`crate::ServiceManager`]
//! trait call and returns canned [`crate::ServiceStatus`] values.
//!
//! All helpers are pure in-memory: nothing here ever shells out.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use spt_core::error::Result;

use crate::{
    RestartPolicy, Scope, ServiceCapabilities, ServiceManager, ServiceSpec, ServiceState,
    ServiceStatus,
};

// Re-exports for parity with sibling crates' `testing` modules.
pub use crate::runner::{MockRunner, RunOutput};

// Re-export the SCM mock + its supporting types so external tests can
// exercise `ScmManagerImpl` against a recording backend without poking
// into the implementation module directly.
pub use crate::windows_scm::{BackendStatus, MockScmBackend, ScmAccess, ScmCall};

/// One observed call against a [`MockServiceManager`].
// 1.88 lint: large_enum_variant — `Install(ServiceSpec)` dwarfs the other
// string-only arms. This is a test-support record type, not a hot allocation
// path; boxing it would churn every construction/match site for no runtime
// benefit, so the size disparity is accepted here.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCall {
    /// `install(spec)`.
    Install(ServiceSpec),
    /// `uninstall(name)`.
    Uninstall(String),
    /// `start(name)`.
    Start(String),
    /// `stop(name)`.
    Stop(String),
    /// `restart(name)`.
    Restart(String),
    /// `reload(name)`.
    Reload(String),
    /// `status(name)`.
    Status(String),
}

#[derive(Debug)]
struct MockState {
    /// Currently-installed service specs, keyed by name.
    installed: BTreeMap<String, ServiceSpec>,
    /// Per-service status (overrides `installed`-derived defaults).
    statuses: BTreeMap<String, ServiceStatus>,
    /// Default status returned when nothing is installed.
    default_status: ServiceStatus,
    /// Capabilities advertised by the mock.
    capabilities: ServiceCapabilities,
}

/// In-memory recording [`ServiceManager`] for hermetic tests.
///
/// Records every trait call into a `Vec<ServiceCall>`. Maintains an installed
/// service map: `install` adds an entry, `uninstall` removes it, `start` /
/// `stop` flip a tracked status, `status` returns the last canned/derived
/// value.
///
/// ```
/// use spt_service::testing::{MockServiceManager, fixtures};
/// use spt_service::ServiceManager;
///
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .build()
///     .unwrap();
/// rt.block_on(async {
///     let svc = MockServiceManager::new();
///     let spec = fixtures::service_spec("svc-test");
///     svc.install(&spec).await.unwrap();
///     svc.start(&spec.name).await.unwrap();
///     let st = svc.status(&spec.name).await.unwrap();
///     assert_eq!(st.state, spt_service::ServiceState::Running);
/// });
/// ```
#[derive(Debug, Clone)]
pub struct MockServiceManager {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<MockState>,
    calls: Mutex<Vec<ServiceCall>>,
}

impl Default for MockServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MockServiceManager {
    /// New mock with `NotInstalled` as the default status and full
    /// capabilities advertised.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(MockState {
                    installed: BTreeMap::new(),
                    statuses: BTreeMap::new(),
                    default_status: ServiceStatus::new(ServiceState::NotInstalled),
                    capabilities: full_capabilities(),
                }),
                calls: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Pre-seed the mock with an initial status returned by `status()` until
    /// the test triggers a state transition.
    #[must_use]
    pub fn with_initial_status(status: ServiceStatus) -> Self {
        let s = Self::new();
        s.inner.state.lock().default_status = status;
        s
    }

    /// Override the advertised [`ServiceCapabilities`].
    #[must_use]
    pub fn with_capabilities(capabilities: ServiceCapabilities) -> Self {
        let s = Self::new();
        s.inner.state.lock().capabilities = capabilities;
        s
    }

    /// Set (or override) the canned status for `name`.
    pub fn set_status(&self, name: &str, status: ServiceStatus) {
        self.inner
            .state
            .lock()
            .statuses
            .insert(name.to_string(), status);
    }

    /// Snapshot of every recorded call, in chronological order.
    #[must_use]
    pub fn calls(&self) -> Vec<ServiceCall> {
        self.inner.calls.lock().clone()
    }

    /// Number of calls observed so far.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.inner.calls.lock().len()
    }

    /// Returns the spec installed under `name`, if any.
    #[must_use]
    pub fn installed_spec(&self, name: &str) -> Option<ServiceSpec> {
        self.inner.state.lock().installed.get(name).cloned()
    }

    fn record(&self, call: ServiceCall) {
        self.inner.calls.lock().push(call);
    }
}

#[async_trait]
impl ServiceManager for MockServiceManager {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn capabilities(&self) -> ServiceCapabilities {
        self.inner.state.lock().capabilities
    }

    async fn install(&self, spec: &ServiceSpec) -> Result<()> {
        self.record(ServiceCall::Install(spec.clone()));
        let mut st = self.inner.state.lock();
        st.installed.insert(spec.name.clone(), spec.clone());
        st.statuses
            .insert(spec.name.clone(), ServiceStatus::new(ServiceState::Stopped));
        Ok(())
    }

    async fn uninstall(&self, name: &str) -> Result<()> {
        self.record(ServiceCall::Uninstall(name.to_string()));
        let mut st = self.inner.state.lock();
        st.installed.remove(name);
        st.statuses.remove(name);
        Ok(())
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        self.record(ServiceCall::Status(name.to_string()));
        let st = self.inner.state.lock();
        Ok(st
            .statuses
            .get(name)
            .cloned()
            .unwrap_or_else(|| st.default_status.clone()))
    }

    async fn start(&self, name: &str) -> Result<()> {
        self.record(ServiceCall::Start(name.to_string()));
        let mut st = self.inner.state.lock();
        if st.installed.contains_key(name) {
            st.statuses
                .insert(name.to_string(), ServiceStatus::new(ServiceState::Running));
        }
        Ok(())
    }

    async fn stop(&self, name: &str) -> Result<()> {
        self.record(ServiceCall::Stop(name.to_string()));
        let mut st = self.inner.state.lock();
        if st.installed.contains_key(name) {
            st.statuses
                .insert(name.to_string(), ServiceStatus::new(ServiceState::Stopped));
        }
        Ok(())
    }

    async fn restart(&self, name: &str) -> Result<()> {
        self.record(ServiceCall::Restart(name.to_string()));
        let mut st = self.inner.state.lock();
        if st.installed.contains_key(name) {
            st.statuses
                .insert(name.to_string(), ServiceStatus::new(ServiceState::Running));
        }
        Ok(())
    }

    async fn reload(&self, name: &str) -> Result<()> {
        self.record(ServiceCall::Reload(name.to_string()));
        Ok(())
    }
}

fn full_capabilities() -> ServiceCapabilities {
    ServiceCapabilities {
        supports_install: true,
        supports_uninstall: true,
        supports_status: true,
        supports_start_stop: true,
        supports_restart: true,
        supports_reload: true,
        supports_user_scope: true,
        supports_status_pid: true,
        supports_status_uptime: true,
        supports_restart_counter: true,
    }
}

/// Pre-built canonical fixtures.
pub mod fixtures {
    use super::{
        BTreeMap, PathBuf, RestartPolicy, Scope, ServiceSpec, ServiceState, ServiceStatus,
    };

    /// Build a [`ServiceSpec`] with sane defaults, named `name`.
    ///
    /// ```
    /// let spec = spt_service::testing::fixtures::service_spec("my-svc");
    /// assert_eq!(spec.name, "my-svc");
    /// ```
    #[must_use]
    pub fn service_spec(name: &str) -> ServiceSpec {
        let mut env = BTreeMap::new();
        env.insert("RUST_LOG".to_string(), "info".to_string());
        ServiceSpec {
            name: name.to_string(),
            description: format!("spt — test service {name}"),
            exec_path: PathBuf::from("/usr/local/bin/spt"),
            args: vec![
                "service".into(),
                "run".into(),
                "--config".into(),
                format!("/etc/spt/{name}.toml"),
            ],
            working_dir: PathBuf::from("/var/lib/spt"),
            env,
            user: Some("spt".into()),
            group: Some("spt".into()),
            scope: Scope::System,
            restart_policy: RestartPolicy::OnFailure,
            sd_notify: false,
            stdout_path: None,
            stderr_path: None,
            watchdog_sec: None,
        }
    }

    /// `Running` status with a synthetic PID.
    ///
    /// ```
    /// let s = spt_service::testing::fixtures::sample_status_running();
    /// assert_eq!(s.state, spt_service::ServiceState::Running);
    /// ```
    #[must_use]
    pub fn sample_status_running() -> ServiceStatus {
        ServiceStatus {
            state: ServiceState::Running,
            pid: Some(4242),
            exit_code: None,
            since: None,
            restart_count: Some(0),
        }
    }

    /// `Stopped` status.
    ///
    /// ```
    /// let s = spt_service::testing::fixtures::sample_status_stopped();
    /// assert_eq!(s.state, spt_service::ServiceState::Stopped);
    /// ```
    #[must_use]
    pub fn sample_status_stopped() -> ServiceStatus {
        ServiceStatus::new(ServiceState::Stopped)
    }

    /// `Failed` status with a non-zero exit code.
    ///
    /// ```
    /// let s = spt_service::testing::fixtures::sample_status_failed();
    /// assert_eq!(s.state, spt_service::ServiceState::Failed);
    /// ```
    #[must_use]
    pub fn sample_status_failed() -> ServiceStatus {
        ServiceStatus {
            state: ServiceState::Failed,
            pid: None,
            exit_code: Some(1),
            since: None,
            restart_count: Some(3),
        }
    }

    /// `NotInstalled` status.
    ///
    /// ```
    /// let s = spt_service::testing::fixtures::sample_status_not_installed();
    /// assert_eq!(s.state, spt_service::ServiceState::NotInstalled);
    /// ```
    #[must_use]
    pub fn sample_status_not_installed() -> ServiceStatus {
        ServiceStatus::new(ServiceState::NotInstalled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn happy_path_records_full_sequence() {
        let svc = MockServiceManager::new();
        let spec = fixtures::service_spec("svc-happy");

        svc.install(&spec).await.unwrap();
        svc.start(&spec.name).await.unwrap();
        let st = svc.status(&spec.name).await.unwrap();
        assert_eq!(st.state, ServiceState::Running);
        svc.stop(&spec.name).await.unwrap();
        svc.uninstall(&spec.name).await.unwrap();

        let calls = svc.calls();
        assert_eq!(calls.len(), 5);
        assert!(matches!(&calls[0], ServiceCall::Install(s) if s.name == "svc-happy"));
        assert!(matches!(&calls[1], ServiceCall::Start(n) if n == "svc-happy"));
        assert!(matches!(&calls[2], ServiceCall::Status(n) if n == "svc-happy"));
        assert!(matches!(&calls[3], ServiceCall::Stop(n) if n == "svc-happy"));
        assert!(matches!(&calls[4], ServiceCall::Uninstall(n) if n == "svc-happy"));
    }

    #[tokio::test]
    async fn with_initial_status_overrides_default() {
        let svc = MockServiceManager::with_initial_status(fixtures::sample_status_failed());
        let st = svc.status("never-installed").await.unwrap();
        assert_eq!(st.state, ServiceState::Failed);
        assert_eq!(st.exit_code, Some(1));
    }

    #[tokio::test]
    async fn with_capabilities_propagates() {
        let caps = ServiceCapabilities {
            supports_install: true,
            ..Default::default()
        };
        let svc = MockServiceManager::with_capabilities(caps);
        assert!(svc.capabilities().supports_install);
        assert!(!svc.capabilities().supports_reload);
    }

    #[test]
    fn fixtures_status_variants() {
        assert_eq!(
            fixtures::sample_status_running().state,
            ServiceState::Running
        );
        assert_eq!(
            fixtures::sample_status_stopped().state,
            ServiceState::Stopped
        );
        assert_eq!(fixtures::sample_status_failed().state, ServiceState::Failed);
        assert_eq!(
            fixtures::sample_status_not_installed().state,
            ServiceState::NotInstalled
        );
    }
}
