//! Service manager integrations (systemd, launchd, SCM, `OpenRC`, `SysV`, Task
//! Scheduler) for spt.
//!
//! Each backend is split into a **render** path (pure, returns a `String`,
//! always available cross-platform for golden tests) and an **install /
//! uninstall / status / start / stop / restart / reload** path (real OS
//! action, may shell out, may require admin). Tests only ever drive the
//! render path; the live paths are gated and run only on the matching OS
//! with admin under `--ignored`.
//!
//! Per spec §13.7 there is exactly **one service per config file**;
//! `ServiceSpec.name` is the only knob that distinguishes services on disk.
//! Profile filters are runtime-only and MUST NOT spawn separate units.

#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use spt_core::error::{Error, Result};

pub mod launchd;
pub mod openrc;
pub mod runner;
pub mod systemd_system;
pub mod systemd_user;
pub mod sysv;
pub mod task_scheduler;
pub mod template;
pub mod windows_scm;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use runner::{CommandRunner, MockRunner, RunOutput, TokioRunner};

/// Whether a service runs at the system or per-user scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// System scope (root / `LocalSystem` / launch daemon).
    System,
    /// User scope (`systemctl --user`, launch agent, current-user task).
    User,
}

/// Restart policy mapped onto each backend's nearest equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Always restart on exit.
    Always,
    /// Restart only on failure (non-zero exit).
    OnFailure,
    /// Never restart automatically.
    Never,
}

impl RestartPolicy {
    /// systemd `Restart=` value.
    #[must_use]
    pub const fn as_systemd(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::OnFailure => "on-failure",
            Self::Never => "no",
        }
    }
}

/// Description of a service to install or render.
///
/// **One service per config file.** The `config_path` field is informational
/// — backends embed it as a `--config <path>` argument when rendering the
/// command line. Profile subsets must be expressed as runtime filters
/// (`--profile foo`) on `args`, not as additional services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    /// Service name (also used as filename stem on disk).
    pub name: String,
    /// Human-readable description (rendered into `Description=` /
    /// `Short-Description:` / `Comment` etc.).
    pub description: String,
    /// Absolute path to the spt binary.
    pub exec_path: PathBuf,
    /// Arguments passed to the binary (already split). Typically begins with
    /// `["service", "run", "--config", "<path>"]`.
    pub args: Vec<String>,
    /// Working directory the binary is started in.
    pub working_dir: PathBuf,
    /// Extra environment variables.
    pub env: BTreeMap<String, String>,
    /// User to drop privileges to (system scope) or `None` for user scope.
    pub user: Option<String>,
    /// Group to run as (system scope only).
    pub group: Option<String>,
    /// System or user scope.
    pub scope: Scope,
    /// Restart behaviour.
    pub restart_policy: RestartPolicy,
    /// Whether to enable systemd's `Type=notify` + `sd_notify` (Linux only).
    pub sd_notify: bool,
    /// Standard output log path (launchd / `SysV`). Optional.
    pub stdout_path: Option<PathBuf>,
    /// Standard error log path (launchd / `SysV`). Optional.
    pub stderr_path: Option<PathBuf>,
}

impl Default for ServiceSpec {
    fn default() -> Self {
        Self {
            name: "spt".to_string(),
            description: "SSH permanent tunnel".to_string(),
            exec_path: PathBuf::from("/usr/bin/spt"),
            args: vec!["service".into(), "run".into()],
            working_dir: PathBuf::from("/"),
            env: BTreeMap::new(),
            user: None,
            group: None,
            scope: Scope::System,
            restart_policy: RestartPolicy::OnFailure,
            sd_notify: false,
            stdout_path: None,
            stderr_path: None,
        }
    }
}

/// Coarse service lifecycle state, normalised across backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    /// Service is running.
    Running,
    /// Service is registered but not running.
    Stopped,
    /// Service exited with failure (last known state).
    Failed,
    /// Service is not installed at all.
    NotInstalled,
    /// Backend cannot determine state (treat as opaque).
    Unknown,
}

/// Live status of an installed service.
///
/// Fields beyond `state` are best-effort: each backend fills what its
/// underlying CLI exposes and leaves the rest `None`. See
/// [`ServiceCapabilities`] for which backend advertises which field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    /// Coarse lifecycle state.
    pub state: ServiceState,
    /// Process ID of the running service, if known.
    pub pid: Option<u32>,
    /// Last observed exit code (Stopped / Failed states).
    pub exit_code: Option<i32>,
    /// Timestamp at which the service entered its current state.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Number of automatic restarts the supervisor has performed.
    pub restart_count: Option<u32>,
}

impl ServiceStatus {
    /// Construct a status with only the coarse state filled in.
    #[must_use]
    pub fn new(state: ServiceState) -> Self {
        Self {
            state,
            pid: None,
            exit_code: None,
            since: None,
            restart_count: None,
        }
    }
}

impl Default for ServiceStatus {
    fn default() -> Self {
        Self::new(ServiceState::Unknown)
    }
}

/// Static description of the operations a backend supports natively.
///
/// The CLI uses this to preflight: e.g. `spt service reload` on Task
/// Scheduler short-circuits to a typed `UnsupportedPlatform` error
/// rather than blindly invoking a shell-out that will fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServiceCapabilities {
    /// Backend can install services on this OS.
    pub supports_install: bool,
    /// Backend can uninstall services.
    pub supports_uninstall: bool,
    /// Backend can report live status.
    pub supports_status: bool,
    /// Backend supports start + stop primitives.
    pub supports_start_stop: bool,
    /// Backend supports an explicit restart primitive (vs. stop+start).
    pub supports_restart: bool,
    /// Backend supports a reload primitive (SIGHUP-equivalent).
    pub supports_reload: bool,
    /// Backend can run services at user scope (per-user agent / `--user`).
    pub supports_user_scope: bool,
    /// Status reports include a PID.
    pub supports_status_pid: bool,
    /// Status reports include an "active since" timestamp.
    pub supports_status_uptime: bool,
    /// Status reports include a restart counter.
    pub supports_restart_counter: bool,
}

/// Service manager trait. `&self` everywhere so a `Box<dyn ServiceManager>`
/// dispatcher works in `spt-bin`.
///
/// Lifecycle methods are async because most backends shell out to a
/// canonical OS CLI (`systemctl`, `launchctl`, `schtasks`, ...) via
/// [`crate::CommandRunner`].
///
/// **No default impls.** Each backend explicitly implements every method.
/// Where the underlying OS lacks the operation, the impl returns
/// [`Error::UnsupportedPlatform`] via [`unsupported`].
#[async_trait::async_trait]
pub trait ServiceManager: Send + Sync {
    /// Stable backend identifier (e.g. `"systemd-system"`,
    /// `"launchd-agent"`). Used in error messages and capability tables.
    fn name(&self) -> &'static str;

    /// What this backend can do natively. The CLI uses this to preflight
    /// operations and avoid blindly invoking unsupported paths.
    fn capabilities(&self) -> ServiceCapabilities;

    /// Install (write definition + register with the OS).
    async fn install(&self, spec: &ServiceSpec) -> Result<()>;

    /// Uninstall (deregister + remove on-disk definition). Idempotent:
    /// uninstalling a service that is not installed returns `Ok(())`.
    async fn uninstall(&self, name: &str) -> Result<()>;

    /// Query live status.
    async fn status(&self, name: &str) -> Result<ServiceStatus>;

    /// Start the service.
    async fn start(&self, name: &str) -> Result<()>;

    /// Stop the service.
    async fn stop(&self, name: &str) -> Result<()>;

    /// Restart the service. Backends without a native restart primitive
    /// implement this as `stop()` followed by `start()`.
    async fn restart(&self, name: &str) -> Result<()>;

    /// Reload the service (SIGHUP / `systemctl reload`). Returns
    /// [`Error::UnsupportedPlatform`] on backends without a reload
    /// primitive.
    async fn reload(&self, name: &str) -> Result<()>;

    /// Render the on-disk unit/script/plist for `spec`, if this backend
    /// has a file-based representation. Backends that register services
    /// through a Win32 API (Windows SCM, Task Scheduler) return `None`.
    fn render_unit(&self, _spec: &ServiceSpec) -> Option<String> {
        None
    }
}

/// Construct a typed [`Error::UnsupportedPlatform`] tagged with the
/// backend name and the method that is unsupported.
///
/// Backends should call this for OS limitations (e.g. Task Scheduler has
/// no reload concept) instead of stuffing the same string into the
/// generic [`Error::ServiceManagerFailed`] variant.
#[must_use]
pub fn unsupported(backend: &'static str, method: &'static str) -> Error {
    Error::UnsupportedPlatform(format!("{method} is not supported on backend '{backend}'"))
}

/// Pick the recommended `ServiceManager` for the running OS.
///
/// On Linux this returns the systemd-system backend (most common); use
/// [`openrc::OpenRcManager`], [`sysv::SysVManager`], or
/// [`systemd_user::SystemdUserManager`] directly when needed.
#[allow(clippy::unnecessary_wraps)]
pub fn new_default_manager() -> Result<Box<dyn ServiceManager>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(systemd_system::SystemdSystemManager::new()))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(launchd::LaunchdManager::new()))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows_scm::WindowsScmManager::new()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(Error::UnsupportedPlatform(format!(
            "no service manager for target {}",
            std::env::consts::OS
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    pub(crate) fn sample_spec() -> ServiceSpec {
        let mut env = BTreeMap::new();
        env.insert("RUST_LOG".into(), "info".into());
        env.insert("SPT_STATE_DIR".into(), "/var/lib/spt".into());
        ServiceSpec {
            name: "spt-relay".into(),
            description: "spt — SMTP relay tunnel".into(),
            exec_path: PathBuf::from("/usr/local/bin/spt"),
            args: vec![
                "service".into(),
                "run".into(),
                "--config".into(),
                "/etc/spt/relay.toml".into(),
            ],
            working_dir: PathBuf::from("/var/lib/spt"),
            env,
            user: Some("spt".into()),
            group: Some("spt".into()),
            scope: Scope::System,
            restart_policy: RestartPolicy::OnFailure,
            sd_notify: true,
            stdout_path: Some(PathBuf::from("/var/log/spt/relay.out.log")),
            stderr_path: Some(PathBuf::from("/var/log/spt/relay.err.log")),
        }
    }

    #[test]
    fn restart_policy_systemd_mapping() {
        assert_eq!(RestartPolicy::Always.as_systemd(), "always");
        assert_eq!(RestartPolicy::OnFailure.as_systemd(), "on-failure");
        assert_eq!(RestartPolicy::Never.as_systemd(), "no");
    }

    #[test]
    fn default_spec_is_valid() {
        let s = ServiceSpec::default();
        assert_eq!(s.name, "spt");
        assert_eq!(s.scope, Scope::System);
    }

    #[test]
    fn unsupported_helper_formats_message() {
        let err = unsupported("task-scheduler", "reload");
        let msg = format!("{err}");
        assert!(msg.contains("reload"));
        assert!(msg.contains("task-scheduler"));
        match err {
            Error::UnsupportedPlatform(_) => {}
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[test]
    fn service_status_defaults_unknown() {
        let s = ServiceStatus::default();
        assert_eq!(s.state, ServiceState::Unknown);
        assert!(s.pid.is_none());
        assert!(s.exit_code.is_none());
        assert!(s.since.is_none());
        assert!(s.restart_count.is_none());
    }
}
