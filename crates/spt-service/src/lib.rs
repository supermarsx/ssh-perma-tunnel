//! Service manager integrations (systemd, launchd, SCM, `OpenRC`, `SysV`, Task
//! Scheduler) for spt.
//!
//! Each backend is split into a **render** path (pure, returns a `String`,
//! always available cross-platform for golden tests) and an **install / *
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
pub mod sysv;
pub mod systemd_system;
pub mod systemd_user;
pub mod task_scheduler;
pub mod template;
pub mod windows_scm;

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

/// Live status of an installed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    /// Service is running.
    Running,
    /// Service is registered but not running.
    Stopped,
    /// Service is not installed at all.
    NotInstalled,
    /// Backend cannot determine status (treat as opaque).
    Unknown,
}

/// Service manager trait. `&self` everywhere so a `Box<dyn ServiceManager>`
/// dispatcher works in `spt-bin`.
pub trait ServiceManager: Send + Sync {
    /// Render the on-disk service definition (unit, plist, init script,
    /// `.bat` for Task Scheduler, etc.) for `spec`. Pure: must not touch
    /// the filesystem.
    fn render(&self, spec: &ServiceSpec) -> Result<String>;

    /// Install (write definition + register with the OS). Default
    /// implementation refuses to act so unit tests never write into
    /// system locations.
    fn install(&self, _spec: &ServiceSpec) -> Result<()> {
        Err(Error::ServiceManagerFailed(
            "install not implemented for this backend in this build".to_string(),
        ))
    }

    /// Uninstall (deregister + remove on-disk definition).
    fn uninstall(&self, _name: &str) -> Result<()> {
        Err(Error::ServiceManagerFailed(
            "uninstall not implemented for this backend".to_string(),
        ))
    }

    /// Query live status.
    fn status(&self, _name: &str) -> Result<ServiceStatus> {
        Ok(ServiceStatus::Unknown)
    }

    /// Start the service.
    fn start(&self, _name: &str) -> Result<()> {
        Err(Error::ServiceManagerFailed("start not implemented".into()))
    }
    /// Stop the service.
    fn stop(&self, _name: &str) -> Result<()> {
        Err(Error::ServiceManagerFailed("stop not implemented".into()))
    }
    /// Restart the service.
    fn restart(&self, _name: &str) -> Result<()> {
        Err(Error::ServiceManagerFailed(
            "restart not implemented".into(),
        ))
    }
    /// Reload the service (SIGHUP / `systemctl reload`). Returns
    /// `UnsupportedPlatform` on backends without a reload primitive.
    fn reload(&self, _name: &str) -> Result<()> {
        Err(Error::UnsupportedPlatform(
            "reload is not supported on this backend".into(),
        ))
    }
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
    fn default_manager_default_install_refuses() {
        struct Mgr;
        impl ServiceManager for Mgr {
            fn render(&self, _: &ServiceSpec) -> Result<String> {
                Ok(String::new())
            }
        }
        let m = Mgr;
        assert!(m.install(&ServiceSpec::default()).is_err());
        assert!(m.uninstall("x").is_err());
        assert!(m.start("x").is_err());
        assert!(m.stop("x").is_err());
        assert!(m.restart("x").is_err());
        assert!(m.reload("x").is_err());
        assert_eq!(m.status("x").unwrap(), ServiceStatus::Unknown);
    }
}
