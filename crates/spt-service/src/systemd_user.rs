//! systemd user-scope service manager.
//!
//! Renders to `~/.config/systemd/user/<name>.service` and uses
//! `systemctl --user`. `User=`/`Group=` are dropped because the unit runs as
//! the invoking user. Lifecycle calls go through a [`CommandRunner`] so that
//! tests stay hermetic.
//!
//! [`CommandRunner`]: crate::CommandRunner

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use spt_core::error::{Error, Result};

use crate::{
    systemd_system, CommandRunner, ServiceCapabilities, ServiceManager, ServiceSpec, ServiceStatus,
    TokioRunner,
};

/// Default per-call timeout for `systemctl --user` invocations.
#[allow(dead_code)]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Manager for systemd in **user** scope.
#[derive(Debug, Clone)]
pub struct SystemdUserManager {
    runner: Arc<dyn CommandRunner>,
    /// Directory holding user unit files. Defaults to
    /// `$HOME/.config/systemd/user`; `None` means "resolve from $HOME at
    /// install time" (production). Tests set this to a `tempdir`.
    unit_root: Option<PathBuf>,
}

impl Default for SystemdUserManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemdUserManager {
    /// Construct a manager backed by a real [`TokioRunner`]. The unit root
    /// resolves from `$HOME` at install time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Arc::new(TokioRunner),
            unit_root: None,
        }
    }

    /// Construct with an injected runner. Used by hermetic tests that want
    /// to assert on exact `systemctl --user` invocations.
    #[must_use]
    pub fn new_with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            unit_root: None,
        }
    }

    /// Override the unit-file directory. Tests use this to point at a
    /// `tempfile::tempdir()`; production should leave it unset.
    #[must_use]
    pub fn with_unit_root(mut self, root: PathBuf) -> Self {
        self.unit_root = Some(root);
        self
    }

    /// Render a unit file for the given spec without writing to disk.
    /// Useful for golden tests.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn render(&self, spec: &ServiceSpec) -> String {
        systemd_system::render_unit(spec, /* user_scope */ true)
    }

    fn resolve_unit_root(&self) -> Result<PathBuf> {
        if let Some(p) = &self.unit_root {
            return Ok(p.clone());
        }
        let home = std::env::var_os("HOME")
            .ok_or_else(|| Error::ServiceManagerFailed("HOME not set".into()))?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user"))
    }

    fn unit_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self.resolve_unit_root()?.join(format!("{name}.service")))
    }
}

#[async_trait]
impl ServiceManager for SystemdUserManager {
    fn name(&self) -> &'static str {
        "systemd-user"
    }

    fn render_unit(&self, spec: &ServiceSpec) -> Option<String> {
        Some(self.render(spec))
    }

    fn capabilities(&self) -> ServiceCapabilities {
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

    async fn install(&self, spec: &ServiceSpec) -> Result<()> {
        tracing::info!(target: "spt_service", backend = "systemd-user", service = %spec.name, "installing service");
        let unit = systemd_system::render_unit(spec, true);
        let dir = self.resolve_unit_root()?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::ServiceManagerFailed(format!("mkdir {}: {e}", dir.display())))?;
        let path = dir.join(format!("{}.service", spec.name));
        std::fs::write(&path, unit)
            .map_err(|e| Error::ServiceManagerFailed(format!("write {}: {e}", path.display())))?;

        systemd_system::run_systemctl_prefixed(
            self.runner.as_ref(),
            &["--user"],
            &["daemon-reload"],
        )
        .await?;
        systemd_system::run_systemctl_prefixed(
            self.runner.as_ref(),
            &["--user"],
            &["enable", &spec.name],
        )
        .await?;
        systemd_system::run_systemctl_prefixed(
            self.runner.as_ref(),
            &["--user"],
            &["start", &spec.name],
        )
        .await?;
        Ok(())
    }

    async fn uninstall(&self, name: &str) -> Result<()> {
        tracing::info!(target: "spt_service", backend = "systemd-user", service = %name, "uninstalling service");
        let _ = self
            .runner
            .run("systemctl", &["--user", "stop", name], DEFAULT_TIMEOUT)
            .await;
        let _ = self
            .runner
            .run("systemctl", &["--user", "disable", name], DEFAULT_TIMEOUT)
            .await;

        let path = self.unit_path(name)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::ServiceManagerFailed(format!(
                    "remove {}: {e}",
                    path.display()
                )));
            }
        }

        let _ = self
            .runner
            .run("systemctl", &["--user", "daemon-reload"], DEFAULT_TIMEOUT)
            .await;
        Ok(())
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        systemd_system::show_status(self.runner.as_ref(), &["--user"], name).await
    }

    async fn start(&self, name: &str) -> Result<()> {
        tracing::info!(target: "spt_service", backend = "systemd-user", service = %name, "starting service");
        systemd_system::run_systemctl_prefixed(self.runner.as_ref(), &["--user"], &["start", name])
            .await
    }

    async fn stop(&self, name: &str) -> Result<()> {
        tracing::info!(target: "spt_service", backend = "systemd-user", service = %name, "stopping service");
        systemd_system::run_systemctl_prefixed(self.runner.as_ref(), &["--user"], &["stop", name])
            .await
    }

    async fn restart(&self, name: &str) -> Result<()> {
        systemd_system::run_systemctl_prefixed(
            self.runner.as_ref(),
            &["--user"],
            &["restart", name],
        )
        .await
    }

    async fn reload(&self, name: &str) -> Result<()> {
        systemd_system::run_systemctl_prefixed(
            self.runner.as_ref(),
            &["--user"],
            &["reload-or-restart", name],
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;
    use crate::{MockRunner, RunOutput, ServiceState};

    fn ok_out(stdout: &str) -> RunOutput {
        RunOutput {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn user_unit_drops_user_group_and_targets_default() {
        let mgr = SystemdUserManager::new();
        let out = mgr.render(&sample_spec());
        assert!(!out.contains("User=spt"));
        assert!(!out.contains("Group=spt"));
        assert!(out.contains("WantedBy=default.target"));
    }

    #[test]
    fn snapshot_systemd_user() {
        let mgr = SystemdUserManager::new();
        let out = mgr.render(&sample_spec());
        insta::assert_snapshot!("systemd_user_unit", out);
    }

    #[test]
    fn name_is_systemd_user() {
        assert_eq!(SystemdUserManager::new().name(), "systemd-user");
    }

    #[test]
    fn capabilities_include_user_scope() {
        let caps = SystemdUserManager::new().capabilities();
        assert!(caps.supports_install);
        assert!(caps.supports_user_scope);
        assert!(caps.supports_status_pid);
        assert!(caps.supports_status_uptime);
        assert!(caps.supports_restart_counter);
    }

    #[tokio::test]
    async fn install_writes_unit_and_calls_user_systemctl() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        let mgr = SystemdUserManager::new_with_runner(mock.clone())
            .with_unit_root(tmp.path().to_path_buf());

        mgr.install(&sample_spec()).await.expect("install");

        let path = tmp.path().join("spt-relay.service");
        assert!(path.exists(), "user unit file should have been written");
        mock.assert_called("systemctl", &["--user", "daemon-reload"]);
        mock.assert_called("systemctl", &["--user", "enable", "spt-relay"]);
        mock.assert_called("systemctl", &["--user", "start", "spt-relay"]);
    }

    #[tokio::test]
    async fn uninstall_idempotent_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        mock.push_output(RunOutput {
            status: 1,
            stdout: String::new(),
            stderr: "no such unit".into(),
        });
        mock.push_output(RunOutput {
            status: 1,
            stdout: String::new(),
            stderr: "no such unit".into(),
        });
        mock.push_output(ok_out(""));
        let mgr = SystemdUserManager::new_with_runner(mock.clone())
            .with_unit_root(tmp.path().to_path_buf());
        mgr.uninstall("ghost").await.expect("idempotent");
        mock.assert_called("systemctl", &["--user", "stop", "ghost"]);
        mock.assert_called("systemctl", &["--user", "disable", "ghost"]);
    }

    #[tokio::test]
    async fn status_running_via_user_systemctl() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(
            "ActiveState=active\n\
             SubState=running\n\
             MainPID=4242\n\
             ExecMainStatus=0\n\
             ActiveEnterTimestamp=Mon 2024-01-15 10:30:45 UTC\n\
             NRestarts=0\n\
             LoadState=loaded\n",
        ));
        let mgr = SystemdUserManager::new_with_runner(mock.clone());
        let st = mgr.status("svc").await.unwrap();
        assert_eq!(st.state, ServiceState::Running);
        assert_eq!(st.pid, Some(4242));
        // Verify --user was prepended.
        let last = mock.last_call().unwrap();
        assert_eq!(last.0, "systemctl");
        assert_eq!(last.1[0], "--user");
    }

    #[tokio::test]
    async fn start_stop_restart_reload_use_user_flag() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        let mgr = SystemdUserManager::new_with_runner(mock.clone());
        mgr.start("svc").await.unwrap();
        mgr.stop("svc").await.unwrap();
        mgr.restart("svc").await.unwrap();
        mgr.reload("svc").await.unwrap();
        mock.assert_called("systemctl", &["--user", "start", "svc"]);
        mock.assert_called("systemctl", &["--user", "stop", "svc"]);
        mock.assert_called("systemctl", &["--user", "restart", "svc"]);
        mock.assert_called("systemctl", &["--user", "reload-or-restart", "svc"]);
    }

    #[tokio::test]
    #[ignore = "requires Linux + systemctl in PATH"]
    async fn integration_status_smoke() {
        let mgr = SystemdUserManager::new();
        let _ = mgr.status("nonexistent-spt-test").await;
    }

    /// Shared process-wide lock guarding tests that mutate `HOME` (F9): the
    /// same lock is used by the `launchd` tests in this binary, so the two
    /// modules cannot race on `HOME` under default `cargo test` parallelism.
    use crate::tests::lock_env;

    #[test]
    fn resolve_unit_root_falls_back_to_home() {
        let _guard = lock_env();
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        // Construct without `with_unit_root` so the resolver uses HOME.
        let mgr = SystemdUserManager::new();
        let p = mgr.unit_path("svc").expect("path");
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        let s = p.display().to_string().replace('\\', "/");
        assert!(s.contains("/.config/systemd/user/svc.service"), "got: {s}");
    }

    #[test]
    fn resolve_unit_root_errors_when_home_unset() {
        let _guard = lock_env();
        let prev = std::env::var_os("HOME");
        std::env::remove_var("HOME");
        let mgr = SystemdUserManager::new();
        let res = mgr.unit_path("svc");
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        let err = res.unwrap_err();
        assert!(format!("{err}").contains("HOME not set"));
    }

    #[test]
    fn render_unit_returns_some() {
        let r = SystemdUserManager::new().render_unit(&sample_spec());
        assert!(r.is_some());
        // User-scope unit drops User=/Group=.
        assert!(!r.unwrap().contains("User=spt"));
    }

    #[test]
    fn default_constructs() {
        let m = SystemdUserManager::default();
        assert_eq!(m.name(), "systemd-user");
    }

    #[tokio::test]
    async fn uninstall_removes_existing_unit() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        // stop, disable, daemon-reload — all best-effort
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        let mgr =
            SystemdUserManager::new_with_runner(mock).with_unit_root(tmp.path().to_path_buf());
        let path = tmp.path().join("spt-relay.service");
        std::fs::write(&path, "[Unit]\n").unwrap();
        assert!(path.exists());
        mgr.uninstall("spt-relay").await.expect("uninstall");
        assert!(!path.exists());
    }
}
