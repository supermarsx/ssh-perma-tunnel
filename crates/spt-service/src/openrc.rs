//! `OpenRC` init script manager.
//!
//! Renders an init script at `/etc/init.d/<name>` from
//! `/packaging/openrc/spt.tmpl` and drives the lifecycle through
//! `rc-service` / `rc-update`.
//!
//! Lifecycle calls go through a [`CommandRunner`] so tests can substitute
//! a [`MockRunner`] and verify exact argument lists without shelling out.
//!
//! [`MockRunner`]: crate::MockRunner

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use spt_core::error::{Error, Result};

use crate::{
    template, unsupported, CommandRunner, ServiceCapabilities, ServiceManager, ServiceSpec,
    ServiceState, ServiceStatus, TokioRunner,
};

const TEMPLATE: &str = include_str!("../../../packaging/openrc/spt.tmpl");

/// Default per-call timeout for shell-outs.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Manager for `OpenRC`.
///
/// Construct with [`OpenRcManager::new`] for production use, or
/// [`OpenRcManager::new_with_runner`] for tests with a mock runner.
#[derive(Debug, Clone)]
pub struct OpenRcManager {
    runner: Arc<dyn CommandRunner>,
    /// Root for init scripts; `/etc/init.d` in production, parameterised
    /// for tests so they can use `tempfile::tempdir()`.
    script_root: PathBuf,
}

impl Default for OpenRcManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenRcManager {
    /// Construct an `OpenRcManager` backed by a real
    /// [`TokioRunner`] and the canonical `/etc/init.d` script root.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Arc::new(TokioRunner),
            script_root: PathBuf::from("/etc/init.d"),
        }
    }

    /// Construct an `OpenRcManager` with an injected runner. Used by
    /// hermetic tests that want to assert on exact `rc-service` /
    /// `rc-update` invocations.
    #[must_use]
    pub fn new_with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            script_root: PathBuf::from("/etc/init.d"),
        }
    }

    /// Override the init-script directory. Tests use this to point at a
    /// `tempfile::tempdir()`; production should not call this.
    #[must_use]
    pub fn with_script_root(mut self, root: PathBuf) -> Self {
        self.script_root = root;
        self
    }

    /// Render an init script for the given spec without writing to disk.
    /// Useful for golden tests.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn render(&self, spec: &ServiceSpec) -> String {
        render_script(spec)
    }

    fn script_path(&self, name: &str) -> PathBuf {
        self.script_root.join(name)
    }
}

#[async_trait]
impl ServiceManager for OpenRcManager {
    fn name(&self) -> &'static str {
        "openrc"
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
            supports_user_scope: false,
            supports_status_pid: true,
            supports_status_uptime: false,
            supports_restart_counter: false,
        }
    }

    async fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let script = render_script(spec);
        let path = self.script_path(&spec.name);

        // Ensure the script root exists (no-op for /etc/init.d on real systems,
        // load-bearing for tempdir-based tests).
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::ServiceManagerFailed(format!(
                    "create script root {}: {e}",
                    parent.display()
                ))
            })?;
        }

        std::fs::write(&path, script).map_err(|e| {
            Error::ServiceManagerFailed(format!("write {}: {e}", path.display()))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)
                .map_err(|e| {
                    Error::ServiceManagerFailed(format!(
                        "metadata {}: {e}",
                        path.display()
                    ))
                })?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).map_err(|e| {
                Error::ServiceManagerFailed(format!("chmod {}: {e}", path.display()))
            })?;
        }

        let out = self
            .runner
            .run(
                "rc-update",
                &["add", &spec.name, "default"],
                DEFAULT_TIMEOUT,
            )
            .await?;
        if !out.ok() {
            return Err(Error::ServiceManagerFailed(format!(
                "rc-update add {} default exited {}: {}",
                spec.name,
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    async fn uninstall(&self, name: &str) -> Result<()> {
        // Best-effort deregistration; ignore exit status.
        let _ = self
            .runner
            .run(
                "rc-update",
                &["del", name, "default"],
                DEFAULT_TIMEOUT,
            )
            .await;

        let path = self.script_path(name);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::ServiceManagerFailed(format!(
                "remove {}: {e}",
                path.display()
            ))),
        }
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        let out = self
            .runner
            .run("rc-service", &[name, "status"], DEFAULT_TIMEOUT)
            .await?;

        if !out.ok() {
            let stderr_lc = out.stderr.to_ascii_lowercase();
            if stderr_lc.contains("no such service")
                || stderr_lc.contains("does not exist")
            {
                return Err(Error::ServiceManagerFailed(format!(
                    "service not found: {name}"
                )));
            }
            // Many init scripts exit non-zero when stopped; fall through to
            // parsing rather than treating non-zero as fatal here. Only
            // surface the error if we can't classify the output.
        }

        let combined = format!("{}\n{}", out.stdout, out.stderr).to_ascii_lowercase();
        let state = if combined.contains("started") {
            ServiceState::Running
        } else if combined.contains("stopped") {
            ServiceState::Stopped
        } else if combined.contains("crashed") {
            ServiceState::Failed
        } else if !out.ok() {
            return Err(Error::ServiceManagerFailed(format!(
                "rc-service {name} status exited {}: {}",
                out.status,
                out.stderr.trim()
            )));
        } else {
            ServiceState::Unknown
        };

        let pid = read_pidfile(name);

        Ok(ServiceStatus {
            state,
            pid,
            exit_code: None,
            since: None,
            restart_count: None,
        })
    }

    async fn start(&self, name: &str) -> Result<()> {
        run_rc_service(self.runner.as_ref(), name, "start").await
    }

    async fn stop(&self, name: &str) -> Result<()> {
        run_rc_service(self.runner.as_ref(), name, "stop").await
    }

    async fn restart(&self, name: &str) -> Result<()> {
        run_rc_service(self.runner.as_ref(), name, "restart").await
    }

    async fn reload(&self, name: &str) -> Result<()> {
        let out = self
            .runner
            .run("rc-service", &[name, "reload"], DEFAULT_TIMEOUT)
            .await?;
        if out.ok() {
            return Ok(());
        }
        let stderr_lc = out.stderr.to_ascii_lowercase();
        let unsupported_reload = stderr_lc.contains("unrecognized command")
            || stderr_lc.contains("not defined")
            || stderr_lc.contains("no such function")
            || stderr_lc.contains("not implemented");
        if unsupported_reload {
            return Err(unsupported("openrc", "reload"));
        }
        Err(Error::ServiceManagerFailed(format!(
            "rc-service {name} reload exited {}: {}",
            out.status,
            out.stderr.trim()
        )))
    }
}

async fn run_rc_service(
    runner: &dyn CommandRunner,
    name: &str,
    action: &str,
) -> Result<()> {
    let out = runner
        .run("rc-service", &[name, action], DEFAULT_TIMEOUT)
        .await?;
    if out.ok() {
        return Ok(());
    }
    let stderr_lc = out.stderr.to_ascii_lowercase();
    if stderr_lc.contains("no such service") || stderr_lc.contains("does not exist") {
        return Err(Error::ServiceManagerFailed(format!(
            "service not found: {name}"
        )));
    }
    Err(Error::ServiceManagerFailed(format!(
        "rc-service {name} {action} exited {}: {}",
        out.status,
        out.stderr.trim()
    )))
}

/// Best-effort PID lookup from `/run/<name>.pid`. Returns `None` if the
/// file does not exist or cannot be parsed.
fn read_pidfile(name: &str) -> Option<u32> {
    let path = format!("/run/{name}.pid");
    let s = std::fs::read_to_string(&path).ok()?;
    s.trim().parse::<u32>().ok()
}

fn render_script(spec: &ServiceSpec) -> String {
    let args = spec.args.join(" ");
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("name", spec.name.clone());
    vars.insert("description", spec.description.clone());
    vars.insert("exec_path", spec.exec_path.display().to_string());
    vars.insert("args", args);
    vars.insert("user", spec.user.clone().unwrap_or_else(|| "root".into()));
    vars.insert(
        "group",
        spec.group.clone().unwrap_or_else(|| "root".into()),
    );
    vars.insert("working_dir", spec.working_dir.display().to_string());
    template::render(TEMPLATE, &vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;
    use crate::{MockRunner, RunOutput};

    fn ok_out(stdout: &str) -> RunOutput {
        RunOutput {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn err_out(status: i32, stderr: &str) -> RunOutput {
        RunOutput {
            status,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn includes_command_and_user() {
        let mgr = OpenRcManager::new();
        let out = mgr.render(&sample_spec());
        assert!(out.contains("command=\"/usr/local/bin/spt\""));
        assert!(out.contains("command_user=\"spt:spt\""));
    }

    #[test]
    fn snapshot_openrc() {
        let mgr = OpenRcManager::new();
        let out = mgr.render(&sample_spec());
        insta::assert_snapshot!("openrc_init", out);
    }

    #[test]
    fn capabilities_match_spec() {
        let caps = OpenRcManager::new().capabilities();
        assert!(caps.supports_install);
        assert!(caps.supports_uninstall);
        assert!(caps.supports_status);
        assert!(caps.supports_start_stop);
        assert!(caps.supports_restart);
        assert!(caps.supports_reload);
        assert!(!caps.supports_user_scope);
        assert!(caps.supports_status_pid);
        assert!(!caps.supports_status_uptime);
        assert!(!caps.supports_restart_counter);
    }

    #[test]
    fn name_is_openrc() {
        assert_eq!(OpenRcManager::new().name(), "openrc");
    }

    #[tokio::test]
    async fn install_writes_script_and_calls_rc_update() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        let mgr = OpenRcManager::new_with_runner(mock.clone())
            .with_script_root(tmp.path().to_path_buf());

        mgr.install(&sample_spec()).await.expect("install");

        let path = tmp.path().join("spt-relay");
        assert!(path.exists(), "init script should have been written");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("/usr/local/bin/spt"));
        mock.assert_called("rc-update", &["add", "spt-relay", "default"]);
    }

    #[tokio::test]
    async fn uninstall_idempotent_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        // rc-update del best-effort; queue a failure to confirm it's ignored.
        mock.push_output(err_out(1, "no such service"));
        let mgr = OpenRcManager::new_with_runner(mock.clone())
            .with_script_root(tmp.path().to_path_buf());
        mgr.uninstall("ghost").await.expect("idempotent");
        mock.assert_called("rc-update", &["del", "ghost", "default"]);
    }

    #[tokio::test]
    async fn uninstall_removes_existing_script() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        let mgr = OpenRcManager::new_with_runner(mock.clone())
            .with_script_root(tmp.path().to_path_buf());
        let path = tmp.path().join("spt-relay");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        assert!(path.exists());
        mgr.uninstall("spt-relay").await.expect("uninstall");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn status_running() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(" * status: started"));
        let mgr = OpenRcManager::new_with_runner(mock);
        let st = mgr.status("svc").await.unwrap();
        assert_eq!(st.state, ServiceState::Running);
    }

    #[tokio::test]
    async fn status_stopped() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(RunOutput {
            status: 3,
            stdout: " * status: stopped".into(),
            stderr: String::new(),
        });
        let mgr = OpenRcManager::new_with_runner(mock);
        let st = mgr.status("svc").await.unwrap();
        assert_eq!(st.state, ServiceState::Stopped);
    }

    #[tokio::test]
    async fn status_crashed_is_failed() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(RunOutput {
            status: 32,
            stdout: " * status: crashed".into(),
            stderr: String::new(),
        });
        let mgr = OpenRcManager::new_with_runner(mock);
        let st = mgr.status("svc").await.unwrap();
        assert_eq!(st.state, ServiceState::Failed);
    }

    #[tokio::test]
    async fn status_unknown_when_unrecognized_output_succeeds() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out("garbled"));
        let mgr = OpenRcManager::new_with_runner(mock);
        let st = mgr.status("svc").await.unwrap();
        assert_eq!(st.state, ServiceState::Unknown);
    }

    #[tokio::test]
    async fn status_service_not_found() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(err_out(1, "rc-service: no such service `ghost'"));
        let mgr = OpenRcManager::new_with_runner(mock);
        let err = mgr.status("ghost").await.expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains("service not found"), "got: {msg}");
    }

    #[tokio::test]
    async fn start_stop_restart_send_correct_args() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        let mgr = OpenRcManager::new_with_runner(mock.clone());
        mgr.start("svc").await.unwrap();
        mgr.stop("svc").await.unwrap();
        mgr.restart("svc").await.unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1, vec!["svc".to_string(), "start".to_string()]);
        assert_eq!(calls[1].1, vec!["svc".to_string(), "stop".to_string()]);
        assert_eq!(calls[2].1, vec!["svc".to_string(), "restart".to_string()]);
    }

    #[tokio::test]
    async fn reload_ok() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        let mgr = OpenRcManager::new_with_runner(mock);
        mgr.reload("svc").await.expect("reload ok");
    }

    #[tokio::test]
    async fn reload_unsupported_when_unrecognized_command() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(err_out(
            1,
            "rc-service: unrecognized command `reload'",
        ));
        let mgr = OpenRcManager::new_with_runner(mock);
        let err = mgr.reload("svc").await.expect_err("must error");
        match err {
            Error::UnsupportedPlatform(msg) => {
                assert!(msg.contains("reload"));
                assert!(msg.contains("openrc"));
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reload_typed_error_for_other_failure() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(err_out(1, "boom"));
        let mgr = OpenRcManager::new_with_runner(mock);
        let err = mgr.reload("svc").await.expect_err("must error");
        match err {
            Error::ServiceManagerFailed(msg) => {
                assert!(msg.contains("reload"));
                assert!(msg.contains("boom"));
            }
            other => panic!("expected ServiceManagerFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "requires Linux + rc-service in PATH"]
    async fn integration_status_smoke() {
        let mgr = OpenRcManager::new();
        // Only smoke: any well-formed result is acceptable.
        let _ = mgr.status("nonexistent-spt-test").await;
    }
}
