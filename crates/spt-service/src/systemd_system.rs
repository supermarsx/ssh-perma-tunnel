//! systemd system-scope service manager.
//!
//! Renders a unit at `/etc/systemd/system/<name>.service` from
//! `/packaging/systemd/spt.service.tmpl`. `install` runs
//! `systemctl daemon-reload && systemctl enable && systemctl start` via the
//! injected [`CommandRunner`] so tests stay hermetic.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use spt_core::error::{Error, Result};

use crate::{
    template, CommandRunner, ServiceCapabilities, ServiceManager, ServiceSpec, ServiceState,
    ServiceStatus, TokioRunner,
};

/// Embedded template — canonical source is `/packaging/systemd/spt.service.tmpl`.
const TEMPLATE: &str = include_str!("../../../packaging/systemd/spt.service.tmpl");

/// Default per-call timeout for `systemctl` invocations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Manager for systemd in **system** scope.
#[derive(Debug, Clone)]
pub struct SystemdSystemManager {
    runner: Arc<dyn CommandRunner>,
    /// Directory holding unit files. Defaults to `/etc/systemd/system`;
    /// parameterised so tests can use `tempfile::tempdir()`.
    unit_root: PathBuf,
}

impl Default for SystemdSystemManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemdSystemManager {
    /// Construct a manager backed by a real [`TokioRunner`] and the canonical
    /// `/etc/systemd/system` unit root.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Arc::new(TokioRunner),
            unit_root: PathBuf::from("/etc/systemd/system"),
        }
    }

    /// Construct with an injected runner. Used by hermetic tests that want to
    /// assert on exact `systemctl` invocations.
    #[must_use]
    pub fn new_with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            unit_root: PathBuf::from("/etc/systemd/system"),
        }
    }

    /// Override the unit-file directory. Tests use this to point at a
    /// `tempfile::tempdir()`; production should not call this.
    #[must_use]
    pub fn with_unit_root(mut self, root: PathBuf) -> Self {
        self.unit_root = root;
        self
    }

    /// Render a unit file for the given spec without writing to disk.
    /// Useful for golden tests.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn render(&self, spec: &ServiceSpec) -> String {
        render_unit(spec, /* user_scope */ false)
    }

    fn unit_path(&self, name: &str) -> Result<PathBuf> {
        validate_unit_name(name)?;
        Ok(self.unit_root.join(format!("{name}.service")))
    }
}

/// Reject service/unit names that could escape the unit root on path joins.
///
/// systemd unit names are limited to `[A-Za-z0-9_.@-]`; anything else (slashes,
/// `..`, whitespace) is refused so that `--name '../../evil'` cannot make
/// install/uninstall write or delete files outside `unit_root`.
fn validate_unit_name(name: &str) -> Result<()> {
    if !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'@' | b'-'))
        // Defence-in-depth: disallow `.`/`..` and any name that is purely dots.
        && name != "."
        && name != ".."
    {
        Ok(())
    } else {
        Err(Error::ServiceManagerFailed(format!(
            "invalid service name {name:?}: must match [A-Za-z0-9_.@-]+"
        )))
    }
}

#[async_trait]
impl ServiceManager for SystemdSystemManager {
    fn name(&self) -> &'static str {
        "systemd-system"
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
            supports_status_uptime: true,
            supports_restart_counter: true,
        }
    }

    async fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let unit = render_unit(spec, false);
        let path = self.unit_path(&spec.name)?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::ServiceManagerFailed(format!("create unit root {}: {e}", parent.display()))
            })?;
        }

        std::fs::write(&path, unit)
            .map_err(|e| Error::ServiceManagerFailed(format!("write {}: {e}", path.display())))?;

        run_systemctl(self.runner.as_ref(), &["daemon-reload"]).await?;
        run_systemctl(self.runner.as_ref(), &["enable", &spec.name]).await?;
        run_systemctl(self.runner.as_ref(), &["start", &spec.name]).await?;
        Ok(())
    }

    async fn uninstall(&self, name: &str) -> Result<()> {
        // Validate before any path join or systemctl call.
        let path = self.unit_path(name)?;
        // Best-effort stop+disable, then remove file.
        let _ = self
            .runner
            .run("systemctl", &["stop", name], DEFAULT_TIMEOUT)
            .await;
        let _ = self
            .runner
            .run("systemctl", &["disable", name], DEFAULT_TIMEOUT)
            .await;

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
            .run("systemctl", &["daemon-reload"], DEFAULT_TIMEOUT)
            .await;
        Ok(())
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        show_status(self.runner.as_ref(), &[], name).await
    }

    async fn start(&self, name: &str) -> Result<()> {
        run_systemctl(self.runner.as_ref(), &["start", name]).await
    }

    async fn stop(&self, name: &str) -> Result<()> {
        run_systemctl(self.runner.as_ref(), &["stop", name]).await
    }

    async fn restart(&self, name: &str) -> Result<()> {
        run_systemctl(self.runner.as_ref(), &["restart", name]).await
    }

    async fn reload(&self, name: &str) -> Result<()> {
        run_systemctl(self.runner.as_ref(), &["reload-or-restart", name]).await
    }
}

/// Run `systemctl` with the given args, with `prefix` prepended (used by the
/// user-scope manager to insert `--user`). Returns `Err` on non-zero exit.
pub(crate) async fn run_systemctl_prefixed(
    runner: &dyn CommandRunner,
    prefix: &[&str],
    args: &[&str],
) -> Result<()> {
    let mut full: Vec<&str> = Vec::with_capacity(prefix.len() + args.len());
    full.extend_from_slice(prefix);
    full.extend_from_slice(args);
    let out = runner.run("systemctl", &full, DEFAULT_TIMEOUT).await?;
    if out.ok() {
        Ok(())
    } else {
        Err(Error::ServiceManagerFailed(format!(
            "systemctl {full:?} exited {}: {}",
            out.status,
            out.stderr.trim()
        )))
    }
}

async fn run_systemctl(runner: &dyn CommandRunner, args: &[&str]) -> Result<()> {
    run_systemctl_prefixed(runner, &[], args).await
}

/// Run `systemctl show -p <props> <name>` (with optional prefix args like
/// `--user`) and parse the output into a [`ServiceStatus`].
pub(crate) async fn show_status(
    runner: &dyn CommandRunner,
    prefix: &[&str],
    name: &str,
) -> Result<ServiceStatus> {
    const PROPS: &str =
        "ActiveState,SubState,MainPID,ExecMainStatus,ActiveEnterTimestamp,NRestarts,LoadState";
    let mut full: Vec<&str> = Vec::with_capacity(prefix.len() + 4);
    full.extend_from_slice(prefix);
    full.extend_from_slice(&["show", "-p", PROPS, name]);

    let out = runner.run("systemctl", &full, DEFAULT_TIMEOUT).await?;

    if !out.ok() {
        return Err(Error::ServiceManagerFailed(format!(
            "systemctl show {name} exited {}: {}",
            out.status,
            out.stderr.trim()
        )));
    }

    Ok(parse_show_output(&out.stdout))
}

/// Parse the `KEY=value` lines emitted by `systemctl show -p ...` into a
/// normalised [`ServiceStatus`].
pub(crate) fn parse_show_output(stdout: &str) -> ServiceStatus {
    let mut active_state = "";
    let mut main_pid: Option<u32> = None;
    let mut exec_main_status: Option<i32> = None;
    let mut active_enter = "";
    let mut n_restarts: Option<u32> = None;
    let mut load_state = "";

    for line in stdout.lines() {
        let line = line.trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "ActiveState" => active_state = v,
            "MainPID" => {
                if let Ok(p) = v.trim().parse::<u32>() {
                    if p > 0 {
                        main_pid = Some(p);
                    }
                }
            }
            "ExecMainStatus" => {
                exec_main_status = v.trim().parse::<i32>().ok();
            }
            "ActiveEnterTimestamp" => active_enter = v.trim(),
            "NRestarts" => {
                n_restarts = v.trim().parse::<u32>().ok();
            }
            "LoadState" => load_state = v,
            _ => {}
        }
    }

    let state = if load_state.eq_ignore_ascii_case("not-found")
        || (load_state.eq_ignore_ascii_case("masked") && active_state.is_empty())
    {
        ServiceState::NotInstalled
    } else {
        match active_state {
            "active" | "activating" | "deactivating" => ServiceState::Running,
            "failed" => ServiceState::Failed,
            "inactive" => ServiceState::Stopped,
            _ => ServiceState::Unknown,
        }
    };

    let exit_code = exec_main_status
        .filter(|c| *c != 0 && matches!(state, ServiceState::Stopped | ServiceState::Failed));

    let since = parse_systemd_timestamp(active_enter);

    ServiceStatus {
        state,
        pid: main_pid,
        exit_code,
        since,
        restart_count: n_restarts,
    }
}

/// Best-effort parser for `systemctl show`'s `ActiveEnterTimestamp` field.
///
/// Examples observed in the wild:
/// * `Mon 2024-01-15 10:30:45 UTC`
/// * `2024-01-15 10:30:45 UTC`
/// * `n/a` (never entered active) — returns `None`.
fn parse_systemd_timestamp(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{Local, NaiveDateTime, TimeZone, Utc};

    const FORMATS: &[&str] = &["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%.f"];

    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("n/a") {
        return None;
    }

    // Drop a leading weekday abbreviation like "Mon ".
    let trimmed = s
        .split_once(' ')
        .filter(|(head, _)| head.len() == 3 && head.chars().all(|c| c.is_ascii_alphabetic()))
        .map_or(s, |(_, rest)| rest);

    // Capture a trailing timezone token if present (e.g. "UTC", "EDT") and drop
    // it from the wall-clock portion we hand to the parser.
    let (core, tz) = trimmed
        .rsplit_once(' ')
        .filter(|(_, tail)| tail.chars().all(|c| c.is_ascii_alphabetic()) && !tail.is_empty())
        .map_or((trimmed, None), |(head, tail)| (head, Some(tail)));

    for fmt in FORMATS {
        if let Ok(naive) = NaiveDateTime::parse_from_str(core, fmt) {
            // `systemctl show` emits the wall clock in the host's local timezone
            // (unless the token is explicitly UTC). Interpret accordingly and
            // normalise to Utc so `ServiceStatus.since` is an absolute instant.
            if tz.is_some_and(|t| t.eq_ignore_ascii_case("UTC") || t.eq_ignore_ascii_case("GMT")) {
                return Some(Utc.from_utc_datetime(&naive));
            }
            return match Local.from_local_datetime(&naive).single() {
                Some(local) => Some(local.with_timezone(&Utc)),
                // Ambiguous/non-existent local time (DST fold): fall back to
                // treating it as UTC rather than dropping the timestamp.
                None => Some(Utc.from_utc_datetime(&naive)),
            };
        }
    }
    None
}

/// Render the unit file. `user_scope` flips the `[Install]` `WantedBy=` and
/// drops `User=`/`Group=`.
pub(crate) fn render_unit(spec: &ServiceSpec, user_scope: bool) -> String {
    let args = spec
        .args
        .iter()
        .map(|a| shell_escape(a))
        .collect::<Vec<_>>()
        .join(" ");
    let env_lines = spec
        .env
        .iter()
        .map(|(k, v)| format!("Environment=\"{k}={v}\""))
        .collect::<Vec<_>>()
        .join("\n");
    let user_line = spec
        .user
        .as_ref()
        .filter(|_| !user_scope)
        .map_or(String::new(), |u| format!("User={u}"));
    let group_line = spec
        .group
        .as_ref()
        .filter(|_| !user_scope)
        .map_or(String::new(), |g| format!("Group={g}"));
    let svc_type = if spec.sd_notify { "notify" } else { "simple" };
    let wanted_by = if user_scope {
        "default.target"
    } else {
        "multi-user.target"
    };

    // E7-F2: pair the sandbox (ProtectSystem=strict / ProtectHome=read-only)
    // with a writable state path, otherwise StateLock fails at boot and the
    // installed service crash-loops. `StateDirectory=spt` creates and binds a
    // 0700 state dir owned by the service user and exports $STATE_DIRECTORY;
    // SPT_STATE_DIR is set explicitly so it is present even when `spec.env`
    // is empty (the CLI install path passes an empty env).
    //
    // System scope resolves to /var/lib/spt; user scope resolves under the
    // user's $XDG_STATE_HOME (~/.local/state/spt). ReadWritePaths and
    // AmbientCapabilities are only valid/appropriate for system units.
    let state_hardening = if user_scope {
        "StateDirectory=spt".to_string()
    } else {
        "# State dir must be writable under the sandbox below; StateDirectory\n\
         # creates and binds /var/lib/spt (0700, owned by User=).\n\
         StateDirectory=spt\n\
         ReadWritePaths=/var/lib/spt /var/log/spt\n\
         Environment=\"SPT_STATE_DIR=/var/lib/spt\""
            .to_string()
    };
    // CAP_NET_BIND_SERVICE lets system services bind privileged ports under
    // NoNewPrivileges=true; user units cannot be granted ambient capabilities.
    let ambient_caps = if user_scope {
        String::new()
    } else {
        "# Allow binding privileged ports (<1024) for forwards under NoNewPrivileges=true.\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE"
            .to_string()
    };

    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("description", spec.description.clone());
    vars.insert("service_type", svc_type.to_string());
    vars.insert("exec_path", spec.exec_path.display().to_string());
    vars.insert("args", args);
    vars.insert("working_dir", spec.working_dir.display().to_string());
    vars.insert("state_hardening", state_hardening);
    vars.insert("ambient_caps", ambient_caps);
    vars.insert("env_lines", env_lines);
    vars.insert("user_line", user_line);
    vars.insert("group_line", group_line);
    vars.insert("restart_policy", spec.restart_policy.as_systemd().into());
    vars.insert("wanted_by", wanted_by.into());

    template::render(TEMPLATE, &vars)
}

fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./=:".contains(c))
    {
        s.to_string()
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
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

    #[test]
    fn render_includes_exec_and_user() {
        let mgr = SystemdSystemManager::new();
        let out = mgr.render(&sample_spec());
        assert!(out.contains("ExecStart=/usr/local/bin/spt"));
        assert!(out.contains("User=spt"));
        assert!(out.contains("Group=spt"));
        assert!(out.contains("Type=notify"));
        assert!(out.contains("WantedBy=multi-user.target"));
    }

    /// E7-F2: the sandbox (`ProtectSystem=strict` / `ProtectHome=read-only`)
    /// must be paired with a writable state path, otherwise `StateLock` fails at
    /// boot and the installed service crash-loops.
    #[test]
    fn render_makes_state_dir_writable() {
        let mgr = SystemdSystemManager::new();
        let out = mgr.render(&sample_spec());
        assert!(
            out.contains("StateDirectory=spt"),
            "unit must declare StateDirectory so /var/lib/spt is writable: {out}"
        );
        assert!(out.contains("ReadWritePaths=/var/lib/spt /var/log/spt"));
        assert!(
            out.contains("Environment=\"SPT_STATE_DIR=/var/lib/spt\""),
            "unit must export SPT_STATE_DIR even when the spec env is empty: {out}"
        );
        // Sanity: the sandbox is still in place.
        assert!(out.contains("ProtectSystem=strict"));
        assert!(out.contains("ProtectHome=read-only"));
        assert!(out.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    }

    /// E7-F3: when the spec does not opt into `sd_notify` the unit must render
    /// `Type=simple` (the binary sends no readiness notification yet).
    #[test]
    fn render_type_simple_when_no_sd_notify() {
        let mgr = SystemdSystemManager::new();
        let mut spec = sample_spec();
        spec.sd_notify = false;
        let out = mgr.render(&spec);
        assert!(out.contains("Type=simple"), "{out}");
        assert!(!out.contains("Type=notify"), "{out}");
        // State-dir writability is independent of the service type.
        assert!(out.contains("StateDirectory=spt"));
    }

    #[test]
    fn validate_unit_name_accepts_systemd_charset() {
        assert!(validate_unit_name("spt").is_ok());
        assert!(validate_unit_name("spt-relay").is_ok());
        assert!(validate_unit_name("spt@inst.service").is_ok());
        assert!(validate_unit_name("A_b.9-x").is_ok());
    }

    #[test]
    fn validate_unit_name_rejects_path_escapes() {
        assert!(validate_unit_name("").is_err());
        assert!(validate_unit_name(".").is_err());
        assert!(validate_unit_name("..").is_err());
        assert!(validate_unit_name("../../evil").is_err());
        assert!(validate_unit_name("a/b").is_err());
        assert!(validate_unit_name("with space").is_err());
        assert!(validate_unit_name("nul\0byte").is_err());
    }

    #[tokio::test]
    async fn install_rejects_unsafe_name() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        let mgr = SystemdSystemManager::new_with_runner(mock)
            .with_unit_root(tmp.path().to_path_buf());
        let mut spec = sample_spec();
        spec.name = "../../evil".into();
        let err = mgr.install(&spec).await.unwrap_err();
        assert!(matches!(err, Error::ServiceManagerFailed(_)));
        // Nothing escaped the unit root.
        assert!(!tmp.path().parent().unwrap().join("evil.service").exists());
    }

    #[tokio::test]
    async fn uninstall_rejects_unsafe_name() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        let mgr = SystemdSystemManager::new_with_runner(mock)
            .with_unit_root(tmp.path().to_path_buf());
        let err = mgr.uninstall("../../evil").await.unwrap_err();
        assert!(matches!(err, Error::ServiceManagerFailed(_)));
    }

    #[test]
    fn parse_timestamp_utc_token_is_utc() {
        // Explicit UTC token → interpreted as UTC regardless of host tz.
        let dt = parse_systemd_timestamp("Mon 2024-01-15 10:30:45 UTC").unwrap();
        assert_eq!(dt.to_rfc3339(), "2024-01-15T10:30:45+00:00");
    }

    #[test]
    fn parse_timestamp_local_token_converts_to_utc() {
        // A local-zone wall clock must round-trip back to the same instant.
        use chrono::{Local, TimeZone};
        let naive = chrono::NaiveDate::from_ymd_opt(2024, 6, 15)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let local = Local.from_local_datetime(&naive).single().unwrap();
        let rendered = format!("{} EDT", naive.format("%Y-%m-%d %H:%M:%S"));
        let parsed = parse_systemd_timestamp(&rendered).unwrap();
        assert_eq!(parsed, local.with_timezone(&chrono::Utc));
    }

    #[test]
    fn snapshot_systemd_system() {
        let mgr = SystemdSystemManager::new();
        let out = mgr.render(&sample_spec());
        insta::assert_snapshot!("systemd_system_unit", out);
    }

    #[test]
    fn name_is_systemd_system() {
        assert_eq!(SystemdSystemManager::new().name(), "systemd-system");
    }

    #[test]
    fn capabilities_match_spec() {
        let caps = SystemdSystemManager::new().capabilities();
        assert!(caps.supports_install);
        assert!(caps.supports_uninstall);
        assert!(caps.supports_status);
        assert!(caps.supports_start_stop);
        assert!(caps.supports_restart);
        assert!(caps.supports_reload);
        assert!(!caps.supports_user_scope);
        assert!(caps.supports_status_pid);
        assert!(caps.supports_status_uptime);
        assert!(caps.supports_restart_counter);
    }

    #[tokio::test]
    async fn install_writes_unit_and_calls_systemctl() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        // daemon-reload, enable, start
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        let mgr = SystemdSystemManager::new_with_runner(mock.clone())
            .with_unit_root(tmp.path().to_path_buf());

        mgr.install(&sample_spec()).await.expect("install");

        let path = tmp.path().join("spt-relay.service");
        assert!(path.exists(), "unit file should have been written");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("/usr/local/bin/spt"));
        mock.assert_called("systemctl", &["daemon-reload"]);
        mock.assert_called("systemctl", &["enable", "spt-relay"]);
        mock.assert_called("systemctl", &["start", "spt-relay"]);
    }

    #[tokio::test]
    async fn uninstall_idempotent_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        // stop, disable, daemon-reload — all best-effort.
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
        let mgr = SystemdSystemManager::new_with_runner(mock.clone())
            .with_unit_root(tmp.path().to_path_buf());
        mgr.uninstall("ghost").await.expect("idempotent");
        mock.assert_called("systemctl", &["stop", "ghost"]);
        mock.assert_called("systemctl", &["disable", "ghost"]);
    }

    #[tokio::test]
    async fn uninstall_removes_existing_unit() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        let mgr = SystemdSystemManager::new_with_runner(mock.clone())
            .with_unit_root(tmp.path().to_path_buf());
        let path = tmp.path().join("spt-relay.service");
        std::fs::write(&path, "[Unit]\n").unwrap();
        assert!(path.exists());
        mgr.uninstall("spt-relay").await.expect("uninstall");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn status_running_parses_full() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(
            "ActiveState=active\n\
             SubState=running\n\
             MainPID=12345\n\
             ExecMainStatus=0\n\
             ActiveEnterTimestamp=Mon 2024-01-15 10:30:45 UTC\n\
             NRestarts=2\n\
             LoadState=loaded\n",
        ));
        let mgr = SystemdSystemManager::new_with_runner(mock);
        let st = mgr.status("svc").await.unwrap();
        assert_eq!(st.state, ServiceState::Running);
        assert_eq!(st.pid, Some(12345));
        assert_eq!(st.exit_code, None);
        assert!(st.since.is_some());
        assert_eq!(st.restart_count, Some(2));
    }

    #[tokio::test]
    async fn status_failed_carries_exit_code() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(
            "ActiveState=failed\n\
             SubState=failed\n\
             MainPID=0\n\
             ExecMainStatus=2\n\
             ActiveEnterTimestamp=n/a\n\
             NRestarts=5\n\
             LoadState=loaded\n",
        ));
        let mgr = SystemdSystemManager::new_with_runner(mock);
        let st = mgr.status("svc").await.unwrap();
        assert_eq!(st.state, ServiceState::Failed);
        assert_eq!(st.pid, None);
        assert_eq!(st.exit_code, Some(2));
        assert!(st.since.is_none());
        assert_eq!(st.restart_count, Some(5));
    }

    #[tokio::test]
    async fn status_inactive_is_stopped() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(
            "ActiveState=inactive\n\
             SubState=dead\n\
             MainPID=0\n\
             ExecMainStatus=0\n\
             ActiveEnterTimestamp=n/a\n\
             NRestarts=0\n\
             LoadState=loaded\n",
        ));
        let mgr = SystemdSystemManager::new_with_runner(mock);
        let st = mgr.status("svc").await.unwrap();
        assert_eq!(st.state, ServiceState::Stopped);
        assert_eq!(st.pid, None);
        // exit_code was 0 → None
        assert_eq!(st.exit_code, None);
    }

    #[tokio::test]
    async fn status_not_installed_when_loadstate_not_found() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(
            "ActiveState=inactive\n\
             SubState=dead\n\
             MainPID=0\n\
             ExecMainStatus=0\n\
             ActiveEnterTimestamp=n/a\n\
             NRestarts=0\n\
             LoadState=not-found\n",
        ));
        let mgr = SystemdSystemManager::new_with_runner(mock);
        let st = mgr.status("ghost").await.unwrap();
        assert_eq!(st.state, ServiceState::NotInstalled);
    }

    #[tokio::test]
    async fn start_stop_restart_reload_send_correct_args() {
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        mock.push_output(ok_out(""));
        let mgr = SystemdSystemManager::new_with_runner(mock.clone());
        mgr.start("svc").await.unwrap();
        mgr.stop("svc").await.unwrap();
        mgr.restart("svc").await.unwrap();
        mgr.reload("svc").await.unwrap();
        mock.assert_called("systemctl", &["start", "svc"]);
        mock.assert_called("systemctl", &["stop", "svc"]);
        mock.assert_called("systemctl", &["restart", "svc"]);
        mock.assert_called("systemctl", &["reload-or-restart", "svc"]);
    }

    #[test]
    fn parse_show_output_unknown_when_empty() {
        let st = parse_show_output("");
        assert_eq!(st.state, ServiceState::Unknown);
        assert_eq!(st.pid, None);
        assert_eq!(st.restart_count, None);
    }

    #[tokio::test]
    #[ignore = "requires Linux + systemctl in PATH"]
    async fn integration_status_smoke() {
        let mgr = SystemdSystemManager::new();
        let _ = mgr.status("nonexistent-spt-test").await;
    }
}
