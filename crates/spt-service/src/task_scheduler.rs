//! Task Scheduler backend (Windows `schtasks.exe`).
//!
//! Renders a `schtasks.exe /Create` argument vector and shells out to
//! `schtasks.exe` for every lifecycle operation. This is the fallback path
//! for hosts where Windows SCM registration isn't desired (e.g. user-scope
//! tasks, logon triggers).
//!
//! All shell-outs go through a `CommandRunner` so tests can inject a
//! `MockRunner` and assert on exact argument lists. Production code uses
//! `TokioRunner` with a 30-second per-call timeout.
//!
//! Task Scheduler has no native "reload" concept — the closest equivalent
//! is `schtasks /Change`, which means re-rendering the task definition
//! (i.e. re-running `install`). That is intentionally **not** exposed
//! through [`ServiceManager::reload`]; callers receive
//! [`spt_core::Error::UnsupportedPlatform`] and must redo `install` if they need to
//! mutate task fields.
//!
//! Reference: <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks>

#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use spt_core::error::Error;
use spt_core::error::Result;

#[cfg(target_os = "windows")]
use crate::runner::{CommandRunner, RunOutput, TokioRunner};
#[cfg(target_os = "windows")]
use crate::{unsupported, ServiceState, ServiceStatus};
use crate::{ServiceCapabilities, ServiceManager, ServiceSpec};

/// Trigger to attach to the scheduled task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Run at system startup.
    AtStartup,
    /// Run when the current user logs on.
    AtLogon,
}

impl Default for Trigger {
    fn default() -> Self {
        Self::AtStartup
    }
}

#[cfg(target_os = "windows")]
const SCHTASKS_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(target_os = "windows")]
const SCHTASKS_BIN: &str = "schtasks.exe";

/// Backend identifier used in error messages and capability tables.
const BACKEND_NAME: &str = "task-scheduler";

/// Validate a service / unit name before it is interpolated into a path
/// join or a shell-out argument.
///
/// Service backends derive on-disk paths (e.g. `/etc/init.d/<name>`,
/// `~/Library/LaunchAgents/io.spt.<name>.plist`) by joining the operator
/// supplied name. An unsanitised `../../evil` would let install/uninstall
/// write or delete files outside the intended unit root. We restrict names
/// to `[A-Za-z0-9_.@-]+` (the union of what systemd, launchd labels, and
/// init-script filenames accept) and reject everything else — including the
/// empty string and any path separator.
///
/// Lives in this always-compiled module so `launchd`/`openrc`/`sysv`
/// (which are `cfg(unix)`-only on most hosts) can share one implementation
/// without duplicating it per backend.
///
/// # Errors
///
/// Returns [`Error::ServiceManagerFailed`] when `name` is empty or contains
/// a disallowed character.
pub(crate) fn validate_service_name(name: &str) -> Result<()> {
    use spt_core::error::Error;
    if name.is_empty() {
        return Err(Error::ServiceManagerFailed(
            "service name must not be empty".into(),
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-')))
    {
        return Err(Error::ServiceManagerFailed(format!(
            "invalid service name {name:?}: character {bad:?} is not allowed \
             (permitted: A-Z a-z 0-9 _ . @ -)"
        )));
    }
    Ok(())
}

// ============================================================================
// Windows implementation
// ============================================================================

/// Task Scheduler service manager (Windows).
///
/// Constructed with a [`Trigger`] (default `AtStartup`) and an
/// `Arc<dyn CommandRunner>` (default [`TokioRunner`]).
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct TaskSchedulerManager {
    /// Trigger applied to created tasks.
    pub trigger: Trigger,
    runner: Arc<dyn CommandRunner>,
}

#[cfg(target_os = "windows")]
impl TaskSchedulerManager {
    /// Construct with `Trigger::AtStartup` and a [`TokioRunner`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            trigger: Trigger::AtStartup,
            runner: Arc::new(TokioRunner::new()),
        }
    }

    /// Construct with a custom [`CommandRunner`] (used by tests via
    /// [`MockRunner`](crate::MockRunner)).
    #[must_use]
    pub fn new_with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            trigger: Trigger::AtStartup,
            runner,
        }
    }

    /// Override the trigger after construction.
    #[must_use]
    pub fn with_trigger(mut self, trigger: Trigger) -> Self {
        self.trigger = trigger;
        self
    }

    /// Render the `schtasks.exe /Create ...` command line for `spec` —
    /// useful as a human-readable plan and stable input for golden tests.
    #[must_use]
    pub fn render(&self, spec: &ServiceSpec) -> String {
        render_schtasks(spec, self.trigger)
    }

    async fn run(&self, args: &[&str]) -> Result<RunOutput> {
        self.runner.run(SCHTASKS_BIN, args, SCHTASKS_TIMEOUT).await
    }
}

#[cfg(target_os = "windows")]
impl Default for TaskSchedulerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl ServiceManager for TaskSchedulerManager {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    fn capabilities(&self) -> ServiceCapabilities {
        capabilities()
    }

    async fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let owned = schtasks_args(spec, self.trigger);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        let out = self.run(&args).await?;
        if !out.ok() {
            return Err(Error::ServiceManagerFailed(format!(
                "schtasks /Create for {name} exited {code}: {stderr}",
                name = spec.name,
                code = out.status,
                stderr = out.stderr.trim(),
            )));
        }
        Ok(())
    }

    async fn uninstall(&self, name: &str) -> Result<()> {
        let out = self.run(&["/Delete", "/TN", name, "/F"]).await?;
        if out.ok() {
            return Ok(());
        }
        if is_not_found(&out) {
            // Idempotent: deleting a missing task is a no-op success.
            tracing::debug!(
                target: "spt_service::task_scheduler",
                task = %name,
                "uninstall: task already absent"
            );
            return Ok(());
        }
        Err(Error::ServiceManagerFailed(format!(
            "schtasks /Delete {name} exited {code}: {stderr}",
            code = out.status,
            stderr = out.stderr.trim(),
        )))
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        let out = self
            .run(&["/Query", "/TN", name, "/FO", "CSV", "/V"])
            .await?;
        if !out.ok() {
            if is_not_found(&out) {
                return Err(service_not_found(name));
            }
            return Err(Error::ServiceManagerFailed(format!(
                "schtasks /Query {name} exited {code}: {stderr}",
                code = out.status,
                stderr = out.stderr.trim(),
            )));
        }
        parse_status_csv(name, &out.stdout)
    }

    async fn start(&self, name: &str) -> Result<()> {
        let out = self.run(&["/Run", "/TN", name]).await?;
        if out.ok() {
            return Ok(());
        }
        if is_not_found(&out) {
            return Err(service_not_found(name));
        }
        Err(Error::ServiceManagerFailed(format!(
            "schtasks /Run {name} exited {code}: {stderr}",
            code = out.status,
            stderr = out.stderr.trim(),
        )))
    }

    async fn stop(&self, name: &str) -> Result<()> {
        let out = self.run(&["/End", "/TN", name]).await?;
        if out.ok() {
            return Ok(());
        }
        if is_not_running(&out) {
            // Idempotent: stopping a not-running task is a no-op success
            // (parity with systemd `stop` of an inactive unit).
            tracing::debug!(
                target: "spt_service::task_scheduler",
                task = %name,
                "stop: task already not running"
            );
            return Ok(());
        }
        if is_not_found(&out) {
            return Err(service_not_found(name));
        }
        Err(Error::ServiceManagerFailed(format!(
            "schtasks /End {name} exited {code}: {stderr}",
            code = out.status,
            stderr = out.stderr.trim(),
        )))
    }

    async fn restart(&self, name: &str) -> Result<()> {
        // `stop` already tolerates "not currently running".
        self.stop(name).await?;
        self.start(name).await
    }

    async fn reload(&self, _name: &str) -> Result<()> {
        // Task Scheduler has no reload primitive. The only mutation path
        // is `schtasks /Change`, which is functionally equivalent to
        // re-running `install`, so we surface this as unsupported rather
        // than silently re-installing.
        Err(unsupported(BACKEND_NAME, "reload"))
    }
}

// ----- helpers (Windows only) -----------------------------------------------

#[cfg(target_os = "windows")]
fn capabilities() -> ServiceCapabilities {
    ServiceCapabilities {
        supports_install: true,
        supports_uninstall: true,
        supports_status: true,
        supports_start_stop: true,
        supports_restart: true,
        supports_reload: false,
        supports_user_scope: true,
        supports_status_pid: false,
        supports_status_uptime: false,
        supports_restart_counter: false,
    }
}

#[cfg(target_os = "windows")]
fn service_not_found(name: &str) -> Error {
    Error::ServiceManagerFailed(format!("scheduled task not found: {name}"))
}

/// Windows system error code `ERROR_FILE_NOT_FOUND` — schtasks surfaces
/// this (rather than its generic exit 1) when the named task is absent on
/// most Windows builds. Preferring it over message text keeps detection
/// working on localized Windows where the English banner differs.
#[cfg(target_os = "windows")]
const ERROR_FILE_NOT_FOUND: i32 = 2;

#[cfg(target_os = "windows")]
fn is_not_found(out: &RunOutput) -> bool {
    if out.status == 0 {
        return false;
    }
    // Prefer the typed exit code (locale-independent); fall back to the
    // English message banners for builds that collapse everything to exit 1.
    if out.status == ERROR_FILE_NOT_FOUND {
        return true;
    }
    let combined = format!("{} {}", out.stderr, out.stdout).to_ascii_lowercase();
    combined.contains("cannot find the file")
        || combined.contains("the system cannot find")
        || combined.contains("does not exist")
}

#[cfg(target_os = "windows")]
fn is_not_running(out: &RunOutput) -> bool {
    if out.status == 0 {
        return false;
    }
    // schtasks `/End` on a not-running task and on a real failure (e.g.
    // access denied) both exit 1, so the exit code alone cannot classify
    // "not running" — we must consult the message banner. This stays
    // English-biased; the not-found path above leads with the locale-
    // independent ERROR_FILE_NOT_FOUND exit code where schtasks provides it.
    let combined = format!("{} {}", out.stderr, out.stdout).to_ascii_lowercase();
    combined.contains("not currently running")
}

/// Parse `schtasks /Query ... /FO CSV /V` output into a [`ServiceStatus`].
///
/// `schtasks /V` emits a header row followed by one row per task. We pick
/// the first data row whose `TaskName` matches `name` (or, failing that,
/// the first data row at all — `/TN <name>` should already filter).
#[cfg(target_os = "windows")]
fn parse_status_csv(name: &str, csv_text: &str) -> Result<ServiceStatus> {
    use csv::ReaderBuilder;

    // schtasks emits a blank line / "INFO:" preamble on some locales —
    // strip leading blank lines to keep csv happy.
    let trimmed = csv_text.trim_start_matches(|c: char| c.is_whitespace());

    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(trimmed.as_bytes());

    let headers = rdr
        .headers()
        .map_err(|e| Error::ServiceManagerFailed(format!("parse schtasks CSV headers: {e}")))?
        .clone();

    let idx =
        |key: &str| -> Option<usize> { headers.iter().position(|h| h.eq_ignore_ascii_case(key)) };

    let i_status = idx("Status");
    let i_taskname = idx("TaskName");
    let i_last_run = idx("Last Run Time");
    let i_last_result = idx("Last Result");

    let mut chosen: Option<csv::StringRecord> = None;
    for rec in rdr.records() {
        let Ok(rec) = rec else { continue };
        // Skip blank / header-repeat rows that schtasks sometimes emits.
        if rec.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        if let Some(i) = i_taskname {
            if let Some(tn) = rec.get(i) {
                let tn = tn.trim();
                let want = name.trim_start_matches('\\');
                if tn.trim_start_matches('\\').eq_ignore_ascii_case(want) {
                    chosen = Some(rec);
                    break;
                }
            }
        }
        if chosen.is_none() {
            chosen = Some(rec);
        }
    }

    let row = chosen.ok_or_else(|| {
        Error::ServiceManagerFailed(format!(
            "schtasks /Query for {name}: no data rows in CSV output"
        ))
    })?;

    let raw_status = i_status.and_then(|i| row.get(i)).map_or("", str::trim);

    let state = match raw_status {
        s if s.eq_ignore_ascii_case("Running") => ServiceState::Running,
        s if s.eq_ignore_ascii_case("Ready") => ServiceState::Stopped,
        s if s.eq_ignore_ascii_case("Disabled") => {
            tracing::warn!(
                target: "spt_service::task_scheduler",
                task = %name,
                "task is Disabled — reporting as Stopped"
            );
            ServiceState::Stopped
        }
        s if s.eq_ignore_ascii_case("Could Not Start") => ServiceState::Failed,
        _ => ServiceState::Unknown,
    };

    let mut status = ServiceStatus::new(state);

    if let Some(ts) = i_last_run.and_then(|i| row.get(i)) {
        if let Some(dt) = parse_schtasks_timestamp(ts.trim()) {
            status.since = Some(dt);
        }
    }

    if let Some(lr) = i_last_result.and_then(|i| row.get(i)) {
        if let Ok(code) = lr.trim().parse::<i32>() {
            // Only surface a non-zero exit code when the task isn't
            // currently running; otherwise it's stale.
            if code != 0 && raw_status.eq_ignore_ascii_case("Ready") {
                status.exit_code = Some(code);
            }
        }
    }

    Ok(status)
}

/// Best-effort parser for `schtasks` "Last Run Time" timestamps.
///
/// Examples observed across locales:
/// * `5/4/2026 3:24:21 PM` (en-US, M/D/YYYY h:m:s AM/PM)
/// * `2026-05-04 15:24:21` (ISO-ish, some configurations)
/// * `N/A` (never run) — returns `None`.
#[cfg(target_os = "windows")]
fn parse_schtasks_timestamp(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{Local, NaiveDateTime, TimeZone};

    // schtasks emits "Last Run Time" as a *local* wall clock with no zone
    // token. Parse it as a naive datetime, interpret it in the host's local
    // zone, then convert to UTC so `ServiceStatus.since` is an absolute
    // instant rather than a UTC value skewed by the host offset (E7-F14).
    const FORMATS: &[&str] = &[
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ];

    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("N/A") {
        return None;
    }

    for fmt in FORMATS {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            // `from_local_datetime` is ambiguous across a DST fall-back and
            // nonexistent across a spring-forward gap. Prefer the
            // unambiguous mapping; on ambiguity take the earliest, and on a
            // gap fall back to treating the wall clock as UTC (best-effort,
            // ordering still holds).
            return match Local.from_local_datetime(&naive) {
                chrono::LocalResult::Single(dt) => Some(dt.with_timezone(&chrono::Utc)),
                chrono::LocalResult::Ambiguous(earlier, _) => {
                    Some(earlier.with_timezone(&chrono::Utc))
                }
                chrono::LocalResult::None => Some(chrono::Utc.from_utc_datetime(&naive)),
            };
        }
    }
    None
}

// ----- argv rendering (always available, used by render + install) ----------

fn render_schtasks(spec: &ServiceSpec, trigger: Trigger) -> String {
    let args = schtasks_args(spec, trigger);
    args.iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn schtasks_args(spec: &ServiceSpec, trigger: Trigger) -> Vec<String> {
    let tr = match trigger {
        Trigger::AtStartup => "ONSTART",
        Trigger::AtLogon => "ONLOGON",
    };
    let bin_with_args = format!(
        "\"{}\" {}",
        spec.exec_path.display(),
        spec.args
            .iter()
            .map(|a| if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            })
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut a: Vec<String> = vec![
        "/Create".into(),
        "/TN".into(),
        spec.name.clone(),
        "/TR".into(),
        bin_with_args,
        "/SC".into(),
        tr.into(),
        "/RL".into(),
        "HIGHEST".into(),
        "/F".into(),
    ];
    if let Some(u) = &spec.user {
        a.push("/RU".into());
        a.push(u.clone());
    }
    a
}

// ============================================================================
// Non-Windows stub
// ============================================================================

/// Task Scheduler service manager (non-Windows stub).
///
/// Every lifecycle method returns `Error::UnsupportedPlatform`. Exists so
/// downstream code can name the type unconditionally; only the Windows
/// build actually shells out to `schtasks.exe`.
#[cfg(not(target_os = "windows"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskSchedulerManager {
    /// Trigger applied to created tasks (rendered into the
    /// `schtasks.exe /Create` argv on Windows; ignored on non-Windows).
    pub trigger: Trigger,
}

#[cfg(not(target_os = "windows"))]
impl TaskSchedulerManager {
    /// Construct a stub manager. All methods return
    /// `Error::UnsupportedPlatform`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trigger: Trigger::AtStartup,
        }
    }

    /// Override the trigger after construction. Mirrors the Windows builder
    /// so cross-platform golden tests can configure the trigger uniformly.
    #[must_use]
    pub fn with_trigger(mut self, trigger: Trigger) -> Self {
        self.trigger = trigger;
        self
    }

    /// Render the `schtasks.exe /Create` command line for `spec` — the
    /// rendering itself is platform-independent and useful for golden
    /// tests on non-Windows CI.
    //
    // Takes `&self` to keep signature parity with the Windows manager (which
    // is not `Copy`); on this stub the struct is `Copy`, so clippy would
    // otherwise nag to pass by value.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn render(&self, spec: &ServiceSpec) -> String {
        render_schtasks(spec, self.trigger)
    }
}

#[cfg(not(target_os = "windows"))]
#[async_trait::async_trait]
impl ServiceManager for TaskSchedulerManager {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    fn capabilities(&self) -> ServiceCapabilities {
        ServiceCapabilities::default()
    }

    async fn install(&self, _spec: &ServiceSpec) -> Result<()> {
        Err(crate::unsupported(BACKEND_NAME, "install"))
    }
    async fn uninstall(&self, _name: &str) -> Result<()> {
        Err(crate::unsupported(BACKEND_NAME, "uninstall"))
    }
    async fn status(&self, _name: &str) -> Result<crate::ServiceStatus> {
        Err(crate::unsupported(BACKEND_NAME, "status"))
    }
    async fn start(&self, _name: &str) -> Result<()> {
        Err(crate::unsupported(BACKEND_NAME, "start"))
    }
    async fn stop(&self, _name: &str) -> Result<()> {
        Err(crate::unsupported(BACKEND_NAME, "stop"))
    }
    async fn restart(&self, _name: &str) -> Result<()> {
        Err(crate::unsupported(BACKEND_NAME, "restart"))
    }
    async fn reload(&self, _name: &str) -> Result<()> {
        Err(crate::unsupported(BACKEND_NAME, "reload"))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;

    // --- Render tests (cross-platform) --------------------------------------

    #[test]
    fn render_contains_create_and_trigger() {
        let mgr = TaskSchedulerManager::new();
        let out = mgr.render(&sample_spec());
        assert!(out.contains("/Create"));
        assert!(out.contains("/SC ONSTART"));
        assert!(out.contains("/TN spt-relay"));
    }

    #[test]
    fn snapshot_task_scheduler() {
        let mgr = TaskSchedulerManager::new();
        let out = mgr.render(&sample_spec());
        insta::assert_snapshot!("task_scheduler_cmd", out);
    }

    #[test]
    fn trigger_default_is_at_startup() {
        let t = Trigger::default();
        assert_eq!(t, Trigger::AtStartup);
    }

    #[test]
    fn render_onlogon_when_trigger_is_atlogon() {
        let mgr = TaskSchedulerManager::new().with_trigger(Trigger::AtLogon);
        let out = mgr.render(&sample_spec());
        assert!(out.contains("/SC ONLOGON"), "got: {out}");
        assert!(!out.contains("/SC ONSTART"));
    }

    #[test]
    fn render_quotes_args_containing_spaces() {
        let mut spec = sample_spec();
        spec.args = vec!["service".into(), "run".into(), "with space".into()];
        let out = TaskSchedulerManager::new().render(&spec);
        assert!(out.contains("\"with space\""), "got: {out}");
    }

    #[test]
    fn render_includes_user_when_set() {
        let mut spec = sample_spec();
        spec.user = Some("DESKTOP\\admin".into());
        let out = TaskSchedulerManager::new().render(&spec);
        // /RU <user> must appear.
        assert!(out.contains("/RU"), "got: {out}");
        assert!(out.contains("DESKTOP\\admin"));
    }

    #[test]
    fn render_drops_user_when_absent() {
        let mut spec = sample_spec();
        spec.user = None;
        let out = TaskSchedulerManager::new().render(&spec);
        assert!(!out.contains("/RU"));
    }

    #[test]
    fn render_always_includes_force_flag() {
        let out = TaskSchedulerManager::new().render(&sample_spec());
        // /F appears as a standalone arg.
        assert!(out.split_whitespace().any(|a| a == "/F"));
    }

    // --- name validation (shared across launchd/openrc/sysv) ----------------

    #[test]
    fn validate_service_name_accepts_typical_names() {
        for ok in [
            "spt",
            "spt-relay",
            "spt_relay",
            "io.spt.relay",
            "svc@1",
            "a.b-c_d",
        ] {
            assert!(validate_service_name(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn validate_service_name_rejects_path_traversal_and_separators() {
        for bad in [
            "",
            "../../evil",
            "../evil",
            "a/b",
            "a\\b",
            "name with space",
            "name;rm",
            "name\nnewline",
            "name*",
        ] {
            let err = validate_service_name(bad).expect_err("should reject");
            assert!(
                matches!(err, spt_core::error::Error::ServiceManagerFailed(_)),
                "bad name {bad:?} should yield ServiceManagerFailed, got {err:?}"
            );
        }
    }

    // --- Lifecycle tests (Windows-shaped, but driven via MockRunner) --------

    #[cfg(target_os = "windows")]
    mod windows {
        use super::*;
        use crate::runner::{MockRunner, RunOutput};
        use std::sync::Arc;

        fn manager(mock: &MockRunner) -> TaskSchedulerManager {
            TaskSchedulerManager::new_with_runner(Arc::new(mock.clone()))
        }

        fn ok_out() -> RunOutput {
            RunOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            }
        }

        #[test]
        fn capabilities_match_spec() {
            let caps = TaskSchedulerManager::new().capabilities();
            assert!(caps.supports_install);
            assert!(caps.supports_uninstall);
            assert!(caps.supports_status);
            assert!(caps.supports_start_stop);
            assert!(caps.supports_restart);
            assert!(!caps.supports_reload);
            assert!(caps.supports_user_scope);
            assert!(!caps.supports_status_pid);
            assert!(!caps.supports_status_uptime);
            assert!(!caps.supports_restart_counter);
        }

        #[test]
        fn name_is_task_scheduler() {
            assert_eq!(TaskSchedulerManager::new().name(), "task-scheduler");
        }

        #[tokio::test]
        async fn install_invokes_schtasks_create_with_expected_args() {
            let mock = MockRunner::new();
            mock.push_output(ok_out());
            let mgr = manager(&mock);
            let spec = sample_spec();
            mgr.install(&spec).await.expect("install ok");

            let calls = mock.calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "schtasks.exe");
            // Spot-check key flags appear in order.
            let args = &calls[0].1;
            assert_eq!(args[0], "/Create");
            assert_eq!(args[1], "/TN");
            assert_eq!(args[2], "spt-relay");
            assert!(args.iter().any(|a| a == "/SC"));
            assert!(args.iter().any(|a| a == "ONSTART"));
            assert!(args.iter().any(|a| a == "/F"));
        }

        #[tokio::test]
        async fn install_propagates_nonzero_exit_as_error() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 1,
                stdout: String::new(),
                stderr: "ERROR: Access is denied.".into(),
            });
            let mgr = manager(&mock);
            let err = mgr
                .install(&sample_spec())
                .await
                .expect_err("non-zero exit must error");
            let msg = format!("{err}");
            assert!(msg.contains("schtasks /Create"), "got: {msg}");
        }

        #[tokio::test]
        async fn uninstall_is_idempotent_when_task_missing() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 1,
                stdout: String::new(),
                stderr: "ERROR: The system cannot find the file specified.".into(),
            });
            let mgr = manager(&mock);
            mgr.uninstall("ghost-task")
                .await
                .expect("missing task → Ok(())");
            mock.assert_called("schtasks.exe", &["/Delete", "/TN", "ghost-task", "/F"]);
        }

        #[tokio::test]
        async fn uninstall_idempotent_on_error_file_not_found_exit_code() {
            // Localized Windows may not emit the English "cannot find" banner;
            // schtasks still surfaces ERROR_FILE_NOT_FOUND (2). Detection must
            // succeed off the exit code alone.
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 2,
                stdout: String::new(),
                stderr: "<localized not-found message>".into(),
            });
            let mgr = manager(&mock);
            mgr.uninstall("ghost-task")
                .await
                .expect("ERROR_FILE_NOT_FOUND → Ok(())");
        }

        #[tokio::test]
        async fn status_not_found_via_exit_code_only() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 2,
                stdout: String::new(),
                stderr: "<localized>".into(),
            });
            let mgr = manager(&mock);
            let err = mgr.status("ghost").await.expect_err("must error");
            assert!(format!("{err}").contains("not found"));
        }

        #[tokio::test]
        async fn uninstall_succeeds_on_zero_exit() {
            let mock = MockRunner::new();
            mock.push_output(ok_out());
            let mgr = manager(&mock);
            mgr.uninstall("spt-relay").await.expect("ok");
        }

        #[tokio::test]
        async fn uninstall_surfaces_unexpected_failures() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 5,
                stdout: String::new(),
                stderr: "ERROR: Access is denied.".into(),
            });
            let mgr = manager(&mock);
            let err = mgr.uninstall("spt-relay").await.expect_err("err");
            assert!(format!("{err}").contains("Access is denied"));
        }

        const RUNNING_CSV: &str = "\
\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Logon Mode\",\"Last Run Time\",\"Last Result\",\"Author\",\"Task To Run\",\"Start In\",\"Comment\",\"Scheduled Task State\",\"Idle Time\",\"Power Management\",\"Run As User\",\"Delete Task If Not Rescheduled\",\"Stop Task If Runs X Hours and X Mins\",\"Schedule\",\"Schedule Type\",\"Start Time\",\"Start Date\",\"End Date\",\"Days\",\"Months\",\"Repeat: Every\",\"Repeat: Until: Time\",\"Repeat: Until: Duration\",\"Repeat: Stop If Still Running\"
\"DESKTOP\",\"\\spt-relay\",\"N/A\",\"Running\",\"Interactive/Background\",\"5/4/2026 3:24:21 PM\",\"267009\",\"DESKTOP\\admin\",\"C:\\spt.exe\",\"N/A\",\"\",\"Enabled\",\"Disabled\",\"Stop On Battery Mode, No Start On Batteries\",\"DESKTOP\\admin\",\"Enabled\",\"Disabled\",\"At system start up\",\"On start\",\"N/A\",\"5/4/2026\",\"N/A\",\"N/A\",\"N/A\",\"Disabled\",\"Disabled\",\"Disabled\",\"Disabled\"
";

        const READY_CSV: &str = "\
\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Last Run Time\",\"Last Result\"
\"DESKTOP\",\"\\spt-relay\",\"N/A\",\"Ready\",\"5/4/2026 3:24:21 PM\",\"0\"
";

        const READY_NONZERO_CSV: &str = "\
\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Last Run Time\",\"Last Result\"
\"DESKTOP\",\"\\spt-relay\",\"N/A\",\"Ready\",\"5/4/2026 3:24:21 PM\",\"2\"
";

        const DISABLED_CSV: &str = "\
\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Last Run Time\",\"Last Result\"
\"DESKTOP\",\"\\spt-relay\",\"N/A\",\"Disabled\",\"N/A\",\"267011\"
";

        const FAILED_CSV: &str = "\
\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Last Run Time\",\"Last Result\"
\"DESKTOP\",\"\\spt-relay\",\"N/A\",\"Could Not Start\",\"5/4/2026 3:24:21 PM\",\"1\"
";

        #[tokio::test]
        async fn status_running() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 0,
                stdout: RUNNING_CSV.into(),
                stderr: String::new(),
            });
            let mgr = manager(&mock);
            let st = mgr.status("spt-relay").await.expect("ok");
            assert_eq!(st.state, ServiceState::Running);
            assert!(st.since.is_some(), "Last Run Time should parse");
            // Running tasks: last_result is stale (e.g. 267009 = still running)
            // — we suppress exit_code unless Status == Ready.
            assert!(st.exit_code.is_none());
        }

        #[tokio::test]
        async fn status_ready_clean() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 0,
                stdout: READY_CSV.into(),
                stderr: String::new(),
            });
            let mgr = manager(&mock);
            let st = mgr.status("spt-relay").await.expect("ok");
            assert_eq!(st.state, ServiceState::Stopped);
            // Last Result == 0 → no exit_code surfaced.
            assert!(st.exit_code.is_none());
            assert!(st.since.is_some());
        }

        #[tokio::test]
        async fn status_ready_nonzero_last_result_surfaces_exit_code() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 0,
                stdout: READY_NONZERO_CSV.into(),
                stderr: String::new(),
            });
            let mgr = manager(&mock);
            let st = mgr.status("spt-relay").await.expect("ok");
            assert_eq!(st.state, ServiceState::Stopped);
            assert_eq!(st.exit_code, Some(2));
        }

        #[tokio::test]
        async fn status_disabled_maps_to_stopped() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 0,
                stdout: DISABLED_CSV.into(),
                stderr: String::new(),
            });
            let mgr = manager(&mock);
            let st = mgr.status("spt-relay").await.expect("ok");
            assert_eq!(st.state, ServiceState::Stopped);
        }

        #[tokio::test]
        async fn status_could_not_start_maps_to_failed() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 0,
                stdout: FAILED_CSV.into(),
                stderr: String::new(),
            });
            let mgr = manager(&mock);
            let st = mgr.status("spt-relay").await.expect("ok");
            assert_eq!(st.state, ServiceState::Failed);
        }

        #[tokio::test]
        async fn status_not_found_returns_typed_error() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 1,
                stdout: String::new(),
                stderr: "ERROR: The system cannot find the file specified.".into(),
            });
            let mgr = manager(&mock);
            let err = mgr.status("ghost").await.expect_err("must error");
            let msg = format!("{err}");
            assert!(msg.contains("not found"), "got: {msg}");
        }

        #[tokio::test]
        async fn start_invokes_schtasks_run() {
            let mock = MockRunner::new();
            mock.push_output(ok_out());
            let mgr = manager(&mock);
            mgr.start("spt-relay").await.expect("ok");
            mock.assert_called("schtasks.exe", &["/Run", "/TN", "spt-relay"]);
        }

        #[tokio::test]
        async fn start_not_found_is_typed_error() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 1,
                stdout: String::new(),
                stderr: "ERROR: The system cannot find the file specified.".into(),
            });
            let mgr = manager(&mock);
            let err = mgr.start("ghost").await.expect_err("err");
            assert!(format!("{err}").contains("not found"));
        }

        #[tokio::test]
        async fn stop_invokes_schtasks_end() {
            let mock = MockRunner::new();
            mock.push_output(ok_out());
            let mgr = manager(&mock);
            mgr.stop("spt-relay").await.expect("ok");
            mock.assert_called("schtasks.exe", &["/End", "/TN", "spt-relay"]);
        }

        #[tokio::test]
        async fn stop_idempotent_when_not_running() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 1,
                stdout: String::new(),
                stderr: "ERROR: The task is not currently running.".into(),
            });
            let mgr = manager(&mock);
            mgr.stop("spt-relay").await.expect("not-running → Ok(())");
        }

        #[tokio::test]
        async fn restart_calls_stop_then_start() {
            let mock = MockRunner::new();
            mock.push_output(ok_out()); // stop
            mock.push_output(ok_out()); // start
            let mgr = manager(&mock);
            mgr.restart("spt-relay").await.expect("ok");
            let calls = mock.calls();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].1[0], "/End");
            assert_eq!(calls[1].1[0], "/Run");
        }

        #[tokio::test]
        async fn restart_tolerates_stop_when_not_running() {
            let mock = MockRunner::new();
            mock.push_output(RunOutput {
                status: 1,
                stdout: String::new(),
                stderr: "ERROR: The task is not currently running.".into(),
            }); // stop says not running — tolerated
            mock.push_output(ok_out()); // start succeeds
            let mgr = manager(&mock);
            mgr.restart("spt-relay").await.expect("ok");
            assert_eq!(mock.calls().len(), 2);
        }

        #[tokio::test]
        async fn reload_returns_unsupported_platform() {
            let mock = MockRunner::new();
            // No canned output: reload must not shell out at all.
            let mgr = manager(&mock);
            let err = mgr
                .reload("spt-relay")
                .await
                .expect_err("reload unsupported");
            match err {
                spt_core::error::Error::UnsupportedPlatform(msg) => {
                    assert!(msg.contains("reload"), "got: {msg}");
                    assert!(msg.contains("task-scheduler"), "got: {msg}");
                }
                other => panic!("expected UnsupportedPlatform, got {other:?}"),
            }
            assert!(mock.calls().is_empty(), "reload must not shell out");
        }

        #[test]
        fn parse_timestamp_handles_us_locale() {
            // The wall clock is interpreted in the host's local zone and
            // converted to UTC, so the absolute instant depends on the host
            // offset. Assert by round-tripping back to local time rather than
            // hard-coding a UTC string (which would only hold on a UTC host).
            use chrono::{Local, NaiveDateTime, TimeZone};
            let dt = parse_schtasks_timestamp("5/4/2026 3:24:21 PM").expect("parse");
            let expected_local =
                NaiveDateTime::parse_from_str("2026-05-04 15:24:21", "%Y-%m-%d %H:%M:%S").unwrap();
            let want = Local
                .from_local_datetime(&expected_local)
                .earliest()
                .unwrap()
                .with_timezone(&chrono::Utc);
            assert_eq!(dt, want);
        }

        #[test]
        fn parse_timestamp_handles_iso() {
            use chrono::{Local, NaiveDateTime, TimeZone};
            let dt = parse_schtasks_timestamp("2026-05-04 15:24:21").expect("parse");
            let expected_local =
                NaiveDateTime::parse_from_str("2026-05-04 15:24:21", "%Y-%m-%d %H:%M:%S").unwrap();
            let want = Local
                .from_local_datetime(&expected_local)
                .earliest()
                .unwrap()
                .with_timezone(&chrono::Utc);
            assert_eq!(dt, want);
        }

        #[test]
        fn parse_timestamp_returns_none_for_na() {
            assert!(parse_schtasks_timestamp("N/A").is_none());
            assert!(parse_schtasks_timestamp("").is_none());
        }
    }

    // --- Non-Windows stub tests --------------------------------------------

    #[cfg(not(target_os = "windows"))]
    mod non_windows {
        use super::*;

        #[tokio::test]
        async fn every_method_is_unsupported_platform() {
            let mgr = TaskSchedulerManager::new();
            for err in [
                mgr.install(&sample_spec()).await.unwrap_err(),
                mgr.uninstall("x").await.unwrap_err(),
                mgr.status("x").await.unwrap_err(),
                mgr.start("x").await.unwrap_err(),
                mgr.stop("x").await.unwrap_err(),
                mgr.restart("x").await.unwrap_err(),
                mgr.reload("x").await.unwrap_err(),
            ] {
                match err {
                    spt_core::error::Error::UnsupportedPlatform(_) => {}
                    other => panic!("expected UnsupportedPlatform, got {other:?}"),
                }
            }
        }

        #[test]
        fn capabilities_default_all_false() {
            let caps = TaskSchedulerManager::new().capabilities();
            assert!(!caps.supports_install);
            assert!(!caps.supports_status);
        }

        #[test]
        fn render_still_works_for_golden_tests() {
            let out = TaskSchedulerManager::new().render(&sample_spec());
            assert!(out.contains("/Create"));
        }
    }
}
