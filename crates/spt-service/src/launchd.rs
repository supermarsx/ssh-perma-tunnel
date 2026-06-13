//! launchd plist manager (macOS Agents and Daemons).
//!
//! `Scope::User` writes to `~/Library/LaunchAgents/<label>.plist`,
//! `Scope::System` writes to `/Library/LaunchDaemons/<label>.plist`. Lifecycle
//! shells out to `launchctl` via the injected [`CommandRunner`] so that tests
//! stay hermetic and assert on exact argument lists.
//!
//! ## Domain model
//!
//! launchd's modern subcommands (`print`, `kickstart`, `kill`) take a
//! domain-qualified service target rather than a bare label:
//!
//! * **Daemon (system scope):** `system/<label>`
//! * **Agent (user scope):** `gui/<uid>/<label>`
//!
//! The legacy `list` / `load` / `unload` subcommands still take the bare
//! label and the plist path respectively. The manager picks the right shape
//! based on the [`Scope`] it was constructed with.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use spt_core::error::{Error, Result};

use crate::task_scheduler::validate_service_name;
use crate::{
    template, unsupported, CommandRunner, Scope, ServiceCapabilities, ServiceManager, ServiceSpec,
    ServiceState, ServiceStatus, TokioRunner,
};

const TEMPLATE: &str = include_str!("../../../packaging/launchd/spt.plist.tmpl");

/// Reverse-DNS prefix for plist labels. Spec doesn't pin one, so use the
/// project repo namespace.
pub const LABEL_PREFIX: &str = "io.spt";

/// Default per-call timeout for `launchctl` invocations.
const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(30);

/// launchctl exit code returned when the requested service / label is not
/// known to the daemon. Mirrors `launchctl(1)`'s `kPOSIXErrorENOENT`-ish
/// mapping; observed empirically on macOS 10.10+.
const LAUNCHCTL_NOT_FOUND: i32 = 113;

/// launchd manager for both Agents (user scope) and Daemons (system scope).
///
/// The scope is fixed at construction; a single manager instance never
/// switches between system and user domains. Callers needing both should
/// hold two managers.
#[derive(Debug, Clone)]
pub struct LaunchdManager {
    scope: Scope,
    runner: Arc<dyn CommandRunner>,
    /// UID used to build the `gui/<uid>/<label>` domain string for user
    /// agents. Ignored for system daemons. Defaults to `$UID` if set, else
    /// `501` (the conventional first user UID on macOS).
    uid: u32,
    /// Whether the host supports `launchctl kickstart` / `print` (macOS
    /// ≥ 10.10). Set to `false` to force the older code path in tests.
    min_kickstart: bool,
}

impl LaunchdManager {
    /// Construct a system-scope (`LaunchDaemon`) manager backed by a real
    /// [`TokioRunner`]. Equivalent to the old zero-arg constructor and
    /// preserves the call-site in [`crate::new_default_manager`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_scope(Scope::System)
    }

    /// Construct a manager for the given `scope` with a default
    /// [`TokioRunner`] and an auto-detected UID.
    #[must_use]
    pub fn with_scope(scope: Scope) -> Self {
        Self {
            scope,
            runner: Arc::new(TokioRunner::new()),
            uid: detect_uid(),
            min_kickstart: true,
        }
    }

    /// Construct a manager with a caller-supplied [`CommandRunner`]. Used
    /// by tests with [`crate::MockRunner`] to assert on exact `launchctl`
    /// invocations without touching the host.
    #[must_use]
    pub fn new_with_runner(scope: Scope, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            scope,
            runner,
            uid: detect_uid(),
            min_kickstart: true,
        }
    }

    /// Override the effective UID used to build agent domain targets.
    /// Returns `self` for builder chaining.
    #[must_use]
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// Toggle the modern (`kickstart` / `print`) code path. Tests use
    /// `false` to exercise the legacy fallback.
    #[must_use]
    pub fn with_kickstart_supported(mut self, supported: bool) -> Self {
        self.min_kickstart = supported;
        self
    }

    /// Compute the full plist path for a spec — agent path under `$HOME`
    /// for [`Scope::User`], `/Library/LaunchDaemons` for [`Scope::System`].
    #[must_use]
    pub fn plist_path(spec: &ServiceSpec) -> PathBuf {
        let label = format!("{LABEL_PREFIX}.{}", spec.name);
        Self::plist_path_for(spec.scope, &label)
    }

    /// Compute the plist path for a given `(scope, label)` pair without
    /// needing a full [`ServiceSpec`].
    #[must_use]
    pub fn plist_path_for(scope: Scope, label: &str) -> PathBuf {
        // launchctl is macOS-only; always emit POSIX-style paths so cross-OS
        // tests assert on the same string a real macOS run would produce.
        match scope {
            Scope::User => {
                let home = std::env::var("HOME").unwrap_or_else(|_| "~".into());
                let home = home.trim_end_matches('/');
                PathBuf::from(format!("{home}/Library/LaunchAgents/{label}.plist"))
            }
            Scope::System => PathBuf::from(format!("/Library/LaunchDaemons/{label}.plist")),
        }
    }

    /// Render the plist for a spec. Free of side effects — used by golden
    /// snapshot tests and by [`Self::install`].
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn render(&self, spec: &ServiceSpec) -> String {
        render_plist(spec)
    }

    /// Build the qualified launchctl service target
    /// (`system/<label>` or `gui/<uid>/<label>`).
    fn domain_target(&self, label: &str) -> String {
        match self.scope {
            Scope::System => format!("system/{label}"),
            Scope::User => format!("gui/{}/{label}", self.uid),
        }
    }

    /// Map a service `name` to its full reverse-DNS label.
    fn label_for(name: &str) -> String {
        format!("{LABEL_PREFIX}.{name}")
    }

    /// Send an arbitrary signal (`SIGHUP`, `SIGTERM`, ...) to the running
    /// service via `launchctl kill`.
    ///
    /// Used by the runtime layer to mirror Unix `SIGHUP`-for-config-reload
    /// semantics on macOS. `signal` is a signal *name* such as `"SIGHUP"`
    /// or a numeric string — both are accepted by `launchctl(1)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ServiceManagerFailed`] if `launchctl` exits
    /// non-zero. A "not found" status is surfaced with a recognisable
    /// `service not found` substring.
    pub async fn kill_signal(&self, name: &str, signal: &str) -> Result<()> {
        validate_service_name(name)?;
        let label = Self::label_for(name);
        let target = self.domain_target(&label);
        let out = self
            .runner
            .run("launchctl", &["kill", signal, &target], LAUNCHCTL_TIMEOUT)
            .await?;
        if out.ok() {
            Ok(())
        } else if out.status == LAUNCHCTL_NOT_FOUND {
            Err(Error::ServiceManagerFailed(format!(
                "service not found: {label}"
            )))
        } else {
            Err(Error::ServiceManagerFailed(format!(
                "launchctl kill {signal} {target} exited {} (stderr: {})",
                out.status,
                out.stderr.trim()
            )))
        }
    }
}

impl Default for LaunchdManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ServiceManager for LaunchdManager {
    fn name(&self) -> &'static str {
        match self.scope {
            Scope::System => "launchd-daemon",
            Scope::User => "launchd-agent",
        }
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
            supports_reload: self.min_kickstart,
            supports_user_scope: true,
            supports_status_pid: true,
            supports_status_uptime: false,
            supports_restart_counter: false,
        }
    }

    async fn install(&self, spec: &ServiceSpec) -> Result<()> {
        validate_service_name(&spec.name)?;
        let plist = render_plist(spec);
        // Derive the path from the manager's own scope, not `spec.scope`, so
        // install and uninstall/start/stop/status all agree on the domain and
        // file location. A `--user` install used to write to
        // `~/Library/LaunchAgents` (from `spec.scope`) while every other verb
        // looked in `/Library/LaunchDaemons` (from `self.scope`), orphaning an
        // auto-starting agent the CLI could never see again (E7-F4).
        let label = Self::label_for(&spec.name);
        let path = Self::plist_path_for(self.scope, &label);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::ServiceManagerFailed(format!("mkdir {}: {e}", parent.display()))
            })?; // 1.88 lint: unnecessary_debug_formatting
        }
        std::fs::write(&path, plist)
            .map_err(|e| Error::ServiceManagerFailed(format!("write {}: {e}", path.display())))?; // 1.88 lint: unnecessary_debug_formatting
        let path_s = path.display().to_string();
        let out = self
            .runner
            .run("launchctl", &["load", "-w", &path_s], LAUNCHCTL_TIMEOUT)
            .await?;
        if !out.ok() {
            return Err(Error::ServiceManagerFailed(format!(
                "launchctl load -w {path_s} exited {} (stderr: {})",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    async fn uninstall(&self, name: &str) -> Result<()> {
        validate_service_name(name)?;
        let label = Self::label_for(name);
        let path = Self::plist_path_for(self.scope, &label);
        if path.exists() {
            let path_s = path.display().to_string();
            // Best-effort unload; missing service is fine.
            let _ = self
                .runner
                .run("launchctl", &["unload", "-w", &path_s], LAUNCHCTL_TIMEOUT)
                .await;
            std::fs::remove_file(&path).map_err(|e| {
                Error::ServiceManagerFailed(format!("remove {}: {e}", path.display()))
            })?; // 1.88 lint: unnecessary_debug_formatting
        }
        Ok(())
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        validate_service_name(name)?;
        let label = Self::label_for(name);

        if self.min_kickstart {
            let target = self.domain_target(&label);
            let out = self
                .runner
                .run("launchctl", &["print", &target], LAUNCHCTL_TIMEOUT)
                .await?;
            if out.ok() {
                return Ok(parse_print_output(&out.stdout));
            }
            if out.status == LAUNCHCTL_NOT_FOUND {
                return Ok(ServiceStatus::new(ServiceState::NotInstalled));
            }
            // Fall through to legacy `list` if `print` produced nothing
            // useful (e.g. the host implements an older `launchctl`).
        }

        let out = self
            .runner
            .run("launchctl", &["list", &label], LAUNCHCTL_TIMEOUT)
            .await?;
        if out.status == LAUNCHCTL_NOT_FOUND {
            return Ok(ServiceStatus::new(ServiceState::NotInstalled));
        }
        if !out.ok() && out.stdout.trim().is_empty() {
            return Ok(ServiceStatus::new(ServiceState::Unknown));
        }
        Ok(parse_list_output(&out.stdout))
    }

    async fn start(&self, name: &str) -> Result<()> {
        validate_service_name(name)?;
        let label = Self::label_for(name);
        let path = Self::plist_path_for(self.scope, &label);
        let path_s = path.display().to_string();
        let out = self
            .runner
            .run("launchctl", &["load", "-w", &path_s], LAUNCHCTL_TIMEOUT)
            .await?;
        if !out.ok() {
            return Err(Error::ServiceManagerFailed(format!(
                "launchctl load -w {path_s} exited {} (stderr: {})",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    async fn stop(&self, name: &str) -> Result<()> {
        validate_service_name(name)?;
        let label = Self::label_for(name);
        let path = Self::plist_path_for(self.scope, &label);
        let path_s = path.display().to_string();
        let out = self
            .runner
            .run("launchctl", &["unload", "-w", &path_s], LAUNCHCTL_TIMEOUT)
            .await?;
        if out.ok() {
            return Ok(());
        }
        if out.status == LAUNCHCTL_NOT_FOUND
            || out
                .stderr
                .to_ascii_lowercase()
                .contains("could not find specified service")
        {
            return Err(Error::ServiceManagerFailed(format!(
                "service not found: {label}"
            )));
        }
        Err(Error::ServiceManagerFailed(format!(
            "launchctl unload -w {path_s} exited {} (stderr: {})",
            out.status,
            out.stderr.trim()
        )))
    }

    async fn restart(&self, name: &str) -> Result<()> {
        // launchd has no native restart. Stop + start, ignoring a
        // "not found" stop because the user may be (re)starting a service
        // that's currently down.
        match self.stop(name).await {
            Ok(()) => {}
            Err(Error::ServiceManagerFailed(msg)) if msg.contains("service not found") => {}
            Err(e) => return Err(e),
        }
        self.start(name).await
    }

    async fn reload(&self, name: &str) -> Result<()> {
        if !self.min_kickstart {
            return Err(unsupported(self.name(), "reload"));
        }
        validate_service_name(name)?;
        let label = Self::label_for(name);
        let target = self.domain_target(&label);
        let out = self
            .runner
            .run(
                "launchctl",
                &["kickstart", "-k", &target],
                LAUNCHCTL_TIMEOUT,
            )
            .await?;
        if out.ok() {
            return Ok(());
        }
        if out.status == LAUNCHCTL_NOT_FOUND {
            return Err(Error::ServiceManagerFailed(format!(
                "service not found: {label}"
            )));
        }
        Err(Error::ServiceManagerFailed(format!(
            "launchctl kickstart -k {target} exited {} (stderr: {})",
            out.status,
            out.stderr.trim()
        )))
    }
}

/// Detect the effective UID for building agent domain targets.
///
/// Order:
/// 1. `SPT_TEST_UID` — an explicit test override (always honoured, all OSes).
/// 2. `nix::unistd::geteuid()` under `cfg(unix)` — the real effective UID.
/// 3. `$SUDO_UID` — when invoked via `sudo`, prefer the invoking user's UID
///    so `gui/<uid>` targets the operator's GUI session rather than root's.
/// 4. `501` — the conventional first-user UID on macOS (last-resort fallback,
///    and the value used on non-unix builds where `geteuid` is unavailable).
///
/// E7-F8: `$UID` is a non-exported shell parameter, so the old `$UID`-first
/// lookup almost never fired and every non-501 user got the wrong domain.
/// `geteuid()` is authoritative; the `SPT_TEST_UID` env keeps tests hermetic
/// without depending on the host UID.
fn detect_uid() -> u32 {
    if let Some(s) = std::env::var_os("SPT_TEST_UID") {
        if let Ok(n) = s.to_string_lossy().parse::<u32>() {
            return n;
        }
    }
    // Under sudo, the GUI session belongs to the invoking user, not root.
    if let Some(s) = std::env::var_os("SUDO_UID") {
        if let Ok(n) = s.to_string_lossy().parse::<u32>() {
            return n;
        }
    }
    #[cfg(unix)]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        501
    }
}

/// Parse `launchctl list <label>` output.
///
/// Output is a `launchd` plist-as-text dictionary, e.g.
///
/// ```text
/// {
///     "LimitLoadToSessionType" = "Aqua";
///     "Label" = "io.spt.relay";
///     "OnDemand" = false;
///     "LastExitStatus" = 0;
///     "PID" = 12345;
///     ...
/// };
/// ```
///
/// We do a permissive line-by-line scan for the fields we care about: a
/// numeric `PID` indicates a running process; otherwise `LastExitStatus`
/// distinguishes Failed (non-zero) from Stopped.
fn parse_list_output(stdout: &str) -> ServiceStatus {
    let kvs = parse_dict_kvs(stdout);
    let pid = kvs
        .get("PID")
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|p| *p > 0);
    let exit = kvs
        .get("LastExitStatus")
        .and_then(|v| v.parse::<i32>().ok());
    if let Some(pid) = pid {
        return ServiceStatus {
            state: ServiceState::Running,
            pid: Some(pid),
            exit_code: exit,
            since: None,
            restart_count: None,
        };
    }
    match exit {
        Some(c) if c != 0 => ServiceStatus {
            state: ServiceState::Failed,
            pid: None,
            exit_code: Some(c),
            since: None,
            restart_count: None,
        },
        _ => ServiceStatus {
            state: ServiceState::Stopped,
            pid: None,
            exit_code: exit,
            since: None,
            restart_count: None,
        },
    }
}

/// Parse `launchctl print <domain>/<label>` output.
///
/// Modern macOS (≥ 10.10) emits a structured but indented record:
///
/// ```text
/// system/io.spt.relay = {
///     active count = 1
///     path = /Library/LaunchDaemons/io.spt.relay.plist
///     state = running
///     pid = 12345
///     last exit code = 0
///     ...
/// }
/// ```
///
/// We extract `state`, `pid`, and `last exit code` with a small line scan.
fn parse_print_output(stdout: &str) -> ServiceStatus {
    let mut state: Option<&str> = None;
    let mut pid: Option<u32> = None;
    let mut last_exit: Option<i32> = None;
    for raw in stdout.lines() {
        let line = raw.trim();
        if let Some(v) = strip_kv(line, "state") {
            state = Some(match v {
                v if v.eq_ignore_ascii_case("running") => "running",
                v if v.eq_ignore_ascii_case("not running") || v.eq_ignore_ascii_case("stopped") => {
                    "stopped"
                }
                _ => "unknown",
            });
        } else if let Some(v) = strip_kv(line, "pid") {
            pid = v.parse::<u32>().ok().filter(|p| *p > 0);
        } else if let Some(v) = strip_kv(line, "last exit code") {
            last_exit = v.parse::<i32>().ok();
        }
    }
    match (state, pid, last_exit) {
        (Some("running"), Some(p), _) => ServiceStatus {
            state: ServiceState::Running,
            pid: Some(p),
            exit_code: last_exit,
            since: None,
            restart_count: None,
        },
        (Some("running"), None, _) => ServiceStatus {
            state: ServiceState::Running,
            pid: None,
            exit_code: last_exit,
            since: None,
            restart_count: None,
        },
        (_, _, Some(c)) if c != 0 => ServiceStatus {
            state: ServiceState::Failed,
            pid: None,
            exit_code: Some(c),
            since: None,
            restart_count: None,
        },
        (Some("stopped"), _, _) => ServiceStatus {
            state: ServiceState::Stopped,
            pid: None,
            exit_code: last_exit,
            since: None,
            restart_count: None,
        },
        _ => ServiceStatus {
            state: ServiceState::Unknown,
            pid,
            exit_code: last_exit,
            since: None,
            restart_count: None,
        },
    }
}

/// Strip `<key> = ` (or `<key>: `) prefix from a line, returning the
/// trimmed value if `key` matches (case-insensitive). Returns `None`
/// otherwise. Used by [`parse_print_output`].
fn strip_kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let lower = line.to_ascii_lowercase();
    let key = key.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(&key) {
        let rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')) {
            // Recover the original-case value at the matching offset in `line`.
            let consumed = line.len() - after.len();
            return Some(line[consumed..].trim_start_matches(['=', ':']).trim());
        }
    }
    None
}

/// Collect `"key" = value;` pairs from a `launchctl list` dictionary
/// dump into a `BTreeMap`. Quotes around keys/values are stripped. Lines
/// that don't match the expected shape are silently ignored — this is a
/// permissive scan, not a full plist parser.
fn parse_dict_kvs(stdout: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for raw in stdout.lines() {
        let line = raw.trim().trim_end_matches(';');
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim().trim_matches('"').to_string();
        let val = line[eq + 1..].trim().trim_matches('"').to_string();
        if !key.is_empty() {
            map.insert(key, val);
        }
    }
    map
}

fn render_plist(spec: &ServiceSpec) -> String {
    let label = format!("{LABEL_PREFIX}.{}", spec.name);
    let args_array = spec
        .args
        .iter()
        .map(|a| format!("        <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n");
    let env_dict = spec
        .env
        .iter()
        .map(|(k, v)| {
            format!(
                "        <key>{}</key>\n        <string>{}</string>",
                xml_escape(k),
                xml_escape(v)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    // Back-compat scalar for the legacy `<{{keep_alive}}/>` template shape.
    // NOTE: this collapses OnFailure to `true`, which restarts even after a
    // *clean* exit — the launchd-correct mapping is the SuccessfulExit dict
    // emitted in `keep_alive_block` below. Once the packaging template
    // switches `<{{keep_alive}}/>` → `{{keep_alive_block}}` this scalar is
    // unused. (E7-F9; template owned by p5-packaging-units.)
    let keep_alive = match spec.restart_policy {
        crate::RestartPolicy::Always | crate::RestartPolicy::OnFailure => "true",
        crate::RestartPolicy::Never => "false",
    };
    let keep_alive_block = keep_alive_element(spec.restart_policy);
    let user_keys = match (&spec.user, spec.scope) {
        (Some(u), Scope::System) => {
            let mut s = format!(
                "    <key>UserName</key>\n    <string>{}</string>",
                xml_escape(u)
            );
            if let Some(g) = &spec.group {
                use std::fmt::Write as _; // 1.88 lint: format_push_string
                let _ = write!(
                    s,
                    "\n    <key>GroupName</key>\n    <string>{}</string>",
                    xml_escape(g)
                );
            }
            s
        }
        _ => String::new(),
    };
    let stdout_path = spec
        .stdout_path
        .as_ref()
        .map_or_else(|| "/dev/null".to_string(), |p| p.display().to_string());
    let stderr_path = spec
        .stderr_path
        .as_ref()
        .map_or_else(|| "/dev/null".to_string(), |p| p.display().to_string());

    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("label", label);
    vars.insert("exec_path", spec.exec_path.display().to_string());
    vars.insert("args_array", args_array);
    vars.insert("working_dir", spec.working_dir.display().to_string());
    vars.insert("keep_alive", keep_alive.to_string());
    vars.insert("keep_alive_block", keep_alive_block);
    vars.insert("stdout_path", stdout_path);
    vars.insert("stderr_path", stderr_path);
    vars.insert("env_dict", env_dict);
    vars.insert("user_keys", user_keys);
    template::render(TEMPLATE, &vars)
}

/// Build the full `<key>KeepAlive</key> ...` plist element for a restart
/// policy with the launchd-correct mapping (E7-F9):
///   * `Always`    → `<true/>`  (restart unconditionally)
///   * `OnFailure` → `{ SuccessfulExit = false; }` (restart only on non-zero exit)
///   * `Never`     → `<false/>` (never auto-restart)
///
/// Rendered into the `{{keep_alive_block}}` template var. Note the legacy
/// `<{{keep_alive}}/>` template shape cannot express the `OnFailure` dict, so
/// the packaging template must adopt `{{keep_alive_block}}` for the correct
/// behavior to land (owned by p5-packaging-units).
fn keep_alive_element(policy: crate::RestartPolicy) -> String {
    match policy {
        crate::RestartPolicy::Always => "    <key>KeepAlive</key>\n    <true/>".to_string(),
        crate::RestartPolicy::Never => "    <key>KeepAlive</key>\n    <false/>".to_string(),
        crate::RestartPolicy::OnFailure => "    <key>KeepAlive</key>\n    \
             <dict>\n        <key>SuccessfulExit</key>\n        <false/>\n    </dict>"
            .to_string(),
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// `Path` is referenced only via `PathBuf` in this module; suppress the
// import when the unused path-handling helpers are stripped on non-macOS.
#[allow(dead_code)]
type _PathRef<'a> = &'a Path;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;
    use crate::{MockRunner, RunOutput};

    fn ok(stdout: &str) -> RunOutput {
        RunOutput {
            status: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn err(status: i32, stderr: &str) -> RunOutput {
        RunOutput {
            status,
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    fn mgr_with(scope: Scope, mock: &MockRunner) -> LaunchdManager {
        LaunchdManager::new_with_runner(scope, Arc::new(mock.clone())).with_uid(501)
    }

    // ---- render goldens (preserved) -------------------------------------

    #[test]
    fn plist_contains_label_and_args() {
        let mut s = sample_spec();
        s.scope = Scope::System;
        let out = LaunchdManager::new().render(&s);
        assert!(out.contains("<string>io.spt.spt-relay</string>"));
        assert!(out.contains("<string>--config</string>"));
        assert!(out.contains("<key>UserName</key>"));
    }

    #[test]
    fn snapshot_launchd_daemon() {
        let mut s = sample_spec();
        s.scope = Scope::System;
        let out = LaunchdManager::new().render(&s);
        insta::assert_snapshot!("launchd_daemon_plist", out);
    }

    #[test]
    fn snapshot_launchd_agent() {
        let mut s = sample_spec();
        s.scope = Scope::User;
        s.user = None;
        s.group = None;
        let out = LaunchdManager::new().render(&s);
        insta::assert_snapshot!("launchd_agent_plist", out);
    }

    // ---- name + capabilities --------------------------------------------

    #[test]
    fn name_reflects_scope() {
        assert_eq!(
            LaunchdManager::with_scope(Scope::System).name(),
            "launchd-daemon"
        );
        assert_eq!(
            LaunchdManager::with_scope(Scope::User).name(),
            "launchd-agent"
        );
    }

    #[test]
    fn capabilities_advertise_modern_macos_features() {
        let mgr = LaunchdManager::with_scope(Scope::System);
        let caps = mgr.capabilities();
        assert!(caps.supports_install);
        assert!(caps.supports_uninstall);
        assert!(caps.supports_status);
        assert!(caps.supports_start_stop);
        assert!(caps.supports_restart);
        assert!(caps.supports_reload);
        assert!(caps.supports_user_scope);
        assert!(caps.supports_status_pid);
        assert!(!caps.supports_status_uptime);
        assert!(!caps.supports_restart_counter);
    }

    #[test]
    fn capabilities_reload_drops_on_old_macos() {
        let mgr = LaunchdManager::with_scope(Scope::System).with_kickstart_supported(false);
        assert!(!mgr.capabilities().supports_reload);
    }

    // ---- status (table-driven) ------------------------------------------

    #[test]
    fn parse_list_running() {
        let out = r#"{
            "Label" = "io.spt.relay";
            "PID" = 12345;
            "LastExitStatus" = 0;
        };"#;
        let s = parse_list_output(out);
        assert_eq!(s.state, ServiceState::Running);
        assert_eq!(s.pid, Some(12345));
        assert_eq!(s.exit_code, Some(0));
    }

    #[test]
    fn parse_list_stopped() {
        let out = r#"{
            "Label" = "io.spt.relay";
            "LastExitStatus" = 0;
        };"#;
        let s = parse_list_output(out);
        assert_eq!(s.state, ServiceState::Stopped);
        assert_eq!(s.pid, None);
    }

    #[test]
    fn parse_list_failed() {
        let out = r#"{
            "Label" = "io.spt.relay";
            "LastExitStatus" = 7;
        };"#;
        let s = parse_list_output(out);
        assert_eq!(s.state, ServiceState::Failed);
        assert_eq!(s.exit_code, Some(7));
    }

    #[tokio::test]
    async fn status_uses_print_then_returns_running() {
        let mock = MockRunner::new();
        // launchctl print succeeds with modern format.
        mock.push_output(ok("system/io.spt.relay = {\n\
             \tstate = running\n\
             \tpid = 4242\n\
             \tlast exit code = 0\n\
             }\n"));
        let mgr = mgr_with(Scope::System, &mock);
        let s = mgr.status("relay").await.unwrap();
        assert_eq!(s.state, ServiceState::Running);
        assert_eq!(s.pid, Some(4242));
        mock.assert_called("launchctl", &["print", "system/io.spt.relay"]);
    }

    #[tokio::test]
    async fn status_print_failed_via_exit_code() {
        let mock = MockRunner::new();
        mock.push_output(ok(
            "system/io.spt.relay = {\n\tstate = not running\n\tlast exit code = 5\n}\n",
        ));
        let mgr = mgr_with(Scope::System, &mock);
        let s = mgr.status("relay").await.unwrap();
        assert_eq!(s.state, ServiceState::Failed);
        assert_eq!(s.exit_code, Some(5));
    }

    #[tokio::test]
    async fn status_print_missing_returns_not_installed() {
        let mock = MockRunner::new();
        mock.push_output(err(LAUNCHCTL_NOT_FOUND, "Could not find service"));
        let mgr = mgr_with(Scope::System, &mock);
        let s = mgr.status("relay").await.unwrap();
        assert_eq!(s.state, ServiceState::NotInstalled);
    }

    #[tokio::test]
    async fn status_falls_back_to_list_when_kickstart_disabled() {
        let mock = MockRunner::new();
        mock.push_output(ok(r#"{
            "Label" = "io.spt.relay";
            "PID" = 9001;
            "LastExitStatus" = 0;
        };"#));
        let mgr = mgr_with(Scope::System, &mock).with_kickstart_supported(false);
        let s = mgr.status("relay").await.unwrap();
        assert_eq!(s.state, ServiceState::Running);
        assert_eq!(s.pid, Some(9001));
        mock.assert_called("launchctl", &["list", "io.spt.relay"]);
    }

    // ---- start / stop ---------------------------------------------------

    #[tokio::test]
    async fn start_loads_plist_with_w_flag() {
        let mock = MockRunner::new();
        mock.push_output(ok(""));
        let mgr = mgr_with(Scope::System, &mock);
        mgr.start("relay").await.unwrap();
        mock.assert_called(
            "launchctl",
            &["load", "-w", "/Library/LaunchDaemons/io.spt.relay.plist"],
        );
    }

    #[tokio::test]
    async fn stop_unloads_plist_with_w_flag() {
        let mock = MockRunner::new();
        mock.push_output(ok(""));
        let mgr = mgr_with(Scope::System, &mock);
        mgr.stop("relay").await.unwrap();
        mock.assert_called(
            "launchctl",
            &["unload", "-w", "/Library/LaunchDaemons/io.spt.relay.plist"],
        );
    }

    #[tokio::test]
    async fn stop_missing_service_maps_to_not_found() {
        let mock = MockRunner::new();
        mock.push_output(err(LAUNCHCTL_NOT_FOUND, "Could not find specified service"));
        let mgr = mgr_with(Scope::System, &mock);
        let err = mgr.stop("relay").await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("service not found"), "got: {msg}");
    }

    // ---- restart --------------------------------------------------------

    #[tokio::test]
    async fn restart_issues_unload_then_load_in_order() {
        let mock = MockRunner::new();
        mock.push_output(ok("")); // stop
        mock.push_output(ok("")); // start
        let mgr = mgr_with(Scope::System, &mock);
        mgr.restart("relay").await.unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1[0], "unload");
        assert_eq!(calls[1].1[0], "load");
    }

    #[tokio::test]
    async fn restart_continues_through_not_found_stop() {
        let mock = MockRunner::new();
        mock.push_output(err(LAUNCHCTL_NOT_FOUND, "Could not find specified service"));
        mock.push_output(ok(""));
        let mgr = mgr_with(Scope::System, &mock);
        mgr.restart("relay").await.unwrap();
        assert_eq!(mock.calls().len(), 2);
    }

    // ---- reload ---------------------------------------------------------

    #[tokio::test]
    async fn reload_issues_kickstart_k_on_modern_macos() {
        let mock = MockRunner::new();
        mock.push_output(ok(""));
        let mgr = mgr_with(Scope::System, &mock);
        mgr.reload("relay").await.unwrap();
        mock.assert_called("launchctl", &["kickstart", "-k", "system/io.spt.relay"]);
    }

    #[tokio::test]
    async fn reload_unsupported_on_old_macos() {
        let mock = MockRunner::new();
        let mgr = mgr_with(Scope::System, &mock).with_kickstart_supported(false);
        let err = mgr.reload("relay").await.unwrap_err();
        match err {
            Error::UnsupportedPlatform(msg) => {
                assert!(msg.contains("reload"));
                assert!(msg.contains("launchd-daemon"));
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
        // No launchctl call should have been issued.
        assert!(mock.calls().is_empty());
    }

    // ---- kill_signal ----------------------------------------------------

    #[tokio::test]
    async fn kill_signal_targets_agent_domain() {
        let mock = MockRunner::new();
        mock.push_output(ok(""));
        let mgr = mgr_with(Scope::User, &mock).with_uid(501);
        mgr.kill_signal("relay", "SIGHUP").await.unwrap();
        mock.assert_called("launchctl", &["kill", "SIGHUP", "gui/501/io.spt.relay"]);
    }

    #[tokio::test]
    async fn kill_signal_targets_system_domain() {
        let mock = MockRunner::new();
        mock.push_output(ok(""));
        let mgr = mgr_with(Scope::System, &mock);
        mgr.kill_signal("relay", "SIGHUP").await.unwrap();
        mock.assert_called("launchctl", &["kill", "SIGHUP", "system/io.spt.relay"]);
    }

    // ---- E7-F4: install/uninstall path agreement for user scope ----------

    #[tokio::test]
    async fn user_install_writes_agent_path_matching_uninstall() {
        // Install a user-scope agent and confirm both install (load -w <path>)
        // and uninstall (unload -w <path>) target the SAME LaunchAgents path —
        // previously install used spec.scope and the rest used self.scope, so a
        // --user install was orphaned under /Library/LaunchDaemons.
        let prev_home = std::env::var_os("HOME");
        let home = std::env::temp_dir().join("spt-launchd-test-home");
        std::env::set_var("HOME", &home);
        let expected = format!(
            "{}/Library/LaunchAgents/io.spt.relay.plist",
            home.display().to_string().trim_end_matches('/')
        );

        let install_mock = MockRunner::new();
        install_mock.push_output(ok(""));
        let mgr = mgr_with(Scope::User, &install_mock);
        // Build a user-scope spec; even if spec.scope said System, self.scope
        // must win — assert that explicitly.
        let mut spec = sample_spec();
        spec.scope = Scope::System; // deliberately diverge from manager scope
        spec.name = "relay".into();
        spec.user = None;
        spec.group = None;
        mgr.install(&spec).await.unwrap();
        let calls = install_mock.calls();
        assert_eq!(calls[0].1[0], "load");
        assert_eq!(
            calls[0].1[2], expected,
            "install must use manager scope path"
        );

        let uninstall_mock = MockRunner::new();
        uninstall_mock.push_output(ok(""));
        let mgr2 = mgr_with(Scope::User, &uninstall_mock);
        // Pre-create the plist so uninstall removes it.
        if let Some(parent) = std::path::Path::new(&expected).parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&expected, "<plist/>").unwrap();
        mgr2.uninstall("relay").await.unwrap();
        let calls2 = uninstall_mock.calls();
        assert_eq!(calls2[0].1[0], "unload");
        assert_eq!(calls2[0].1[2], expected, "uninstall must use same path");
        assert!(
            !std::path::Path::new(&expected).exists(),
            "uninstall should have removed the agent plist"
        );

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    // ---- E7-F17: name validation rejection -------------------------------

    #[tokio::test]
    async fn install_rejects_path_traversal_name() {
        let mock = MockRunner::new();
        let mgr = mgr_with(Scope::System, &mock);
        let mut spec = sample_spec();
        spec.name = "../../evil".into();
        let err = mgr.install(&spec).await.expect_err("must reject");
        assert!(format!("{err}").contains("invalid service name"));
        assert!(
            mock.calls().is_empty(),
            "no launchctl call on rejected name"
        );
    }

    #[tokio::test]
    async fn uninstall_rejects_path_traversal_name() {
        let mock = MockRunner::new();
        let mgr = mgr_with(Scope::System, &mock);
        let err = mgr.uninstall("../evil").await.expect_err("must reject");
        assert!(format!("{err}").contains("invalid service name"));
    }

    // ---- E7-F8: detect_uid env override ----------------------------------

    #[test]
    fn detect_uid_honours_test_override() {
        std::env::set_var("SPT_TEST_UID", "4242");
        let got = detect_uid();
        std::env::remove_var("SPT_TEST_UID");
        assert_eq!(got, 4242);
    }

    // ---- E7-F9: OnFailure renders the SuccessfulExit dict -----------------

    #[test]
    fn keep_alive_block_maps_on_failure_to_successful_exit_dict() {
        let block = keep_alive_element(crate::RestartPolicy::OnFailure);
        assert!(block.contains("<key>KeepAlive</key>"));
        assert!(block.contains("<key>SuccessfulExit</key>"));
        assert!(block.contains("<false/>"));
        assert!(!block.contains("<true/>"), "OnFailure must not be <true/>");
    }

    #[test]
    fn keep_alive_block_maps_always_and_never() {
        let always = keep_alive_element(crate::RestartPolicy::Always);
        assert!(always.contains("<true/>"));
        assert!(!always.contains("SuccessfulExit"));
        let never = keep_alive_element(crate::RestartPolicy::Never);
        assert!(never.contains("<false/>"));
        assert!(!never.contains("SuccessfulExit"));
    }
}
