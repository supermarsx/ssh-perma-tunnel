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

use crate::task_scheduler::validate_service_name;
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
        validate_service_name(&spec.name)?;
        tracing::info!(target: "spt_service", backend = "openrc", service = %spec.name, "installing service");
        let script = render_script(spec);
        let path = self.script_path(&spec.name);

        // Ensure the script root exists (no-op for /etc/init.d on real systems,
        // load-bearing for tempdir-based tests).
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::ServiceManagerFailed(format!("create script root {}: {e}", parent.display()))
            })?;
        }

        std::fs::write(&path, script)
            .map_err(|e| Error::ServiceManagerFailed(format!("write {}: {e}", path.display())))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)
                .map_err(|e| {
                    Error::ServiceManagerFailed(format!("metadata {}: {e}", path.display()))
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
        validate_service_name(name)?;
        tracing::info!(target: "spt_service", backend = "openrc", service = %name, "uninstalling service");
        // Best-effort deregistration; ignore exit status.
        let _ = self
            .runner
            .run("rc-update", &["del", name, "default"], DEFAULT_TIMEOUT)
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
        validate_service_name(name)?;
        let out = self
            .runner
            .run("rc-service", &[name, "status"], DEFAULT_TIMEOUT)
            .await?;

        if !out.ok() {
            let stderr_lc = out.stderr.to_ascii_lowercase();
            if stderr_lc.contains("no such service") || stderr_lc.contains("does not exist") {
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
        validate_service_name(name)?;
        tracing::info!(target: "spt_service", backend = "openrc", service = %name, "starting service");
        run_rc_service(self.runner.as_ref(), name, "start").await
    }

    async fn stop(&self, name: &str) -> Result<()> {
        validate_service_name(name)?;
        tracing::info!(target: "spt_service", backend = "openrc", service = %name, "stopping service");
        run_rc_service(self.runner.as_ref(), name, "stop").await
    }

    async fn restart(&self, name: &str) -> Result<()> {
        validate_service_name(name)?;
        run_rc_service(self.runner.as_ref(), name, "restart").await
    }

    async fn reload(&self, name: &str) -> Result<()> {
        validate_service_name(name)?;
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

async fn run_rc_service(runner: &dyn CommandRunner, name: &str, action: &str) -> Result<()> {
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
    // M2: shell-quote each arg (POSIX single-quote escaping) so spaces and
    // shell metacharacters in operator-supplied args cannot word-split or
    // inject when OpenRC expands `command_args`.
    let args = shell_single_quote_args(&spec.args);
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    // F5: `name`/`description`/`exec_path`/`user`/`group`/`working_dir` are
    // interpolated into double-quoted shell assignments in the template
    // (e.g. `description="{{description}}"`). In a POSIX double-quoted string
    // `$(...)`, backticks, and an embedded `"` still expand / break out, so a
    // value like `$(touch /tmp/pwn)` or `"; evil` would execute when OpenRC
    // sources the script. Escape them for the double-quoted context (mirrors
    // M2's arg quoting decision that these fields warrant neutralizing).
    vars.insert("name", shell_double_quote_escape(&spec.name));
    vars.insert("description", shell_double_quote_escape(&spec.description));
    vars.insert(
        "exec_path",
        shell_double_quote_escape(&spec.exec_path.display().to_string()),
    );
    vars.insert("args", args);
    vars.insert(
        "user",
        shell_double_quote_escape(spec.user.as_deref().unwrap_or("root")),
    );
    vars.insert(
        "group",
        shell_double_quote_escape(spec.group.as_deref().unwrap_or("root")),
    );
    vars.insert(
        "working_dir",
        shell_double_quote_escape(&spec.working_dir.display().to_string()),
    );
    // E7-F9: render `[profiles].env` as `export K="V"` lines so OpenRC honours
    // ServiceSpec.env (previously dropped — only systemd/launchd applied env).
    // Rendered into the `{{env_exports}}` template placeholder; the template
    // is owned by p5-packaging-units and must add that placeholder for these
    // exports to take effect.
    vars.insert("env_exports", render_env_exports(spec));
    // F4/F6: honour `restart_policy` on OpenRC (previously silently dropped).
    // `supervise-daemon` monitors the child and respawns it when it exits, which
    // is the closest OpenRC primitive to systemd's Restart=. `Never` keeps the
    // legacy plain-backgrounded start-stop-daemon behaviour (no respawn).
    vars.insert(
        "supervisor_directives",
        openrc_supervisor_directives(spec.restart_policy),
    );
    template::render(TEMPLATE, &vars)
}

/// Map a [`crate::RestartPolicy`] onto `OpenRC` supervision directives.
///
/// `Always`/`OnFailure` select `supervise-daemon` (respawn on exit; `OpenRC` has
/// no native "only on non-zero exit" distinction, so both map to respawn — the
/// operator-visible intent "keep it running" is honoured). `Never` falls back
/// to a plain backgrounded start-stop-daemon with no respawn.
fn openrc_supervisor_directives(policy: crate::RestartPolicy) -> String {
    use crate::RestartPolicy;
    match policy {
        RestartPolicy::Always | RestartPolicy::OnFailure => {
            "supervisor=supervise-daemon\nrespawn_delay=5".to_string()
        }
        RestartPolicy::Never => "command_background=true".to_string(),
    }
}

/// Render `ServiceSpec.env` as POSIX `export KEY="VALUE"` lines for shell
/// init scripts (`OpenRC` / `SysV`). Values are double-quoted with `"`, `$`,
/// `` ` `` and `\` backslash-escaped so the shell treats them literally.
/// Returns an empty string when there is no env (so the template line
/// collapses).
///
/// F5: the env-var **NAME** (`k`) is emitted OUTSIDE any quoting
/// (`export {k}="…"`), so a name like `K;rm -rf /` or `K$(id)` would inject
/// shell after the `export` word — and there is no way to safely quote an
/// arbitrary shell variable *name*. Names that are not valid POSIX shell
/// identifiers (`[A-Za-z_][A-Za-z0-9_]*`) are therefore rejected (skipped)
/// rather than escaped. Legitimate names (`RUST_LOG`, `SPT_STATE_DIR`, …) are
/// unaffected.
pub(crate) fn render_env_exports(spec: &ServiceSpec) -> String {
    spec.env
        .iter()
        .filter(|(k, _)| is_valid_shell_name(k))
        .map(|(k, v)| format!("export {k}=\"{}\"", shell_double_quote_escape(v)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// True iff `name` is a valid POSIX shell/environment variable identifier:
/// a leading letter or underscore, then letters, digits, or underscores.
/// Anything else (`;`, `=`, space, `$`, `.`, empty, …) is invalid and would
/// be a shell-injection vector if emitted as an `export` target.
fn is_valid_shell_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Shell-quote each arg with POSIX single-quote escaping and join with spaces.
///
/// Each arg is wrapped in single quotes; any embedded `'` is rendered as the
/// canonical `'\''` sequence (close-quote, escaped-quote, re-open-quote). The
/// result is safe to expand under `eval` / `OpenRC`'s `command_args`: no space,
/// `;`, `$(...)`, backtick, or other metacharacter can word-split or be
/// interpreted as shell syntax. An empty arg becomes `''` (a preserved empty
/// argument). Shared by the `OpenRC` and `SysV` renderers (M2).
pub(crate) fn shell_single_quote_args(args: &[String]) -> String {
    args.iter()
        .map(|a| shell_single_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Single-quote one argument for a POSIX shell. See [`shell_single_quote_args`].
pub(crate) fn shell_single_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Escape a value for inclusion inside a POSIX double-quoted string.
pub(crate) fn shell_double_quote_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '"' | '\\' | '$' | '`' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
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

    // F4/F6: restart_policy must be honoured on OpenRC. Always/OnFailure emit a
    // supervise-daemon respawn block; Never keeps plain backgrounding.
    #[test]
    fn render_wires_restart_policy() {
        use crate::RestartPolicy;
        let mut spec = sample_spec();

        spec.restart_policy = RestartPolicy::Always;
        let out = OpenRcManager::new().render(&spec);
        assert!(out.contains("supervisor=supervise-daemon"), "always: {out}");
        assert!(out.contains("respawn_delay=5"), "always: {out}");

        spec.restart_policy = RestartPolicy::OnFailure;
        let out = OpenRcManager::new().render(&spec);
        assert!(
            out.contains("supervisor=supervise-daemon"),
            "on-failure: {out}"
        );

        spec.restart_policy = RestartPolicy::Never;
        let out = OpenRcManager::new().render(&spec);
        assert!(
            !out.contains("supervisor=supervise-daemon"),
            "never must not respawn: {out}"
        );
        assert!(out.contains("command_background=true"), "never: {out}");
    }

    #[test]
    fn snapshot_openrc() {
        let mgr = OpenRcManager::new();
        let out = mgr.render(&sample_spec());
        insta::assert_snapshot!("openrc_init", out);
    }

    #[test]
    fn shell_single_quote_wraps_and_escapes() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("a b"), "'a b'");
        assert_eq!(shell_single_quote(""), "''");
        // Embedded single quote → close, escaped-quote, reopen.
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    // M2: an arg with a space and an arg laced with shell metacharacters must
    // each be single-quoted so OpenRC cannot word-split or interpret them.
    #[test]
    fn render_single_quotes_args_with_spaces_and_metachars() {
        let mut spec = sample_spec();
        spec.args = vec![
            "run".into(),
            "--note".into(),
            "with space".into(),
            "; touch /tmp/pwn".into(),
            "$(id)".into(),
            "`id`".into(),
        ];
        let out = OpenRcManager::new().render(&spec);
        let line = out
            .lines()
            .find(|l| l.starts_with("command_args="))
            .expect("command_args line");
        assert!(
            line.contains("'with space'"),
            "space arg not quoted: {line}"
        );
        assert!(
            line.contains("'; touch /tmp/pwn'"),
            "metachar arg not quoted: {line}"
        );
        assert!(line.contains("'$(id)'"), "subshell arg not quoted: {line}");
        assert!(line.contains("'`id`'"), "backtick arg not quoted: {line}");
        // No bare (unquoted) injection survives outside the quoting.
        assert!(
            !line.contains("= touch") && !out.contains("\ntouch /tmp/pwn"),
            "metachar leaked unquoted: {out}"
        );
    }

    // F5: `description`/`exec_path`/`user`/`group`/`working_dir` land in
    // double-quoted shell assignments. `$(...)`, backticks, and `"` must be
    // neutralized so nothing executes / breaks out when OpenRC sources the
    // script. Fails against the pre-fix raw interpolation.
    #[test]
    fn render_neutralizes_shell_injection_in_assignments() {
        let mut spec = sample_spec();
        spec.description = "$(touch /tmp/pwn)".into();
        spec.exec_path = "/bin/sh\"; touch /tmp/pwn; :\"".into();
        spec.user = Some("`id`".into());
        spec.working_dir = "/var/lib/spt$(id)".into();
        let out = OpenRcManager::new().render(&spec);
        // Command-substitution / backticks are backslash-escaped (inert in a
        // double-quoted string), and the injected `"` cannot close the quote.
        assert!(
            out.contains(r#"description="\$(touch /tmp/pwn)""#),
            "description not escaped: {out}"
        );
        assert!(out.contains(r"\`id\`"), "user not escaped: {out}");
        assert!(
            out.contains(r"/var/lib/spt\$(id)"),
            "workdir not escaped: {out}"
        );
        assert!(
            out.contains(r#"/bin/sh\"; touch /tmp/pwn; :\""#),
            "exec_path quote not escaped: {out}"
        );
        // No bare `touch /tmp/pwn` command survives on its own line, and every
        // `$(` is backslash-escaped (removing escaped `\$` leaves no live `$(`).
        assert!(
            !out.lines().any(|l| l.trim_start().starts_with("touch ")),
            "injected command leaked: {out}"
        );
        assert!(
            !out.replace("\\$", "").contains("$(touch"),
            "unescaped command sub leaked: {out}"
        );
    }

    // F5: an env-var NAME that is not a valid shell identifier is a shell
    // injection vector (`export K;rm -rf /="…"`) and cannot be safely quoted;
    // it must be rejected/skipped. Fails against the pre-fix code.
    #[test]
    fn render_env_exports_rejects_injecting_name() {
        let mut spec = sample_spec();
        spec.env.clear();
        spec.env.insert("K;touch /tmp/pwn".into(), "v".into());
        spec.env.insert("GOOD".into(), "1".into());
        let out = render_env_exports(&spec);
        assert!(
            !out.contains("touch /tmp/pwn"),
            "injecting env name leaked: {out}"
        );
        assert!(!out.contains("K;"), "invalid name emitted: {out}");
        // The valid sibling is still exported.
        assert!(
            out.contains("export GOOD=\"1\""),
            "valid name dropped: {out}"
        );
    }

    #[test]
    fn is_valid_shell_name_accepts_ids_rejects_injection() {
        assert!(is_valid_shell_name("RUST_LOG"));
        assert!(is_valid_shell_name("_x9"));
        assert!(!is_valid_shell_name(""));
        assert!(!is_valid_shell_name("1BAD"));
        assert!(!is_valid_shell_name("K;rm"));
        assert!(!is_valid_shell_name("K=v"));
        assert!(!is_valid_shell_name("K$(id)"));
        assert!(!is_valid_shell_name("K X"));
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
        let mgr =
            OpenRcManager::new_with_runner(mock.clone()).with_script_root(tmp.path().to_path_buf());

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
        let mgr =
            OpenRcManager::new_with_runner(mock.clone()).with_script_root(tmp.path().to_path_buf());
        mgr.uninstall("ghost").await.expect("idempotent");
        mock.assert_called("rc-update", &["del", "ghost", "default"]);
    }

    #[tokio::test]
    async fn uninstall_removes_existing_script() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        mock.push_output(ok_out(""));
        let mgr =
            OpenRcManager::new_with_runner(mock.clone()).with_script_root(tmp.path().to_path_buf());
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
        mock.push_output(err_out(1, "rc-service: unrecognized command `reload'"));
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

    // ---- E7-F17: name validation -----------------------------------------

    #[tokio::test]
    async fn install_rejects_traversal_name() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockRunner::new());
        let mgr =
            OpenRcManager::new_with_runner(mock.clone()).with_script_root(tmp.path().to_path_buf());
        let mut spec = sample_spec();
        spec.name = "../../evil".into();
        let err = mgr.install(&spec).await.expect_err("must reject");
        assert!(format!("{err}").contains("invalid service name"));
        assert!(mock.calls().is_empty(), "no rc-update on rejected name");
    }

    #[tokio::test]
    async fn lifecycle_rejects_traversal_name() {
        let mock = Arc::new(MockRunner::new());
        let mgr = OpenRcManager::new_with_runner(mock.clone());
        assert!(mgr.start("a/b").await.is_err());
        assert!(mgr.stop("a/b").await.is_err());
        assert!(mgr.status("a/b").await.is_err());
        assert!(mgr.reload("a/b").await.is_err());
        assert!(mock.calls().is_empty());
    }

    // ---- E7-F9: env exports ----------------------------------------------

    #[test]
    fn render_env_exports_emits_export_lines() {
        let spec = sample_spec();
        let out = render_env_exports(&spec);
        // sample_spec has RUST_LOG=info and SPT_STATE_DIR=/var/lib/spt.
        assert!(out.contains("export RUST_LOG=\"info\""), "got: {out}");
        assert!(
            out.contains("export SPT_STATE_DIR=\"/var/lib/spt\""),
            "got: {out}"
        );
    }

    #[test]
    fn render_env_exports_escapes_special_chars() {
        let mut spec = sample_spec();
        spec.env.clear();
        spec.env.insert("K".into(), "a\"b$c`d\\e".into());
        let out = render_env_exports(&spec);
        assert_eq!(out, "export K=\"a\\\"b\\$c\\`d\\\\e\"");
    }

    #[test]
    fn render_env_exports_empty_when_no_env() {
        let mut spec = sample_spec();
        spec.env.clear();
        assert_eq!(render_env_exports(&spec), "");
    }
}
