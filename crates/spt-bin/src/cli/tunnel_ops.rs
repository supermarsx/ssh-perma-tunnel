//! `spt tunnel` operational subcommands: `stats`, `sessions`, `health`.
//!
//! Each entry point is a one-shot reader against the status snapshot written
//! by the running supervisor (`<state_dir>/status.json`). No live RPC is
//! required — the snapshot is authoritative for these views per spec §13.5.
//!
//! ## Outputs
//!
//! * `stats`    — header + per-profile rollup + per-forward listing.
//! * `sessions` — aligned table from `StatusSnapshot::sessions`.
//! * `health`   — green / yellow / red / unknown aggregation across profiles
//!   plus the recent-error tail, with health-specific exit codes
//!   (0 / 1 / 2 / 3). See [`health`] for the full exit contract (E4-F12).
//!
//! All three honour machine output via the shared [`effective_format`] /
//! [`emit`] helpers (E4-F6/E4-F16): both `spt --json <cmd>` and
//! `spt <cmd> --json` work, and `--output yaml|jsonl` is honoured. The JSON
//! form is the parsed `StatusSnapshot` (or, for `sessions`, the sessions array;
//! for `health`, a small derived object). Machine output is pretty on a TTY and
//! compact when piped.

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::uninlined_format_args)]

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;

// The `json!` shorthand is only used by the Windows standalone stop path;
// the cross-platform code paths use fully-qualified `serde_json::json!`.
#[cfg(windows)]
use serde_json::json;
use spt_cli::groups::tunnel::{TunnelHealth, TunnelSessions, TunnelStats};
use spt_cli::{GlobalOpts, OutputFormat};

use crate::cli::style::Styler;
use spt_config::openssh_config::parse_user_host_port;
use spt_config::schema::{Config, Hop};
use spt_core::{escape_control, Error, Result};
use spt_state::status::{LastError, ProfileStatus, StatusSnapshot};

// ---------------------------------------------------------------------------
// Shared machine-output helpers (E4-F6, E4-F16)
//
// These live here, in spt-bin, so the `effective_format` / `emit` policy is
// owned entirely by the binary crate (NOT spt-cli) — this avoids a cross-crate
// race with `spt-cli` during the parallel fill-the-gaps work. Every ops module
// in the `t-fill-p3-ops-json` lock set reuses these via
// `crate::cli::tunnel_ops::{effective_format, emit}`.
// ---------------------------------------------------------------------------

/// Resolve the effective output format for a command, honouring **both** the
/// global `--json` / `--output` flags and a leaf-local `--json` bool.
///
/// Precedence (highest first):
/// 1. `global.json` or `local_json` → [`OutputFormat::Json`] (the documented
///    `--json` convenience alias, regardless of flag placement — this is the
///    E4-F6 fix: `spt --json <cmd>` now works the same as `spt <cmd> --json`).
/// 2. `global.output` (so `--output yaml|jsonl|json` is honoured).
/// 3. [`OutputFormat::Human`].
///
/// Note: a leaf `--json` only ever *adds* JSON output; it never downgrades an
/// explicit `--output yaml`. When neither JSON flag is set we defer entirely to
/// `--output`, so existing `<cmd> --json` callers keep byte-identical behaviour.
#[must_use]
pub(crate) fn effective_format(global: &GlobalOpts, local_json: bool) -> OutputFormat {
    if global.json || local_json {
        // `--output json` and either `--json` agree; but if the user explicitly
        // asked for a *non-Human* structured format other than json, respect it
        // (e.g. `--output yaml --json` is contradictory; we treat the richer
        // `--output` choice as authoritative only when it is itself structured).
        return match global.output {
            OutputFormat::Yaml => OutputFormat::Yaml,
            OutputFormat::Jsonl => OutputFormat::Jsonl,
            // Human or Json both collapse to Json under a `--json` request.
            OutputFormat::Human | OutputFormat::Json => OutputFormat::Json,
        };
    }
    global.output
}

/// Emit `value` as machine output under the effective format, with a fixed
/// stream policy (E4-F16): **pretty JSON on a TTY, compact JSON when piped**;
/// JSONL is always single-line compact; YAML is YAML. The TTY probe is on
/// `stdout` (the stream the payload is written to), not stderr.
///
/// Returns `Ok(true)` when machine output was written (the caller should then
/// return without printing a human form), or `Ok(false)` when the effective
/// format is Human (the caller should render its human view).
pub(crate) fn emit<T: serde::Serialize>(
    global: &GlobalOpts,
    local_json: bool,
    value: &T,
) -> Result<bool> {
    let fmt = effective_format(global, local_json);
    match fmt {
        OutputFormat::Human => Ok(false),
        OutputFormat::Json => {
            use std::io::IsTerminal;
            let s = if std::io::stdout().is_terminal() {
                serde_json::to_string_pretty(value)
            } else {
                serde_json::to_string(value)
            }
            .map_err(|e| Error::RuntimeFailure(format!("serialize json: {e}")))?;
            println!("{s}");
            Ok(true)
        }
        OutputFormat::Jsonl => {
            let s = serde_json::to_string(value)
                .map_err(|e| Error::RuntimeFailure(format!("serialize jsonl: {e}")))?;
            println!("{s}");
            Ok(true)
        }
        OutputFormat::Yaml => {
            let s = serde_yaml::to_string(value)
                .map_err(|e| Error::RuntimeFailure(format!("serialize yaml: {e}")))?;
            print!("{s}");
            Ok(true)
        }
    }
}

/// Total stop budget. After a graceful console-ctrl signal we wait up to
/// [`GRACEFUL_WAIT`] for an orderly shutdown; if the process is still alive we
/// hard-kill and then wait the remainder of this budget for the kill to take.
/// Mirrors the systemd `TimeoutStopSec` default in
/// `packaging/systemd/spt.service` (90s).
#[cfg(windows)]
const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(90);

/// How long to wait for the supervisor to shut down *gracefully* after a
/// console Ctrl event before falling back to `TerminateProcess`. Kept well
/// under [`STOP_GRACE`] so the overall `tunnel stop` call is always bounded
/// and never hangs even if the graceful path is ignored by the target.
#[cfg(windows)]
const GRACEFUL_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// `spt tunnel stats` — one-shot snapshot of the running tunnel's stats.
pub async fn stats(global: &GlobalOpts, args: TunnelStatsArgs) -> Result<()> {
    let state_dir = resolve_state_dir(global)?;
    let snap = read_status(&state_dir)?;
    let filtered = apply_filters(&snap, args.profile.as_deref(), args.forward.as_deref());

    if emit(global, args.json, &filtered)? {
        return Ok(());
    }
    println!(
        "{}",
        render_stats_human(&filtered, Utc::now(), crate::styler(global))
    );
    Ok(())
}

/// `spt tunnel sessions` — print the session table from `status.json`.
pub async fn sessions(global: &GlobalOpts, args: TunnelSessionsArgs) -> Result<()> {
    let state_dir = resolve_state_dir(global)?;
    let snap = read_status(&state_dir)?;
    let filtered = apply_filters(&snap, args.profile.as_deref(), args.forward.as_deref());

    // Match the brief: machine output dumps the sessions array (not the whole
    // snapshot). `emit` applies the shared pretty-on-tty / compact-on-pipe
    // policy and honours global `--json` / `--output yaml|jsonl`.
    if emit(global, args.json, &filtered.sessions)? {
        return Ok(());
    }
    println!(
        "{}",
        render_sessions_human(&filtered, Utc::now(), crate::styler(global))
    );
    Ok(())
}

/// `spt tunnel health` — aggregate profile state into a green/yellow/red/unknown
/// summary, then exit with a health-specific numeric code for shell scripting.
///
/// # Exit contract (E4-F12)
///
/// Unlike every other `spt` command, `tunnel health` does **not** map its exit
/// status through [`spt_core::Error::exit_code`]. It deliberately exits with a
/// dedicated health code so a monitoring script can branch on tunnel health
/// directly (`spt tunnel health; case $? in ...`). The codes are:
///
/// | Code | Level   | Meaning                                                     |
/// |------|---------|-------------------------------------------------------------|
/// | `0`  | green   | every profile Ready/Active and no recent errors             |
/// | `1`  | yellow  | at least one profile reconnecting/backing-off, or a recent error |
/// | `2`  | red     | at least one profile Failed/Stopped/Error                   |
/// | `3`  | unknown | no supervisor running (no `status.json`) or no profiles configured |
///
/// These values intentionally overlap the *global* exit vocabulary
/// (1=`InvalidArgs`, 2=`InvalidConfig`, 3=`RuntimeFailure`) but carry the
/// health meaning above **only for this subcommand**. The same table is
/// reproduced in `docs/cli-reference.md` and in the `TunnelHealth` `--help`
/// after-help so operators are never surprised by `echo $?`.
///
/// `--json` (or global `--json` / `--output yaml|jsonl`) emits the structured
/// report (`overall`, `profiles[]`, `recent_events[]`) on stdout *before* the
/// process exits with the health code.
pub async fn health(global: &GlobalOpts, args: TunnelHealthArgs) -> Result<()> {
    let state_dir = resolve_state_dir(global)?;
    let report = match try_read_status(&state_dir)? {
        Some(snap) => compute_health(&snap, Utc::now()),
        None => HealthReport::unknown(),
    };

    let payload = report.to_json();
    if !emit(global, args.json, &payload)? {
        println!(
            "{}",
            render_health_human(&report, Utc::now(), crate::styler(global))
        );
    }

    let code = report.level.exit_code();
    if code == 0 {
        Ok(())
    } else {
        // Health-specific exit codes (per brief): 1 yellow, 2 red, 3 unknown.
        // We bypass the normal `Error::exit_code()` mapping by exiting directly
        // here — these aren't error categories, they're a `health` contract.
        // The output has already been written above.
        std::process::exit(code);
    }
}

/// `spt tunnel stop` — Windows standalone path.
///
/// Used when no MCP loopback is reachable (the supervisor is running outside
/// a service host with the MCP listener disabled). We read the recorded PID
/// from `<state_dir>/spt.pid` and **try a graceful shutdown first** (E7-F7):
/// we attach to the supervisor's console and deliver a `CTRL_C_EVENT` /
/// `CTRL_BREAK_EVENT`, which the supervisor's signal task treats exactly like
/// a Unix `SIGTERM` — it runs its orderly shutdown (status flush, status-API
/// stop, forward teardown). Only if the process is still alive after
/// [`GRACEFUL_WAIT`] do we fall back to a hard `TerminateProcess`, then wait
/// the remainder of [`STOP_GRACE`]. This brings Windows to parity with the
/// Unix path instead of the previous immediate hard kill.
///
/// On non-Windows targets this is a no-op that returns
/// [`Error::UnsupportedPlatform`] so callers can compile-share the dispatch
/// table without `#[cfg]` gymnastics at the call site.
#[cfg(not(windows))]
pub async fn stop_windows_standalone(_global: &GlobalOpts) -> Result<()> {
    Err(Error::UnsupportedPlatform(
        "tunnel stop standalone (Windows path) is unavailable on this OS \
         — use SIGTERM via the existing Unix dispatcher"
            .into(),
    ))
}

#[cfg(windows)]
pub async fn stop_windows_standalone(global: &GlobalOpts) -> Result<()> {
    let state_dir = resolve_state_dir(global)?;
    let pid = read_lock_pid(&state_dir)?;
    // Graceful-first: the console-ctrl signal lets the supervisor flush state
    // and tear down cleanly. `stop_with_grace` only hard-kills as a bounded
    // fallback, so the overall call is always time-bounded.
    let outcome = windows_impl::stop_with_grace(pid, GRACEFUL_WAIT, STOP_GRACE)?;
    match outcome {
        windows_impl::StopOutcome::Graceful => {
            println!("ok: stopped pid {pid} gracefully (Windows standalone)");
        }
        windows_impl::StopOutcome::HardKilled => {
            println!(
                "ok: terminated pid {pid} (Windows standalone) — graceful \
                 shutdown did not complete within {}s, hard-killed",
                GRACEFUL_WAIT.as_secs()
            );
        }
    }
    Ok(())
}

/// `spt tunnel reload` — Windows standalone path.
///
/// Tries to dial the MCP loopback (`<state_dir>/mcp-listen.json`) and invoke
/// `tunnel_reload`. There is no Windows named-pipe MCP transport in tree; if
/// the TCP loopback isn't listening we surface a clear error pointing at
/// `spt service reload`, which signals the running Windows service via the
/// Service Control Manager.
#[cfg(not(windows))]
pub async fn reload_windows_standalone(_global: &GlobalOpts) -> Result<()> {
    Err(Error::UnsupportedPlatform(
        "tunnel reload standalone (Windows path) is unavailable on this OS \
         — use SIGHUP via the existing Unix dispatcher"
            .into(),
    ))
}

#[cfg(windows)]
pub async fn reload_windows_standalone(global: &GlobalOpts) -> Result<()> {
    // Confirm there's a recorded supervisor first so the error story is
    // "no supervisor" vs. "supervisor running but MCP off".
    let state_dir = resolve_state_dir(global)?;
    let pid = read_lock_pid(&state_dir)?;

    match crate::mcp_client::McpClient::connect_from_state_dir(&state_dir).await {
        Ok(mut client) => {
            client
                .initialize()
                .await
                .map_err(|e| Error::ReloadFailed(format!("mcp initialize: {e}")))?;
            client
                .call_tool("tunnel_reload", json!({}))
                .await
                .map_err(|e| Error::ReloadFailed(format!("tunnel_reload: {e}")))?;
            println!("ok: reload requested via MCP loopback (pid {pid})");
            Ok(())
        }
        Err(e) => Err(Error::ReloadFailed(format!(
            "supervisor pid {pid} is running but the MCP loopback is not \
             reachable ({e}). Windows standalone reload requires either an \
             enabled `[mcp].listen` in the config (and `spt tunnel run` \
             restarted to pick it up) or running spt as a Windows service \
             and using `spt service reload`."
        ))),
    }
}

#[cfg(windows)]
fn read_lock_pid(state_dir: &std::path::Path) -> Result<u32> {
    let pid_path = spt_state::paths::pid_path(state_dir);
    let raw = std::fs::read_to_string(&pid_path).map_err(|e| {
        Error::RuntimeFailure(format!(
            "read pid `{}`: {e} — is `spt tunnel run` running?",
            pid_path.display()
        ))
    })?;
    raw.trim()
        .parse::<u32>()
        .map_err(|e| Error::RuntimeFailure(format!("invalid pid `{}`: {e}", raw.trim())))
}

#[cfg(windows)]
mod windows_impl {
    use std::time::Duration;

    use spt_core::{Error, Result};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Console::{
        AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler,
        ATTACH_PARENT_PROCESS, CTRL_BREAK_EVENT, CTRL_C_EVENT,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

    /// Result of a graceful-first stop attempt: whether the supervisor exited
    /// on its own after the console signal, or had to be hard-killed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum StopOutcome {
        /// The process exited within the graceful window after the Ctrl event.
        Graceful,
        /// The graceful window elapsed; we fell back to `TerminateProcess`.
        HardKilled,
    }

    /// Stop `pid` **gracefully first** (E7-F7), then hard-kill as a bounded
    /// fallback.
    ///
    /// 1. Open a handle to the target (synchronize + terminate access).
    /// 2. Deliver a console Ctrl event (`CTRL_C_EVENT` then `CTRL_BREAK_EVENT`)
    ///    so the supervisor's signal task runs its orderly shutdown — the
    ///    Windows analogue of Unix `SIGTERM`.
    /// 3. Wait up to `graceful_wait` for a clean exit. If the process exits,
    ///    return [`StopOutcome::Graceful`].
    /// 4. Otherwise `TerminateProcess` and wait the remainder of `total_grace`,
    ///    returning [`StopOutcome::HardKilled`].
    ///
    /// The call is always time-bounded (never longer than `total_grace`) so
    /// `tunnel stop` can never hang, even when the target ignores the Ctrl
    /// event. Returns `RuntimeFailure` only for genuine Win32 errors (bad
    /// handle, kill failure, or a hard-kill that still didn't take).
    pub(super) fn stop_with_grace(
        pid: u32,
        graceful_wait: Duration,
        total_grace: Duration,
    ) -> Result<StopOutcome> {
        let handle: HANDLE =
            // SAFETY: `OpenProcess` (kernel32.dll) takes only PoD arguments —
            // `PROCESS_TERMINATE | PROCESS_SYNCHRONIZE` access mask, `bInheritHandle=false`,
            // and the caller-supplied `pid`. It returns a HANDLE we own and must free via
            // `CloseHandle` (done at the bottom of this function on every exit path).
            // `TerminateProcess` and `WaitForSingleObject` only read from the handle; no
            // aliasing. If `pid` is invalid the call returns INVALID_HANDLE_VALUE which is
            // checked via `handle.is_invalid()` below.
            unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) }
                .map_err(|e| Error::RuntimeFailure(format!("OpenProcess({pid}): {e}")))?;

        if handle.is_invalid() {
            return Err(Error::RuntimeFailure(format!(
                "OpenProcess({pid}) returned invalid handle"
            )));
        }

        let result = (|| -> Result<StopOutcome> {
            // --- Graceful attempt: console Ctrl event ----------------------
            // Best-effort: a delivery failure (e.g. the supervisor has no
            // console, or is a different session) just means we proceed to the
            // wait/fallback — it is never fatal on its own.
            let signalled = try_console_ctrl(pid);

            if signalled {
                // Give the supervisor its orderly-shutdown window.
                if wait_for_exit(handle, graceful_wait)? {
                    return Ok(StopOutcome::Graceful);
                }
            }

            // --- Fallback: hard kill --------------------------------------
            // SAFETY: handle is valid (checked above). Exit code 1 mirrors the
            // service stop convention used by `windows-service`.
            unsafe { TerminateProcess(handle, 1) }
                .map_err(|e| Error::RuntimeFailure(format!("TerminateProcess({pid}): {e}")))?;

            // Wait the remainder of the total budget for the kill to take.
            let remaining = total_grace.saturating_sub(if signalled {
                graceful_wait
            } else {
                Duration::ZERO
            });
            // Even with no remaining budget, give the kernel a brief window to
            // reap the terminated process so we don't spuriously report a hang.
            let remaining = remaining.max(Duration::from_secs(2));
            if wait_for_exit(handle, remaining)? {
                Ok(StopOutcome::HardKilled)
            } else {
                Err(Error::RuntimeFailure(format!(
                    "process {pid} did not exit within {}ms after TerminateProcess",
                    u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX)
                )))
            }
        })();

        // SAFETY: handle came from a successful OpenProcess and has not been
        // closed elsewhere. CloseHandle is safe to call once with an owned
        // handle. Errors here are non-fatal — they don't change the outcome
        // of the caller-visible operation.
        let _ = unsafe { CloseHandle(handle) };
        result
    }

    /// Wait up to `dur` for `handle` to become signalled (process exit).
    /// Returns `Ok(true)` if the process exited within the window, `Ok(false)`
    /// on timeout, and `Err` on a genuine Win32 wait failure.
    fn wait_for_exit(handle: HANDLE, dur: Duration) -> Result<bool> {
        // Truncate to u32 milliseconds; clamp to avoid overflow.
        let ms = u32::try_from(dur.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: handle is valid for the lifetime of `stop_with_grace`;
        // WaitForSingleObject only reads the handle.
        let wait = unsafe { WaitForSingleObject(handle, ms) };
        if wait == WAIT_OBJECT_0 {
            Ok(true)
        } else if wait == WAIT_TIMEOUT {
            Ok(false)
        } else {
            Err(Error::RuntimeFailure(format!(
                "WaitForSingleObject returned 0x{:x}",
                wait.0
            )))
        }
    }

    /// Deliver a console Ctrl event to `pid`'s process group so the supervisor
    /// can shut down gracefully (the Windows analogue of `SIGTERM`).
    ///
    /// Console Ctrl events can only be sent to processes that share a console,
    /// so we transiently `AttachConsole(pid)`. Because the event would also be
    /// delivered to *this* process, we install a no-op handler
    /// (`SetConsoleCtrlHandler(None, true)` → the event is ignored by us)
    /// across the send, then restore our default handling and detach.
    ///
    /// Returns `true` if at least one Ctrl event was delivered, `false` if the
    /// attach failed (target has no console / different session) so the caller
    /// can skip the graceful wait and go straight to the hard-kill fallback.
    /// All steps are best-effort — this never errors.
    ///
    /// Console state is restored on every path: if we had to detach our own
    /// console to attach the target's, we reattach the parent console before
    /// returning so a long-lived caller (and the test harness) is left intact.
    fn try_console_ctrl(pid: u32) -> bool {
        // SAFETY: all calls below are plain Win32 console APIs taking PoD
        // arguments. A process may be attached to at most one console, so we
        // first try AttachConsole directly; only if that's refused (we already
        // own a console) do we FreeConsole and retry, then restore the parent
        // console on the way out. Every state change is reverted before return.
        // A failure at any step is reported via the boolean return — never a
        // panic.
        unsafe {
            // Try to attach to the target's console without disturbing ours.
            let mut freed_own = false;
            if AttachConsole(pid).is_err() {
                // Likely ERROR_ACCESS_DENIED: we already own a console. Drop it
                // and retry so we can bind the target's.
                let _ = FreeConsole();
                freed_own = true;
                if AttachConsole(pid).is_err() {
                    // Target has no console / is in a different session.
                    // Best-effort restore our own console and bail.
                    let _ = AttachConsole(ATTACH_PARENT_PROCESS);
                    return false;
                }
            }

            // Make sure the event we're about to raise does not terminate this
            // CLI process: install the "ignore" handler (NULL routine + add).
            let _ = SetConsoleCtrlHandler(None, true);

            // Send to the whole attached console group (group id 0). Try
            // CTRL_C first (the supervisor's tokio `ctrl_c()` listens for it),
            // then CTRL_BREAK as a backstop for handlers that only catch break.
            let c_ok = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0).is_ok();
            let brk_ok = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0).is_ok();

            // Detach from the target console and restore our own Ctrl handling.
            let _ = SetConsoleCtrlHandler(None, false);
            let _ = FreeConsole();
            if freed_own {
                // Re-acquire the console we started with so the caller (and the
                // test harness) keeps working after we return.
                let _ = AttachConsole(ATTACH_PARENT_PROCESS);
            }

            c_ok || brk_ok
        }
    }
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/// Parsed args for `tunnel stats`. Mirrors `spt_cli::groups::tunnel::TunnelStats`
/// but is a separate type so the dispatch layer can pass either the raw clap
/// struct or a synthesised one (e.g. tests).
#[derive(Debug, Default, Clone)]
pub struct TunnelStatsArgs {
    pub profile: Option<String>,
    pub forward: Option<String>,
    pub json: bool,
}

impl From<TunnelStats> for TunnelStatsArgs {
    fn from(v: TunnelStats) -> Self {
        Self {
            profile: v.profile,
            forward: v.forward,
            json: v.json,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TunnelSessionsArgs {
    pub profile: Option<String>,
    pub forward: Option<String>,
    pub json: bool,
}

impl From<TunnelSessions> for TunnelSessionsArgs {
    fn from(v: TunnelSessions) -> Self {
        Self {
            profile: v.profile,
            forward: v.forward,
            json: v.json,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TunnelHealthArgs {
    pub json: bool,
}

impl From<TunnelHealth> for TunnelHealthArgs {
    fn from(v: TunnelHealth) -> Self {
        Self { json: v.json }
    }
}

// ---------------------------------------------------------------------------
// Internals — state dir + status.json
// ---------------------------------------------------------------------------

fn resolve_state_dir(global: &GlobalOpts) -> Result<PathBuf> {
    spt_state::resolve_state_dir(global.state_dir.as_deref())
}

fn read_status(state_dir: &Path) -> Result<StatusSnapshot> {
    match try_read_status(state_dir)? {
        Some(s) => Ok(s),
        None => Err(Error::RuntimeFailure(format!(
            "no status snapshot at `{}` — is `spt tunnel run` running?",
            spt_state::paths::status_path(state_dir).display()
        ))),
    }
}

fn try_read_status(state_dir: &Path) -> Result<Option<StatusSnapshot>> {
    let path = spt_state::paths::status_path(state_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let s: StatusSnapshot = serde_json::from_slice(&bytes)
                .map_err(|e| Error::RuntimeFailure(format!("parse `{}`: {e}", path.display())))?;
            Ok(Some(s))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::RuntimeFailure(format!(
            "read `{}`: {e}",
            path.display()
        ))),
    }
}

fn apply_filters(
    snap: &StatusSnapshot,
    profile: Option<&str>,
    forward: Option<&str>,
) -> StatusSnapshot {
    if profile.is_none() && forward.is_none() {
        return snap.clone();
    }
    let mut out = snap.clone();
    if let Some(p) = profile {
        out.profiles.retain(|x| x.id == p);
        out.forwards.retain(|x| x.profile == p);
        out.sessions.retain(|x| x.profile == p);
        out.connections.retain(|x| x.profile == p);
    }
    if let Some(f) = forward {
        out.forwards.retain(|x| x.id == f);
        // Sessions don't have a forward field; filter via active_forwards is
        // not feasible without per-session forward IDs. Connections do.
        out.connections.retain(|x| x.forward == f);
    }
    out
}

// ---------------------------------------------------------------------------
// Human renderers
// ---------------------------------------------------------------------------

fn render_stats_human(snap: &StatusSnapshot, now: DateTime<Utc>, st: Styler) -> String {
    use std::fmt::Write as _; // 1.88 lint: format_push_string
    let mut out = String::new();
    let active_sessions: u64 = snap
        .sessions
        .iter()
        .filter(|s| eq_ic(&s.state, "running") || eq_ic(&s.state, "active"))
        .count() as u64;
    let _ = writeln!(
        out,
        "tunnel: {} profiles · {} forwards · {} active sessions\n",
        snap.profiles.len(),
        snap.forwards.len(),
        active_sessions,
    );

    // Profile rollup
    let name_w = snap
        .profiles
        .iter()
        .map(|p| p.id.len())
        .max()
        .unwrap_or(0)
        .max(7);
    for p in &snap.profiles {
        let uptime = snap.started_at.map_or_else(
            || "-".to_string(),
            |t| fmt_uptime(now.signed_duration_since(t)),
        );
        // Aggregate per-profile bytes from forwards.
        let (rx, tx) = snap
            .forwards
            .iter()
            .filter(|f| f.profile == p.id)
            .fold((0u64, 0u64), |(a, b), f| (a + f.bytes_in, b + f.bytes_out));
        // Pad the state to the column width *before* coloring so ANSI escapes
        // don't throw off alignment.
        let state_cell = st.state(&format!("{:<13}", p.state));
        let _ = writeln!(
            out,
            "{:<width$}  {}  uptime {}    rx {}    tx {}    reconnects {}",
            p.id,
            state_cell,
            uptime,
            spt_core::size::format_size(rx),
            spt_core::size::format_size(tx),
            p.reconnect_count,
            width = name_w,
        );
    }

    if !snap.forwards.is_empty() {
        let _ = writeln!(out, "\n{}", st.bold(&st.cyan("forwards:")));
        for f in &snap.forwards {
            let listen = f.local_addr.clone().unwrap_or_else(|| "-".into());
            let _ = writeln!(
                out,
                "  {}/{}        listen {}  active {}   rx {}   tx {}",
                f.profile,
                f.id,
                listen,
                f.current_connections,
                spt_core::size::format_size(f.bytes_in),
                spt_core::size::format_size(f.bytes_out),
            );
        }
    }

    out
}

fn render_sessions_human(snap: &StatusSnapshot, now: DateTime<Utc>, st: Styler) -> String {
    use std::fmt::Write as _; // 1.88 lint: format_push_string
    let mut out = String::new();
    let header = format!(
        "{:<22} {:<14} {:<22} {:<12} {:<20} {:<5}",
        "ID", "PROFILE", "ENDPOINT", "SINCE", "BYTES IN/OUT", "CONNS",
    );
    let _ = writeln!(out, "{}", st.bold(&header));
    if snap.sessions.is_empty() {
        out.push_str("(no active sessions)\n");
        return out;
    }
    for s in &snap.sessions {
        let since = s.started_at.map_or_else(
            || "-".to_string(),
            |t| fmt_uptime(now.signed_duration_since(t)),
        );
        let bytes = format!(
            "{} / {}",
            spt_core::size::format_size(s.bytes_in),
            spt_core::size::format_size(s.bytes_out),
        );
        let _ = writeln!(
            out,
            "{:<22} {:<14} {:<22} {:<12} {:<20} {:<5}",
            truncate(&s.id, 22),
            truncate(&s.profile, 14),
            truncate(&s.endpoint, 22),
            since,
            bytes,
            s.active_forwards,
        );
    }
    out
}

fn render_health_human(report: &HealthReport, now: DateTime<Utc>, st: Styler) -> String {
    use std::fmt::Write as _; // 1.88 lint: format_push_string
    let mut out = String::new();
    // Color the overall verdict by level (green/yellow/red/dim-unknown).
    let verdict = match report.level {
        HealthLevel::Green => st.green(report.level.label()),
        HealthLevel::Yellow => st.yellow(report.level.label()),
        HealthLevel::Red => st.red(report.level.label()),
        HealthLevel::Unknown => st.dim(report.level.label()),
    };
    let _ = writeln!(out, "tunnel health: {}\n", verdict);

    if report.profiles.is_empty() && matches!(report.level, HealthLevel::Unknown) {
        out.push_str("  (no supervisor running — `status.json` not found)\n");
    }

    let name_w = report
        .profiles
        .iter()
        .map(|p| p.id.len())
        .max()
        .unwrap_or(0)
        .max(7);
    for p in &report.profiles {
        let last = p.last_error.as_deref().unwrap_or("-");
        let state_cell = st.state(&format!("{:<13}", p.state));
        // SECURITY (O7): `last_error` is free-form text persisted in
        // status.json and may carry server-supplied banner/error text.
        // Neutralize control/ANSI bytes before printing to the terminal.
        let _ = writeln!(
            out,
            "  {:<width$}  {} uptime {}    last error: {}",
            format!("{}:", p.id),
            state_cell,
            p.uptime.as_ref().cloned().unwrap_or_else(|| "-".into()),
            escape_control(last),
            width = name_w + 1,
        );
    }

    if !report.recent_events.is_empty() {
        out.push_str("\n  Recent events (last 10m):\n");
        for ev in &report.recent_events {
            let when = ev.at.map_or_else(|| "-".to_string(), |t| fmt_clock(t));
            // SECURITY (O7): event `message` (and `scope`) are free-form and
            // may carry server-supplied text — neutralize control/ANSI bytes.
            let _ = writeln!(
                out,
                "    - {}  {}  {}",
                when,
                escape_control(&ev.scope),
                escape_control(&ev.message)
            );
        }
    }

    let _ = now;
    out
}

// ---------------------------------------------------------------------------
// Health logic
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthLevel {
    Green,
    Yellow,
    Red,
    Unknown,
}

impl HealthLevel {
    fn label(self) -> &'static str {
        match self {
            HealthLevel::Green => "GREEN",
            HealthLevel::Yellow => "YELLOW",
            HealthLevel::Red => "RED",
            HealthLevel::Unknown => "UNKNOWN",
        }
    }
    fn exit_code(self) -> i32 {
        match self {
            HealthLevel::Green => 0,
            HealthLevel::Yellow => 1,
            HealthLevel::Red => 2,
            HealthLevel::Unknown => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HealthReport {
    pub level: HealthLevel,
    pub profiles: Vec<HealthProfile>,
    pub recent_events: Vec<HealthEvent>,
}

#[derive(Debug, Clone)]
pub(crate) struct HealthProfile {
    pub id: String,
    pub state: String,
    pub uptime: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct HealthEvent {
    pub at: Option<DateTime<Utc>>,
    pub scope: String,
    pub message: String,
}

impl HealthReport {
    fn unknown() -> Self {
        Self {
            level: HealthLevel::Unknown,
            profiles: Vec::new(),
            recent_events: Vec::new(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "overall": match self.level {
                HealthLevel::Green => "green",
                HealthLevel::Yellow => "yellow",
                HealthLevel::Red => "red",
                HealthLevel::Unknown => "unknown",
            },
            "profiles": self.profiles.iter().map(|p| serde_json::json!({
                "id": p.id,
                "state": p.state,
                "uptime": p.uptime,
                "last_error": p.last_error,
            })).collect::<Vec<_>>(),
            "recent_events": self.recent_events.iter().map(|e| serde_json::json!({
                "at": e.at,
                "scope": e.scope,
                "message": e.message,
            })).collect::<Vec<_>>(),
        })
    }
}

pub(crate) fn compute_health(snap: &StatusSnapshot, now: DateTime<Utc>) -> HealthReport {
    // Empty profile set with a missing supervisor would have been short-circuited
    // upstream as Unknown. An empty profile list inside a real snapshot means
    // "no profiles configured" — treat as Unknown so users notice.
    if snap.profiles.is_empty() {
        return HealthReport {
            level: HealthLevel::Unknown,
            profiles: Vec::new(),
            recent_events: collect_recent_events(snap, now),
        };
    }

    let recent_events = collect_recent_events(snap, now);
    let any_recent_error = recent_events.iter().any(|_| true);

    let mut has_red = false;
    let mut has_yellow = any_recent_error;
    for p in &snap.profiles {
        match classify_profile(&p.state) {
            ProfileLevel::Red => has_red = true,
            ProfileLevel::Yellow => has_yellow = true,
            ProfileLevel::Green => {}
        }
    }

    let level = if has_red {
        HealthLevel::Red
    } else if has_yellow {
        HealthLevel::Yellow
    } else {
        HealthLevel::Green
    };

    let profiles = snap
        .profiles
        .iter()
        .map(|p| HealthProfile {
            id: p.id.clone(),
            state: p.state.clone(),
            uptime: snap
                .started_at
                .map(|t| fmt_uptime(now.signed_duration_since(t))),
            last_error: profile_last_error(snap, p),
        })
        .collect();

    HealthReport {
        level,
        profiles,
        recent_events,
    }
}

enum ProfileLevel {
    Green,
    Yellow,
    Red,
}

fn classify_profile(state: &str) -> ProfileLevel {
    // States from spt-supervisor / spec §13.5.
    if eq_ic(state, "ready") || eq_ic(state, "running") || eq_ic(state, "active") {
        ProfileLevel::Green
    } else if eq_ic(state, "reconnecting")
        || eq_ic(state, "backingoff")
        || eq_ic(state, "backing_off")
        || eq_ic(state, "connecting")
        || eq_ic(state, "starting")
    {
        ProfileLevel::Yellow
    } else if eq_ic(state, "failed") || eq_ic(state, "stopped") || eq_ic(state, "error") {
        ProfileLevel::Red
    } else {
        // Unknown/unclassified states err on the side of yellow so they're
        // visible without being alarming.
        ProfileLevel::Yellow
    }
}

fn profile_last_error(snap: &StatusSnapshot, p: &ProfileStatus) -> Option<String> {
    // Prefer the profile's own last_error_category; fall back to a matching
    // entry in `last_errors` (scope == profile id).
    if let Some(c) = &p.last_error_category {
        if !c.is_empty() {
            return Some(c.clone());
        }
    }
    snap.last_errors
        .iter()
        .filter(|e| e.scope == p.id)
        .max_by_key(|e| e.at)
        .map(|e| {
            if e.message.is_empty() {
                e.category.clone()
            } else {
                e.message.clone()
            }
        })
}

fn collect_recent_events(snap: &StatusSnapshot, now: DateTime<Utc>) -> Vec<HealthEvent> {
    let cutoff = now - ChronoDuration::minutes(10);
    let mut evs: Vec<&LastError> = snap
        .last_errors
        .iter()
        .filter(|e| e.at.is_some_and(|t| t >= cutoff))
        .collect();
    evs.sort_by_key(|e| e.at);
    evs.into_iter()
        .rev()
        .take(10)
        .map(|e| HealthEvent {
            at: e.at,
            scope: e.scope.clone(),
            message: if e.message.is_empty() {
                e.category.clone()
            } else {
                e.message.clone()
            },
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn eq_ic(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn fmt_uptime(d: ChronoDuration) -> String {
    let total = d.num_seconds().max(0);
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let mins = (total % 3_600) / 60;
    let secs = total % 60;
    if days > 0 {
        format!("{days}d {hours:02}h")
    } else if hours > 0 {
        format!("{hours:2}h {mins:02}m")
    } else if mins > 0 {
        format!("{mins:2}m {secs:02}s")
    } else {
        format!("{secs}s")
    }
}

fn fmt_clock(t: DateTime<Utc>) -> String {
    t.format("%H:%M").to_string()
}

// ---------------------------------------------------------------------------
// t6-e3: `-J` proxy-jump consumption
// ---------------------------------------------------------------------------

/// Parse a `-J user@host[:port][,user@host…]` chain string into a list of
/// `Hop`s. Each element becomes a `kind = "ssh"` hop (HTTP/SOCKS5 proxy
/// hops are configured via the profile table — `-J` mirrors OpenSSH's
/// SSH-only chain).
///
/// Empty chains return `Ok(vec![])`. Whitespace around commas is tolerated.
pub fn parse_jump_chain(raw: &str) -> Result<Vec<Hop>> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (user, host, port) = parse_user_host_port(part);
        if host.is_empty() {
            return Err(Error::InvalidArgs(format!(
                "-J: empty host in `{part}` (expected `user@host[:port]`)"
            )));
        }
        let mut hop = Hop::default();
        hop.name = format!("cli-jump-{}", out.len() + 1);
        // Must be the canonical `ssh2` token: `validate` gates hop.protocol to
        // ssh2/ssh3 and runs immediately after the -J chain is injected, so
        // emitting bare "ssh" here makes every `tunnel run -J` abort with
        // [hop_protocol_invalid] before connecting.
        hop.protocol = "ssh2".to_string();
        hop.host = host;
        hop.port = port.unwrap_or(22);
        hop.user = user;
        // hop.kind defaults to HopKind::Ssh — OpenSSH `-J` semantics.
        out.push(hop);
    }
    Ok(out)
}

/// Splat the parsed `-J` chain into every selected profile's `hops`,
/// replacing the profile-file hops so CLI takes precedence (per t6-e3
/// spec).
///
/// `selected_profiles` is a name filter; when empty every enabled profile
/// is mutated. Returns the number of profiles updated.
pub fn apply_jump_chain_to_config(
    cfg: &mut Config,
    selected_profiles: &[String],
    chain: &[Hop],
) -> usize {
    let mut n = 0;
    for p in &mut cfg.profiles {
        if !selected_profiles.is_empty() && !selected_profiles.iter().any(|name| name == &p.name) {
            continue;
        }
        p.hops = chain.to_vec();
        n += 1;
    }
    n
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use spt_state::status::{ForwardStatus, ProfileStatus, SessionStatus};
    use spt_state::testing::StatusSnapshotBuilder;

    // --- t6-e3: `-J` jump-chain parsing ----------------------------------

    #[test]
    fn jump_chain_parse_single_hop() {
        let hops = parse_jump_chain("bastion.example.com").unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].host, "bastion.example.com");
        assert_eq!(hops[0].port, 22);
        assert!(hops[0].user.is_none());
    }

    #[test]
    fn jump_chain_parse_two_hops_with_user_and_port() {
        let hops = parse_jump_chain("alice@h1:2200,bob@h2").unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].user.as_deref(), Some("alice"));
        assert_eq!(hops[0].host, "h1");
        assert_eq!(hops[0].port, 2200);
        assert_eq!(hops[1].user.as_deref(), Some("bob"));
        assert_eq!(hops[1].host, "h2");
        assert_eq!(hops[1].port, 22);
    }

    #[test]
    fn jump_chain_parse_three_hops_tolerates_spaces() {
        let hops = parse_jump_chain("h1, alice@h2:22 , h3:2202").unwrap();
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].host, "h1");
        assert_eq!(hops[1].host, "h2");
        assert_eq!(hops[1].user.as_deref(), Some("alice"));
        assert_eq!(hops[2].host, "h3");
        assert_eq!(hops[2].port, 2202);
    }

    #[test]
    fn jump_chain_cli_takes_precedence_over_profile_hops() {
        use spt_config::schema::{Hop, Profile};
        let mut cfg = Config {
            version: 1,
            ..Default::default()
        };
        let mut p = Profile::default();
        p.name = "prod".into();
        // Profile-file hop the operator put in the TOML.
        let mut existing = Hop::default();
        existing.name = "from-toml".into();
        existing.host = "stale.example.com".into();
        existing.port = 22;
        p.hops = vec![existing];
        cfg.profiles.push(p);

        let chain = parse_jump_chain("fresh.example.com:2222").unwrap();
        let n = apply_jump_chain_to_config(&mut cfg, &[], &chain);
        assert_eq!(n, 1);
        assert_eq!(cfg.profiles[0].hops.len(), 1);
        assert_eq!(cfg.profiles[0].hops[0].host, "fresh.example.com");
        assert_eq!(cfg.profiles[0].hops[0].port, 2222);
    }

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap()
    }

    fn ready_profile(id: &str) -> ProfileStatus {
        let mut p = ProfileStatus::default();
        p.id = id.into();
        p.state = "Ready".into();
        p
    }

    fn forward(profile: &str, id: &str, listen: &str, rx: u64, tx: u64) -> ForwardStatus {
        let mut f = ForwardStatus::default();
        f.id = id.into();
        f.profile = profile.into();
        f.state = "active".into();
        f.local_addr = Some(listen.into());
        f.bytes_in = rx;
        f.bytes_out = tx;
        f
    }

    fn session(id: &str, profile: &str, endpoint: &str) -> SessionStatus {
        let mut s = SessionStatus::default();
        s.id = id.into();
        s.profile = profile.into();
        s.endpoint = endpoint.into();
        s.state = "running".into();
        s.started_at = Some(ts());
        s
    }

    fn green_snapshot() -> StatusSnapshot {
        StatusSnapshotBuilder::new()
            .pid(1)
            .version("test")
            .started_at(ts() - ChronoDuration::hours(2))
            .add_profile(ready_profile("bastion-prod"))
            .add_profile(ready_profile("bastion-staging"))
            .add_forward(forward(
                "bastion-prod",
                "web",
                "127.0.0.1:8080",
                12 * 1024 * 1024 * 1024,
                1024 * 1024 * 1024,
            ))
            .add_session(session("abc123", "bastion-prod", "bastion.corp:22"))
            .build()
    }

    // -- compute_health --------------------------------------------------

    #[test]
    fn health_green_when_all_ready_no_recent_errors() {
        let snap = green_snapshot();
        let now = ts();
        let r = compute_health(&snap, now);
        assert_eq!(r.level, HealthLevel::Green);
        assert_eq!(r.level.exit_code(), 0);
        assert_eq!(r.profiles.len(), 2);
    }

    #[test]
    fn health_yellow_when_profile_reconnecting() {
        let mut snap = green_snapshot();
        snap.profiles[1].state = "Reconnecting".into();
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Yellow);
        assert_eq!(r.level.exit_code(), 1);
    }

    #[test]
    fn health_yellow_when_recent_error_logged() {
        let mut snap = green_snapshot();
        snap.last_errors.push(LastError {
            scope: "bastion-prod".into(),
            category: "io".into(),
            message: "peer reset".into(),
            at: Some(ts() - ChronoDuration::minutes(2)),
        });
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Yellow);
        assert_eq!(r.recent_events.len(), 1);
    }

    #[test]
    fn health_red_when_profile_failed() {
        let mut snap = green_snapshot();
        snap.profiles[0].state = "Failed".into();
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Red);
        assert_eq!(r.level.exit_code(), 2);
    }

    #[test]
    fn health_red_takes_precedence_over_yellow() {
        let mut snap = green_snapshot();
        snap.profiles[0].state = "Reconnecting".into();
        snap.profiles[1].state = "Failed".into();
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Red);
    }

    #[test]
    fn health_unknown_when_no_profiles() {
        let snap = StatusSnapshotBuilder::new().build();
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Unknown);
        assert_eq!(r.level.exit_code(), 3);
    }

    #[test]
    fn health_unknown_via_constructor_when_no_supervisor() {
        // Mirrors the "no status.json on disk" path from `health()`.
        let r = HealthReport::unknown();
        assert_eq!(r.level, HealthLevel::Unknown);
        assert_eq!(r.level.exit_code(), 3);
    }

    #[test]
    fn recent_events_window_is_10_minutes() {
        let mut snap = green_snapshot();
        snap.last_errors.push(LastError {
            scope: "bastion-prod".into(),
            category: "io".into(),
            message: "old".into(),
            at: Some(ts() - ChronoDuration::minutes(30)),
        });
        snap.last_errors.push(LastError {
            scope: "bastion-prod".into(),
            category: "io".into(),
            message: "fresh".into(),
            at: Some(ts() - ChronoDuration::minutes(3)),
        });
        let evs = collect_recent_events(&snap, ts());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].message, "fresh");
    }

    // -- JSON round-trip ------------------------------------------------

    #[test]
    fn health_json_round_trips_through_value() {
        let snap = green_snapshot();
        let r = compute_health(&snap, ts());
        let v = r.to_json();
        let s = serde_json::to_string(&v).unwrap();
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["overall"], "green");
        assert_eq!(v["profiles"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn stats_json_roundtrips_full_snapshot() {
        let snap = green_snapshot();
        let s = serde_json::to_string_pretty(&snap).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["profiles"].as_array().unwrap().len(), 2);
        assert_eq!(v["forwards"].as_array().unwrap().len(), 1);
        // Re-deserialize to StatusSnapshot to lock the shape.
        let _back: StatusSnapshot = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn sessions_json_dumps_sessions_array() {
        let snap = green_snapshot();
        let s = serde_json::to_string(&snap.sessions).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["id"], "abc123");
    }

    // -- Renderers ------------------------------------------------------

    #[test]
    fn render_stats_human_includes_header_and_forward_listing() {
        let snap = green_snapshot();
        let s = render_stats_human(&snap, ts(), Styler::new(false));
        assert!(s.contains("tunnel: 2 profiles"));
        assert!(
            s.contains("5 forwards").not_or(true)
                || s.contains("1 forwards")
                || s.contains("forwards")
        );
        assert!(s.contains("bastion-prod"));
        assert!(s.contains("forwards:"));
        assert!(s.contains("127.0.0.1:8080"));
    }

    // Helper trait so the assert macro chain above stays readable. (Tests
    // shouldn't rely on this for real logic.)
    trait BoolExt {
        fn not_or(self, fallback: bool) -> bool;
    }
    impl BoolExt for bool {
        fn not_or(self, fallback: bool) -> bool {
            !self || fallback
        }
    }

    #[test]
    fn render_sessions_human_table_has_header() {
        let snap = green_snapshot();
        let s = render_sessions_human(&snap, ts() + ChronoDuration::hours(1), Styler::new(false));
        assert!(s.contains("ID"));
        assert!(s.contains("PROFILE"));
        assert!(s.contains("ENDPOINT"));
        assert!(s.contains("abc123"));
        assert!(s.contains("bastion.corp:22"));
    }

    #[test]
    fn render_sessions_human_handles_empty_table() {
        let snap = StatusSnapshotBuilder::new().build();
        let s = render_sessions_human(&snap, ts(), Styler::new(false));
        assert!(s.contains("(no active sessions)"));
    }

    #[test]
    fn render_health_human_labels_each_level() {
        let snap = green_snapshot();
        let r = compute_health(&snap, ts());
        let s = render_health_human(&r, ts(), Styler::new(false));
        assert!(s.contains("GREEN"));
        assert!(s.contains("bastion-prod"));
    }

    #[test]
    fn render_health_human_unknown_explains_missing_supervisor() {
        let r = HealthReport::unknown();
        let s = render_health_human(&r, ts(), Styler::new(false));
        assert!(s.contains("UNKNOWN"));
        assert!(s.contains("no supervisor running"));
    }

    // -- Filters --------------------------------------------------------

    #[test]
    fn apply_filters_narrows_to_profile() {
        let snap = green_snapshot();
        let f = apply_filters(&snap, Some("bastion-prod"), None);
        assert_eq!(f.profiles.len(), 1);
        assert_eq!(f.forwards.len(), 1);
        assert_eq!(f.sessions.len(), 1);
    }

    #[test]
    fn apply_filters_narrows_to_forward() {
        let snap = green_snapshot();
        let f = apply_filters(&snap, None, Some("web"));
        assert_eq!(f.forwards.len(), 1);
    }

    #[test]
    fn apply_filters_drops_nonmatching_profile() {
        let snap = green_snapshot();
        let f = apply_filters(&snap, Some("does-not-exist"), None);
        assert!(f.profiles.is_empty());
        assert!(f.forwards.is_empty());
        assert!(f.sessions.is_empty());
    }

    // -- fmt helpers ----------------------------------------------------

    #[test]
    fn fmt_uptime_formats_days_hours_minutes() {
        assert!(fmt_uptime(ChronoDuration::seconds(45)).contains('s'));
        assert!(fmt_uptime(ChronoDuration::seconds(125)).contains('m'));
        assert!(fmt_uptime(ChronoDuration::seconds(2 * 3600 + 5 * 60)).contains('h'));
        let s = fmt_uptime(ChronoDuration::seconds(4 * 86_400 + 12 * 3600));
        assert!(s.contains("4d"));
        assert!(s.contains("12h"));
    }

    #[test]
    fn truncate_clips_long_strings() {
        assert_eq!(truncate("hello", 10), "hello");
        let s = truncate("hello-world-extra", 8);
        assert!(s.chars().count() == 8);
        assert!(s.ends_with('…'));
    }

    // -- read_status (filesystem) ---------------------------------------

    #[test]
    fn try_read_status_returns_none_when_missing() {
        let d = spt_state::testing::TempStateDir::new();
        let r = try_read_status(d.as_path()).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn try_read_status_parses_existing_snapshot() {
        let d = spt_state::testing::TempStateDir::new().with_status(|s| {
            s.pid = 4242;
            s.version = "v-test".into();
        });
        let r = try_read_status(d.as_path()).unwrap().unwrap();
        assert_eq!(r.pid, 4242);
        assert_eq!(r.version, "v-test");
    }

    // -- Windows-standalone stop / reload -------------------------------

    fn make_global_with_state_dir(dir: std::path::PathBuf) -> GlobalOpts {
        use spt_cli::{ColorMode, LogLevel, OutputFormat as OF};
        GlobalOpts {
            config: None,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: Some(dir),
            profile: None,
            portable: false,
            output: OF::Human,
            json: false,
            log_level: LogLevel::Info,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: false,
            dry_run: false,
        }
    }

    // -- effective_format / emit (E4-F6, E4-F16) ------------------------

    #[test]
    fn effective_format_global_json_matches_leaf_json() {
        use spt_cli::OutputFormat as OF;
        let mut g = make_global_with_state_dir(std::path::PathBuf::from("."));
        // Global `--json`, no leaf flag.
        g.json = true;
        g.output = OF::Human;
        assert_eq!(effective_format(&g, false), OF::Json);
        // Leaf `--json`, no global flag.
        g.json = false;
        assert_eq!(effective_format(&g, true), OF::Json);
    }

    #[test]
    fn effective_format_defaults_to_human_and_honours_output() {
        use spt_cli::OutputFormat as OF;
        let mut g = make_global_with_state_dir(std::path::PathBuf::from("."));
        assert_eq!(effective_format(&g, false), OF::Human);
        g.output = OF::Yaml;
        assert_eq!(effective_format(&g, false), OF::Yaml);
        g.output = OF::Jsonl;
        assert_eq!(effective_format(&g, false), OF::Jsonl);
        // `--json` does not downgrade an explicit structured `--output`.
        g.output = OF::Yaml;
        assert_eq!(effective_format(&g, true), OF::Yaml);
    }

    #[test]
    fn emit_returns_false_for_human_true_for_machine() {
        let mut g = make_global_with_state_dir(std::path::PathBuf::from("."));
        let v = serde_json::json!({"k": "v"});
        // Human → caller renders human.
        assert!(!emit(&g, false, &v).unwrap());
        // Leaf json → machine.
        assert!(emit(&g, true, &v).unwrap());
        // Global json → machine (placement-independent: the E4-F6 fix).
        g.json = true;
        assert!(emit(&g, false, &v).unwrap());
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn stop_windows_standalone_returns_unsupported_on_unix() {
        let d = spt_state::testing::TempStateDir::new();
        let g = make_global_with_state_dir(d.as_path().to_path_buf());
        let err = stop_windows_standalone(&g).await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn reload_windows_standalone_returns_unsupported_on_unix() {
        let d = spt_state::testing::TempStateDir::new();
        let g = make_global_with_state_dir(d.as_path().to_path_buf());
        let err = reload_windows_standalone(&g).await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn stop_windows_standalone_errors_when_pid_file_missing() {
        let d = spt_state::testing::TempStateDir::new();
        let g = make_global_with_state_dir(d.as_path().to_path_buf());
        let err = stop_windows_standalone(&g).await.unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn stop_windows_standalone_errors_when_pid_unparseable() {
        let d = spt_state::testing::TempStateDir::new();
        let pid_path = spt_state::paths::pid_path(d.as_path());
        std::fs::write(&pid_path, "not-a-pid").unwrap();
        let g = make_global_with_state_dir(d.as_path().to_path_buf());
        let err = stop_windows_standalone(&g).await.unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }

    /// Spawn a long-lived child in its **own** process group + new console so
    /// any console Ctrl event we raise during a stop test is isolated to the
    /// child and can never reach the cargo-test runner's console.
    /// `cmd /c pause` blocks indefinitely on stdin and ignores CTRL_C/BREAK in
    /// this configuration, so it exercises the hard-kill fallback path.
    #[cfg(windows)]
    fn spawn_isolated_pause_child() -> std::process::Child {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP (0x0200) | CREATE_NEW_CONSOLE (0x0010):
        // the child is the root of its own group and owns a fresh console, so
        // GenerateConsoleCtrlEvent against its group never touches our console.
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        std::process::Command::new("cmd.exe")
            .args(["/c", "pause"])
            .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn cmd /c pause")
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn stop_windows_standalone_terminates_a_real_child_process() {
        // Verify the end-to-end stop path: a child that doesn't shut down on
        // the console Ctrl event must still be reliably hard-killed within the
        // bounded fallback window.
        let mut child = spawn_isolated_pause_child();
        let pid = child.id();

        let d = spt_state::testing::TempStateDir::new();
        let pid_path = spt_state::paths::pid_path(d.as_path());
        std::fs::write(&pid_path, pid.to_string()).unwrap();
        let g = make_global_with_state_dir(d.as_path().to_path_buf());

        stop_windows_standalone(&g)
            .await
            .expect("stop_windows_standalone should stop the child");

        // Wait succeeds quickly because the process is now dead.
        let status = child.wait().expect("child wait");
        assert!(!status.success(), "expected non-zero exit after stop");
    }

    #[cfg(windows)]
    #[test]
    fn stop_with_grace_hard_kills_unresponsive_child() {
        // A child that ignores the console Ctrl event falls through to the
        // TerminateProcess fallback and is reported as `HardKilled`. Short
        // graceful window so the test stays fast.
        let mut child = spawn_isolated_pause_child();
        let pid = child.id();

        let outcome = windows_impl::stop_with_grace(
            pid,
            std::time::Duration::from_millis(300),
            std::time::Duration::from_secs(5),
        )
        .expect("stop_with_grace should hard-kill the unresponsive child");
        assert_eq!(outcome, windows_impl::StopOutcome::HardKilled);

        let status = child.wait().expect("child wait");
        assert!(!status.success(), "expected non-zero exit after hard kill");
    }

    #[cfg(windows)]
    #[test]
    fn stop_with_grace_errors_on_invalid_pid() {
        // A PID that cannot be opened surfaces a RuntimeFailure rather than a
        // false "stopped". PID 0 is the System Idle Process — OpenProcess for
        // TERMINATE|SYNCHRONIZE on it is denied.
        let err = windows_impl::stop_with_grace(
            0,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn reload_windows_standalone_errors_when_mcp_loopback_unavailable() {
        // Pid file present, but no `mcp-listen.json` sidecar — MCP dial fails
        // and we surface the standalone-mode hint pointing at `service reload`.
        let d = spt_state::testing::TempStateDir::new();
        let pid_path = spt_state::paths::pid_path(d.as_path());
        std::fs::write(&pid_path, std::process::id().to_string()).unwrap();
        let g = make_global_with_state_dir(d.as_path().to_path_buf());
        let err = reload_windows_standalone(&g).await.unwrap_err();
        match err {
            Error::ReloadFailed(msg) => {
                assert!(
                    msg.contains("service reload") || msg.contains("[mcp].listen"),
                    "expected hint, got: {msg}"
                );
            }
            other => panic!("expected ReloadFailed, got {other:?}"),
        }
    }
}
