//! `spt kill` — terminate every running `spt` instance on this host.
//!
//! Cross-platform: enumerates processes via `sysinfo`, filters down to
//! ones whose executable basename matches `spt` (or the operator-supplied
//! override), then signals each one via the existing platform-specific
//! terminate path:
//!
//! * Unix: `nix::sys::signal::kill(pid, SIGTERM)` (or `SIGKILL` when
//!   `--force`).
//! * Windows: `OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE)` +
//!   `TerminateProcess` + `WaitForSingleObject(timeout)`. The hard-kill
//!   path is identical on Windows — `TerminateProcess` is unconditional.
//!
//! The current process is skipped by default so a user running
//! `spt kill` in a still-active session doesn't terminate the shell that
//! invoked them.
//!
//! See [`packaging/cli`] for the user-facing flags; the [`KillOpts`]
//! struct mirrors them 1:1.

use std::path::Path;
use std::time::Duration;

use spt_cli::groups;
use spt_core::{Error, Result};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

/// Default executable basename matched when no `--name` override is set.
#[cfg(unix)]
const DEFAULT_NAME: &str = "spt";
#[cfg(windows)]
const DEFAULT_NAME: &str = "spt.exe";

/// Outcome of one process-termination attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KillOutcome {
    pid: u32,
    /// Best-effort executable path (may be empty if the OS refused access).
    exe: String,
    /// `Ok(())` on success, `Err(message)` on a per-process failure that
    /// did not abort the overall command.
    result: std::result::Result<(), String>,
}

/// `spt kill` entry point.
///
/// Walks every visible process, filters by executable basename, then
/// terminates the matches. Returns the per-process outcomes for the
/// caller to render. Errors out only on enumeration failures or when
/// every targeted termination fails; partial successes return `Ok(_)`
/// so a single permission-denied process doesn't mask a successful
/// run on the others.
pub async fn run(opts: groups::kill::KillCmd) -> Result<()> {
    let self_pid = std::process::id();
    let pattern = opts
        .name
        .clone()
        .unwrap_or_else(|| DEFAULT_NAME.to_string());

    // sysinfo refresh: ask only for what we need — exe path + name.
    // `RefreshKind::nothing()` keeps memory/cpu/io off the table so the
    // walk is fast and we don't pay for snapshots we won't read.
    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_processes(ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always)),
    );
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always),
    );

    let matches = collect_matches(&sys, &pattern, self_pid, opts.include_self);
    if matches.is_empty() {
        println!(
            "no running `{}` processes found{}",
            pattern,
            if opts.include_self {
                ""
            } else {
                " (self excluded)"
            }
        );
        return Ok(());
    }

    if opts.dry_run {
        println!("dry-run: would terminate {} process(es):", matches.len());
        for (pid, exe) in &matches {
            println!("  pid {pid:>7}  {exe}");
        }
        return Ok(());
    }

    let timeout: Duration = opts.timeout.into();
    let outcomes: Vec<KillOutcome> = matches
        .into_iter()
        .map(|(pid, exe)| KillOutcome {
            pid,
            exe: exe.clone(),
            result: terminate(pid, opts.force, timeout).map_err(|e| e.to_string()),
        })
        .collect();

    let (ok, err): (Vec<_>, Vec<_>) = outcomes.iter().partition(|o| o.result.is_ok());
    for o in &ok {
        println!("killed pid {:>7}  {}", o.pid, o.exe);
    }
    for o in &err {
        let why = o.result.as_ref().err().map(String::as_str).unwrap_or("?");
        eprintln!("FAILED  pid {:>7}  {}  ({why})", o.pid, o.exe);
    }
    if ok.is_empty() && !err.is_empty() {
        return Err(Error::RuntimeFailure(format!(
            "spt kill: every targeted process failed to terminate ({} attempt(s))",
            err.len()
        )));
    }
    Ok(())
}

/// Find every visible process whose executable basename (case-insensitive)
/// contains `pattern`. Returns `(pid, exe-as-string)` pairs.
fn collect_matches(
    sys: &System,
    pattern: &str,
    self_pid: u32,
    include_self: bool,
) -> Vec<(u32, String)> {
    let needle = pattern.to_ascii_lowercase();
    let mut out: Vec<(u32, String)> = sys
        .processes()
        .iter()
        .filter_map(|(pid, p)| {
            // Some platforms refuse to expose `exe` for other-user processes
            // (Windows w/o admin, hardened Linux). Fall back to `name()`,
            // which sysinfo synthesises from `/proc/<pid>/comm` (Linux) /
            // ToolHelp32 (Windows) / sysctl kinfo (macOS).
            let exe_path = p.exe().map(Path::to_path_buf);
            let basename = exe_path
                .as_deref()
                .and_then(|p| p.file_name())
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| p.name().to_string_lossy().to_string());

            if !basename.to_ascii_lowercase().contains(&needle) {
                return None;
            }
            let pid_u32 = pid.as_u32();
            if !include_self && pid_u32 == self_pid {
                return None;
            }
            let display = exe_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or(basename);
            Some((pid_u32, display))
        })
        .collect();
    out.sort_by_key(|(pid, _)| *pid);
    out
}

/// Send a graceful (or forced) termination to one PID. Returns `Ok` on the
/// signal being delivered; non-fatal per-process errors flow back so the
/// caller can keep going against the remaining matches.
fn terminate(pid: u32, force: bool, timeout: Duration) -> Result<()> {
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        let sig = if force {
            Signal::SIGKILL
        } else {
            Signal::SIGTERM
        };
        let pid_i32 = i32::try_from(pid).map_err(|_| {
            Error::RuntimeFailure(format!("pid {pid} does not fit in i32 (POSIX kill)"))
        })?;
        kill(Pid::from_raw(pid_i32), sig)
            .map_err(|e| Error::RuntimeFailure(format!("kill({pid}, {sig:?}): {e}")))?;
        // Best-effort wait: poll `/proc/<pid>` until it disappears or
        // `timeout` elapses. We do NOT escalate to SIGKILL automatically —
        // operators get that with `--force` explicitly.
        wait_for_exit_unix(pid, timeout);
        Ok(())
    }
    #[cfg(windows)]
    {
        // The existing windows_impl::terminate_with_grace path used by
        // `tunnel stop standalone` does exactly what we need: OpenProcess
        // + TerminateProcess + WaitForSingleObject. `--force` has no
        // distinct mode on Windows — TerminateProcess is unconditional.
        let _ = force;
        windows_impl::terminate_with_grace(pid, timeout)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, force, timeout);
        Err(Error::UnsupportedPlatform(
            "spt kill is not implemented for this platform".into(),
        ))
    }
}

#[cfg(unix)]
fn wait_for_exit_unix(pid: u32, timeout: Duration) {
    use std::thread::sleep;
    use std::time::Instant;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        // `kill -0` probes existence without sending a signal. ESRCH means
        // the process is gone (success). EPERM means it exists but we
        // can't signal it (treat as still running).
        let probe = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            None::<nix::sys::signal::Signal>,
        );
        if matches!(probe, Err(nix::errno::Errno::ESRCH)) {
            return;
        }
        sleep(Duration::from_millis(50));
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::time::Duration;

    use spt_core::{Error, Result};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

    /// `OpenProcess` + `TerminateProcess` + `WaitForSingleObject(timeout)`.
    /// Mirrors `crate::cli::tunnel_ops::windows_impl::terminate_with_grace`
    /// — the two could share a `crate::win::` module if a third caller
    /// ever shows up. Duplicated here for now because `tunnel_ops` is
    /// behind `#[cfg(windows)]` and exporting it through that module
    /// would muddy its public surface.
    pub(super) fn terminate_with_grace(pid: u32, grace: Duration) -> Result<()> {
        let handle: HANDLE =
            // SAFETY: PoD inputs; OpenProcess returns a HANDLE we own and
            // close before returning. Invalid handles are checked below.
            unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) }
                .map_err(|e| Error::RuntimeFailure(format!("OpenProcess({pid}): {e}")))?;

        if handle.is_invalid() {
            return Err(Error::RuntimeFailure(format!(
                "OpenProcess({pid}) returned an invalid handle"
            )));
        }

        let result = (|| -> Result<()> {
            // SAFETY: handle is valid (checked above).
            unsafe { TerminateProcess(handle, 1) }
                .map_err(|e| Error::RuntimeFailure(format!("TerminateProcess({pid}): {e}")))?;
            let ms = u32::try_from(grace.as_millis()).unwrap_or(u32::MAX);
            // SAFETY: handle is valid; WaitForSingleObject only reads.
            let wait = unsafe { WaitForSingleObject(handle, ms) };
            if wait == WAIT_OBJECT_0 {
                Ok(())
            } else if wait == WAIT_TIMEOUT {
                Err(Error::RuntimeFailure(format!(
                    "process {pid} did not exit within {ms}ms after TerminateProcess"
                )))
            } else {
                Err(Error::RuntimeFailure(format!(
                    "WaitForSingleObject returned 0x{:x}",
                    wait.0
                )))
            }
        })();

        // SAFETY: handle came from a successful OpenProcess; close once.
        let _ = unsafe { CloseHandle(handle) };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke: the enumerator must always find the *current* test process
    /// when `include_self = true` and the pattern matches its exe name.
    #[test]
    fn enumeration_finds_current_process_with_include_self() {
        let self_pid = std::process::id();
        let exe = std::env::current_exe().expect("current_exe");
        let basename = exe
            .file_name()
            .and_then(|s| s.to_str())
            .expect("non-empty basename");
        let mut sys = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always)),
        );
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always),
        );
        let hits = collect_matches(&sys, basename, self_pid, /* include_self */ true);
        assert!(
            hits.iter().any(|(pid, _)| *pid == self_pid),
            "self_pid {self_pid} (basename `{basename}`) must be in the hit list"
        );
    }

    /// Self must be excluded when `include_self = false`.
    #[test]
    fn enumeration_excludes_current_process_by_default() {
        let self_pid = std::process::id();
        let exe = std::env::current_exe().expect("current_exe");
        let basename = exe
            .file_name()
            .and_then(|s| s.to_str())
            .expect("non-empty basename");
        let mut sys = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always)),
        );
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always),
        );
        let hits = collect_matches(&sys, basename, self_pid, /* include_self */ false);
        assert!(
            !hits.iter().any(|(pid, _)| *pid == self_pid),
            "self_pid {self_pid} must NOT appear when include_self=false"
        );
    }

    /// A pattern that matches nothing returns an empty list — *not* an
    /// error. The dispatch prints "no processes found" and exits clean.
    #[test]
    fn enumeration_no_match_returns_empty() {
        let mut sys = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always)),
        );
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always),
        );
        let hits = collect_matches(
            &sys,
            "no-process-named-this-9d2c8c54-3f3a-44e7-86c5-bfb50d4b09e3",
            std::process::id(),
            true,
        );
        assert!(hits.is_empty());
    }

    /// End-to-end: spawn a sacrificial child process, kill it via `run()`,
    /// confirm exit. Uses a platform-appropriate "sleep" sentinel: `sleep`
    /// on Unix, `cmd /c ping -n 60 127.0.0.1` on Windows (no /timeout
    /// without a console).
    #[tokio::test]
    async fn end_to_end_kills_a_spawned_child() {
        // Silence the child's stdio so the ping/sleep output doesn't bleed
        // into the test runner's transcript.
        use std::process::Stdio;
        #[cfg(unix)]
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        #[cfg(windows)]
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping", "-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cmd ping");
        let child_pid = child.id();

        // Verify the child is alive before we go knocking.
        assert!(
            matches!(child.try_wait(), Ok(None)),
            "child should be alive"
        );

        let exe = std::env::current_exe().unwrap();
        let basename = exe.file_name().unwrap().to_str().unwrap().to_string();
        // Aim at the sacrificial process, not self.
        #[cfg(unix)]
        let pattern = "sleep".to_string();
        #[cfg(windows)]
        let pattern = "cmd.exe".to_string();
        let _ = basename; // silence unused on the matched cfg

        let opts = groups::kill::KillCmd {
            force: true,
            include_self: false,
            dry_run: false,
            name: Some(pattern),
            timeout: humantime::Duration::from(Duration::from_secs(3)),
        };
        run(opts).await.expect("kill run");

        // Give the OS a moment to reap, then confirm exit.
        for _ in 0..30 {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Be defensive — clean up if the test failed for other reasons so
        // we don't leak a sleep/ping into the runner.
        let _ = child.kill();
        panic!("child {child_pid} did not exit after spt kill");
    }
}
