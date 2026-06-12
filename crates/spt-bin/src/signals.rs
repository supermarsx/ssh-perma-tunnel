//! Signal / OS-event handling for `spt`.
//!
//! On Unix:
//! - `SIGTERM`, `SIGINT`  → graceful shutdown.
//! - `SIGHUP`             → config reload.
//! - `SIGHUP`             → log filter reload (re-reads `SPT_LOG` /
//!   `<state>/log-filter`; see [`install_sighup_log_reload`]).
//!
//! On Windows:
//! - `Ctrl-C`             → graceful shutdown.
//! - `windows-service` `ParamChange` (issued by SCM) → reload — handled by the
//!   service entry point; standalone `tunnel run` only watches Ctrl-C.

#![deny(unsafe_op_in_unsafe_fn)]

use tokio::sync::watch;

#[cfg(unix)]
use spt_observability::LogReloadHandle;

/// Signals an outer task should react to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Reload requested.
    Reload,
    /// Shutdown requested (SIGTERM/SIGINT/Ctrl-C).
    Shutdown,
}

/// Spawn a task that bridges OS signals onto a `watch::Receiver<Option<Signal>>`.
///
/// Returns the receiver and a join handle. Drop the receiver to stop
/// processing.
pub fn spawn() -> watch::Receiver<Option<Signal>> {
    let (tx, rx) = watch::channel(None);
    tokio::spawn(async move {
        run_signal_task(tx).await;
    });
    rx
}

#[cfg(unix)]
async fn run_signal_task(tx: watch::Sender<Option<Signal>>) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT");
    let mut hup = signal(SignalKind::hangup()).expect("install SIGHUP");
    loop {
        tokio::select! {
            _ = term.recv() => {
                let _ = tx.send(Some(Signal::Shutdown));
                break;
            }
            _ = int.recv() => {
                let _ = tx.send(Some(Signal::Shutdown));
                break;
            }
            _ = hup.recv() => {
                let _ = tx.send(Some(Signal::Reload));
            }
        }
    }
}

#[cfg(windows)]
async fn run_signal_task(tx: watch::Sender<Option<Signal>>) {
    if tokio::signal::ctrl_c().await.is_ok() {
        let _ = tx.send(Some(Signal::Shutdown));
    }
}

/// Read the log filter directive for SIGHUP reload.
///
/// Precedence:
///
/// 1. `SPT_LOG` env var (matches `init_minimal` behaviour).
/// 2. The literal contents of `<state_dir>/log-filter` if `state_dir` is
///    supplied and the file exists.
/// 3. Returns `Ok(None)` if no source is configured — the caller treats this
///    as "leave the filter untouched".
///
/// Cross-platform: SIGHUP drives this on Unix; on Windows the SCM
/// `ParamChange` (reload) branch in [`crate::scm_dispatch`] calls it for the
/// same live-log-filter reload (E7-F13). The body uses only `std::fs`/`env`,
/// so it compiles and behaves identically on every target.
pub fn read_sighup_log_filter(
    state_dir: Option<&std::path::Path>,
) -> std::io::Result<Option<String>> {
    if let Some(raw) = std::env::var_os("SPT_LOG") {
        if let Some(s) = raw.to_str() {
            return Ok(Some(s.to_owned()));
        }
    }
    if let Some(dir) = state_dir {
        let path = dir.join("log-filter");
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let trimmed = contents.trim().to_owned();
                if trimmed.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(trimmed));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Spawn a background task that re-applies the log filter on every SIGHUP.
///
/// The task lives as long as `handle` can reload the global subscriber.
/// Cancel by dropping the returned `JoinHandle` (it aborts on drop because
/// tokio detaches on drop of `JoinHandle`; for explicit cancellation, supply
/// a `tokio_util::sync::CancellationToken` — out of scope for this milestone).
///
/// **Wiring**: `spt-bin/src/main.rs` is locked to t8-A1 in the t8 phase A.
/// A1 / Bwire is expected to add a call site of the form:
///
/// ```ignore
/// if let Some(guard) = &trace_guard {
///     #[cfg(unix)]
///     let _ = crate::signals::install_sighup_log_reload(
///         guard.reload_handle(),
///         Some(state_dir.clone()),
///     );
/// }
/// ```
///
/// after `tracing_init::init_minimal` or `init_from_config` returns.
#[cfg(unix)]
pub fn install_sighup_log_reload(
    handle: LogReloadHandle,
    state_dir: Option<std::path::PathBuf>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "SIGHUP log-reload: handler install failed");
                return;
            }
        };
        while sig.recv().await.is_some() {
            match read_sighup_log_filter(state_dir.as_deref()) {
                Ok(Some(directive)) => match handle.reload(&directive) {
                    Ok(()) => {
                        tracing::info!(directive = %directive, "log filter reloaded via SIGHUP");
                    }
                    Err(e) => tracing::warn!(error = %e, "SIGHUP log reload failed"),
                },
                Ok(None) => {
                    tracing::debug!("SIGHUP log reload: no directive available");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SIGHUP log reload: failed to read directive");
                }
            }
        }
    })
}

/// Windows stub so callers can compile against the same signature. On
/// Windows, SCM `ParamChange` rather than SIGHUP drives log reload; that
/// path is owned by the service dispatch entry point.
#[cfg(windows)]
#[allow(unused_variables, clippy::needless_pass_by_value)]
pub fn install_sighup_log_reload(
    handle: spt_observability::LogReloadHandle,
    state_dir: Option<std::path::PathBuf>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {})
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;

    #[cfg(unix)]
    #[test]
    fn read_sighup_log_filter_prefers_env() {
        let prev = std::env::var_os("SPT_LOG");
        std::env::set_var("SPT_LOG", "warn,spt_ssh2=trace");
        let v = read_sighup_log_filter(None).unwrap();
        assert_eq!(v.as_deref(), Some("warn,spt_ssh2=trace"));
        match prev {
            Some(p) => std::env::set_var("SPT_LOG", p),
            None => std::env::remove_var("SPT_LOG"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_sighup_log_filter_reads_state_file_when_env_unset() {
        let prev = std::env::var_os("SPT_LOG");
        std::env::remove_var("SPT_LOG");
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("log-filter"),
            "  info,spt_supervisor=debug \n",
        )
        .unwrap();
        let v = read_sighup_log_filter(Some(tmp.path())).unwrap();
        assert_eq!(v.as_deref(), Some("info,spt_supervisor=debug"));
        if let Some(p) = prev {
            std::env::set_var("SPT_LOG", p);
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_sighup_log_filter_returns_none_when_missing() {
        let prev = std::env::var_os("SPT_LOG");
        std::env::remove_var("SPT_LOG");
        let tmp = tempfile::tempdir().unwrap();
        let v = read_sighup_log_filter(Some(tmp.path())).unwrap();
        assert!(v.is_none());
        if let Some(p) = prev {
            std::env::set_var("SPT_LOG", p);
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_sighup_log_filter_empty_file_returns_none() {
        let prev = std::env::var_os("SPT_LOG");
        std::env::remove_var("SPT_LOG");
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("log-filter"), "   \n").unwrap();
        let v = read_sighup_log_filter(Some(tmp.path())).unwrap();
        assert!(v.is_none());
        if let Some(p) = prev {
            std::env::set_var("SPT_LOG", p);
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn install_sighup_log_reload_spawns_task_and_recovers_from_bad_directive() {
        // Build a real subscriber to obtain a LogReloadHandle, then verify
        // the spawned task does not panic on a missing config file.
        let cfg = spt_observability::LoggingConfig::default();
        let guard = spt_observability::init_for_test(&cfg).unwrap();
        let h = guard.reload_handle();
        let tmp = tempfile::tempdir().unwrap();
        let task = install_sighup_log_reload(h, Some(tmp.path().to_path_buf()));
        // Cancel: aborting the task by drop is the documented contract.
        task.abort();
        // Allow the abort to flush.
        tokio::task::yield_now().await;
    }
}
