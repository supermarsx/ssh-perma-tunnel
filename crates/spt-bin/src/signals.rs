//! Signal / OS-event handling for `spt`.
//!
//! On Unix:
//! - `SIGTERM`, `SIGINT`  → graceful shutdown.
//! - `SIGHUP`             → config reload.
//!
//! On Windows:
//! - `Ctrl-C`             → graceful shutdown.
//! - `windows-service` `ParamChange` (issued by SCM) → reload — handled by the
//!   service entry point; standalone `tunnel run` only watches Ctrl-C.

use tokio::sync::watch;

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
