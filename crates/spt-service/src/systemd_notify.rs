//! Real `sd_notify` support: send service-readiness / lifecycle notifications
//! to systemd over the `$NOTIFY_SOCKET` datagram protocol, with **no
//! `libsystemd` C dependency**.
//!
//! systemd's notification protocol (see `sd_notify(3)`) is simply a `AF_UNIX`
//! datagram socket whose path (or abstract name) is exported in the
//! `NOTIFY_SOCKET` environment variable. A service that runs under
//! `Type=notify` is expected to send `READY=1\n` once it has finished starting
//! up, and (optionally) `STOPPING=1\n` when it begins an orderly shutdown.
//!
//! This module writes those datagrams directly via
//! [`std::os::unix::net::UnixDatagram`] (cfg(unix)) and is a **no-op** when:
//! * `NOTIFY_SOCKET` is unset (i.e. the process was not started by systemd in
//!   notify mode, or under `Type=simple`), or
//! * the target is not unix (Windows/macOS launchd) — see the non-unix stub.
//!
//! Everything here is **best-effort**: failures are logged at `debug` and never
//! propagate, so a missing/broken notify socket can never crash the daemon.
//!
//! ## Where to call this (Wave 2 — `tunnel run` in `cli_dispatch.rs`)
//!
//! ```ignore
//! use spt_service::{sd_notify_ready, sd_notify_stopping};
//!
//! // ... after the orchestrator/supervisor is fully up and accepting work:
//! sd_notify_ready();
//!
//! // ... at the very start of the graceful-shutdown path (on SIGTERM/CTRL-C,
//! //     before tearing down forwards):
//! sd_notify_stopping();
//! ```
//!
//! These calls are safe unconditionally: when not run under `Type=notify`
//! (`NOTIFY_SOCKET` unset) they do nothing and return without error.

/// Environment variable systemd exports for the notification socket.
pub const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";

/// Environment variable systemd exports (in **microseconds**) with the watchdog
/// timeout when the unit sets `WatchdogSec=`. Its presence is what arms the
/// watchdog; the service must send `WATCHDOG=1` more often than this or systemd
/// declares it failed and restarts it. See `sd_watchdog_enabled(3)`.
pub const WATCHDOG_USEC_ENV: &str = "WATCHDOG_USEC";

/// Environment variable systemd exports naming the PID the watchdog applies to.
/// When set and it does not match our PID the watchdog is meant for another
/// process (e.g. a forked helper) and this process must **not** ping.
pub const WATCHDOG_PID_ENV: &str = "WATCHDOG_PID";

/// Recommended systemd `TimeoutStopSec` (seconds) for the shipped unit.
///
/// The daemon derives its internal aggregate graceful-shutdown deadline as
/// ~80% of this value, leaving headroom so the critical on-disk status flush
/// always completes before systemd escalates to `SIGKILL`. Keep this in sync
/// with `TimeoutStopSec=` in `packaging/systemd/spt.service{,.tmpl}`.
pub const RECOMMENDED_STOP_TIMEOUT_SECS: u64 = 45;

/// Send `READY=1` to systemd, indicating the service has finished starting and
/// is now operational. Call this once, after the orchestrator is fully up.
///
/// No-op (returns immediately) when `NOTIFY_SOCKET` is unset or on non-unix.
pub fn sd_notify_ready() {
    sd_notify("READY=1");
}

/// Send `STOPPING=1` to systemd, indicating the service has begun an orderly
/// shutdown. Call this at the start of the graceful-shutdown path.
///
/// No-op (returns immediately) when `NOTIFY_SOCKET` is unset or on non-unix.
pub fn sd_notify_stopping() {
    sd_notify("STOPPING=1");
}

/// Send `WATCHDOG=1` to systemd, resetting the hardware/software watchdog timer.
/// Sent periodically by the [`spawn_watchdog`] pinger.
///
/// No-op (returns immediately) when `NOTIFY_SOCKET` is unset or on non-unix.
pub fn sd_notify_watchdog() {
    sd_notify("WATCHDOG=1");
}

/// Handle to the background systemd watchdog pinger. Dropping it stops the
/// pinger (aborts its task).
///
/// Cross-platform so callers can hold an `Option<WatchdogHandle>`
/// unconditionally; it is only ever constructed under systemd on unix (see
/// [`spawn_watchdog`]).
#[derive(Debug)]
pub struct WatchdogHandle {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WatchdogHandle {
    fn drop(&mut self) {
        // Stop pinging as soon as the daemon lets the handle go (teardown).
        self.task.abort();
    }
}

/// Start the systemd watchdog pinger **iff** this process runs under systemd
/// with `WatchdogSec=` configured — i.e. `WATCHDOG_USEC` is set (and, when
/// present, `WATCHDOG_PID` matches our PID).
///
/// Returns `None` (a clean no-op) otherwise, including on non-systemd platforms
/// and whenever `NOTIFY_SOCKET` is unset. When `Some`, a detached tokio task
/// sends `WATCHDOG=1` every ~half the configured interval (the `sd_notify`
/// convention: ping at twice the required rate to tolerate a missed beat) until
/// the returned handle is dropped.
///
/// The pinger is deliberately self-contained: it owns only a timer and the
/// notify-socket address, sends best-effort datagrams (a wedged/unreadable
/// socket is logged and ignored, never awaited on a channel), and keeps ticking
/// independent of the rest of the process's load. It does **not** gate on any
/// subsystem's liveness — a naive always-ping is strictly safer than today's
/// never-ping, and cannot itself wedge.
///
/// Must be called from within a tokio runtime.
#[cfg(unix)]
#[must_use]
pub fn spawn_watchdog() -> Option<WatchdogHandle> {
    let interval = watchdog_ping_interval(
        std::env::var_os(WATCHDOG_USEC_ENV),
        std::env::var_os(WATCHDOG_PID_ENV),
        std::process::id(),
    )?;
    let addr = std::env::var_os(NOTIFY_SOCKET_ENV)?;
    if addr.is_empty() {
        return None;
    }
    tracing::debug!(
        target: "spt_service::sd_notify",
        interval_ms = interval.as_millis() as u64,
        "systemd watchdog armed; starting WATCHDOG=1 pinger"
    );
    Some(spawn_pinger(interval, addr))
}

/// Non-unix stub: systemd (and its watchdog) does not exist; never pings.
#[cfg(not(unix))]
#[must_use]
#[allow(clippy::missing_const_for_fn)]
pub fn spawn_watchdog() -> Option<WatchdogHandle> {
    None
}

/// Spawn the pinger task on the given cadence, sending `WATCHDOG=1` to `addr`.
///
/// Split out from [`spawn_watchdog`] so tests can drive a known interval at a
/// hermetic socket without mutating the process-global environment.
#[cfg(unix)]
fn spawn_pinger(interval: std::time::Duration, addr: std::ffi::OsString) -> WatchdogHandle {
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Ping immediately (first tick fires at once) so systemd sees liveness
        // right after arming, then hold the cadence. If a beat is delayed under
        // load, skip the missed ticks rather than bursting — a burst can't
        // improve liveness and would only add load.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            // Best-effort, non-blocking local datagram. A failing/wedged socket
            // must never stall the pinger, so the error is logged and dropped.
            if let Err(e) = send_to(&addr, "WATCHDOG=1") {
                tracing::debug!(
                    target: "spt_service::sd_notify",
                    error = %e,
                    "watchdog ping failed (best-effort, ignored)"
                );
            }
        }
    });
    WatchdogHandle { task }
}

/// Compute the `WATCHDOG=1` ping interval from systemd's exported environment.
///
/// Returns `None` when the watchdog is not enabled for THIS process:
///   * `WATCHDOG_USEC` unset, non-UTF-8, unparsable, or zero; or
///   * `WATCHDOG_PID` set and not equal to `my_pid` (the watchdog belongs to
///     another process — `sd_watchdog_enabled(3)` semantics).
///
/// Otherwise returns half the configured timeout (the `sd_notify` convention),
/// clamped to a strictly positive duration.
#[cfg(unix)]
fn watchdog_ping_interval(
    usec: Option<std::ffi::OsString>,
    pid: Option<std::ffi::OsString>,
    my_pid: u32,
) -> Option<std::time::Duration> {
    // Honor WATCHDOG_PID: when present it must name our PID, else the watchdog
    // is for a different process and we must stay silent.
    if let Some(pid) = pid {
        let pid: u32 = pid.to_str()?.trim().parse().ok()?;
        if pid != my_pid {
            return None;
        }
    }
    let usec: u64 = usec?.to_str()?.trim().parse().ok()?;
    if usec == 0 {
        return None;
    }
    // Ping at half the timeout; guarantee a non-zero interval for tiny values.
    Some(std::time::Duration::from_micros((usec / 2).max(1)))
}

/// Send an arbitrary single-line notification `state` (e.g. `"READY=1"`,
/// `"STOPPING=1"`, `"RELOADING=1"`, `"STATUS=..."`) to systemd's
/// `$NOTIFY_SOCKET`.
///
/// A trailing newline is appended if `state` does not already end with one.
/// Best-effort: any failure (socket missing, send error) is logged at `debug`
/// and swallowed.
///
/// On non-unix targets this is a no-op.
#[cfg(unix)]
pub fn sd_notify(state: &str) {
    match notify_inner(state) {
        Ok(true) => tracing::debug!(target: "spt_service::sd_notify", state, "sent sd_notify"),
        Ok(false) => {
            // NOTIFY_SOCKET unset → not run under Type=notify. Expected/normal.
            tracing::trace!(
                target: "spt_service::sd_notify",
                "NOTIFY_SOCKET unset; skipping sd_notify"
            );
        }
        Err(e) => tracing::debug!(
            target: "spt_service::sd_notify",
            error = %e,
            state,
            "sd_notify failed (best-effort, ignored)"
        ),
    }
}

/// Non-unix stub: systemd does not exist; do nothing.
#[cfg(not(unix))]
#[allow(clippy::missing_const_for_fn)]
pub fn sd_notify(_state: &str) {}

/// Core sender. Returns `Ok(true)` if a datagram was sent, `Ok(false)` if
/// `NOTIFY_SOCKET` was unset (a legitimate no-op), or `Err` on a real I/O
/// failure. Kept separate so it can be unit-tested against a real socket.
#[cfg(unix)]
fn notify_inner(state: &str) -> std::io::Result<bool> {
    resolve_and_send(std::env::var_os(NOTIFY_SOCKET_ENV), state)
}

/// Send to `addr` if it names a non-empty socket, else a clean no-op.
///
/// Split out from [`notify_inner`] so it can be unit-tested without mutating
/// the process-global `NOTIFY_SOCKET` environment variable.
#[cfg(unix)]
fn resolve_and_send(addr: Option<std::ffi::OsString>, state: &str) -> std::io::Result<bool> {
    let Some(addr) = addr else {
        return Ok(false);
    };
    // An empty NOTIFY_SOCKET is treated the same as unset.
    if addr.is_empty() {
        return Ok(false);
    }
    send_to(&addr, state)?;
    Ok(true)
}

/// Send `state` (newline-terminated) to the notify socket named by `addr`.
///
/// `addr` is either:
/// * an absolute filesystem path (`/run/systemd/notify`), or
/// * an abstract-namespace name, denoted by a leading `@` (Linux) which maps to
///   a NUL-prefixed abstract address.
///
/// We bind an unnamed autobind socket and `send_to` the target so we do not
/// need to create any file ourselves.
#[cfg(unix)]
fn send_to(addr: &std::ffi::OsStr, state: &str) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixDatagram;

    // Build the datagram payload (newline-terminated, per the protocol).
    let mut payload = state.as_bytes().to_vec();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }

    // Unbound socket; the kernel autobinds an address on first send.
    let sock = UnixDatagram::unbound()?;

    let bytes = addr.as_bytes();
    if bytes.first() == Some(&b'@') {
        // Abstract namespace: systemd uses a leading '@' in NOTIFY_SOCKET to
        // mean the Linux abstract socket namespace, where the address starts
        // with a NUL byte and the '@' is the placeholder for that NUL.
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;
            // Strip the leading '@'; the remainder is the abstract name.
            let name = &bytes[1..];
            let sock_addr = SocketAddr::from_abstract_name(name)?;
            sock.send_to_addr(&payload, &sock_addr)?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Abstract sockets are Linux-only; nothing we can do elsewhere.
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "abstract NOTIFY_SOCKET is only supported on Linux",
            ));
        }
    }

    // Path-based socket.
    let path = std::path::Path::new(addr);
    sock.send_to(&payload, path)?;
    Ok(())
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    /// On non-unix targets every entry point is a no-op that must not panic.
    #[test]
    fn helpers_are_noops() {
        sd_notify_ready();
        sd_notify_stopping();
        sd_notify("READY=1");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::net::UnixDatagram;

    /// `None` address (i.e. `NOTIFY_SOCKET` unset) → clean no-op, `Ok(false)`.
    ///
    /// Tested via [`resolve_and_send`] so we never mutate the process-global
    /// `NOTIFY_SOCKET` env var (which is `unsafe` and racy across tests).
    #[test]
    fn noop_when_socket_unset() {
        assert!(!resolve_and_send(None, "READY=1").unwrap());
        // The public wrappers also read the real env; under `cargo test` it is
        // unset, so they must be no-ops that never panic.
        sd_notify_ready();
        sd_notify_stopping();
        sd_notify("STATUS=test");
    }

    /// An empty `NOTIFY_SOCKET` is treated the same as unset.
    #[test]
    fn noop_when_socket_empty() {
        assert!(!resolve_and_send(Some(OsString::new()), "READY=1").unwrap());
    }

    /// End-to-end: bind a real path-based datagram listener, hand its path to
    /// `resolve_and_send`, and confirm `READY=1\n` is delivered verbatim.
    #[test]
    fn ready_datagram_delivered_to_path_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let sent = resolve_and_send(Some(sock_path.into_os_string()), "READY=1").unwrap();
        assert!(sent, "expected a datagram to be sent");

        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\n");
    }

    // ---- F-S3: systemd watchdog support ------------------------------------

    /// Unset `WATCHDOG_USEC` → watchdog is not armed for us.
    #[test]
    fn watchdog_interval_none_when_usec_unset() {
        assert!(watchdog_ping_interval(None, None, 1000).is_none());
    }

    /// `WATCHDOG_USEC` present, no PID pin → ping at half the timeout.
    #[test]
    fn watchdog_interval_is_half_of_usec() {
        let d = watchdog_ping_interval(Some(OsString::from("30000000")), None, 1000).unwrap();
        assert_eq!(d, std::time::Duration::from_secs(15));
    }

    /// A zero / unparsable timeout is treated as "not armed".
    #[test]
    fn watchdog_interval_none_for_zero_or_garbage() {
        assert!(watchdog_ping_interval(Some(OsString::from("0")), None, 7).is_none());
        assert!(watchdog_ping_interval(Some(OsString::from("nope")), None, 7).is_none());
    }

    /// `WATCHDOG_PID` matching our PID arms us; a mismatch does not.
    #[test]
    fn watchdog_interval_honors_pid_pin() {
        let armed = watchdog_ping_interval(
            Some(OsString::from("10000000")),
            Some(OsString::from("4242")),
            4242,
        );
        assert_eq!(armed, Some(std::time::Duration::from_secs(5)));

        let other = watchdog_ping_interval(
            Some(OsString::from("10000000")),
            Some(OsString::from("4242")),
            9999,
        );
        assert!(other.is_none());
    }

    /// The pinger sends `WATCHDOG=1` on the expected cadence: with a 40ms
    /// interval we must observe at least three datagrams within a short window
    /// (immediate first tick + two more). Hermetic — no env mutation.
    // Multi-thread runtime: the test blocks on the std `UnixDatagram::recv`
    // below, which on a current-thread runtime would starve the spawned pinger
    // task (it would never run → no datagram → timeout). A second worker lets
    // the pinger tick while the test thread blocks on recv.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pinger_sends_watchdog_on_cadence() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("wd.sock");
        let listener = UnixDatagram::bind(&sock_path).unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let handle = spawn_pinger(
            std::time::Duration::from_millis(40),
            sock_path.clone().into_os_string(),
        );

        let mut seen = 0;
        let mut buf = [0u8; 64];
        for _ in 0..3 {
            let n = listener.recv(&mut buf).expect("watchdog datagram");
            assert_eq!(&buf[..n], b"WATCHDOG=1\n");
            seen += 1;
        }
        assert_eq!(seen, 3, "expected three cadence pings");
        drop(handle); // aborts the pinger task
    }

    /// End-to-end via the public [`spawn_watchdog`], exercising the env-driven
    /// arming path. Mutates process-global env, so it serialises on the crate
    /// env lock. Holds the guard across `.await` (the socket recv) — allowed
    /// because the lock only guards env, not the awaited future.
    // Multi-thread runtime (see `pinger_sends_watchdog_on_cadence`): the blocking
    // std `recv` below must not starve the spawned pinger task.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn spawn_watchdog_arms_from_env_and_noops_when_unset() {
        let _env = crate::tests::lock_env();

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("wd-env.sock");
        let listener = UnixDatagram::bind(&sock_path).unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        // Snapshot + set the arming env.
        let prev_notify = std::env::var_os(NOTIFY_SOCKET_ENV);
        let prev_usec = std::env::var_os(WATCHDOG_USEC_ENV);
        let prev_pid = std::env::var_os(WATCHDOG_PID_ENV);
        std::env::set_var(NOTIFY_SOCKET_ENV, &sock_path);
        std::env::set_var(WATCHDOG_USEC_ENV, "40000"); // 40ms → 20ms ping
        std::env::remove_var(WATCHDOG_PID_ENV);

        let handle = spawn_watchdog().expect("watchdog should arm from env");
        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).expect("watchdog datagram");
        assert_eq!(&buf[..n], b"WATCHDOG=1\n");
        drop(handle);

        // Unset → no-op (returns None).
        std::env::remove_var(WATCHDOG_USEC_ENV);
        assert!(
            spawn_watchdog().is_none(),
            "watchdog must be a no-op when WATCHDOG_USEC is unset"
        );

        // Restore prior env.
        match prev_notify {
            Some(v) => std::env::set_var(NOTIFY_SOCKET_ENV, v),
            None => std::env::remove_var(NOTIFY_SOCKET_ENV),
        }
        match prev_usec {
            Some(v) => std::env::set_var(WATCHDOG_USEC_ENV, v),
            None => std::env::remove_var(WATCHDOG_USEC_ENV),
        }
        if let Some(v) = prev_pid {
            std::env::set_var(WATCHDOG_PID_ENV, v);
        }
    }

    /// A state string already ending in `\n` is not double-terminated.
    #[test]
    fn payload_not_double_newline_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        send_to(sock_path.as_os_str(), "STOPPING=1\n").unwrap();

        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1\n");
    }
}
