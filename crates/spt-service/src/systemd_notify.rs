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
