//! TCP socket options + listener construction (spec §17 runtime sockets).

use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::net::TcpListener;

use spt_core::error::{Error, Result};

/// TCP socket options applied to listeners and dialed sockets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpOptions {
    /// Enable `TCP_NODELAY` (Nagle off).
    pub nodelay: bool,
    /// Idle time before keepalive probes (Linux/macOS/Windows).
    pub keepalive_idle: Option<Duration>,
    /// Interval between keepalive probes (Linux/macOS).
    pub keepalive_interval: Option<Duration>,
    /// Maximum keepalive probes (Linux only).
    pub keepalive_retries: Option<u32>,
    /// Set `IP_FREEBIND` so the socket can bind to a non-local address (Linux only).
    pub freebind: bool,
    /// For an IPv6 socket, allow IPv4 connections too (`IPV6_V6ONLY = 0`).
    pub dual_stack_v6: bool,
}

impl TcpOptions {
    /// Convenience preset: production defaults (nodelay, ~30s keepalives).
    #[must_use]
    pub fn production() -> Self {
        Self {
            nodelay: true,
            keepalive_idle: Some(Duration::from_secs(30)),
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_retries: Some(4),
            freebind: false,
            dual_stack_v6: false,
        }
    }
}

/// Apply the configured options to an already-created socket.
///
/// Best-effort: options not supported on the running OS are silently ignored
/// (e.g. `IP_FREEBIND` on Windows). Hard failures bubble up.
pub fn apply(socket: &Socket, opts: &TcpOptions) -> Result<()> {
    // t9-Bump: socket2 0.6 renamed `set_nodelay` → `set_tcp_nodelay` so it
    // does not shadow `std::net::TcpStream::set_nodelay` (which has a
    // different signature). Same behaviour, new name.
    socket
        .set_tcp_nodelay(opts.nodelay)
        .map_err(|e| Error::RuntimeFailure(format!("set TCP_NODELAY: {e}")))?;

    let mut keepalive = TcpKeepalive::new();
    let mut want_keepalive = false;
    if let Some(idle) = opts.keepalive_idle {
        keepalive = keepalive.with_time(idle);
        want_keepalive = true;
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "android",
    ))]
    if let Some(interval) = opts.keepalive_interval {
        keepalive = keepalive.with_interval(interval);
        want_keepalive = true;
    }
    #[cfg(target_os = "linux")]
    if let Some(retries) = opts.keepalive_retries {
        keepalive = keepalive.with_retries(retries);
        want_keepalive = true;
    }
    // Suppress unused-warning when feature gates above don't fire.
    let _ = (&opts.keepalive_interval, &opts.keepalive_retries);

    if want_keepalive {
        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| Error::RuntimeFailure(format!("set keepalive: {e}")))?;
    }

    #[cfg(target_os = "linux")]
    if opts.freebind {
        socket
            .set_freebind_v4(true)
            .map_err(|e| Error::RuntimeFailure(format!("set IP_FREEBIND: {e}")))?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = opts.freebind;

    // IPV6_V6ONLY is only valid on IPv6 sockets; setting it on a v4 socket
    // returns an error. The caller must invoke `apply_v6_only` separately if
    // their socket is IPv6.
    Ok(())
}

/// Apply `IPV6_V6ONLY` based on `dual_stack_v6` (IPv6 sockets only).
pub fn apply_v6_only(socket: &Socket, dual_stack_v6: bool) -> Result<()> {
    socket
        .set_only_v6(!dual_stack_v6)
        .map_err(|e| Error::RuntimeFailure(format!("set IPV6_V6ONLY: {e}")))
}

/// Create a Tokio [`TcpListener`] bound to `addr` with `opts` applied.
pub fn bind_tcp(addr: SocketAddr, opts: &TcpOptions) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| Error::RuntimeFailure(format!("create socket: {e}")))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| Error::RuntimeFailure(format!("set SO_REUSEADDR: {e}")))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| Error::RuntimeFailure(format!("set non-blocking: {e}")))?;

    apply(&socket, opts)?;
    if addr.is_ipv6() {
        apply_v6_only(&socket, opts.dual_stack_v6)?;
    }

    socket
        .bind(&addr.into())
        .map_err(|e| Error::LocalBindFailed {
            address: addr.to_string(),
            reason: e.to_string(),
        })?;
    // Default backlog 1024; OS may clamp.
    socket.listen(1024).map_err(|e| Error::LocalBindFailed {
        address: addr.to_string(),
        reason: format!("listen: {e}"),
    })?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
        .map_err(|e| Error::RuntimeFailure(format!("tokio listener: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test(flavor = "current_thread")]
    async fn bind_tcp_to_ephemeral_loopback() {
        let opts = TcpOptions::production();
        let listener =
            bind_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &opts).unwrap();
        let local = listener.local_addr().unwrap();
        assert!(local.ip().is_loopback());
        assert!(local.port() != 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nodelay_round_trips_via_socket2() {
        let opts = TcpOptions {
            nodelay: true,
            ..TcpOptions::default()
        };
        let listener =
            bind_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &opts).unwrap();
        // Use std fd to inspect with socket2 (nodelay is on the listener itself).
        let std = listener.into_std().unwrap();
        std.set_nonblocking(false).unwrap();
        let s = Socket::from(std);
        assert!(s.tcp_nodelay().unwrap());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dual_stack_v6_when_requested() {
        let opts = TcpOptions {
            dual_stack_v6: true,
            ..TcpOptions::default()
        };
        let listener = bind_tcp(
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0),
            &opts,
        )
        .unwrap();
        let std = listener.into_std().unwrap();
        std.set_nonblocking(false).unwrap();
        let s = Socket::from(std);
        // only_v6 should be false when dual-stack is requested.
        assert!(!s.only_v6().unwrap());
    }

    #[test]
    fn apply_supports_minimal_opts() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        apply(&socket, &TcpOptions::default()).unwrap();
        apply(&socket, &TcpOptions::production()).unwrap();
    }
}
