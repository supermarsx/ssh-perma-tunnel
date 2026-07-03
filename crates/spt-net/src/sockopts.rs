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
    /// Interval between keepalive probes (Linux/macOS/Windows/BSD).
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

    /// Build socket options from config-derived [`OffloadOptions`], starting
    /// from `base` (typically [`TcpOptions::default`]). This is the wiring
    /// seam for the `[network.offload]` config table (Wave 6): spt-bin maps
    /// `spt_config::NetworkOffload` into an [`OffloadOptions`] and calls this to
    /// derive the [`TcpOptions`] it then applies to the sockets it controls.
    ///
    /// Returns the resulting options plus the list of requested-but-unsupported
    /// offload flag names — flags set to `Some(true)` that this crate has no
    /// mechanism to honor (`tcp_fast_open`, `reuse_port`, `io_uring`,
    /// `zerocopy`, `sendfile`, `checksum_offload`, `large_send_offload`). The
    /// caller is expected to emit a single WARN for those rather than silently
    /// ignoring an operator's request.
    ///
    /// Mapping:
    /// * `tcp_nodelay` → [`TcpOptions::nodelay`].
    /// * `socket_keepalive = Some(true)` → enable keepalive, filling any unset
    ///   probe timing with production defaults (30s idle / 15s interval / 4
    ///   retries).
    /// * `socket_keepalive = Some(false)` → clear all keepalive fields.
    /// * an unset (`None`) flag preserves whatever `base` had (so an absent
    ///   `[network.offload]` is behavior-preserving).
    #[must_use]
    pub fn from_offload(base: Self, off: &OffloadOptions) -> (Self, Vec<&'static str>) {
        let mut opts = base;
        if let Some(nodelay) = off.tcp_nodelay {
            opts.nodelay = nodelay;
        }
        match off.socket_keepalive {
            Some(true) => {
                if opts.keepalive_idle.is_none() {
                    opts.keepalive_idle = Some(Duration::from_secs(30));
                }
                if opts.keepalive_interval.is_none() {
                    opts.keepalive_interval = Some(Duration::from_secs(15));
                }
                if opts.keepalive_retries.is_none() {
                    opts.keepalive_retries = Some(4);
                }
            }
            Some(false) => {
                opts.keepalive_idle = None;
                opts.keepalive_interval = None;
                opts.keepalive_retries = None;
            }
            None => {}
        }

        let mut unsupported = Vec::new();
        for (name, requested) in [
            ("tcp_fast_open", off.tcp_fast_open),
            ("reuse_port", off.reuse_port),
            ("io_uring", off.io_uring),
            ("zerocopy", off.zerocopy),
            ("sendfile", off.sendfile),
            ("checksum_offload", off.checksum_offload),
            ("large_send_offload", off.large_send_offload),
        ] {
            if requested == Some(true) {
                unsupported.push(name);
            }
        }
        (opts, unsupported)
    }
}

/// Config-agnostic view of the `[network.offload]` knobs that map onto TCP
/// socket options. `spt-net` deliberately stays free of any dependency on
/// `spt-config`; the caller (spt-bin) maps `spt_config::NetworkOffload` into
/// this struct and passes it to [`TcpOptions::from_offload`].
///
/// Every field is `Option<bool>`, mirroring the schema's tri-state (unset =
/// keep the base/platform default). The flags with no `socket2`/kernel mapping
/// in this crate are carried anyway so [`TcpOptions::from_offload`] can report
/// them as unsupported instead of silently discarding an operator's request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OffloadOptions {
    /// `TCP_NODELAY` (Nagle off) — maps to [`TcpOptions::nodelay`].
    pub tcp_nodelay: Option<bool>,
    /// Socket keepalive — enables [`TcpOptions`] keepalive probes.
    pub socket_keepalive: Option<bool>,
    /// TCP Fast Open — no mapping in this crate (reported unsupported).
    pub tcp_fast_open: Option<bool>,
    /// `SO_REUSEPORT` — no mapping in this crate (reported unsupported).
    pub reuse_port: Option<bool>,
    /// `io_uring` backing — no mapping in this crate (reported unsupported).
    pub io_uring: Option<bool>,
    /// Zero-copy send — no mapping in this crate (reported unsupported).
    pub zerocopy: Option<bool>,
    /// sendfile transfer — no mapping in this crate (reported unsupported).
    pub sendfile: Option<bool>,
    /// NIC checksum offload — no mapping in this crate (reported unsupported).
    pub checksum_offload: Option<bool>,
    /// Large-send/TSO offload — no mapping in this crate (reported unsupported).
    pub large_send_offload: Option<bool>,
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
    // socket2 implements the keepalive *interval* on Windows too
    // (SIO_KEEPALIVE_VALS), so include `target_os = "windows"` here to avoid
    // silently dropping `TcpOptions::production()`'s 15s interval on Windows
    // (E7-F16).
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "android",
        target_os = "windows",
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

    // E7-F10: SO_REUSEADDR has different, dangerous semantics on Windows.
    // On Unix it only relaxes TIME_WAIT reuse; on Windows it permits *another
    // process* to bind the same address/port as an active listener, which would
    // let any local process hijack spt's forward listeners (whose listeners
    // often front credentials-bearing protocols). We therefore set it only on
    // Unix. On Windows we leave the OS default, which already refuses a second
    // bind to an address/port held by an active listener (the safe behaviour);
    // socket2 0.6 does not expose `SO_EXCLUSIVEADDRUSE`, and the default is
    // equivalent for our forward-listener use case.
    #[cfg(unix)]
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
        // only_v6 should be false when dual-stack is requested. Some CI hosts
        // and containers force IPV6_V6ONLY and ignore attempts to clear it
        // (bind_tcp sets it correctly, before bind); skip rather than fail
        // when the kernel won't honor dual-stack.
        match s.only_v6() {
            Ok(false) => {}
            Ok(true) => {
                eprintln!("skipping: host does not honor dual-stack IPv6 (IPV6_V6ONLY forced)");
            }
            Err(e) => eprintln!("skipping: only_v6() query failed: {e}"),
        }
    }

    #[test]
    fn apply_supports_minimal_opts() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        apply(&socket, &TcpOptions::default()).unwrap();
        apply(&socket, &TcpOptions::production()).unwrap();
    }

    // E7-F16: the production keepalive interval must apply without error on
    // Windows too (socket2 supports SIO_KEEPALIVE_VALS there). Setting an
    // interval-only keepalive should succeed on every supported target.
    #[test]
    fn keepalive_interval_applies_cross_platform() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let opts = TcpOptions {
            keepalive_idle: Some(Duration::from_secs(30)),
            keepalive_interval: Some(Duration::from_secs(15)),
            ..TcpOptions::default()
        };
        apply(&socket, &opts).expect("keepalive (idle+interval) should apply on this platform");
    }

    // E7-F10 regression: bind_tcp must succeed on every platform without
    // relying on SO_REUSEADDR (which is now Unix-only). A fresh ephemeral
    // bind exercises the post-gate path.
    #[tokio::test(flavor = "current_thread")]
    async fn bind_tcp_succeeds_without_reuseaddr_on_all_platforms() {
        let opts = TcpOptions::production();
        let listener =
            bind_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &opts).unwrap();
        assert!(listener.local_addr().unwrap().port() != 0);
    }

    // ---- Wave 6: [network.offload] → TcpOptions -------------------------

    // A bare `TcpOptions::default()` (what a plain `TcpListener::bind` gives)
    // has nodelay OFF and no keepalive; an EMPTY offload table must not change
    // it (behavior-preserving when `[network.offload]` is absent/empty).
    #[test]
    fn from_offload_empty_is_behavior_preserving() {
        let (opts, unsupported) =
            TcpOptions::from_offload(TcpOptions::default(), &OffloadOptions::default());
        assert_eq!(opts, TcpOptions::default());
        assert!(unsupported.is_empty());
    }

    // tcp_nodelay + socket_keepalive must build the expected TcpOptions: nodelay
    // on and keepalive filled with the production probe timings.
    #[test]
    fn from_offload_builds_expected_tcp_options() {
        let off = OffloadOptions {
            tcp_nodelay: Some(true),
            socket_keepalive: Some(true),
            ..OffloadOptions::default()
        };
        let (opts, unsupported) = TcpOptions::from_offload(TcpOptions::default(), &off);
        assert!(opts.nodelay, "tcp_nodelay=true must set nodelay");
        assert_eq!(opts.keepalive_idle, Some(Duration::from_secs(30)));
        assert_eq!(opts.keepalive_interval, Some(Duration::from_secs(15)));
        assert_eq!(opts.keepalive_retries, Some(4));
        assert!(unsupported.is_empty());
    }

    // socket_keepalive=false must clear keepalive even when the base carried it
    // (e.g. base = production()), and tcp_nodelay=false must turn Nagle back on.
    #[test]
    fn from_offload_can_disable_over_production_base() {
        let off = OffloadOptions {
            tcp_nodelay: Some(false),
            socket_keepalive: Some(false),
            ..OffloadOptions::default()
        };
        let (opts, _) = TcpOptions::from_offload(TcpOptions::production(), &off);
        assert!(!opts.nodelay);
        assert_eq!(opts.keepalive_idle, None);
        assert_eq!(opts.keepalive_interval, None);
        assert_eq!(opts.keepalive_retries, None);
    }

    // The offload flags with no socket mapping must be reported (not silently
    // dropped) so the caller can WARN instead of a silent no-op.
    #[test]
    fn from_offload_reports_unsupported_flags() {
        let off = OffloadOptions {
            tcp_fast_open: Some(true),
            io_uring: Some(true),
            zerocopy: Some(true),
            sendfile: Some(true),
            checksum_offload: Some(true),
            large_send_offload: Some(true),
            reuse_port: Some(true),
            // A `Some(false)` must NOT be reported — the operator disabled it.
            ..OffloadOptions::default()
        };
        let (_opts, unsupported) = TcpOptions::from_offload(TcpOptions::default(), &off);
        assert_eq!(unsupported.len(), 7, "all 7 set-true flags reported");
        assert!(unsupported.contains(&"tcp_fast_open"));
        assert!(unsupported.contains(&"large_send_offload"));

        let off_off = OffloadOptions {
            tcp_fast_open: Some(false),
            io_uring: Some(false),
            ..OffloadOptions::default()
        };
        let (_o, none) = TcpOptions::from_offload(TcpOptions::default(), &off_off);
        assert!(none.is_empty(), "flags set false are not 'unsupported'");
    }

    // End-to-end: an offload-derived TcpOptions must actually take effect on a
    // real bound listener (nodelay round-trips through socket2). This proves the
    // whole [network.offload] → TcpOptions → socket seam, independent of which
    // higher-level call-site routes through bind_tcp.
    #[tokio::test(flavor = "current_thread")]
    async fn offload_derived_options_apply_to_bound_socket() {
        let off = OffloadOptions {
            tcp_nodelay: Some(true),
            ..OffloadOptions::default()
        };
        let (opts, _) = TcpOptions::from_offload(TcpOptions::default(), &off);
        let listener =
            bind_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &opts).unwrap();
        let std = listener.into_std().unwrap();
        std.set_nonblocking(false).unwrap();
        let s = Socket::from(std);
        assert!(s.tcp_nodelay().unwrap(), "offload nodelay must be applied");
    }
}
