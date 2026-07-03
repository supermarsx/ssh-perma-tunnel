//! Wave 6: map `[network.offload]` → [`spt_net::TcpOptions`].
//!
//! `[network.offload]` was structurally dead before this wave — the offload
//! flags were parsed and displayed (`spt firewall gateway show`) but never
//! built a [`spt_net::TcpOptions`], so socket tuning (nodelay / keepalive) was
//! dropped. This module builds the effective socket options from the config
//! and logs what it derived, so callers can apply them to the sockets spt-bin
//! controls (currently the TLS status-api listener; the data-plane forward
//! listeners live in `spt-forward`/`spt-ssh3` and are noted for a follow-up
//! wave — see `.orchestration/logs/w6-fwnet.md`).
//!
//! Config-agnostic mapping + the actual field→field derivation live in
//! `spt_net::sockopts` (`OffloadOptions` / `TcpOptions::from_offload`); this
//! module is only the `spt-config` bridge + logging.

use spt_config::schema::Config;
use spt_net::{OffloadOptions, TcpOptions};

/// Build the effective [`spt_net::TcpOptions`] from `[network.offload]`.
///
/// Returns `None` when `[network]` or `[network.offload]` is absent — callers
/// treat `None` as "leave socket creation exactly as before" so an unconfigured
/// deployment is behavior-preserving. When offload IS configured this logs an
/// INFO line describing the derived options and a WARN naming any flags that
/// this build cannot honor (so a set-but-unsupported flag is never a silent
/// no-op).
pub fn tcp_options(cfg: &Config) -> Option<TcpOptions> {
    let offload = cfg.network.as_ref()?.offload.as_ref()?;
    let off = OffloadOptions {
        tcp_nodelay: offload.tcp_nodelay,
        socket_keepalive: offload.socket_keepalive,
        tcp_fast_open: offload.tcp_fast_open,
        reuse_port: offload.reuse_port,
        io_uring: offload.io_uring,
        zerocopy: offload.zerocopy,
        sendfile: offload.sendfile,
        checksum_offload: offload.checksum_offload,
        large_send_offload: offload.large_send_offload,
    };
    let (opts, unsupported) = TcpOptions::from_offload(TcpOptions::default(), &off);
    tracing::info!(
        nodelay = opts.nodelay,
        keepalive = opts.keepalive_idle.is_some(),
        "[network.offload] socket options built and will be applied to spt-controlled listeners"
    );
    if !unsupported.is_empty() {
        tracing::warn!(
            flags = ?unsupported,
            "[network.offload] flags set but unsupported by this build — ignored: {}",
            unsupported.join(", ")
        );
    }
    Some(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    // No [network] → None (behavior-preserving).
    #[test]
    fn none_when_no_network_table() {
        let (cfg, _) = spt_config::load_str("version = 1\n", false).unwrap();
        assert!(tcp_options(&cfg).is_none());
    }

    // [network.offload] with tcp_nodelay=true builds nodelay-on options — proves
    // the config table is actually consumed (pre-fix: always dropped).
    #[test]
    fn builds_tcp_options_from_offload_table() {
        let s = "\
version = 1
[network.offload]
tcp_nodelay = true
socket_keepalive = true
";
        let (cfg, _) = spt_config::load_str(s, false).unwrap();
        let opts = tcp_options(&cfg).expect("offload table present → Some");
        assert!(opts.nodelay);
        assert!(opts.keepalive_idle.is_some());
    }

    // A set-but-unsupported flag still yields Some(options) (nodelay default)
    // and does not panic — the WARN is emitted as a side effect.
    #[test]
    fn unsupported_flag_still_returns_options() {
        let s = "\
version = 1
[network.offload]
io_uring = true
";
        let (cfg, _) = spt_config::load_str(s, false).unwrap();
        assert!(tcp_options(&cfg).is_some());
    }
}
