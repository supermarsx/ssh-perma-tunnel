//! Static capability advertisement for a [`TunnelProtocol`](crate::TunnelProtocol).

use serde::{Deserialize, Serialize};

/// What a protocol backend can do.
///
/// Backends declare these so the supervisor can reject configurations that
/// require a forward direction or feature the backend does not support
/// (spec §10.4: SSH2 has no UDP; spec §10.2: SSH3 negotiates remote TCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolCapabilities {
    /// Can open client-initiated TCP forwards (`local`).
    pub local_tcp: bool,
    /// Can request server-listener TCP forwards (`remote`).
    pub remote_tcp: bool,
    /// Can open client-initiated UDP forwards.
    pub local_udp: bool,
    /// Can request server-listener UDP forwards.
    pub remote_udp: bool,
    /// Can open client-initiated unix-domain-socket forwards (`cfg(unix)`): bind
    /// a local `AF_UNIX` listener and bridge each accepted connection to a remote
    /// unix socket path.
    pub local_uds: bool,
    /// Can request server-listener unix-domain-socket forwards (`cfg(unix)`):
    /// ask the peer to bind a remote `AF_UNIX` listener and bridge each accepted
    /// connection back to a local unix socket path.
    pub remote_uds: bool,
    /// Can open client-side SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT dynamic TCP
    /// proxy listeners.
    pub dynamic_tcp: bool,
    /// Supports tunnelling through one or more intermediate hops (jump hosts).
    pub multi_hop: bool,
    /// Supports forwarding the user's SSH agent into the session.
    pub agent_forwarding: bool,
    /// Verifies host keys (SSH2) — distinct from TLS verification (SSH3).
    pub host_keys: bool,
    /// Multiple independent forwards may share one underlying session.
    pub multiplex: bool,
}

impl ProtocolCapabilities {
    /// Builder helper used by SSH2: TCP both ways, no UDP, host keys + multiplex.
    #[must_use]
    pub const fn ssh2() -> Self {
        Self {
            local_tcp: true,
            remote_tcp: true,
            local_udp: false,
            remote_udp: false,
            // russh implements local/remote UDS forwards on Unix targets
            // (`cfg(unix)`); on Windows the backend surfaces
            // `UnsupportedPlatform` at open time. The capability advertises the
            // backend's support, not the current host's, mirroring how the
            // supervisor uses caps to reject configurations the *protocol*
            // cannot honour.
            local_uds: true,
            remote_uds: true,
            dynamic_tcp: true,
            multi_hop: true,
            agent_forwarding: true,
            host_keys: true,
            multiplex: true,
        }
    }

    /// Builder helper used by SSH3: full TCP+UDP, TLS-verified, no SSH host keys.
    #[must_use]
    pub const fn ssh3() -> Self {
        Self {
            local_tcp: true,
            remote_tcp: true,
            local_udp: true,
            remote_udp: true,
            // SSH3 carries UDS forwards over a dedicated channel-open frame
            // convention (`cfg(unix)`); on Windows the backend surfaces
            // `UnsupportedPlatform` at open time.
            local_uds: true,
            remote_uds: true,
            dynamic_tcp: false,
            multi_hop: false,
            agent_forwarding: false,
            host_keys: false,
            multiplex: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh2_caps() {
        let c = ProtocolCapabilities::ssh2();
        assert!(c.local_tcp && c.remote_tcp && c.host_keys);
        assert!(c.dynamic_tcp);
        assert!(!c.local_udp && !c.remote_udp);
        assert!(c.local_uds && c.remote_uds);
    }

    #[test]
    fn ssh3_caps() {
        let c = ProtocolCapabilities::ssh3();
        assert!(c.local_udp && c.remote_udp && !c.host_keys);
        assert!(!c.dynamic_tcp);
        assert!(c.local_uds && c.remote_uds);
    }
}
