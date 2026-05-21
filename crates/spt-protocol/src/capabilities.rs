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
    /// Can open client-side SOCKS5/HTTP CONNECT dynamic TCP proxy listeners.
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
    }

    #[test]
    fn ssh3_caps() {
        let c = ProtocolCapabilities::ssh3();
        assert!(c.local_udp && c.remote_udp && !c.host_keys);
        assert!(!c.dynamic_tcp);
    }
}
