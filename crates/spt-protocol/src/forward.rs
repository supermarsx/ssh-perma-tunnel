//! Forward specifications — protocol-agnostic descriptions of one forward.
//!
//! These types are populated by `spt-config`/`spt-supervisor` and handed to a
//! [`TunnelSession`](crate::TunnelSession) when a forward should be opened.

use serde::{Deserialize, Serialize};
use spt_core::BindAddr;

use crate::endpoint::TargetAddr;

/// Direction of a forward — `local` listens on the client, `remote` on the
/// server. Mirrors the user-facing flag of `spt forward add`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardDirection {
    /// Client-side listener forwards into the session.
    Local,
    /// Server-side listener forwards back to the client.
    Remote,
}

/// L4 transport — TCP for SSH2/SSH3, UDP only for SSH3 (§10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardTransport {
    /// Stream-oriented TCP.
    Tcp,
    /// Datagram-oriented UDP.
    Udp,
}

/// Specification for a TCP forward whose listener lives on the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalForwardSpec {
    /// User-facing forward name.
    pub name: String,
    /// Local socket the supervisor will bind.
    pub listen: BindAddr,
    /// Target the remote side will dial when accepting an inbound connection.
    pub target: TargetAddr,
    /// Optional max concurrent connections through this forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
}

/// Specification for a TCP forward whose listener lives on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteForwardSpec {
    /// User-facing forward name.
    pub name: String,
    /// Address the *server* should listen on.
    pub listen: BindAddr,
    /// Address (on the *client*) to forward accepted connections to.
    pub target: TargetAddr,
    /// Optional max concurrent connections through this forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
}

/// Specification for a client-side dynamic TCP proxy.
///
/// The local listener accepts SOCKS4, SOCKS4A, SOCKS5, and HTTP CONNECT
/// requests. Each accepted request selects its own remote target, which the SSH
/// backend dials through a fresh direct TCP channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicForwardSpec {
    /// User-facing forward name.
    pub name: String,
    /// Local socket the supervisor will bind.
    pub listen: BindAddr,
    /// Optional max concurrent proxy connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// Accept SOCKS4 CONNECT requests with IPv4 targets.
    pub allow_socks4: bool,
    /// Accept SOCKS4A CONNECT requests with remote DNS targets.
    pub allow_socks4a: bool,
    /// Accept SOCKS5 CONNECT requests.
    pub allow_socks5: bool,
    /// Accept HTTP CONNECT requests.
    pub allow_http_connect: bool,
}

/// Specification for a UDP forward (SSH3 only — see [`ProtocolCapabilities`](crate::ProtocolCapabilities)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpForwardSpec {
    /// User-facing forward name.
    pub name: String,
    /// Direction (`local` or `remote`).
    pub direction: ForwardDirection,
    /// Local or remote bind socket.
    pub listen: BindAddr,
    /// Target peer address.
    pub target: TargetAddr,
    /// Per-flow idle timeout in seconds (spec §10.4 requires a configured idle timeout).
    pub idle_timeout_secs: u32,
    /// Optional cap on concurrent flow mappings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_flows: Option<u32>,
}

/// Public state of a forward as exposed via [`crate::ForwardHandle`].
///
/// Mirrors spec §11.1 forward states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardState {
    /// Forward exists in config but is administratively disabled.
    Disabled,
    /// Acquiring the local or remote bind.
    Binding,
    /// Listening on the local bind (local forwards).
    Listening,
    /// Server-side listener was requested; awaiting confirmation.
    RemoteRequested,
    /// Forward is fully active and serving traffic.
    Active,
    /// Forward is up but a problem has been detected.
    Degraded,
    /// Forward is sleeping before a retry.
    RetryWait,
    /// Forward stopped cleanly.
    Stopped,
    /// Forward stopped due to a non-recoverable error.
    Failed,
}

impl ForwardState {
    /// Whether `self` is a terminal (no further transitions) state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed | Self::Disabled)
    }
}
