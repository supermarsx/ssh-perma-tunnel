//! Forward specifications — protocol-agnostic descriptions of one forward.
//!
//! These types are populated by `spt-config`/`spt-supervisor` and handed to a
//! [`TunnelSession`](crate::TunnelSession) when a forward should be opened.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use spt_core::BindAddr;

use crate::endpoint::TargetAddr;

/// Per-forward rate-limiting knobs.
///
/// All fields default to `0`, which means **unlimited** (the limiter is inert).
/// Non-zero values are interpreted by the forward runtime (`spt-forward`):
/// byte rates feed a `TokenBucket`, connection/packet rates feed accept-loop /
/// datagram gates. A whole-struct `Default` therefore yields an unlimited
/// forward, preserving prior behaviour for specs that omit the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ForwardRateLimits {
    /// Upstream (client→remote) byte rate cap, bytes/sec. `0` = unlimited.
    #[serde(default)]
    pub rate_bps_up: u64,
    /// Downstream (remote→client) byte rate cap, bytes/sec. `0` = unlimited.
    #[serde(default)]
    pub rate_bps_down: u64,
    /// Upstream token-bucket burst allowance, bytes. `0` = unlimited.
    #[serde(default)]
    pub burst_up: u64,
    /// Downstream token-bucket burst allowance, bytes. `0` = unlimited.
    #[serde(default)]
    pub burst_down: u64,
    /// Cap on newly accepted connections per second. `0` = unlimited.
    #[serde(default)]
    pub max_new_conns_per_sec: u32,
    /// Cap on forwarded packets per second (UDP/datagram). `0` = unlimited.
    #[serde(default)]
    pub max_packets_per_sec: u32,
}

impl ForwardRateLimits {
    /// Whether every limit is unset (`0`), i.e. the forward is unthrottled.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.rate_bps_up == 0
            && self.rate_bps_down == 0
            && self.burst_up == 0
            && self.burst_down == 0
            && self.max_new_conns_per_sec == 0
            && self.max_packets_per_sec == 0
    }
}

/// Behaviour when a forward's local/remote bind address is already in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindConflictPolicy {
    /// Fail the forward immediately (default — preserves prior behaviour).
    #[default]
    Fail,
    /// Retry binding the same address after a backoff.
    Retry,
    /// Try the next port number until a free one is found.
    NextPort,
}

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
    /// Per-forward rate limits (`Default` = unlimited).
    #[serde(default)]
    pub limits: ForwardRateLimits,
    /// Idle timeout for an established connection; `None` = no idle timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<Duration>,
    /// What to do when the local bind address is already in use.
    #[serde(default)]
    pub on_bind_conflict: BindConflictPolicy,
    /// Whether failing to open this forward should fail the whole profile
    /// (`true`) versus degrade-and-continue (`false`, default).
    #[serde(default)]
    pub required: bool,
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
    /// Per-forward rate limits (`Default` = unlimited).
    #[serde(default)]
    pub limits: ForwardRateLimits,
    /// Idle timeout for an established connection; `None` = no idle timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<Duration>,
    /// What to do when the remote bind address is already in use.
    #[serde(default)]
    pub on_bind_conflict: BindConflictPolicy,
    /// Whether failing to open this forward should fail the whole profile
    /// (`true`) versus degrade-and-continue (`false`, default).
    #[serde(default)]
    pub required: bool,
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
    /// Per-forward rate limits (`Default` = unlimited).
    #[serde(default)]
    pub limits: ForwardRateLimits,
    /// Idle timeout for an established proxied connection; `None` = none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<Duration>,
    /// What to do when the local bind address is already in use.
    #[serde(default)]
    pub on_bind_conflict: BindConflictPolicy,
    /// Whether failing to open this forward should fail the whole profile
    /// (`true`) versus degrade-and-continue (`false`, default).
    #[serde(default)]
    pub required: bool,
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
    /// Per-forward rate limits (`Default` = unlimited).
    #[serde(default)]
    pub limits: ForwardRateLimits,
}

/// Specification for a unix-domain-socket forward.
///
/// Mirrors the common fields of the TCP-style specs but binds a filesystem
/// socket path locally and bridges it to a remote unix socket path. UDS
/// forwarding is a `cfg(unix)` capability; backends that cannot honour it
/// return [`spt_core::Error::UnsupportedPlatform`] from
/// [`TunnelSession::open_uds_forward`](crate::TunnelSession::open_uds_forward).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UdsForwardSpec {
    /// User-facing forward name.
    pub name: String,
    /// Local filesystem path the supervisor will bind a listening socket on.
    pub listen_path: PathBuf,
    /// Remote unix socket path the backend bridges accepted connections to.
    pub remote_socket_path: String,
    /// Per-forward rate limits (`Default` = unlimited).
    #[serde(default)]
    pub limits: ForwardRateLimits,
    /// Whether failing to open this forward should fail the whole profile
    /// (`true`) versus degrade-and-continue (`false`, default).
    #[serde(default)]
    pub required: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limits_default_is_unlimited() {
        let l = ForwardRateLimits::default();
        assert!(l.is_unlimited());
        assert_eq!(l.rate_bps_up, 0);
        assert_eq!(l.rate_bps_down, 0);
        assert_eq!(l.burst_up, 0);
        assert_eq!(l.burst_down, 0);
        assert_eq!(l.max_new_conns_per_sec, 0);
        assert_eq!(l.max_packets_per_sec, 0);
    }

    #[test]
    fn rate_limits_non_zero_is_limited() {
        let l = ForwardRateLimits {
            rate_bps_up: 1,
            ..Default::default()
        };
        assert!(!l.is_unlimited());
    }

    #[test]
    fn bind_conflict_policy_default_is_fail() {
        assert_eq!(BindConflictPolicy::default(), BindConflictPolicy::Fail);
    }

    #[test]
    fn rate_limits_round_trip() {
        let l = ForwardRateLimits {
            rate_bps_up: 100,
            rate_bps_down: 200,
            burst_up: 10,
            burst_down: 20,
            max_new_conns_per_sec: 5,
            max_packets_per_sec: 7,
        };
        let json = serde_json::to_string(&l).unwrap();
        let back: ForwardRateLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn bind_conflict_policy_round_trip() {
        for p in [
            BindConflictPolicy::Fail,
            BindConflictPolicy::Retry,
            BindConflictPolicy::NextPort,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let back: BindConflictPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
        // snake_case wire form.
        assert_eq!(
            serde_json::to_string(&BindConflictPolicy::NextPort).unwrap(),
            "\"next_port\""
        );
    }

    #[test]
    fn local_spec_missing_new_fields_deserialize_to_defaults() {
        // A pre-existing config literal that predates the new fields must still
        // deserialize, with the new fields taking their defaults.
        let json = r#"{
            "name": "l",
            "listen": "127.0.0.1:8080",
            "target": {"host": "localhost", "port": 80}
        }"#;
        let spec: LocalForwardSpec = serde_json::from_str(json).unwrap();
        assert!(spec.limits.is_unlimited());
        assert_eq!(spec.idle_timeout, None);
        assert_eq!(spec.on_bind_conflict, BindConflictPolicy::Fail);
        assert!(!spec.required);
    }

    #[test]
    fn uds_spec_default_and_round_trip() {
        let s = UdsForwardSpec::default();
        assert!(s.limits.is_unlimited());
        assert!(!s.required);
        assert_eq!(s.name, "");

        let full = UdsForwardSpec {
            name: "u".to_owned(),
            listen_path: PathBuf::from("/tmp/a.sock"),
            remote_socket_path: "/run/b.sock".to_owned(),
            limits: ForwardRateLimits {
                rate_bps_up: 1,
                ..Default::default()
            },
            required: true,
        };
        let json = serde_json::to_string(&full).unwrap();
        let back: UdsForwardSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(full, back);
    }

    #[test]
    fn dynamic_and_remote_specs_round_trip_with_limits() {
        let d = DynamicForwardSpec {
            name: "d".to_owned(),
            listen: BindAddr::Tcp("127.0.0.1:1080".parse().unwrap()),
            max_connections: Some(10),
            allow_socks4: true,
            allow_socks4a: false,
            allow_socks5: true,
            allow_http_connect: false,
            limits: ForwardRateLimits {
                max_new_conns_per_sec: 3,
                ..Default::default()
            },
            idle_timeout: Some(Duration::from_secs(30)),
            on_bind_conflict: BindConflictPolicy::NextPort,
            required: true,
        };
        let back: DynamicForwardSpec =
            serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(d, back);
    }
}
