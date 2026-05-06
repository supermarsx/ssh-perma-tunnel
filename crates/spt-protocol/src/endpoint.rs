//! Endpoint and target-address types passed to [`TunnelProtocol::connect`](crate::TunnelProtocol::connect).

use serde::{Deserialize, Serialize};

/// A single connection target for a profile, taken from `[[profiles.endpoints]]`.
///
/// Endpoints are tried in priority/weight order by the supervisor; this type
/// is the protocol-facing distillation — auth lives in [`crate::AuthConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// Hostname or IP literal.
    pub host: String,
    /// TCP/UDP port the protocol listens on.
    pub port: u16,
    /// Optional `[runtime].address_family` hint — `"ipv4"`, `"ipv6"`, or `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_family: Option<AddressFamily>,
    /// Priority for failover selection (lower is preferred).
    #[serde(default)]
    pub priority: u32,
    /// Weight for weighted-random tie-breaking among equal-priority endpoints.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

const fn default_weight() -> u32 {
    1
}

/// Optional address-family pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// Force IPv4.
    Ipv4,
    /// Force IPv6.
    Ipv6,
}

impl Endpoint {
    /// Convenience constructor for tests and CLI plumbing.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            address_family: None,
            priority: 0,
            weight: 1,
        }
    }
}

/// Resolved target address handed across the tunnel ("connect there:" of §10.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetAddr {
    /// Target host (resolved on the remote side unless config says otherwise).
    pub host: String,
    /// Target port.
    pub port: u16,
}

impl TargetAddr {
    /// Construct a `host:port` target.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_roundtrip() {
        let e = Endpoint::new("example.com", 22);
        let s = serde_json::to_string(&e).unwrap();
        let de: Endpoint = serde_json::from_str(&s).unwrap();
        assert_eq!(e, de);
    }
}
