//! Source-address scoping for the transparent-forwarder (recursion) path.
//!
//! An embedded DNS resolver that recursively resolves **arbitrary** unmanaged
//! names for **any** client is an open resolver — a UDP reflection/amplification
//! vector when bound to a non-loopback interface and reachable with a spoofed
//! source address. To stay default-safe, the [`SplitHorizonHandler`] only
//! recurses upstream for clients whose source IP falls inside the configured
//! [`ForwardScope`]; out-of-scope clients get `REFUSED`.
//!
//! This gate applies **only** to the upstream-forwarding path. Authoritative
//! answers for managed zones (names the server owns) are bounded and are served
//! to every client regardless of scope — they carry no amplification risk.
//!
//! [`SplitHorizonHandler`]: crate::split_horizon::SplitHorizonHandler

use std::net::IpAddr;

/// Which client source addresses the transparent forwarder will recurse
/// upstream for.
///
/// Defaults to [`ForwardScope::LoopbackOnly`] — the safe posture for the
/// default `127.0.0.1` bind. Widen it deliberately for a LAN/operator
/// deployment; binding a public interface with [`ForwardScope::Any`] turns the
/// listener into an open resolver and should only be done behind a firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardScope {
    /// Recurse only for loopback clients (`127.0.0.0/8`, `::1`). Default-safe:
    /// a misconfigured non-loopback bind cannot be abused as an amplifier.
    #[default]
    LoopbackOnly,
    /// Recurse for loopback **plus** RFC1918 / unique-local / link-local
    /// (private) clients. Suitable for a trusted LAN deployment.
    PrivateNetworks,
    /// Recurse for any client. Only safe on a trusted/firewalled deployment —
    /// an open forwarder on a public interface is a UDP amplification vector.
    Any,
}

impl ForwardScope {
    /// Whether the forwarder should recurse upstream for a client at `src`.
    #[must_use]
    pub fn allows(self, src: IpAddr) -> bool {
        match self {
            ForwardScope::Any => true,
            ForwardScope::LoopbackOnly => src.is_loopback(),
            ForwardScope::PrivateNetworks => src.is_loopback() || is_private(src),
        }
    }
}

/// Classify an address as belonging to a private/local network range
/// (RFC1918 v4, link-local v4, unique-local v6 `fc00::/7`, link-local v6
/// `fe80::/10`). Loopback is handled separately by the caller.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        // `Ipv6Addr::is_unique_local` / `is_unicast_link_local` are unstable on
        // the MSRV, so match the prefixes directly.
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // fc00::/7 (unique local) — top 7 bits are 1111110.
            let ula = (seg[0] & 0xfe00) == 0xfc00;
            // fe80::/10 (link local) — top 10 bits are 1111111010.
            let ll = (seg[0] & 0xffc0) == 0xfe80;
            ula || ll
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn default_is_loopback_only() {
        assert_eq!(ForwardScope::default(), ForwardScope::LoopbackOnly);
    }

    #[test]
    fn loopback_only_allows_loopback_rejects_rest() {
        let s = ForwardScope::LoopbackOnly;
        assert!(s.allows(v4("127.0.0.1")));
        assert!(s.allows(v6("::1")));
        assert!(!s.allows(v4("192.168.1.5")), "private must be rejected");
        assert!(!s.allows(v4("8.8.8.8")), "public must be rejected");
        assert!(!s.allows(v6("2606:4700::1111")), "public v6 rejected");
    }

    #[test]
    fn private_networks_allows_loopback_and_private_only() {
        let s = ForwardScope::PrivateNetworks;
        assert!(s.allows(v4("127.0.0.1")));
        assert!(s.allows(v4("10.1.2.3")));
        assert!(s.allows(v4("192.168.0.1")));
        assert!(s.allows(v4("172.16.5.5")));
        assert!(s.allows(v4("169.254.1.1")), "v4 link-local allowed");
        assert!(s.allows(v6("fd00::1")), "v6 ULA allowed");
        assert!(s.allows(v6("fe80::1")), "v6 link-local allowed");
        assert!(!s.allows(v4("8.8.8.8")), "public v4 rejected");
        assert!(!s.allows(v6("2606:4700::1111")), "public v6 rejected");
    }

    #[test]
    fn any_allows_everything() {
        let s = ForwardScope::Any;
        assert!(s.allows(v4("127.0.0.1")));
        assert!(s.allows(v4("192.168.1.1")));
        assert!(s.allows(v4("8.8.8.8")));
        assert!(s.allows(v6("2606:4700::1111")));
    }
}
