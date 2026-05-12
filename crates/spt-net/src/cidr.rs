//! CIDR allow/deny ACL.
//!
//! Semantics (deny-wins): if any deny rule matches, reject. Otherwise, if any
//! allow rule matches, accept. With no rules at all, the ACL accepts every
//! address (open by default — gating is the caller's job).

use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;

/// A CIDR-based access-control list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CidrAcl {
    /// Allow rules. Empty = allow everything not denied.
    pub allow: Vec<IpNet>,
    /// Deny rules. Always evaluated first.
    pub deny: Vec<IpNet>,
}

impl CidrAcl {
    /// Construct an ACL from raw allow/deny lists.
    #[must_use]
    pub fn new(allow: Vec<IpNet>, deny: Vec<IpNet>) -> Self {
        Self { allow, deny }
    }

    /// Check whether `ip` is permitted.
    ///
    /// Behaviour:
    /// 1. If any `deny` rule matches → `false` (deny wins).
    /// 2. Else if `allow` is empty → `true` (open by default).
    /// 3. Else if any `allow` rule matches → `true`.
    /// 4. Else → `false`.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) are normalised to their
    /// IPv4 form before matching, so an IPv4 deny rule still wins against a
    /// mapped peer.
    #[must_use]
    pub fn matches(&self, ip: IpAddr) -> bool {
        let ip = unmap_v4(ip);
        if self.deny.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|net| net.contains(&ip))
    }
}

/// Collapse an IPv4-mapped IPv6 address (`::ffff:0:0/96`) to its IPv4 form.
fn unmap_v4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v4_from_mapped(v6) {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn v4_from_mapped(v6: Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let segments = v6.segments();
    if segments[0..5].iter().all(|s| *s == 0) && segments[5] == 0xffff {
        let octets = v6.octets();
        Some(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn empty_acl_allows_everything() {
        let acl = CidrAcl::default();
        assert!(acl.matches(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(acl.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn allow_only_filters() {
        let acl = CidrAcl::new(vec![net("10.0.0.0/8")], vec![]);
        assert!(acl.matches(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!acl.matches(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn deny_wins_over_allow() {
        let acl = CidrAcl::new(vec![net("10.0.0.0/8")], vec![net("10.1.0.0/16")]);
        assert!(acl.matches(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!acl.matches(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
    }

    #[test]
    fn deny_only_blocks_listed() {
        let acl = CidrAcl::new(vec![], vec![net("192.168.0.0/16")]);
        assert!(!acl.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(acl.matches(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn ipv6_is_supported() {
        let acl = CidrAcl::new(vec![net("2001:db8::/32")], vec![net("2001:db8:dead::/48")]);
        assert!(acl.matches(IpAddr::V6("2001:db8::1".parse().unwrap())));
        assert!(!acl.matches(IpAddr::V6("2001:db8:dead::1".parse().unwrap())));
        assert!(!acl.matches(IpAddr::V6("2001:0:0::1".parse().unwrap())));
    }

    #[test]
    fn v4_mapped_v6_treated_as_v4() {
        let acl = CidrAcl::new(vec![], vec![net("10.0.0.0/8")]);
        // ::ffff:10.1.2.3
        let mapped: Ipv6Addr = "::ffff:10.1.2.3".parse().unwrap();
        assert!(!acl.matches(IpAddr::V6(mapped)));
        // Non-mapped v6 still allowed (no allow rules, no deny match).
        assert!(acl.matches(IpAddr::V6("2001:db8::1".parse().unwrap())));
    }
}
