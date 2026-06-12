//! Per-forward CIDR allow/deny enforcement.
//!
//! Wraps [`spt_net::CidrAcl`] with a forward-friendly `decide` returning a
//! tagged decision and event-friendly fields.

use std::net::IpAddr;

use spt_net::CidrAcl;

/// Outcome of an ACL check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    /// Connection permitted.
    Allow,
    /// Connection rejected.
    Deny,
}

impl AclDecision {
    /// Whether the decision is `Allow`.
    #[must_use]
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Per-forward ACL — newtype around [`CidrAcl`] with explicit default policy
/// when both lists are empty.
#[derive(Debug, Clone)]
pub struct ForwardAcl {
    inner: CidrAcl,
    default_allow: bool,
}

impl ForwardAcl {
    /// Build a new ACL.
    ///
    /// * `default_allow = true` (recommended for client-side local-TCP forwards
    ///   used as private localhost listeners): empty allow + empty deny ⇒
    ///   allow.
    /// * `default_allow = false` (recommended for non-loopback binds and
    ///   remote-side forwards): empty allow + empty deny ⇒ deny.
    ///
    /// When `deny` lists are non-empty they always win — matching the
    /// underlying [`CidrAcl`] semantics.
    #[must_use]
    pub fn new(inner: CidrAcl, default_allow: bool) -> Self {
        Self {
            inner,
            default_allow,
        }
    }

    /// Open ACL — allows everything.
    #[must_use]
    pub fn allow_all() -> Self {
        Self::new(CidrAcl::default(), true)
    }

    /// Closed ACL — denies everything (useful as a tightening default).
    #[must_use]
    pub fn deny_all() -> Self {
        Self::new(CidrAcl::default(), false)
    }

    /// Decide for a peer IP.
    ///
    /// Evaluation honors the forward-level default policy even when rules are
    /// present (E1-F6):
    ///
    /// * `default_allow == true` — defer to [`CidrAcl::matches`] (deny wins;
    ///   empty or matching allow ⇒ allow). This is the right behavior for
    ///   private localhost listeners.
    /// * `default_allow == false` — a peer is admitted only on a *positive*
    ///   allow match. If no allow rules are configured at all, every unlisted
    ///   peer is denied (the deny-by-default contract), so adding a lone deny
    ///   rule no longer silently flips the forward to allow-everything-else.
    #[must_use]
    pub fn decide(&self, ip: IpAddr) -> AclDecision {
        if self.default_allow {
            return if self.inner.matches(ip) {
                AclDecision::Allow
            } else {
                AclDecision::Deny
            };
        }

        // default_allow == false: never open-by-default.
        if self.inner.allow.is_empty() {
            // No positive allow possible -> deny everything (E1-F6 core fix).
            return AclDecision::Deny;
        }
        // Allow rules present: `matches` requires a positive allow match and
        // honors deny-wins — exactly the deny-by-default behavior here.
        if self.inner.matches(ip) {
            AclDecision::Allow
        } else {
            AclDecision::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn empty_default_allow() {
        let acl = ForwardAcl::allow_all();
        assert_eq!(acl.decide(ip("1.2.3.4")), AclDecision::Allow);
    }

    #[test]
    fn empty_default_deny() {
        let acl = ForwardAcl::deny_all();
        assert_eq!(acl.decide(ip("1.2.3.4")), AclDecision::Deny);
    }

    #[test]
    fn deny_wins_over_allow() {
        let acl = ForwardAcl::new(
            CidrAcl::new(vec![net("10.0.0.0/8")], vec![net("10.0.0.5/32")]),
            true,
        );
        assert_eq!(acl.decide(ip("10.0.0.5")), AclDecision::Deny);
        assert_eq!(acl.decide(ip("10.0.0.6")), AclDecision::Allow);
        assert_eq!(acl.decide(ip("11.0.0.1")), AclDecision::Deny); // outside allow
    }

    #[test]
    fn deny_only_denies_listed() {
        // default_allow=true: deny rules without allow rules ->
        // deny matches are denied, everything else allowed.
        let acl = ForwardAcl::new(CidrAcl::new(vec![], vec![net("10.0.0.0/8")]), true);
        assert_eq!(acl.decide(ip("10.5.5.5")), AclDecision::Deny);
        assert_eq!(acl.decide(ip("8.8.8.8")), AclDecision::Allow);
    }

    #[test]
    fn deny_only_with_default_deny_denies_everything() {
        // E1-F6 regression: a default-deny forward with only a deny rule must
        // NOT silently flip to allow-everything-else. Every unlisted peer is
        // still denied because no positive allow match is possible.
        let acl = ForwardAcl::new(CidrAcl::new(vec![], vec![net("10.0.0.0/8")]), false);
        assert_eq!(acl.decide(ip("10.5.5.5")), AclDecision::Deny); // explicitly denied
        assert_eq!(acl.decide(ip("8.8.8.8")), AclDecision::Deny); // unlisted -> deny by default
        assert_eq!(acl.decide(ip("192.168.1.1")), AclDecision::Deny);
    }

    #[test]
    fn allow_list_with_default_deny_requires_positive_match() {
        // default_allow=false with an allow list: only listed peers admitted,
        // deny still wins within the allow range.
        let acl = ForwardAcl::new(
            CidrAcl::new(vec![net("10.0.0.0/8")], vec![net("10.0.0.5/32")]),
            false,
        );
        assert_eq!(acl.decide(ip("10.0.0.6")), AclDecision::Allow); // positive allow
        assert_eq!(acl.decide(ip("10.0.0.5")), AclDecision::Deny); // deny wins
        assert_eq!(acl.decide(ip("8.8.8.8")), AclDecision::Deny); // outside allow -> deny
    }
}
