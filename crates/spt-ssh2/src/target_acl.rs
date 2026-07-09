//! Destination (target) allow/deny policy for dynamic SOCKS forwards.
//!
//! The dynamic (SOCKS5 / SOCKS4 / HTTP CONNECT) forward lets a *local* proxy
//! client ask the SSH server to dial an arbitrary `(host, port)` target over a
//! fresh `direct-tcpip` channel. Without restriction this is an SSRF / abuse
//! surface (the server can be steered at its own loopback / metadata service /
//! internal network).
//!
//! [`TargetAcl`] adds an OPTIONAL allow/deny list evaluated *before* the
//! channel is opened. Patterns are matched against the requested target host:
//!
//! * A pattern that parses as an [`ipnet::IpNet`] or a bare [`std::net::IpAddr`]
//!   is treated as a CIDR/IP rule and matched against the target host when that
//!   host is an IP literal or a legacy numeric IPv4 form accepted by common
//!   resolvers (for example `2130706433` or `127.1`). Non-numeric hostname
//!   targets are resolved on the SSH server, so CIDR rules cannot match them.
//! * Any other pattern is a case-insensitive host glob supporting `*`
//!   (matches any run of characters, including `.`). It is matched against the
//!   target host string.
//!
//! Semantics (deny-wins, mirrors [`spt_net::CidrAcl`]):
//! 1. If any deny pattern matches the target → **Deny**.
//! 2. Else if the allow list is empty → **Allow** (back-compat: unset ⇒ allow
//!    all, preserving pre-ACL behaviour).
//! 3. Else if any allow pattern matches → **Allow**.
//! 4. Else → **Deny**.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

/// One target-matching rule: either an IP/CIDR rule or a host glob.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetRule {
    /// CIDR or bare-IP rule (matched against IP-literal targets only).
    Net(IpNet),
    /// Case-insensitive host glob (lower-cased pattern, `*` wildcard).
    Glob(String),
}

impl TargetRule {
    /// Parse a raw pattern into a rule. A value that parses as `IpNet` or a
    /// bare `IpAddr` becomes a [`TargetRule::Net`]; everything else is a
    /// host glob.
    fn parse(pattern: &str) -> Result<Self, TargetAclError> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Err(TargetAclError::Empty);
        }
        if let Ok(net) = pattern.parse::<IpNet>() {
            return Ok(Self::Net(net));
        }
        if let Some(ip) = parse_target_ip(pattern) {
            // A bare IP is a /32 (or /128) host rule. Canonicalize so an
            // IPv4-mapped IPv6 literal (`::ffff:10.0.0.1`) collapses to its v4
            // form and matches v4 targets symmetrically with the lookup side.
            // Also normalize legacy IPv4 numeric forms accepted by common
            // resolvers (for example `2130706433`, `0x7f000001`, `127.1`) so
            // operators can write either spelling and still get an IP rule.
            return Ok(Self::Net(IpNet::from(ip)));
        }
        // Reject patterns that look like a malformed CIDR (contain `/`) so an
        // operator typo such as `10.0.0.0/33` fails closed at config load
        // instead of silently becoming a host glob that never matches an IP.
        if let Some((addr, _)) = pattern.split_once('/') {
            if parse_target_ip(addr).is_some() {
                return Err(TargetAclError::BadCidr(pattern.to_string()));
            }
        }
        Ok(Self::Glob(pattern.to_ascii_lowercase()))
    }

    /// Whether this rule matches the requested target host.
    fn matches(&self, host: &str, host_ip: Option<IpAddr>) -> bool {
        match self {
            Self::Net(net) => host_ip.is_some_and(|ip| net.contains(&ip)),
            Self::Glob(pat) => glob_match(pat, &host.to_ascii_lowercase()),
        }
    }
}

/// Error raised when a target ACL pattern fails to validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAclError {
    /// An empty/whitespace-only pattern.
    Empty,
    /// A pattern that looks like a CIDR (`addr/prefix`) but does not parse.
    BadCidr(String),
}

impl std::fmt::Display for TargetAclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("target ACL pattern cannot be empty"),
            Self::BadCidr(p) => write!(f, "invalid target ACL CIDR `{p}`"),
        }
    }
}

impl std::error::Error for TargetAclError {}

/// Destination allow/deny policy for a dynamic forward.
///
/// An ACL with both lists empty is the back-compat "allow all" policy. Build
/// one from raw config patterns with [`TargetAcl::from_patterns`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetAcl {
    allow: Vec<TargetRule>,
    deny: Vec<TargetRule>,
}

impl TargetAcl {
    /// An empty ACL: allows every target (pre-ACL behaviour).
    #[must_use]
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Whether this ACL imposes any restriction. An ACL with no rules permits
    /// everything, so callers may skip evaluation entirely.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Build an ACL from optional allow/deny pattern lists, validating each
    /// pattern. `None`/empty lists contribute no rules.
    ///
    /// # Errors
    /// Returns [`TargetAclError`] if any pattern is empty or a malformed CIDR.
    pub fn from_patterns(
        allow: Option<&[String]>,
        deny: Option<&[String]>,
    ) -> Result<Self, TargetAclError> {
        let parse_all = |patterns: Option<&[String]>| -> Result<Vec<TargetRule>, TargetAclError> {
            patterns
                .unwrap_or(&[])
                .iter()
                .map(|p| TargetRule::parse(p))
                .collect()
        };
        Ok(Self {
            allow: parse_all(allow)?,
            deny: parse_all(deny)?,
        })
    }

    /// Decide whether a `(host, port)` target is permitted.
    ///
    /// `port` is currently informational (no port-scoped rules) but is part of
    /// the signature so a future port ACL is non-breaking.
    #[must_use]
    pub fn permits(&self, host: &str, _port: u16) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        // Normalize the target host before matching so common equivalent forms
        // cannot evade a deny rule:
        // * strip a single trailing dot — an absolute FQDN (`example.com.`) is
        //   treated identically to `example.com` by server-side resolvers, so a
        //   `example.com` deny glob must catch it;
        // * canonicalize IP literals — an IPv4-mapped IPv6 literal
        //   (`::ffff:10.0.0.1`) collapses to its v4 address and is tested
        //   against v4 CIDR/IP rules (closes the deny-list family-mismatch
        //   bypass). `to_canonical` is a no-op for plain v4 / non-mapped v6.
        //
        // * normalize legacy IPv4 numeric forms accepted by common resolvers
        //   (`2130706433`, `0x7f000001`, `127.1`, `169.254.43518`, etc.) before
        //   applying IP/CIDR rules. These arrive as SOCKS/CONNECT host strings
        //   but may be resolved by the SSH server as IP addresses, so treating
        //   them as ordinary hostnames would bypass deny-only IP policies.
        let host = host.strip_suffix('.').unwrap_or(host);
        let host_ip = parse_target_ip(host);
        if self.deny.iter().any(|r| r.matches(host, host_ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|r| r.matches(host, host_ip))
    }
}

/// Parse target strings that common system resolvers may treat as IP addresses.
///
/// Rust's `IpAddr` intentionally accepts only standard IP literals. For ACL
/// enforcement we also need the legacy IPv4 numeric forms accepted by
/// `inet_aton`/`getaddrinfo`, because the SSH server may resolve a SOCKS domain
/// or CONNECT host string such as `2130706433` to `127.0.0.1`.
fn parse_target_ip(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
        .or_else(|| parse_legacy_ipv4(host).map(IpAddr::V4))
}

fn parse_legacy_ipv4(host: &str) -> Option<Ipv4Addr> {
    if host.is_empty() || host.contains(':') {
        return None;
    }

    let mut parts = Vec::new();
    for part in host.split('.') {
        if part.is_empty() {
            return None;
        }
        parts.push(parse_ipv4_number(part)?);
        if parts.len() > 4 {
            return None;
        }
    }

    let addr = match parts.as_slice() {
        // a (32 bits)
        [a] => *a,
        // a.b (8.24 bits)
        [a, b] if *a <= 0xff && *b <= 0x00ff_ffff => (a << 24) | b,
        // a.b.c (8.8.16 bits)
        [a, b, c] if *a <= 0xff && *b <= 0xff && *c <= 0xffff => (a << 24) | (b << 16) | c,
        // a.b.c.d (8.8.8.8 bits)
        [a, b, c, d] if *a <= 0xff && *b <= 0xff && *c <= 0xff && *d <= 0xff => {
            (a << 24) | (b << 16) | (c << 8) | d
        }
        _ => return None,
    };

    Some(Ipv4Addr::from(addr))
}

fn parse_ipv4_number(part: &str) -> Option<u32> {
    let (digits, radix) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else {
            (part, 10)
        };
    if digits.is_empty() {
        return Some(0);
    }
    u32::from_str_radix(digits, radix).ok()
}

/// Minimal case-sensitive glob matcher supporting `*` (any run, incl. empty).
/// Inputs are expected to already be lower-cased by the caller.
fn glob_match(pattern: &str, text: &str) -> bool {
    // Iterative wildcard match with backtracking, O(n*m) worst case but no
    // allocation. `*` matches any (possibly empty) run of bytes.
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut star_ti): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star {
            // Backtrack: let the last `*` consume one more byte.
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // Consume any trailing `*`s.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_allows_everything() {
        let acl = TargetAcl::allow_all();
        assert!(acl.is_unrestricted());
        assert!(acl.permits("example.com", 443));
        assert!(acl.permits("169.254.169.254", 80));
        assert!(acl.permits("10.0.0.1", 22));
    }

    #[test]
    fn allow_list_requires_positive_match() {
        let acl =
            TargetAcl::from_patterns(Some(&["*.internal.example".to_string()]), None).unwrap();
        assert!(!acl.is_unrestricted());
        assert!(acl.permits("db.internal.example", 5432));
        assert!(acl.permits("a.b.internal.example", 5432));
        assert!(!acl.permits("evil.com", 443));
    }

    #[test]
    fn deny_wins_over_allow() {
        let acl = TargetAcl::from_patterns(
            Some(&["*.example.com".to_string()]),
            Some(&["secret.example.com".to_string()]),
        )
        .unwrap();
        assert!(acl.permits("www.example.com", 443));
        assert!(!acl.permits("secret.example.com", 443));
    }

    #[test]
    fn deny_only_blocks_listed_allows_rest() {
        // Deny list with empty allow: deny matches blocked, everything else
        // permitted (deny-wins, allow-empty ⇒ allow).
        let acl = TargetAcl::from_patterns(None, Some(&["169.254.169.254".to_string()])).unwrap();
        assert!(!acl.permits("169.254.169.254", 80));
        assert!(acl.permits("8.8.8.8", 53));
        assert!(acl.permits("example.com", 443));
    }

    #[test]
    fn cidr_matches_ip_literal_targets() {
        let acl = TargetAcl::from_patterns(None, Some(&["10.0.0.0/8".to_string()])).unwrap();
        assert!(!acl.permits("10.1.2.3", 22));
        assert!(acl.permits("11.0.0.1", 22));
        // CIDR cannot match a non-numeric hostname target (resolved server-side).
        assert!(acl.permits("internal.host", 22));
    }

    #[test]
    fn bare_ip_is_host_rule() {
        let acl = TargetAcl::from_patterns(Some(&["127.0.0.1".to_string()]), None).unwrap();
        assert!(acl.permits("127.0.0.1", 80));
        assert!(!acl.permits("127.0.0.2", 80));
    }

    #[test]
    fn ipv6_cidr_matches() {
        let acl = TargetAcl::from_patterns(None, Some(&["::1/128".to_string()])).unwrap();
        assert!(!acl.permits("::1", 80));
        assert!(acl.permits("2001:db8::1", 80));
    }

    #[test]
    fn host_glob_is_case_insensitive() {
        let acl = TargetAcl::from_patterns(Some(&["*.Example.COM".to_string()]), None).unwrap();
        assert!(acl.permits("WWW.EXAMPLE.COM", 443));
    }

    #[test]
    fn bad_cidr_rejected_at_validation() {
        let err = TargetAcl::from_patterns(Some(&["10.0.0.0/33".to_string()]), None).unwrap_err();
        assert!(matches!(err, TargetAclError::BadCidr(_)));
        let err2 =
            TargetAcl::from_patterns(None, Some(&["192.168.1.1/40".to_string()])).unwrap_err();
        assert!(matches!(err2, TargetAclError::BadCidr(_)));
    }

    #[test]
    fn empty_pattern_rejected() {
        let err = TargetAcl::from_patterns(Some(&["   ".to_string()]), None).unwrap_err();
        assert!(matches!(err, TargetAclError::Empty));
    }

    #[test]
    fn glob_edge_cases() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*c", "abc"));
        assert!(glob_match("a*c", "ac"));
        assert!(glob_match("a*c", "aXXXc"));
        assert!(!glob_match("a*c", "abd"));
        assert!(glob_match("*.com", "x.com"));
        assert!(!glob_match("*.com", "com"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exacto"));
    }

    #[test]
    fn exact_host_no_wildcard() {
        let acl = TargetAcl::from_patterns(Some(&["db.example.com".to_string()]), None).unwrap();
        assert!(acl.permits("db.example.com", 5432));
        assert!(!acl.permits("x.db.example.com", 5432));
        assert!(!acl.permits("db.example.org", 5432));
    }

    #[test]
    fn mapped_v6_denied_by_v4_cidr() {
        // `::ffff:10.0.0.1` (IPv4-mapped IPv6, ATYP=IPv6 SOCKS5 request) must be
        // canonicalized to 10.0.0.1 and caught by a v4 CIDR deny rule.
        let acl = TargetAcl::from_patterns(None, Some(&["10.0.0.0/8".to_string()])).unwrap();
        assert!(!acl.permits("::ffff:10.0.0.1", 22));
        assert!(!acl.permits("::ffff:10.255.255.255", 22));
        // Genuine v4 still blocked; out-of-range v4 still allowed.
        assert!(!acl.permits("10.0.0.1", 22));
        assert!(acl.permits("11.0.0.1", 22));
    }

    #[test]
    fn mapped_v6_metadata_denied() {
        // The headline SSRF case: deny the cloud metadata IP, attacker tries
        // the v4-mapped v6 literal.
        let acl = TargetAcl::from_patterns(None, Some(&["169.254.169.254".to_string()])).unwrap();
        assert!(!acl.permits("169.254.169.254", 80));
        assert!(!acl.permits("::ffff:169.254.169.254", 80));
        // Unrelated address still allowed.
        assert!(acl.permits("::ffff:8.8.8.8", 80));
    }

    #[test]
    fn mapped_v6_rule_canonicalized_too() {
        // A deny rule written as a mapped-v6 literal must also match the v4 target.
        let acl =
            TargetAcl::from_patterns(None, Some(&["::ffff:169.254.169.254".to_string()])).unwrap();
        assert!(!acl.permits("169.254.169.254", 80));
        assert!(!acl.permits("::ffff:169.254.169.254", 80));
    }

    #[test]
    fn mapped_v6_loopback_denied_by_v4_cidr() {
        let acl = TargetAcl::from_patterns(None, Some(&["127.0.0.0/8".to_string()])).unwrap();
        assert!(!acl.permits("127.0.0.1", 80));
        assert!(!acl.permits("::ffff:127.0.0.1", 80));
        // True IPv6 loopback is a distinct family — a v4 rule does NOT cover it.
        assert!(acl.permits("::1", 80));
    }

    #[test]
    fn v6_loopback_matched_by_v6_rule() {
        // To block IPv6 loopback the operator uses a v6 rule; canonicalization
        // does not interfere with non-mapped v6 addresses.
        let acl = TargetAcl::from_patterns(None, Some(&["::1/128".to_string()])).unwrap();
        assert!(!acl.permits("::1", 80));
        assert!(acl.permits("127.0.0.1", 80));
    }

    #[test]
    fn trailing_dot_fqdn_denied_by_glob() {
        // Absolute FQDN with a trailing dot must match a dot-less deny glob.
        let acl =
            TargetAcl::from_patterns(None, Some(&["secret.example.com".to_string()])).unwrap();
        assert!(!acl.permits("secret.example.com", 443));
        assert!(!acl.permits("secret.example.com.", 443));
        // Unrelated host still allowed.
        assert!(acl.permits("public.example.com", 443));
    }

    #[test]
    fn trailing_dot_wildcard_glob() {
        let acl = TargetAcl::from_patterns(None, Some(&["*.internal".to_string()])).unwrap();
        assert!(!acl.permits("db.internal", 5432));
        assert!(!acl.permits("db.internal.", 5432));
    }

    #[test]
    fn deny_glob_case_insensitive() {
        // Deny side must be case-insensitive too (matches() lowercases host).
        let acl =
            TargetAcl::from_patterns(None, Some(&["*.Internal.EXAMPLE".to_string()])).unwrap();
        assert!(!acl.permits("DB.internal.example", 5432));
        assert!(!acl.permits("Db.Internal.Example.", 5432));
    }

    #[test]
    fn mapped_v6_allowlist_fails_closed() {
        // Allow-list mode stays fail-closed: a mapped v6 within the allowed
        // range passes; one outside is denied (no family-mismatch escape).
        let acl = TargetAcl::from_patterns(Some(&["10.0.0.0/8".to_string()]), None).unwrap();
        assert!(acl.permits("::ffff:10.1.2.3", 22));
        assert!(acl.permits("10.1.2.3", 22));
        assert!(!acl.permits("::ffff:8.8.8.8", 22));
        assert!(!acl.permits("8.8.8.8", 22));
    }

    #[test]
    fn numeric_ip_encodings_are_normalized_for_deny_rules() {
        // Rust's `IpAddr` parser rejects legacy `inet_aton`-style encodings,
        // but common resolvers may still map them to IP addresses on the SSH
        // server. Normalize them here so deny-only IP policies cannot be
        // bypassed by sending the alternate spelling as a SOCKS/CONNECT host.
        let deny = TargetAcl::from_patterns(
            None,
            Some(&["127.0.0.0/8".to_string(), "169.254.169.254".to_string()]),
        )
        .unwrap();
        for form in [
            "127.000.000.001", // octal zero-padded octets
            "0x7f.0.0.1",      // hex octet
            "0x7f000001",      // hex 32-bit dword
            "2130706433",      // decimal 32-bit dword
            "127.1",           // classful short form
            "0xa9fea9fe",      // metadata IP as hex dword
            "169.254.43518",   // metadata IP with 16-bit final component
        ] {
            assert!(
                !deny.permits(form, 22),
                "{form:?} must normalize to a denied IP address"
            );
        }
        assert!(!deny.permits("127.0.0.1", 22));
        assert!(deny.permits("8.8.8.8", 53));
        assert!(deny.permits("example.com", 443));
    }

    #[test]
    fn numeric_ip_encodings_fail_closed_under_allow_list() {
        // With an allow-list set, numeric forms either normalize outside the
        // allowed range or match no allow rule and are denied.
        let allow =
            TargetAcl::from_patterns(Some(&["*.internal.example".to_string()]), None).unwrap();
        for form in [
            "127.000.000.001",
            "0x7f.0.0.1",
            "2130706433",
            "127.1",
            "169.254.169.254", // the metadata IP, canonical — still not allowed
        ] {
            assert!(
                !allow.permits(form, 80),
                "{form:?} matches no allow rule and must be denied (fail-closed)"
            );
        }
        // A genuinely allowed host still passes.
        assert!(allow.permits("db.internal.example", 5432));
    }

    #[test]
    fn mapped_v6_hex_group_form_is_canonicalized_not_bypassed() {
        // The mapped-IPv6 form written with hex groups (`::ffff:7f00:1`) is a
        // valid IPv6 literal that DOES parse, and `to_canonical` collapses it to
        // 127.0.0.1 — so a v4 CIDR deny catches it. This pins that the one
        // numeric form std parses is not a deny-list bypass.
        let deny = TargetAcl::from_patterns(None, Some(&["127.0.0.0/8".to_string()])).unwrap();
        assert!(!deny.permits("::ffff:7f00:1", 22));
        assert!(!deny.permits("::ffff:127.0.0.1", 22));
        // And the metadata IP in mapped hex-group form against its own deny.
        let deny_md =
            TargetAcl::from_patterns(None, Some(&["169.254.169.254".to_string()])).unwrap();
        assert!(!deny_md.permits("::ffff:a9fe:a9fe", 80));
    }

    #[test]
    fn legitimate_targets_still_pass_with_deny_list() {
        // Behavior-preserving for valid inputs: a deny on internal ranges must
        // not block legitimate public IPs or hostnames.
        let acl = TargetAcl::from_patterns(
            None,
            Some(&[
                "10.0.0.0/8".to_string(),
                "127.0.0.0/8".to_string(),
                "169.254.0.0/16".to_string(),
            ]),
        )
        .unwrap();
        assert!(acl.permits("93.184.216.34", 443));
        assert!(acl.permits("::ffff:93.184.216.34", 443));
        assert!(acl.permits("api.example.com", 443));
        assert!(acl.permits("api.example.com.", 443));
        assert!(acl.permits("2001:db8::1", 443));
    }
}
