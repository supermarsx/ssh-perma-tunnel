//! Runtime DNS mode — the listener-level posture of [`crate::DnsServer`].
//!
//! The `[dns] mode` config key (`spt_config::schema::Dns::mode`) takes one of
//! four documented values (docs/dns.md):
//!
//! * `disabled` — the resolver is not started at all.
//! * `transparent_forwarder` — managed names answered locally; everything else
//!   forwarded to the configured upstream resolvers.
//! * `synthetic_only` — only managed names are answered; unmanaged names are
//!   `NXDOMAIN` (no upstream recursion). The "authoritative-only" posture.
//! * `hosts_file` — no listener; the managed zone is rendered into the system
//!   hosts file (see [`crate::hosts`]).
//!
//! Two of those — `disabled` and `hosts_file` — are decided *before* a
//! [`crate::DnsServer`] is built (the binary simply does not call
//! [`crate::DnsServerBuilder::run`] for them), so they have no in-listener
//! behavior. The remaining two control how the running listener treats
//! unmanaged names, and are modeled by [`DnsMode`]. The full config-string set
//! is preserved by [`DnsMode::from_config_str`] so the binary can map the
//! schema value directly and learn whether a listener should even be spawned.

/// How a running DNS listener treats names outside its managed zones.
///
/// Maps from the `[dns] mode` config values that actually start a listener.
/// `disabled` / `hosts_file` are handled by the binary (no listener), so they
/// are reported by [`DnsMode::from_config_str`] as `None` rather than being
/// variants here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsMode {
    /// `transparent_forwarder`: forward unmanaged names to the upstream
    /// resolver (if configured), else `REFUSED`. This is the historical
    /// default behavior.
    #[default]
    TransparentForwarder,
    /// `synthetic_only`: answer only for managed names; unmanaged names are
    /// `NXDOMAIN`, never recursed upstream. Authoritative-only posture.
    SyntheticOnly,
}

impl DnsMode {
    /// Parse a `[dns] mode` config string into the runtime mode.
    ///
    /// Returns:
    /// * `Ok(Some(mode))` for the two listener modes
    ///   (`transparent_forwarder`, `synthetic_only`),
    /// * `Ok(None)` for the no-listener modes (`disabled`, `hosts_file`) —
    ///   the caller should not start a [`crate::DnsServer`],
    /// * `Err(unknown)` for anything else (validation in `spt-config` should
    ///   already have rejected these, but we fail closed here too).
    ///
    /// An absent/empty value defaults to
    /// [`DnsMode::TransparentForwarder`] to match the historical behavior.
    pub fn from_config_str(s: &str) -> std::result::Result<Option<Self>, String> {
        match s.trim() {
            "" | "transparent_forwarder" => Ok(Some(Self::TransparentForwarder)),
            "synthetic_only" => Ok(Some(Self::SyntheticOnly)),
            "disabled" | "hosts_file" => Ok(None),
            other => Err(other.to_string()),
        }
    }

    /// `true` when unmanaged names must never be recursed upstream.
    #[must_use]
    pub fn is_authoritative_only(self) -> bool {
        matches!(self, Self::SyntheticOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_str_listener_modes() {
        assert_eq!(
            DnsMode::from_config_str("transparent_forwarder").unwrap(),
            Some(DnsMode::TransparentForwarder)
        );
        assert_eq!(
            DnsMode::from_config_str("synthetic_only").unwrap(),
            Some(DnsMode::SyntheticOnly)
        );
    }

    #[test]
    fn from_config_str_no_listener_modes_yield_none() {
        assert_eq!(DnsMode::from_config_str("disabled").unwrap(), None);
        assert_eq!(DnsMode::from_config_str("hosts_file").unwrap(), None);
    }

    #[test]
    fn from_config_str_empty_defaults_to_forwarder() {
        assert_eq!(
            DnsMode::from_config_str("").unwrap(),
            Some(DnsMode::TransparentForwarder)
        );
        assert_eq!(
            DnsMode::from_config_str("   ").unwrap(),
            Some(DnsMode::TransparentForwarder)
        );
    }

    #[test]
    fn from_config_str_unknown_is_err() {
        let err = DnsMode::from_config_str("bogus").unwrap_err();
        assert_eq!(err, "bogus");
    }

    #[test]
    fn default_is_transparent_forwarder() {
        assert_eq!(DnsMode::default(), DnsMode::TransparentForwarder);
    }

    #[test]
    fn authoritative_only_only_for_synthetic() {
        assert!(DnsMode::SyntheticOnly.is_authoritative_only());
        assert!(!DnsMode::TransparentForwarder.is_authoritative_only());
    }
}
