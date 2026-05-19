//! Round-robin endpoint cycling configuration (`[round_robin]` table).
//!
//! Disabled by default. When enabled, the supervisor uses one of several
//! [`SelectionPolicy`] strategies to cycle through endpoints (and, optionally,
//! DNS A/AAAA records of each endpoint hostname).
//!
//! See `t4-e4` in `.orchestration/plans/t4.md`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// `[round_robin]` table — per-profile endpoint cycling configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundRobinConfig {
    /// Master enable flag. Default `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Selection policy to use when `enabled = true`.
    #[serde(default)]
    pub policy: SelectionPolicy,

    /// If `true`, expand each endpoint hostname into its A/AAAA records and
    /// cycle through those as well as through the endpoint list.
    #[serde(default)]
    pub dns_round_robin: bool,

    /// How often to re-resolve hostnames (TTL is ignored; this knob wins).
    #[serde(
        default = "default_dns_refresh",
        with = "spt_core::duration::serde_duration"
    )]
    pub dns_refresh_interval: Duration,

    /// Skip a failing endpoint for at least this long after a failure.
    #[serde(
        default = "default_cooldown",
        with = "spt_core::duration::serde_duration"
    )]
    pub cooldown_after_failure: Duration,

    /// For [`SelectionPolicy::Sticky`] — how long a chosen endpoint stays
    /// pinned before the next selection rotates.
    #[serde(
        default = "default_sticky_ttl",
        with = "spt_core::duration::serde_duration"
    )]
    pub sticky_session_ttl: Duration,
}

impl Default for RoundRobinConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: SelectionPolicy::default(),
            dns_round_robin: false,
            dns_refresh_interval: default_dns_refresh(),
            cooldown_after_failure: default_cooldown(),
            sticky_session_ttl: default_sticky_ttl(),
        }
    }
}

/// Endpoint selection algorithm.
///
/// Default is [`SelectionPolicy::RoundRobin`], but the surrounding
/// [`RoundRobinConfig`] defaults to `enabled = false` — the policy field only
/// takes effect once the table is explicitly enabled.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionPolicy {
    /// Cycle endpoints in declared order.
    #[default]
    RoundRobin,
    /// Uniformly random across endpoints.
    Random,
    /// Weighted-random by `[[profiles.endpoints]].weight`.
    Weighted,
    /// Pin to a chosen endpoint for `sticky_session_ttl`, then advance.
    Sticky,
    /// Prefer the endpoint with the lowest recorded failure count.
    LeastErrors,
}

const fn default_dns_refresh() -> Duration {
    Duration::from_secs(60)
}

const fn default_cooldown() -> Duration {
    Duration::from_secs(30)
}

const fn default_sticky_ttl() -> Duration {
    Duration::from_secs(5 * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let c = RoundRobinConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.policy, SelectionPolicy::RoundRobin);
        assert!(!c.dns_round_robin);
        assert_eq!(c.dns_refresh_interval, Duration::from_secs(60));
        assert_eq!(c.cooldown_after_failure, Duration::from_secs(30));
        assert_eq!(c.sticky_session_ttl, Duration::from_secs(300));
    }

    #[test]
    fn policy_default_is_round_robin() {
        assert_eq!(SelectionPolicy::default(), SelectionPolicy::RoundRobin);
    }

    #[test]
    fn toml_roundtrip_full() {
        let original = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::Weighted,
            dns_round_robin: true,
            dns_refresh_interval: Duration::from_secs(120),
            cooldown_after_failure: Duration::from_secs(45),
            sticky_session_ttl: Duration::from_secs(600),
        };
        let s = toml::to_string(&original).expect("serialize");
        let back: RoundRobinConfig = toml::from_str(&s).expect("deserialize");
        assert_eq!(original, back);
    }

    #[test]
    fn toml_roundtrip_minimal_uses_defaults() {
        let s = "";
        let c: RoundRobinConfig = toml::from_str(s).expect("deserialize");
        assert_eq!(c, RoundRobinConfig::default());
    }

    #[test]
    fn toml_policy_kebab_case() {
        let s = r#"
enabled = true
policy = "least-errors"
"#;
        let c: RoundRobinConfig = toml::from_str(s).expect("deserialize");
        assert!(c.enabled);
        assert_eq!(c.policy, SelectionPolicy::LeastErrors);
    }

    #[test]
    fn toml_duration_humantime() {
        let s = r#"
dns_refresh_interval = "2m"
cooldown_after_failure = "1m 30s"
sticky_session_ttl = "10m"
"#;
        let c: RoundRobinConfig = toml::from_str(s).expect("deserialize");
        assert_eq!(c.dns_refresh_interval, Duration::from_secs(120));
        assert_eq!(c.cooldown_after_failure, Duration::from_secs(90));
        assert_eq!(c.sticky_session_ttl, Duration::from_secs(600));
    }
}
