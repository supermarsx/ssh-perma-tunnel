//! Runtime enforcement of `[network.gateway]` — the network-safety guard.
//!
//! `[network.gateway]` lets an operator declare the network the host is
//! *expected* to be on ("only run the tunnel when I'm actually on the office
//! LAN / the right VPN"). Before any profile connects, [`enforce`] resolves the
//! host's live default gateway / egress interface (via [`spt_net::gateway`])
//! and compares it against the configured expectations:
//!
//! * `require_gateway_match = true` → **fail closed**: a mismatch (or an
//!   inability to determine the live route) returns a terminal
//!   [`Error::RuntimeFailure`] that aborts startup before any connection is
//!   attempted.
//! * `require_gateway_match` absent / `false` → a mismatch is a `tracing::warn!`
//!   and startup proceeds.
//!
//! `policy` selects *which* facts are checked:
//!
//! | `policy` | behaviour |
//! |----------|-----------|
//! | `disabled` | enforcement skipped entirely |
//! | `default_route` | compare `default_gateway` + `interface` against the default route |
//! | `interface_only` | compare only `interface` against the default route |
//! | `route_to_target` | compare `default_gateway` + `interface` against the route to `route_check_target` |
//! | absent | auto: `route_to_target` when `route_check_target` is set, else `default_route` |
//!
//! The comparison is split from the resolver behind the
//! [`spt_net::gateway::GatewayResolver`] seam so it is unit-tested with a fake
//! (see the tests below) rather than depending on the CI runner's live network.
//!
//! ## Platform caveat
//!
//! Interface-name matching is only as precise as the OS routing table exposes.
//! On Windows the compared name is the adapter *alias* (`"Ethernet"`); on
//! macOS/BSD it is the BSD device (`"en0"`) parsed from `route -n get`; on
//! Linux it is the kernel interface name (`"eth0"`). Configure `interface` to
//! match the platform's own naming.

use std::net::IpAddr;

use spt_config::schema::{Config, NetworkGateway};
use spt_core::{Error, Result};
use spt_net::gateway::{GatewayResolver, RouteInfo, SystemGatewayResolver};

/// Which routing facts the configured `policy` asks us to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `policy = "disabled"` — skip enforcement.
    Disabled,
    /// Compare against the system default route.
    DefaultRoute,
    /// Compare only the interface against the system default route.
    InterfaceOnly,
    /// Compare against the route to `route_check_target`.
    RouteToTarget,
}

fn resolve_mode(gateway: &NetworkGateway) -> Mode {
    match gateway.policy.as_deref() {
        Some("disabled") => Mode::Disabled,
        Some("default_route") => Mode::DefaultRoute,
        Some("interface_only") => Mode::InterfaceOnly,
        Some("route_to_target") => Mode::RouteToTarget,
        // Auto: prefer the target-route path when a target is configured.
        _ if gateway.route_check_target.is_some() => Mode::RouteToTarget,
        _ => Mode::DefaultRoute,
    }
}

/// Enforce `[network.gateway]` against the live routing table using the real
/// system resolver. No-op when `[network.gateway]` is absent.
pub fn enforce(cfg: &Config) -> Result<()> {
    let Some(gateway) = cfg.network.as_ref().and_then(|n| n.gateway.as_ref()) else {
        return Ok(());
    };
    enforce_with(gateway, &SystemGatewayResolver)
}

/// Testable core: enforce `gateway` using an injected [`GatewayResolver`].
fn enforce_with(gateway: &NetworkGateway, resolver: &dyn GatewayResolver) -> Result<()> {
    let require = gateway.require_gateway_match == Some(true);
    let mode = resolve_mode(gateway);

    if mode == Mode::Disabled {
        tracing::info!(
            target: "spt_bin::gateway",
            "[network.gateway] policy = disabled — enforcement skipped",
        );
        return Ok(());
    }

    let check_gateway = matches!(mode, Mode::DefaultRoute | Mode::RouteToTarget);
    let has_comparable =
        gateway.interface.is_some() || (check_gateway && gateway.default_gateway.is_some());
    if !has_comparable {
        tracing::info!(
            target: "spt_bin::gateway",
            "[network.gateway] configured but no default_gateway/interface to compare — nothing to enforce",
        );
        return Ok(());
    }

    // Resolve the observed route for this mode. A resolver error or an empty
    // result is folded into an empty `RouteInfo`, so the per-field checks below
    // report "could not be determined" and fail closed under `require`.
    let (observed, source): (RouteInfo, String) = match mode {
        Mode::RouteToTarget => {
            let Some(raw) = gateway.route_check_target.as_deref() else {
                tracing::warn!(
                    target: "spt_bin::gateway",
                    warning_code = "network_gateway_no_target",
                    "[network.gateway] policy = route_to_target but route_check_target is unset — nothing to enforce",
                );
                return Ok(());
            };
            let target: IpAddr = match raw.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    return decide(
                        require,
                        vec![format!("route_check_target `{raw}` is not a valid IP: {e}")],
                    );
                }
            };
            (
                resolve(|| resolver.route_to(target)),
                format!("route to {target}"),
            )
        }
        _ => (
            resolve(|| resolver.default_route()),
            "default route".to_owned(),
        ),
    };

    let mut mismatches: Vec<String> = Vec::new();

    if check_gateway {
        if let Some(expected_raw) = gateway.default_gateway.as_deref() {
            match expected_raw.parse::<IpAddr>() {
                Ok(expected) => match observed.gateway {
                    Some(actual) if actual == expected => {}
                    Some(actual) => mismatches.push(format!(
                        "expected gateway {expected} but the {source} egresses via {actual}"
                    )),
                    None => mismatches.push(format!(
                        "expected gateway {expected} but the {source} has no gateway / could not be determined"
                    )),
                },
                Err(e) => mismatches.push(format!(
                    "configured default_gateway `{expected_raw}` is not a valid IP: {e}"
                )),
            }
        }
    }

    if let Some(expected) = gateway.interface.as_deref() {
        match observed.interface.as_deref() {
            Some(actual) if actual == expected => {}
            Some(actual) => mismatches.push(format!(
                "expected egress interface `{expected}` but the {source} uses `{actual}`"
            )),
            None => mismatches.push(format!(
                "expected egress interface `{expected}` but the {source} interface could not be determined"
            )),
        }
    }

    if mismatches.is_empty() {
        tracing::info!(
            target: "spt_bin::gateway",
            source = %source,
            "[network.gateway] host is on the expected network",
        );
        Ok(())
    } else {
        decide(require, mismatches)
    }
}

/// Resolve a route, folding both resolver errors and empty results into an
/// empty [`RouteInfo`] (logged at debug). "Undetermined" then flows through the
/// per-field checks as a mismatch, so it fails closed under `require`.
fn resolve(f: impl FnOnce() -> Result<RouteInfo>) -> RouteInfo {
    match f() {
        Ok(info) => info,
        Err(e) => {
            tracing::debug!(
                target: "spt_bin::gateway",
                error = %e,
                "gateway resolution failed; treating the live route as undetermined",
            );
            RouteInfo::default()
        }
    }
}

/// Turn a non-empty mismatch list into either a fail-closed error (`require`)
/// or a warning (advisory). An empty list must not reach here.
fn decide(require: bool, mismatches: Vec<String>) -> Result<()> {
    let detail = mismatches.join("; ");
    if require {
        tracing::error!(
            target: "spt_bin::gateway",
            warning_code = "network_gateway_mismatch",
            "[network.gateway] require_gateway_match = true and the host is NOT on the expected network — refusing to connect: {detail}",
        );
        Err(Error::RuntimeFailure(format!(
            "[network.gateway] fail-closed: host is not on the expected network ({detail})"
        )))
    } else {
        tracing::warn!(
            target: "spt_bin::gateway",
            warning_code = "network_gateway_mismatch",
            "[network.gateway] host may not be on the expected network (require_gateway_match not set — continuing): {detail}",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake resolver: `None` fields simulate a table-read failure.
    struct Fake {
        default: Option<RouteInfo>,
        target: Option<RouteInfo>,
    }

    impl Fake {
        fn with_default(gateway: &str, iface: &str) -> Self {
            Self {
                default: Some(RouteInfo {
                    gateway: Some(gateway.parse().unwrap()),
                    interface: Some(iface.to_owned()),
                }),
                target: None,
            }
        }
    }

    impl GatewayResolver for Fake {
        fn default_route(&self) -> Result<RouteInfo> {
            self.default
                .clone()
                .ok_or_else(|| Error::RuntimeFailure("no default route".into()))
        }
        fn route_to(&self, _target: IpAddr) -> Result<RouteInfo> {
            self.target
                .clone()
                .ok_or_else(|| Error::RuntimeFailure("no route".into()))
        }
    }

    fn cfg(
        default_gateway: Option<&str>,
        interface: Option<&str>,
        require: bool,
    ) -> NetworkGateway {
        NetworkGateway {
            default_gateway: default_gateway.map(str::to_owned),
            interface: interface.map(str::to_owned),
            require_gateway_match: Some(require),
            ..Default::default()
        }
    }

    #[test]
    fn matching_gateway_and_interface_passes() {
        let resolver = Fake::with_default("192.168.1.1", "eth0");
        let gw = cfg(Some("192.168.1.1"), Some("eth0"), true);
        assert!(enforce_with(&gw, &resolver).is_ok());
    }

    #[test]
    fn mismatch_with_require_fails_closed() {
        let resolver = Fake::with_default("10.0.0.1", "eth0");
        let gw = cfg(Some("192.168.1.1"), Some("eth0"), true);
        let err = enforce_with(&gw, &resolver).unwrap_err();
        assert!(
            matches!(err, Error::RuntimeFailure(_)),
            "fail-closed must be a terminal RuntimeFailure, got {err:?}"
        );
    }

    #[test]
    fn mismatch_without_require_warns_and_proceeds() {
        let resolver = Fake::with_default("10.0.0.1", "eth0");
        let gw = cfg(Some("192.168.1.1"), Some("eth0"), false);
        assert!(
            enforce_with(&gw, &resolver).is_ok(),
            "advisory mismatch must not block startup"
        );
    }

    #[test]
    fn interface_mismatch_with_require_fails_closed() {
        let resolver = Fake::with_default("192.168.1.1", "wlan0");
        let gw = cfg(Some("192.168.1.1"), Some("eth0"), true);
        assert!(enforce_with(&gw, &resolver).is_err());
    }

    #[test]
    fn undetermined_route_fails_closed_under_require() {
        // Resolver returns Err → undetermined → fail closed.
        let resolver = Fake {
            default: None,
            target: None,
        };
        let gw = cfg(Some("192.168.1.1"), Some("eth0"), true);
        assert!(
            enforce_with(&gw, &resolver).is_err(),
            "cannot-determine must fail closed, not be treated as a match"
        );
    }

    #[test]
    fn undetermined_route_without_require_only_warns() {
        let resolver = Fake {
            default: None,
            target: None,
        };
        let gw = cfg(Some("192.168.1.1"), Some("eth0"), false);
        assert!(enforce_with(&gw, &resolver).is_ok());
    }

    #[test]
    fn disabled_policy_skips_even_on_mismatch() {
        let resolver = Fake::with_default("10.0.0.1", "wlan0");
        let mut gw = cfg(Some("192.168.1.1"), Some("eth0"), true);
        gw.policy = Some("disabled".to_owned());
        assert!(
            enforce_with(&gw, &resolver).is_ok(),
            "policy=disabled must short-circuit before any comparison"
        );
    }

    #[test]
    fn interface_only_ignores_gateway_mismatch() {
        // Gateway differs, but interface_only only checks the interface.
        let resolver = Fake::with_default("10.0.0.1", "eth0");
        let mut gw = cfg(Some("192.168.1.1"), Some("eth0"), true);
        gw.policy = Some("interface_only".to_owned());
        assert!(enforce_with(&gw, &resolver).is_ok());
    }

    #[test]
    fn route_to_target_matches_target_interface() {
        let resolver = Fake {
            default: None,
            target: Some(RouteInfo {
                gateway: Some("192.168.1.1".parse().unwrap()),
                interface: Some("eth0".to_owned()),
            }),
        };
        let mut gw = cfg(Some("192.168.1.1"), Some("eth0"), true);
        gw.route_check_target = Some("8.8.8.8".to_owned());
        // No explicit policy → auto-selects route_to_target because a target is set.
        assert!(enforce_with(&gw, &resolver).is_ok());
    }

    #[test]
    fn route_to_target_interface_mismatch_fails_closed() {
        let resolver = Fake {
            default: None,
            target: Some(RouteInfo {
                gateway: Some("192.168.1.1".parse().unwrap()),
                interface: Some("wlan0".to_owned()),
            }),
        };
        let mut gw = cfg(None, Some("eth0"), true);
        gw.route_check_target = Some("8.8.8.8".to_owned());
        assert!(enforce_with(&gw, &resolver).is_err());
    }

    #[test]
    fn no_comparable_fields_is_ok() {
        // require + policy but neither gateway nor interface set → nothing to do.
        let resolver = Fake::with_default("192.168.1.1", "eth0");
        let gw = NetworkGateway {
            policy: Some("default_route".to_owned()),
            ..Default::default()
        };
        assert!(enforce_with(&gw, &resolver).is_ok());
    }
}
