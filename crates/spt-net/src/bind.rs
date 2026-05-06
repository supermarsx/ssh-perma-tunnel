//! Bind-mode resolution: convert spec §9.5 / §9.14 user preferences into
//! concrete socket addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;

use spt_core::error::{Error, Result};

use crate::interfaces::{self, Interface};

/// IP family preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv4 only.
    Ipv4,
    /// IPv6 only.
    Ipv6,
    /// Both, where supported.
    Both,
}

/// `auto_interface` selection preferences (spec §9.5: name, prefix, CIDR,
/// route-to-target, platform default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoPrefer {
    /// Prefer interfaces whose name equals one of the given names, in order.
    Name(Vec<String>),
    /// Prefer interfaces whose name starts with one of the given prefixes.
    Prefix(Vec<String>),
    /// Prefer addresses falling inside one of the given CIDRs.
    Cidr(Vec<IpNet>),
    /// Prefer the platform default (any non-loopback interface that's up).
    PlatformDefault,
    /// Restrict to a particular family regardless of preference (used for
    /// tests and for `bind_ipv6 = "off"`).
    Family(Family),
}

/// Resolved bind preference per spec §9.5 / §9.14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindMode {
    /// Loopback only (`127.0.0.1` and/or `::1`).
    Loopback,
    /// A specific numeric IP address.
    SpecificIp(IpAddr),
    /// All addresses on a named interface, optionally filtered by family.
    SpecificInterface {
        /// OS interface name.
        name: String,
        /// IP family filter.
        family: Family,
    },
    /// Wildcard bind on every interface (`0.0.0.0` and/or `::`).
    AllInterfaces,
    /// Pick an interface using the supplied preference.
    AutoInterface {
        /// How to choose.
        prefer: AutoPrefer,
    },
}

impl BindMode {
    /// Whether this mode results in a non-loopback bind. Useful upstream as
    /// the trigger for the `expose = true` requirement (spec §9.14).
    #[must_use]
    pub fn requires_expose(&self) -> bool {
        match self {
            Self::Loopback => false,
            Self::SpecificIp(ip) => !ip.is_loopback() && !ip.is_unspecified(),
            Self::SpecificInterface { .. } | Self::AutoInterface { .. } | Self::AllInterfaces => {
                true
            }
        }
    }
}

/// Resolve a bind mode into a sorted, deduplicated list of concrete socket
/// addresses to bind.
///
/// Errors with [`Error::LocalBindFailed`] when the named interface does not
/// exist, the auto preference matches nothing, or the family filter excludes
/// every available address.
pub fn resolve_bind(mode: &BindMode, port: u16) -> Result<Vec<SocketAddr>> {
    let ifaces = interfaces::list()?;
    let addrs = match mode {
        BindMode::Loopback => vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ],
        BindMode::SpecificIp(ip) => vec![SocketAddr::new(*ip, port)],
        BindMode::AllInterfaces => vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
        ],
        BindMode::SpecificInterface { name, family } => {
            let iface = interfaces::find_by_name(&ifaces, name).ok_or_else(|| {
                Error::LocalBindFailed {
                    address: name.clone(),
                    reason: format!("interface `{name}` not found"),
                }
            })?;
            let out = collect_for_family(iface, *family, port);
            if out.is_empty() {
                return Err(Error::LocalBindFailed {
                    address: name.clone(),
                    reason: format!(
                        "interface `{name}` has no addresses matching family {family:?}"
                    ),
                });
            }
            out
        }
        BindMode::AutoInterface { prefer } => resolve_auto(&ifaces, prefer, port)?,
    };

    Ok(sort_dedup(addrs))
}

fn collect_for_family(iface: &Interface, family: Family, port: u16) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if matches!(family, Family::Ipv4 | Family::Both) {
        for ip in &iface.ipv4 {
            out.push(SocketAddr::new(IpAddr::V4(*ip), port));
        }
    }
    if matches!(family, Family::Ipv6 | Family::Both) {
        for ip in &iface.ipv6 {
            out.push(SocketAddr::new(IpAddr::V6(*ip), port));
        }
    }
    out
}

fn resolve_auto(
    ifaces: &[Interface],
    prefer: &AutoPrefer,
    port: u16,
) -> Result<Vec<SocketAddr>> {
    let mut out: Vec<SocketAddr> = Vec::new();
    match prefer {
        AutoPrefer::Name(names) => {
            for name in names {
                if let Some(iface) = interfaces::find_by_name(ifaces, name) {
                    out.extend(collect_for_family(iface, Family::Both, port));
                }
            }
        }
        AutoPrefer::Prefix(prefixes) => {
            for iface in ifaces {
                if prefixes.iter().any(|p| iface.name.starts_with(p)) {
                    out.extend(collect_for_family(iface, Family::Both, port));
                }
            }
        }
        AutoPrefer::Cidr(nets) => {
            for iface in ifaces {
                for ip in &iface.ipv4 {
                    if nets.iter().any(|n| n.contains(&IpAddr::V4(*ip))) {
                        out.push(SocketAddr::new(IpAddr::V4(*ip), port));
                    }
                }
                for ip in &iface.ipv6 {
                    if nets.iter().any(|n| n.contains(&IpAddr::V6(*ip))) {
                        out.push(SocketAddr::new(IpAddr::V6(*ip), port));
                    }
                }
            }
        }
        AutoPrefer::PlatformDefault => {
            for iface in ifaces.iter().filter(|i| !i.is_loopback) {
                out.extend(collect_for_family(iface, Family::Both, port));
            }
        }
        AutoPrefer::Family(family) => {
            for iface in ifaces.iter().filter(|i| !i.is_loopback) {
                out.extend(collect_for_family(iface, *family, port));
            }
        }
    }

    if out.is_empty() {
        return Err(Error::LocalBindFailed {
            address: format!("auto:{prefer:?}"),
            reason: "no interface matched the auto preference".into(),
        });
    }
    Ok(out)
}

fn sort_dedup(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.sort_by(|a, b| {
        // v4 first, then v6; then by IP, then by port.
        let fam_a = u8::from(a.is_ipv6());
        let fam_b = u8::from(b.is_ipv6());
        fam_a
            .cmp(&fam_b)
            .then_with(|| a.ip().to_string().cmp(&b.ip().to_string()))
            .then_with(|| a.port().cmp(&b.port()))
    });
    addrs.dedup();
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_resolves_to_v4_and_v6() {
        let addrs = resolve_bind(&BindMode::Loopback, 8080).unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)));
        assert!(addrs.contains(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)));
    }

    #[test]
    fn all_interfaces_resolves_to_unspecified() {
        let addrs = resolve_bind(&BindMode::AllInterfaces, 9000).unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000)));
        assert!(addrs.contains(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 9000)));
    }

    #[test]
    fn specific_ip_passes_through() {
        let addrs =
            resolve_bind(&BindMode::SpecificIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), 22)
                .unwrap();
        assert_eq!(addrs, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22)]);
    }

    #[test]
    fn specific_interface_filters_by_name() {
        // Find a real loopback interface name on the host and ensure it resolves.
        let ifaces = interfaces::list().unwrap();
        let lo = ifaces.iter().find(|i| i.is_loopback).expect("loopback present");
        let addrs = resolve_bind(
            &BindMode::SpecificInterface {
                name: lo.name.clone(),
                family: Family::Both,
            },
            5555,
        )
        .unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 5555));
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }

    #[test]
    fn specific_interface_unknown_errors() {
        let err = resolve_bind(
            &BindMode::SpecificInterface {
                name: "definitely-not-a-real-iface-xyzzy".into(),
                family: Family::Both,
            },
            1,
        )
        .unwrap_err();
        assert!(matches!(err, Error::LocalBindFailed { .. }), "got {err}");
    }

    #[test]
    fn auto_interface_family_v4_excludes_v6() {
        // Use Family preference forcing v4 only; loopback exists everywhere
        // but PlatformDefault excludes loopback. Use Family on a non-loopback
        // search: there might be no non-loopback interface in CI containers.
        // Fall back: build the result manually to ensure the filter is right.
        let ifaces = interfaces::list().unwrap();
        let has_non_loopback = ifaces.iter().any(|i| !i.is_loopback);
        if !has_non_loopback {
            return;
        }
        let addrs = resolve_bind(
            &BindMode::AutoInterface {
                prefer: AutoPrefer::Family(Family::Ipv4),
            },
            1234,
        );
        if let Ok(addrs) = addrs {
            assert!(addrs.iter().all(SocketAddr::is_ipv4), "got {addrs:?}");
        }
    }

    #[test]
    fn auto_interface_unmatched_errors() {
        let err = resolve_bind(
            &BindMode::AutoInterface {
                prefer: AutoPrefer::Name(vec!["nope-xyzzy".into()]),
            },
            1,
        )
        .unwrap_err();
        assert!(matches!(err, Error::LocalBindFailed { .. }));
    }

    #[test]
    fn requires_expose_flag() {
        assert!(!BindMode::Loopback.requires_expose());
        assert!(BindMode::AllInterfaces.requires_expose());
        assert!(!BindMode::SpecificIp(IpAddr::V4(Ipv4Addr::LOCALHOST)).requires_expose());
        assert!(BindMode::SpecificIp(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).requires_expose());
    }

    #[test]
    fn results_are_sorted_and_deduped() {
        let addrs = resolve_bind(&BindMode::AllInterfaces, 80).unwrap();
        let mut sorted = addrs.clone();
        sorted.sort_by(|a, b| {
            u8::from(a.is_ipv6())
                .cmp(&u8::from(b.is_ipv6()))
                .then_with(|| a.ip().to_string().cmp(&b.ip().to_string()))
                .then_with(|| a.port().cmp(&b.port()))
        });
        assert_eq!(addrs, sorted);
        let mut dedup = addrs.clone();
        dedup.dedup();
        assert_eq!(addrs.len(), dedup.len());
    }
}
