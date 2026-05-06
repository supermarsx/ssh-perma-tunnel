//! Cross-platform network interface enumeration.
//!
//! Wraps the `if-addrs` crate and folds per-address records into one
//! [`Interface`] per logical interface name with split IPv4/IPv6 lists.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use spt_core::error::{Error, Result};

/// A logical network interface with its bound addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// OS interface name (e.g. `lo`, `eth0`, `Loopback Pseudo-Interface 1`).
    pub name: String,
    /// IPv4 addresses bound to this interface.
    pub ipv4: Vec<Ipv4Addr>,
    /// IPv6 addresses bound to this interface.
    pub ipv6: Vec<Ipv6Addr>,
    /// Whether this interface is the loopback interface.
    pub is_loopback: bool,
    /// Whether this interface is administratively up. `if-addrs` lists only
    /// up interfaces, so this is `true` for any returned interface.
    pub is_up: bool,
    /// Hardware (MAC) address, if available.
    pub mac: Option<[u8; 6]>,
}

impl Interface {
    /// Returns true if this interface has at least one IPv4 address.
    #[must_use]
    pub fn has_ipv4(&self) -> bool {
        !self.ipv4.is_empty()
    }

    /// Returns true if this interface has at least one IPv6 address.
    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        !self.ipv6.is_empty()
    }
}

/// Enumerate all up network interfaces on the host.
///
/// Returns an [`Error::RuntimeFailure`] if the OS query fails. The result is
/// stable-ordered by interface name.
pub fn list() -> Result<Vec<Interface>> {
    let raw = if_addrs::get_if_addrs()
        .map_err(|e| Error::RuntimeFailure(format!("interface enumeration failed: {e}")))?;

    let mut by_name: BTreeMap<String, Interface> = BTreeMap::new();
    for entry in raw {
        let iface = by_name.entry(entry.name.clone()).or_insert_with(|| Interface {
            name: entry.name.clone(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            is_loopback: false,
            is_up: true,
            mac: None,
        });
        if entry.is_loopback() {
            iface.is_loopback = true;
        }
        match entry.ip() {
            std::net::IpAddr::V4(v4) => {
                if !iface.ipv4.contains(&v4) {
                    iface.ipv4.push(v4);
                }
            }
            std::net::IpAddr::V6(v6) => {
                if !iface.ipv6.contains(&v6) {
                    iface.ipv6.push(v6);
                }
            }
        }
    }

    Ok(by_name.into_values().collect())
}

/// Find an interface by exact name.
#[must_use]
pub fn find_by_name<'a>(ifaces: &'a [Interface], name: &str) -> Option<&'a Interface> {
    ifaces.iter().find(|i| i.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_returns_at_least_loopback() {
        let ifaces = list().expect("enumerate interfaces");
        assert!(!ifaces.is_empty(), "expected at least one interface");
        assert!(
            ifaces.iter().any(|i| i.is_loopback),
            "expected at least one loopback interface, got {ifaces:?}"
        );
    }

    #[test]
    fn loopback_has_loopback_address() {
        let ifaces = list().expect("enumerate interfaces");
        let lo = ifaces.iter().find(|i| i.is_loopback).expect("loopback present");
        let has_v4_loopback = lo.ipv4.iter().any(Ipv4Addr::is_loopback);
        let has_v6_loopback = lo.ipv6.iter().any(|ip| *ip == Ipv6Addr::LOCALHOST);
        assert!(
            has_v4_loopback || has_v6_loopback,
            "loopback interface should have a loopback ip; got {lo:?}"
        );
    }
}
