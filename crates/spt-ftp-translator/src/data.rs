//! Passive data-channel binding helpers.
//!
//! The translator NEVER opens active connections (PORT/EPRT are refused
//! with 502). Every transfer uses a listener bound from
//! [`TranslatorConfig::passive_port_range`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::TcpListener;

use crate::config::TranslatorConfig;
use crate::error::TranslatorError;

/// Newly-bound passive listener plus the port it ended up on.
pub struct PassiveListener {
    /// The bound listener — accept exactly one connection from it.
    pub listener: TcpListener,
    /// The chosen port (in `passive_port_range`).
    pub port: u16,
}

/// Bind a passive listener on the given IP, scanning the configured port
/// range linearly. Returns the first port that bound, or
/// [`TranslatorError::NoPassivePort`] if the range is exhausted.
pub async fn bind_passive(
    cfg: &TranslatorConfig,
    ip: IpAddr,
) -> Result<PassiveListener, TranslatorError> {
    let (lo, hi) = cfg.passive_port_range;
    for port in lo..=hi {
        let addr = SocketAddr::new(ip, port);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
                return Ok(PassiveListener { listener, port });
            }
            // Most often EADDRINUSE — keep walking.
            Err(_) => continue,
        }
    }
    Err(TranslatorError::NoPassivePort { low: lo, high: hi })
}

/// Format the IPv4 PASV reply (227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)).
///
/// IPv6 callers must use [`format_epsv_reply`] instead — PASV's wire
/// format has no IPv6 representation.
#[must_use]
pub fn format_pasv_reply(ip: Ipv4Addr, port: u16) -> String {
    let o = ip.octets();
    let p1 = port / 256;
    let p2 = port % 256;
    format!(
        "227 Entering Passive Mode ({},{},{},{},{},{}).",
        o[0], o[1], o[2], o[3], p1, p2
    )
}

/// Format the EPSV reply (RFC 2428 §3) — `(|||port|)`.
#[must_use]
pub fn format_epsv_reply(port: u16) -> String {
    format!("229 Entering Extended Passive Mode (|||{}|).", port)
}

/// Resolve the IP to advertise in PASV replies, given the
/// control-connection peer and config.
#[must_use]
pub fn advertise_ip(cfg: &TranslatorConfig, local_addr: IpAddr) -> IpAddr {
    cfg.external_addr.unwrap_or(local_addr)
}

/// Convert an arbitrary IpAddr to an Ipv4Addr where possible, mapping
/// `::ffff:a.b.c.d` to its v4 form. Returns `None` for native IPv6.
#[must_use]
pub fn as_ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// Convert an arbitrary IpAddr to an Ipv6Addr, mapping v4 to v6-mapped
/// form. Used when binding `[::]:port` listeners for EPSV.
#[must_use]
pub fn as_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pasv_format_matches_rfc959() {
        // 192.168.1.42:50100 → (192,168,1,42,195,180)
        let s = format_pasv_reply(Ipv4Addr::new(192, 168, 1, 42), 50100);
        assert!(s.contains("(192,168,1,42,195,180)"));
        assert!(s.starts_with("227 "));
    }

    #[test]
    fn epsv_format_matches_rfc2428() {
        let s = format_epsv_reply(50001);
        assert_eq!(s, "229 Entering Extended Passive Mode (|||50001|).");
    }

    #[test]
    fn as_ipv4_handles_v4_mapped_v6() {
        let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(as_ipv4(IpAddr::V6(mapped)), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(as_ipv4(IpAddr::V4(Ipv4Addr::LOCALHOST)), Some(Ipv4Addr::LOCALHOST));
        let pure_v6: Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(as_ipv4(IpAddr::V6(pure_v6)), None);
    }
}
