//! Test facilities for `spt-net`.
//!
//! Behind the `testing` feature flag (and automatically under `cfg(test)`).
//! Provides:
//!
//! * [`fake_loopback_only`], [`fake_dual_stack`], [`fake_with_v6_only`] —
//!   pre-built [`Interface`] vectors used by tests that need a deterministic
//!   alternative to live OS enumeration.
//! * [`MockTcpPair`] — two named ends of a [`tokio::io::DuplexStream`] for
//!   testing forward bridges without real sockets.
//! * [`assert_cidr_match`] — convenience assertion helper for [`CidrAcl`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{duplex, DuplexStream};

use crate::cidr::CidrAcl;
use crate::interfaces::Interface;

// ---------------------------------------------------------------------------
// Fake interface sets
// ---------------------------------------------------------------------------

/// Single loopback interface (IPv4 + IPv6).
///
/// # Examples
///
/// ```
/// use spt_net::testing::fake_loopback_only;
/// let ifaces = fake_loopback_only();
/// assert_eq!(ifaces.len(), 1);
/// assert!(ifaces[0].is_loopback);
/// ```
#[must_use]
pub fn fake_loopback_only() -> Vec<Interface> {
    vec![Interface {
        name: "lo".into(),
        ipv4: vec![Ipv4Addr::LOCALHOST],
        ipv6: vec![Ipv6Addr::LOCALHOST],
        is_loopback: true,
        is_up: true,
        mac: None,
    }]
}

/// `lo` plus an `eth0` with IPv4 and IPv6 unicast addresses.
///
/// # Examples
///
/// ```
/// use spt_net::testing::fake_dual_stack;
/// let ifaces = fake_dual_stack();
/// assert!(ifaces.iter().any(|i| i.name == "eth0"));
/// ```
#[must_use]
pub fn fake_dual_stack() -> Vec<Interface> {
    vec![
        Interface {
            name: "lo".into(),
            ipv4: vec![Ipv4Addr::LOCALHOST],
            ipv6: vec![Ipv6Addr::LOCALHOST],
            is_loopback: true,
            is_up: true,
            mac: None,
        },
        Interface {
            name: "eth0".into(),
            ipv4: vec![Ipv4Addr::new(192, 168, 1, 50)],
            ipv6: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50)],
            is_loopback: false,
            is_up: true,
            mac: Some([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]),
        },
    ]
}

/// `lo` plus an `eth0` with IPv6 only.
///
/// # Examples
///
/// ```
/// use spt_net::testing::fake_with_v6_only;
/// let ifaces = fake_with_v6_only();
/// let eth = ifaces.iter().find(|i| i.name == "eth0").unwrap();
/// assert!(eth.ipv4.is_empty());
/// assert!(!eth.ipv6.is_empty());
/// ```
#[must_use]
pub fn fake_with_v6_only() -> Vec<Interface> {
    vec![
        Interface {
            name: "lo".into(),
            ipv4: vec![Ipv4Addr::LOCALHOST],
            ipv6: vec![Ipv6Addr::LOCALHOST],
            is_loopback: true,
            is_up: true,
            mac: None,
        },
        Interface {
            name: "eth0".into(),
            ipv4: vec![],
            ipv6: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
            is_loopback: false,
            is_up: true,
            mac: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// MockTcpPair
// ---------------------------------------------------------------------------

/// Two ends of a [`tokio::io::DuplexStream`], named `client` and `server` for
/// readability. Allocate one and split it: writes on `client` are read on
/// `server`, and vice versa.
///
/// # Examples
///
/// ```
/// use spt_net::testing::MockTcpPair;
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .enable_all().build().unwrap();
/// rt.block_on(async {
///     let MockTcpPair { mut client, mut server } = MockTcpPair::new(64);
///     client.write_all(b"ping").await.unwrap();
///     let mut buf = [0u8; 4];
///     server.read_exact(&mut buf).await.unwrap();
///     assert_eq!(&buf, b"ping");
/// });
/// ```
pub struct MockTcpPair {
    /// Client-side end.
    pub client: DuplexStream,
    /// Server-side end.
    pub server: DuplexStream,
}

impl MockTcpPair {
    /// Allocate a new pair with `buffer_size` bytes of internal capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_net::testing::MockTcpPair;
    /// let _p = MockTcpPair::new(1024);
    /// ```
    #[must_use]
    pub fn new(buffer_size: usize) -> Self {
        let (a, b) = duplex(buffer_size);
        Self {
            client: a,
            server: b,
        }
    }

    /// Allocate a pair with the default 8 KiB buffer size.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_net::testing::MockTcpPair;
    /// let _p = MockTcpPair::default();
    /// ```
    #[must_use]
    pub fn default_size() -> Self {
        Self::new(8 * 1024)
    }
}

impl Default for MockTcpPair {
    fn default() -> Self {
        Self::default_size()
    }
}

// ---------------------------------------------------------------------------
// CIDR assertion helper
// ---------------------------------------------------------------------------

/// Assert that [`CidrAcl::matches`] returns `expected` for `ip`. Panics with
/// a formatted message on mismatch.
///
/// # Examples
///
/// ```
/// use spt_net::CidrAcl;
/// use spt_net::testing::assert_cidr_match;
/// use std::net::{IpAddr, Ipv4Addr};
/// let acl = CidrAcl::default();
/// assert_cidr_match(&acl, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), true);
/// ```
///
/// # Panics
///
/// Panics if the actual match outcome does not equal `expected`.
pub fn assert_cidr_match(acl: &CidrAcl, ip: IpAddr, expected: bool) {
    let got = acl.matches(ip);
    assert!(
        got == expected,
        "CidrAcl({acl:?}).matches({ip}) = {got}, expected {expected}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    #[test]
    fn loopback_only_has_localhost() {
        let v = fake_loopback_only();
        assert_eq!(v.len(), 1);
        assert!(v[0].ipv4.contains(&Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn dual_stack_has_v4_and_v6_on_eth0() {
        let v = fake_dual_stack();
        let eth = v.iter().find(|i| i.name == "eth0").unwrap();
        assert!(!eth.ipv4.is_empty());
        assert!(!eth.ipv6.is_empty());
    }

    #[test]
    fn v6_only_has_no_v4_on_eth0() {
        let v = fake_with_v6_only();
        let eth = v.iter().find(|i| i.name == "eth0").unwrap();
        assert!(eth.ipv4.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mock_tcp_pair_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let MockTcpPair {
            mut client,
            mut server,
        } = MockTcpPair::new(64);
        client.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
    }

    #[test]
    fn assert_cidr_match_ok() {
        let acl = CidrAcl::new(
            vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
            vec!["10.0.0.5/32".parse::<IpNet>().unwrap()],
        );
        assert_cidr_match(&acl, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), true);
        assert_cidr_match(&acl, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), false);
        assert_cidr_match(&acl, IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1)), false);
    }

    #[test]
    #[should_panic(expected = "expected true")]
    fn assert_cidr_match_panics_on_mismatch() {
        let acl = CidrAcl::new(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()], vec![]);
        assert_cidr_match(&acl, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), true);
    }
}
