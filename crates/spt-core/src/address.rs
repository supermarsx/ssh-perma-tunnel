//! Spec-style bind/target address parsing.
//!
//! Accepted forms:
//!
//! * `127.0.0.1:53` — IPv4 socket address.
//! * `[::1]:8080` — IPv6 socket address (square-bracketed host required).
//! * `unix:///run/spt.sock` — Unix domain socket path.
//! * `example.com:443` — opaque host:port (resolved later by the network
//!   layer; held as [`BindAddr::TcpHostPort`]).

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A parsed bind or target address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum BindAddr {
    /// Resolved IPv4/IPv6 socket address.
    Tcp(SocketAddr),
    /// Unix domain socket path (`unix:///path`).
    Unix(PathBuf),
    /// Unresolved `host:port` for DNS-deferred resolution.
    TcpHostPort {
        /// DNS host portion.
        host: String,
        /// TCP port.
        port: u16,
    },
}

impl BindAddr {
    /// Parse a bind address.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::InvalidArgs("address must not be empty".into()));
        }

        if let Some(path) = s.strip_prefix("unix://") {
            if path.is_empty() {
                return Err(Error::InvalidArgs("unix:// address requires a path".into()));
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }

        // Try as a fully-numeric socket address first; this handles both
        // `1.2.3.4:5` and `[::1]:5`.
        if let Ok(sock) = s.parse::<SocketAddr>() {
            return Ok(Self::Tcp(sock));
        }

        // Bracketed form whose host failed numeric parse → bad IPv6 literal.
        if s.starts_with('[') {
            return Err(Error::InvalidArgs(format!(
                "invalid bracketed IPv6 address `{s}`"
            )));
        }

        // Fall back to host:port.
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| Error::InvalidArgs(format!("address `{s}` is missing `:port`")))?;
        if host.is_empty() {
            return Err(Error::InvalidArgs(format!("address `{s}` has empty host")));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| Error::InvalidArgs(format!("address `{s}` has invalid port `{port}`")))?;
        Ok(Self::TcpHostPort {
            host: host.to_owned(),
            port,
        })
    }
}

impl fmt::Display for BindAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(sock) => write!(f, "{sock}"),
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
            Self::TcpHostPort { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

impl FromStr for BindAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl From<BindAddr> for String {
    fn from(value: BindAddr) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for BindAddr {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::BindAddr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::PathBuf;

    #[test]
    fn parses_ipv4() {
        let a = BindAddr::parse("127.0.0.1:53").unwrap();
        assert_eq!(
            a,
            BindAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53))
        );
    }

    #[test]
    fn parses_ipv6() {
        let a = BindAddr::parse("[::1]:8080").unwrap();
        assert_eq!(
            a,
            BindAddr::Tcp(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080))
        );
    }

    #[test]
    fn parses_uds() {
        let a = BindAddr::parse("unix:///run/spt.sock").unwrap();
        assert_eq!(a, BindAddr::Unix(PathBuf::from("/run/spt.sock")));
    }

    #[test]
    fn parses_host_port() {
        let a = BindAddr::parse("example.com:443").unwrap();
        assert_eq!(
            a,
            BindAddr::TcpHostPort {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn rejects_empty() {
        assert!(BindAddr::parse("").is_err());
    }

    #[test]
    fn rejects_missing_port() {
        assert!(BindAddr::parse("example.com").is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(BindAddr::parse("example.com:not-a-port").is_err());
    }

    #[test]
    fn rejects_bad_ipv6_brackets() {
        assert!(BindAddr::parse("[notv6]:80").is_err());
    }

    #[test]
    fn rejects_unix_no_path() {
        assert!(BindAddr::parse("unix://").is_err());
    }

    #[test]
    fn display_round_trip_all_variants() {
        for case in [
            "127.0.0.1:53",
            "[::1]:8080",
            "unix:///run/spt.sock",
            "example.com:443",
        ] {
            let parsed = BindAddr::parse(case).unwrap();
            let rendered = parsed.to_string();
            let reparsed = BindAddr::parse(&rendered).unwrap();
            assert_eq!(parsed, reparsed, "case {case}");
        }
    }

    #[test]
    fn serde_round_trip() {
        let a = BindAddr::parse("[::1]:9000").unwrap();
        let json = serde_json::to_string(&a).unwrap();
        let back: BindAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}
