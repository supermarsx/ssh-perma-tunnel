//! Translator configuration types.
//!
//! See the crate root for a discussion of the security policy these
//! options encode.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// Top-level translator config — what `serve` consumes.
#[derive(Clone)]
pub struct TranslatorConfig {
    /// Address the control channel listens on.
    pub bind_addr: SocketAddr,
    /// Inclusive `(low, high)` range of TCP ports the passive data channel
    /// may bind. Both ports are inclusive. Empty / inverted ranges are
    /// rejected by [`TranslatorConfig::validate`].
    pub passive_port_range: (u16, u16),
    /// IPv4 address advertised in PASV replies. If `None`, the local
    /// address of the accepted control connection is used.
    pub external_addr: Option<IpAddr>,
    /// Single-line welcome banner sent on connect (220).
    pub welcome_banner: String,
    /// Authentication policy.
    pub auth: AuthPolicy,
    /// Optional TLS termination on the control channel.
    pub tls: Option<TlsConfig>,
    /// Maximum concurrent control sessions; further accepts return 421.
    pub max_clients: usize,
    /// Idle timeout for the control channel. The data channel uses a
    /// derived per-transfer timeout.
    pub idle_timeout: Duration,
}

impl TranslatorConfig {
    /// Sensible defaults useful for tests and the CLI default flag set.
    #[must_use]
    pub fn defaults_for(bind: SocketAddr) -> Self {
        Self {
            bind_addr: bind,
            passive_port_range: (50000, 50100),
            external_addr: None,
            welcome_banner: "spt-ftp-translator ready (passive-only)".to_string(),
            auth: AuthPolicy::Deny,
            tls: None,
            max_clients: 32,
            idle_timeout: Duration::from_secs(300),
        }
    }

    /// Validate the config. Used by both `serve` and the CLI front-end.
    pub fn validate(&self) -> Result<(), String> {
        let (lo, hi) = self.passive_port_range;
        if lo == 0 || hi == 0 || lo > hi {
            return Err(format!(
                "passive_port_range {lo}-{hi} is invalid (require 0 < lo <= hi)"
            ));
        }
        if self.max_clients == 0 {
            return Err("max_clients must be >= 1".into());
        }
        if self.welcome_banner.contains('\n') || self.welcome_banner.contains('\r') {
            return Err("welcome_banner must be a single line".into());
        }
        Ok(())
    }
}

/// Authentication policy. RFC 959 USER/PASS handshake is enforced
/// regardless — this enum only governs whether the credentials are
/// honoured.
///
/// Note: deliberately not `Debug`/`PartialEq` because the `Callback`
/// variant holds an opaque closure.
#[derive(Clone)]
pub enum AuthPolicy {
    /// Refuse every login (530). Useful for ports that exist only to
    /// reflect "service exists but is locked down" to scanners.
    Deny,
    /// Allow exactly the named user with the given password. Both are
    /// compared verbatim. Production deployments should source these
    /// from `spt_secrets` and convert here.
    Static {
        /// Required USER.
        username: String,
        /// Required PASS.
        password: String,
    },
    /// RFC 1635 anonymous: USER must be `anonymous` (case-insensitive)
    /// or `ftp`; the password is ignored but logged.
    Anonymous,
    /// Delegate to a closure. The boxed fn is `Send + Sync` so it lives
    /// behind `Arc` in the running session.
    #[allow(clippy::type_complexity)]
    Callback(std::sync::Arc<dyn Fn(&str, &str) -> bool + Send + Sync>),
}

impl AuthPolicy {
    /// Evaluate the policy.
    #[must_use]
    pub fn authorise(&self, user: &str, password: &str) -> bool {
        match self {
            Self::Deny => false,
            Self::Static { username, password: p } => username == user && p == password,
            Self::Anonymous => {
                user.eq_ignore_ascii_case("anonymous") || user.eq_ignore_ascii_case("ftp")
            }
            Self::Callback(cb) => cb(user, password),
        }
    }
}

/// TLS configuration for AUTH TLS / explicit FTPS.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// Path to a PEM-encoded certificate chain.
    pub cert_file: PathBuf,
    /// Path to a PEM-encoded private key (PKCS#8 or RSA).
    pub key_file: PathBuf,
    /// If set, AUTH TLS is **required** before USER/PASS will be accepted.
    /// Otherwise (false, default) plaintext logins are accepted but the
    /// `AUTH TLS` upgrade is honoured if the client asks for it.
    pub require_tls: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn defaults_are_valid() {
        let cfg = TranslatorConfig::defaults_for(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ));
        cfg.validate().unwrap();
    }

    #[test]
    fn inverted_range_rejected() {
        let mut cfg = TranslatorConfig::defaults_for(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ));
        cfg.passive_port_range = (50100, 50000);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn auth_static_match() {
        let p = AuthPolicy::Static {
            username: "alice".into(),
            password: "s3cret".into(),
        };
        assert!(p.authorise("alice", "s3cret"));
        assert!(!p.authorise("alice", "wrong"));
        assert!(!p.authorise("bob", "s3cret"));
    }

    #[test]
    fn auth_anonymous_accepts_ftp_and_anonymous() {
        let p = AuthPolicy::Anonymous;
        assert!(p.authorise("anonymous", "x@y"));
        assert!(p.authorise("FTP", ""));
        assert!(!p.authorise("alice", "anything"));
    }

    #[test]
    fn auth_deny_default() {
        let p = AuthPolicy::Deny;
        assert!(!p.authorise("anyone", "anything"));
    }
}
