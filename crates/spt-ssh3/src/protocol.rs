//! [`Ssh3Protocol`] — the [`TunnelProtocol`] implementation for SSH3.
//!
//! ## Status: PARTIAL-REAL (spt↔spt channel framing live)
//!
//! - QUIC client + rustls TLS 1.3 (system roots, optional CA file, optional
//!   SHA-256 SPKI pin via [`spt_trust::TlsPin`], `allow_self_signed`,
//!   ALPN=`h3`) — **live**.
//! - HTTP/3 Extended CONNECT with `:protocol = ssh3`, Bearer/Basic auth —
//!   **live**.
//! - Per-forward channel framing (direct-tcp, tcpip-forward, UDP datagram
//!   association) — **live for spt↔spt**, gapped against
//!   francoismichel/ssh3's exact wire format. See `forward.rs` and
//!   `session.rs` top-of-file. Real-server interop is gated on
//!   `SPT_SSH3_TEST_SERVER`.
//!
//! The experimental warning emission contract is preserved: `connect()`
//! emits the spec-§4.2 warning unless
//! [`Ssh3Config::acknowledge_experimental`] is `true`.

use async_trait::async_trait;
use spt_auth::AuthConfig;
use spt_core::Result;
use spt_protocol::{Endpoint, ProtocolCapabilities, TunnelProtocol, TunnelSession};
use tracing::warn;

use crate::config::Ssh3Config;
use crate::session::Ssh3Session;
use crate::transport::bootstrap;

/// Build-blocker reason emitted by `open_*_forward` calls — kept exported for
/// CLI/diagnostics surfaces and for the README.
pub const PARTIAL_REAL_REASON: &str =
    "SSH3 backend is in partial-real mode: QUIC + TLS + Extended CONNECT \
     bootstrap is implemented, but per-forward channel framing is not yet \
     wired against the francoismichel/ssh3 reference. Run with \
     `acknowledge_experimental = true` and watch the spt-ssh3 issue tracker.";

/// The verbatim experimental-warning message emitted on every `connect()`
/// (and on every `validate`/`doctor`/`tunnel run` startup, when those code
/// paths reach into spt-ssh3) unless `acknowledge_experimental = true`.
pub const EXPERIMENTAL_WARNING: &str =
    "SSH3 backend is EXPERIMENTAL — built against the francoismichel/ssh3 \
     prototype, not a standards-track protocol. Do not rely on it in \
     production. Set `[profiles.ssh3] acknowledge_experimental = true` to \
     silence this warning.";

/// SSH3 protocol adapter.
///
/// Construct with [`Ssh3Protocol::new`] and pass to the supervisor as a
/// `Box<dyn TunnelProtocol>`.
///
/// ```no_run
/// use spt_protocol::TunnelProtocol;
/// use spt_ssh3::{Ssh3Config, Ssh3Protocol};
///
/// let cfg = Ssh3Config {
///     acknowledge_experimental: true,
///     ..Ssh3Config::default()
/// };
/// let proto = Ssh3Protocol::new(cfg);
/// assert_eq!(proto.name(), "ssh3");
/// ```
#[derive(Debug, Clone, Default)]
pub struct Ssh3Protocol {
    config: Ssh3Config,
}

impl Ssh3Protocol {
    /// Build a new SSH3 adapter with the given profile config.
    #[must_use]
    pub fn new(config: Ssh3Config) -> Self {
        Self { config }
    }

    /// Borrow the configuration this adapter was built with.
    #[must_use]
    pub fn config(&self) -> &Ssh3Config {
        &self.config
    }

    /// Emit the experimental warning **unless** the operator has acknowledged
    /// experimental status on the configuration.
    ///
    /// Public so that startup paths (`validate`, `doctor`, `tunnel run`) can
    /// emit the warning without going through `connect()`.
    pub fn emit_experimental_warning_if_needed(&self) {
        if !self.config.acknowledge_experimental {
            warn!(experimental = true, "{EXPERIMENTAL_WARNING}");
        }
    }
}

#[async_trait]
impl TunnelProtocol for Ssh3Protocol {
    async fn connect(
        &self,
        endpoint: &Endpoint,
        auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        self.emit_experimental_warning_if_needed();
        self.config.validate()?;
        let bs = bootstrap(&endpoint.host, endpoint.port, &self.config, auth).await?;
        // Retain the dial parameters so `preflight_connect` (used by the
        // `ssh3_endpoint` / `ssh_auth_preflight` health-check styles) can run a
        // fresh connect+auth side-dial without disturbing the live session.
        let redial = crate::session::RedialParams {
            host: endpoint.host.clone(),
            port: endpoint.port,
            config: self.config.clone(),
            auth: auth.clone(),
        };
        let session = Ssh3Session::from_bootstrap_with_redial(bs, Some(redial));
        Ok(Box::new(session))
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh3()
    }

    fn name(&self) -> &'static str {
        "ssh3"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_auth::{AuthConfig, AuthMethod, SecretRef};
    use spt_core::Error;
    use tracing_test::traced_test;

    fn dummy_auth() -> AuthConfig {
        AuthConfig::new(
            "alice",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SSH3_TEST_TOKEN").unwrap(),
            }],
        )
    }

    #[test]
    fn capabilities_match_ssh3_helper() {
        let p = Ssh3Protocol::default();
        assert_eq!(p.capabilities(), ProtocolCapabilities::ssh3());
        let c = p.capabilities();
        assert!(c.local_tcp && c.remote_tcp);
        assert!(c.local_udp && c.remote_udp);
        assert!(c.multiplex);
        assert!(!c.host_keys);
        assert!(!c.multi_hop);
    }

    #[test]
    fn name_is_ssh3() {
        assert_eq!(Ssh3Protocol::default().name(), "ssh3");
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_emits_experimental_warning_by_default() {
        // This test only checks the warning emission — the connect call will
        // fail when env-var resolution / DNS / QUIC handshake fail (the env
        // var is unset on a typical CI box). What we assert is that the
        // experimental warning fires before any of that.
        std::env::set_var("SSH3_TEST_TOKEN", "x");
        let p = Ssh3Protocol::default();
        let endpoint = Endpoint::new("127.0.0.1", 1); // unlikely to be SSH3
        let _ = p.connect(&endpoint, &dummy_auth()).await; // expect Err
        assert!(logs_contain("EXPERIMENTAL"));
        std::env::remove_var("SSH3_TEST_TOKEN");
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_suppresses_warning_when_acknowledged() {
        std::env::set_var("SSH3_TEST_TOKEN", "x");
        let cfg = Ssh3Config {
            acknowledge_experimental: true,
            ..Ssh3Config::default()
        };
        let p = Ssh3Protocol::new(cfg);
        let endpoint = Endpoint::new("127.0.0.1", 1);
        let _ = p.connect(&endpoint, &dummy_auth()).await;
        assert!(!logs_contain("EXPERIMENTAL"));
        std::env::remove_var("SSH3_TEST_TOKEN");
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_validates_config_first() {
        std::env::set_var("SSH3_TEST_TOKEN", "x");
        let cfg = Ssh3Config {
            tls: crate::Ssh3TlsConfig {
                allow_self_signed: true,
                ..crate::Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        };
        let p = Ssh3Protocol::new(cfg);
        let endpoint = Endpoint::new("127.0.0.1", 1);
        let res = p.connect(&endpoint, &dummy_auth()).await;
        let err = match res {
            Ok(_) => panic!("expected validation error"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::InvalidConfig(_)));
        assert!(logs_contain("EXPERIMENTAL"));
        std::env::remove_var("SSH3_TEST_TOKEN");
    }

    #[test]
    fn ssh3_protocol_is_object_safe() {
        fn accepts(_p: Box<dyn TunnelProtocol>) {}
        accepts(Box::new(Ssh3Protocol::default()));
    }
}
