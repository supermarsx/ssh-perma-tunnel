//! [`Ssh3Protocol`] — the [`TunnelProtocol`] implementation for SSH3.
//!
//! This is the **stub-mode** implementation. `connect()` always emits the
//! experimental warning (unless acknowledged) and then returns
//! [`Error::UnsupportedPlatform`] with a build-blocker reason. The capability
//! set, name, and trait shape are real so downstream code compiles unchanged.

use async_trait::async_trait;
use spt_auth::AuthConfig;
use spt_core::{Error, Result};
use spt_protocol::{Endpoint, ProtocolCapabilities, TunnelProtocol, TunnelSession};
use tracing::warn;

use crate::config::Ssh3Config;

/// Reason returned when the stubbed `connect()` is invoked.
///
/// Wired into the error message so operators see the build-time blocker
/// directly in CLI output.
pub const STUB_BLOCKER_REASON: &str =
    "SSH3 backend disabled at build: stub mode (quinn/h3 transport not yet wired \
     under MSRV 1.83 — see crates/spt-ssh3/README.md)";

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
        _endpoint: &Endpoint,
        _auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        self.emit_experimental_warning_if_needed();
        self.config.validate()?;
        // Stub mode: no transport. Surface the blocker reason verbatim.
        Err(Error::UnsupportedPlatform(STUB_BLOCKER_REASON.to_string()))
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
    use tracing_test::traced_test;

    fn dummy_auth() -> AuthConfig {
        AuthConfig::new(
            "alice",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SSH3_TOKEN").unwrap(),
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

    fn assert_err(r: Result<Box<dyn TunnelSession>>) -> Error {
        match r {
            Ok(_) => panic!("expected Err from stub-mode connect"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_emits_experimental_warning_by_default() {
        let p = Ssh3Protocol::default();
        let endpoint = Endpoint::new("ssh3.example.com", 443);
        let err = assert_err(p.connect(&endpoint, &dummy_auth()).await);
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
        assert!(format!("{err}").contains("SSH3 backend disabled at build"));
        assert!(logs_contain("EXPERIMENTAL"));
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_suppresses_warning_when_acknowledged() {
        let cfg = Ssh3Config {
            acknowledge_experimental: true,
            ..Ssh3Config::default()
        };
        let p = Ssh3Protocol::new(cfg);
        let endpoint = Endpoint::new("ssh3.example.com", 443);
        let err = assert_err(p.connect(&endpoint, &dummy_auth()).await);
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
        assert!(!logs_contain("EXPERIMENTAL"));
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_validates_config_first() {
        // ack=false, allow_self_signed=true triggers a validate() error before
        // the stub blocker — but the warning still fires.
        let cfg = Ssh3Config {
            tls: crate::Ssh3TlsConfig {
                allow_self_signed: true,
                ..crate::Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        };
        let p = Ssh3Protocol::new(cfg);
        let endpoint = Endpoint::new("ssh3.example.com", 443);
        let err = assert_err(p.connect(&endpoint, &dummy_auth()).await);
        assert!(matches!(err, Error::InvalidConfig(_)));
        assert!(logs_contain("EXPERIMENTAL"));
    }

    #[test]
    fn ssh3_protocol_is_object_safe() {
        fn accepts(_p: Box<dyn TunnelProtocol>) {}
        accepts(Box::new(Ssh3Protocol::default()));
    }
}
