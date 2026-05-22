//! [`Ssh2Protocol`] — the [`spt_protocol::TunnelProtocol`] implementation.
//!
//! Connect flow:
//! 1. Resolve `endpoint.host:port`, hand off to `crate::russh_backend::connect`.
//! 2. russh applies the crypto policy via [`russh::Preferred`] (kex / cipher
//!    / mac / hostkey / compression allow-lists).
//! 3. russh drives the SSH2 handshake.
//! 4. Server host key verified against [`TrustVerifier`] inside the russh
//!    [`russh::client::Handler`] callback.
//! 5. Auth dispatch drives password / publickey / agent / keyboard-interactive
//!    / certificate / gssapi / sspi against the resolver chain.
//! 6. A `SessionInfo` snapshot is wrapped in the russh-backed
//!    [`crate::session::Ssh2Session`].
//!
//! Multi-hop variant: open subsequent sessions through prior `direct-tcpip`
//! channels via [`crate::multi_hop`] — every byte stream after the first hop
//! is a `russh::Channel::into_stream()` rather than an OS socket, so no
//! socketpair trick is needed.

use std::sync::Arc;

use async_trait::async_trait;
use spt_auth::AuthConfig;
use spt_core::Result;
use spt_protocol::{Endpoint, ProtocolCapabilities, TunnelProtocol, TunnelSession};
use spt_secrets::SecretBackend;
use tracing::warn;

use crate::crypto::CryptoPolicy;
use crate::hostkey::TrustVerifier;
use crate::sftp::SftpClient;
// t7-A2:start — scripting engine handle threaded into every session built
// through this protocol. The Arc is shared across every connect attempt for
// the owning profile, so the engine is loaded once and reused.
use spt_scripting::ScriptEngine;
// t7-A2:end
// t7-Bwire:start — GSSAPI/SSPI audit hook threaded through to the russh
// backend's `try_gssapi_auth` / `try_sspi_auth` dispatchers (closes B1
// follow-up #1).
use spt_auth_sspi::AuditHook as GssAuditHook;
// t7-Bwire:end

/// Trust-verification policy attached to one [`Ssh2Protocol`] instance.
///
/// Re-export of [`crate::hostkey::TrustVerifier`] for the public API.
pub type TrustPolicy = TrustVerifier;

#[derive(Clone)]
#[allow(dead_code)] // fields consulted only once the russh backend grows real multi-hop dispatch
struct HopConfig {
    host: String,
    port: u16,
    auth: Option<AuthConfig>,
    trust: Option<TrustPolicy>,
}

/// SSH2 transport adapter (russh-only since t7-Phase0).
pub struct Ssh2Protocol {
    crypto: CryptoPolicy,
    trust: TrustPolicy,
    /// Optional intermediate hops `(host, port)` traversed before reaching
    /// `endpoint`. Each is reached via a `direct-tcpip` channel through the
    /// previous session.
    hops: Vec<HopConfig>,
    /// Secret-backend chain owned by this protocol — the auth flow consults
    /// these to resolve `secret://`/`env:`/`file://` references.
    backends: Vec<Arc<dyn SecretBackend>>,
    // t7-A2:start
    /// Optional scripting engine, cloned into every `Ssh2Session` produced
    /// by [`Self::connect`]. Built by `spt-bin` from the profile's
    /// `[profiles.script]` block and threaded here via
    /// [`Ssh2ProtocolBuilder::script_engine`].
    script_engine: Option<Arc<ScriptEngine>>,
    // t7-A2:end
    // t7-Bwire:start — installed into [`spt_auth_sspi::GssApiConfig::audit_hook`]
    // and [`spt_auth_sspi::SspiConfig::audit_hook`] for every GSSAPI/SSPI
    // userauth attempt run through this protocol.
    gssapi_audit_hook: Option<Arc<dyn GssAuditHook>>,
    // t7-Bwire:end
}

/// Builder for [`Ssh2Protocol`].
pub struct Ssh2ProtocolBuilder {
    crypto: CryptoPolicy,
    trust: TrustPolicy,
    hops: Vec<HopConfig>,
    backends: Vec<Arc<dyn SecretBackend>>,
    // t7-A2:start
    script_engine: Option<Arc<ScriptEngine>>,
    // t7-A2:end
    // t7-Bwire:start
    gssapi_audit_hook: Option<Arc<dyn GssAuditHook>>,
    // t7-Bwire:end
}

impl Default for Ssh2ProtocolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ssh2ProtocolBuilder {
    /// New builder with empty crypto policy and no trust verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            crypto: CryptoPolicy::default(),
            trust: TrustPolicy::default(),
            hops: Vec::new(),
            backends: Vec::new(),
            // t7-A2:start
            script_engine: None,
            // t7-A2:end
            // t7-Bwire:start
            gssapi_audit_hook: None,
            // t7-Bwire:end
        }
    }

    /// Set the crypto allow-lists.
    #[must_use]
    pub fn crypto(mut self, c: CryptoPolicy) -> Self {
        self.crypto = c;
        self
    }

    /// Set the host-key trust verifier.
    #[must_use]
    pub fn trust(mut self, t: TrustPolicy) -> Self {
        self.trust = t;
        self
    }

    /// Add a hop traversed before reaching the final endpoint.
    #[must_use]
    pub fn hop(mut self, host: impl Into<String>, port: u16) -> Self {
        self.hops.push(HopConfig {
            host: host.into(),
            port,
            auth: None,
            trust: None,
        });
        self
    }

    /// Add a hop with explicit hop-local auth and trust policy.
    #[must_use]
    pub fn hop_with_auth_trust(
        mut self,
        host: impl Into<String>,
        port: u16,
        auth: AuthConfig,
        trust: TrustPolicy,
    ) -> Self {
        self.hops.push(HopConfig {
            host: host.into(),
            port,
            auth: Some(auth),
            trust: Some(trust),
        });
        self
    }

    /// Append a secret backend to the resolver chain.
    #[must_use]
    pub fn backend(mut self, b: Arc<dyn SecretBackend>) -> Self {
        self.backends.push(b);
        self
    }

    // t7-A2:start
    /// Attach a scripting engine that will be cloned into every
    /// [`crate::session::Ssh2Session`] produced by [`Ssh2Protocol::connect`]. `None`
    /// (the default) keeps every hook a no-op.
    #[must_use]
    pub fn script_engine(mut self, engine: Option<Arc<ScriptEngine>>) -> Self {
        self.script_engine = engine;
        self
    }
    // t7-A2:end

    // t7-Bwire:start
    /// Attach a GSSAPI/SSPI audit hook. Installed into the
    /// [`spt_auth_sspi::GssApiConfig::audit_hook`] /
    /// [`spt_auth_sspi::SspiConfig::audit_hook`] of every GSSAPI/SSPI auth
    /// attempt run through this protocol. `None` (the default) leaves the
    /// hook unset (the spt-auth-sspi provider falls back to its built-in
    /// no-op).
    #[must_use]
    pub fn gssapi_audit_hook(mut self, hook: Option<Arc<dyn GssAuditHook>>) -> Self {
        self.gssapi_audit_hook = hook;
        self
    }
    // t7-Bwire:end

    /// Finalize the builder.
    #[must_use]
    pub fn build(self) -> Ssh2Protocol {
        Ssh2Protocol {
            crypto: self.crypto,
            trust: self.trust,
            hops: self.hops,
            backends: self.backends,
            // t7-A2:start
            script_engine: self.script_engine,
            // t7-A2:end
            // t7-Bwire:start
            gssapi_audit_hook: self.gssapi_audit_hook,
            // t7-Bwire:end
        }
    }
}

impl Ssh2Protocol {
    /// Construct a default `Ssh2Protocol` with empty crypto policy and
    /// permissive trust (no host-key verification).
    #[must_use]
    pub fn new() -> Self {
        Ssh2ProtocolBuilder::new().build()
    }

    /// Open a builder.
    #[must_use]
    pub fn builder() -> Ssh2ProtocolBuilder {
        Ssh2ProtocolBuilder::new()
    }

    /// Establish an SSH2 session and start the SFTP subsystem.
    pub async fn connect_sftp(
        &self,
        endpoint: &Endpoint,
        auth_cfg: &AuthConfig,
    ) -> Result<SftpClient> {
        let session = crate::russh_backend::connect(
            endpoint.clone(),
            auth_cfg.clone(),
            self.crypto.clone(),
            self.trust.clone(),
            self.backends.clone(),
            self.hop_specs(),
            self.gssapi_audit_hook.clone(),
        )
        .await?;
        session.open_sftp_client().await
    }

    /// Snapshot the hop chain as (host, port, hop-local auth, hop-local trust)
    /// tuples — the russh backend needs all four for the per-hop walk.
    fn hop_specs(&self) -> Vec<crate::russh_backend::HopSpec> {
        self.hops
            .iter()
            .map(|h| crate::russh_backend::HopSpec {
                host: h.host.clone(),
                port: h.port,
                auth: h.auth.clone(),
                trust: h.trust.clone(),
            })
            .collect()
    }

    /// Hop count — exposed for diagnostics.
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

impl Default for Ssh2Protocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunnelProtocol for Ssh2Protocol {
    async fn connect(
        &self,
        endpoint: &Endpoint,
        auth_cfg: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        // Apply deprecated-algorithm warnings up-front so the operator sees a
        // single log line per profile load regardless of which configuration
        // surfaced them.
        for w in self.crypto.deprecated_warnings() {
            warn!(target: "spt_ssh2::crypto", "{w}");
        }

        let endpoint = endpoint.clone();
        let auth_cfg = auth_cfg.clone();
        let crypto = self.crypto.clone();
        let trust = self.trust.clone();
        let backends = self.backends.clone();
        let hops = self.hop_specs();
        let gss_audit = self.gssapi_audit_hook.clone();
        let mut session = crate::russh_backend::connect(
            endpoint, auth_cfg, crypto, trust, backends, hops, gss_audit,
        )
        .await?;
        // t7-A2: attach scripting engine (if any) before boxing.
        if let Some(engine) = self.script_engine.clone() {
            session = session.with_script_engine(Some(engine));
        }
        Ok(Box::new(session))
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh2()
    }

    fn name(&self) -> &'static str {
        "ssh2"
    }
}

#[doc(hidden)]
/// Backwards-compatible re-export name. The pre-t7 builder exposed a
/// `Ssh2BackendKind` enum to switch between russh and libssh2; russh is now
/// the only backend, but downstream callers still pass the (ignored) value
/// to `backend_kind()`. We keep the type as a stub so calling sites continue
/// to compile during the migration window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Ssh2BackendKind {
    /// Pure-Rust SSH2 implementation built on `russh`. The only remaining
    /// variant.
    #[default]
    Russh,
}

impl Ssh2ProtocolBuilder {
    /// Deprecated no-op preserved so callers that still spell
    /// `.backend_kind(Ssh2BackendKind::Russh)` continue to compile during the
    /// t7-to-t8 migration. The libssh2 variant was removed in t7-Phase0.
    #[must_use]
    #[doc(hidden)]
    #[deprecated(
        since = "0.1.0",
        note = "libssh2 backend removed in t7-Phase0; russh is the only SSH2 backend"
    )]
    pub fn backend_kind(self, _kind: Ssh2BackendKind) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// t7-Bwire: the audit-hook builder setter accepts a hook and the value
    /// survives through `build()`. Pins the surface that
    /// `profile_factory::build_ssh2` depends on for GSSAPI/SSPI audit
    /// instrumentation.
    #[test]
    fn gssapi_audit_hook_setter_round_trips_through_builder() {
        #[derive(Debug)]
        struct DummyHook;
        impl spt_auth_sspi::AuditHook for DummyHook {
            fn on_event(&self, _: &spt_auth_sspi::AuditEvent) {}
        }
        let hook: Arc<dyn spt_auth_sspi::AuditHook> = Arc::new(DummyHook);
        let proto = Ssh2Protocol::builder()
            .gssapi_audit_hook(Some(Arc::clone(&hook)))
            .build();
        assert!(
            proto.gssapi_audit_hook.is_some(),
            "builder must propagate gssapi_audit_hook"
        );
        // Round-trip via `None` clears.
        let proto = Ssh2Protocol::builder().gssapi_audit_hook(None).build();
        assert!(proto.gssapi_audit_hook.is_none());
    }

    /// `hop_count` reflects each hop pushed through the builder. Indirectly
    /// pins the multi-hop dispatch precondition (`!hops.is_empty()`) used by
    /// `russh_backend::connect_inner`.
    #[test]
    fn hop_count_matches_pushed_hops() {
        let p = Ssh2Protocol::new();
        assert_eq!(p.hop_count(), 0);
        let p = Ssh2Protocol::builder()
            .hop("bastion-a", 22)
            .hop("bastion-b", 2222)
            .build();
        assert_eq!(p.hop_count(), 2);
    }
}
