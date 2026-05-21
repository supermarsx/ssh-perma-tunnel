//! [`Ssh2Protocol`] — the [`spt_protocol::TunnelProtocol`] implementation.
//!
//! Connect flow (single-hop):
//! 1. Resolve `endpoint.host:port`, open a `tokio::net::TcpStream`.
//! 2. Hand the stream to `AsyncSession::new` (libssh2 in non-blocking mode).
//! 3. Apply the crypto policy via `method_pref`.
//! 4. `handshake()`.
//! 5. Verify the host key against `TrustVerifier` (`known_hosts` + sha256 pin).
//! 6. Run `auth::run` against the resolver chain.
//! 7. Build a [`SessionInfo`] snapshot and wrap in [`Ssh2Session`].
//!
//! Multi-hop variant: open subsequent sessions through prior `direct-tcpip`
//! channels via [`crate::multi_hop`].

use std::net::ToSocketAddrs as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_ssh2_lite::{AsyncSession, SessionConfiguration};
use async_trait::async_trait;
use spt_auth::AuthConfig;
use spt_core::{Error, Result};
use spt_protocol::session::SessionInfo;
use spt_protocol::{Endpoint, ProtocolCapabilities, TunnelProtocol, TunnelSession};
use spt_secrets::SecretBackend;
use ssh2::MethodType;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::auth;
use crate::crypto::CryptoPolicy;
use crate::errors::from_async_ssh;
use crate::hostkey::{rebuild_public_key, TrustVerifier};
use crate::session::Ssh2Session;
use crate::sftp::SftpClient;

/// Trust-verification policy attached to one [`Ssh2Protocol`] instance.
///
/// Re-export of [`crate::hostkey::TrustVerifier`] for the public API.
pub type TrustPolicy = TrustVerifier;

/// SSH2 implementation backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ssh2BackendKind {
    /// Pure-Rust SSH2 implementation built on `russh`.
    Russh,
    /// Legacy libssh2 implementation through `async-ssh2-lite`.
    Libssh2,
}

impl Default for Ssh2BackendKind {
    fn default() -> Self {
        Self::Libssh2
    }
}

impl std::str::FromStr for Ssh2BackendKind {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "russh" => Ok(Self::Russh),
            "libssh2" => Ok(Self::Libssh2),
            other => Err(Error::InvalidConfig(format!(
                "unknown SSH2 backend `{other}` (expected russh|libssh2)"
            ))),
        }
    }
}

#[derive(Clone)]
struct HopConfig {
    host: String,
    port: u16,
    auth: Option<AuthConfig>,
    trust: Option<TrustPolicy>,
}

/// SSH2 transport adapter.
pub struct Ssh2Protocol {
    backend_kind: Ssh2BackendKind,
    crypto: CryptoPolicy,
    trust: TrustPolicy,
    /// Optional intermediate hops `(host, port)` traversed before reaching
    /// `endpoint`. Each is reached via a `direct-tcpip` channel through the
    /// previous session.
    hops: Vec<HopConfig>,
    /// Secret-backend chain owned by this protocol — the auth flow consults
    /// these to resolve `secret://`/`env:`/`file://` references.
    backends: Vec<Arc<dyn SecretBackend>>,
    /// `SessionConfiguration` applied to every new `AsyncSession` (banner,
    /// timeout, keepalive period).
    config: SessionConfiguration,
}

/// Builder for [`Ssh2Protocol`].
pub struct Ssh2ProtocolBuilder {
    backend_kind: Ssh2BackendKind,
    crypto: CryptoPolicy,
    trust: TrustPolicy,
    hops: Vec<HopConfig>,
    backends: Vec<Arc<dyn SecretBackend>>,
    config: SessionConfiguration,
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
            backend_kind: Ssh2BackendKind::default(),
            crypto: CryptoPolicy::default(),
            trust: TrustPolicy::default(),
            hops: Vec::new(),
            backends: Vec::new(),
            config: SessionConfiguration::default(),
        }
    }

    /// Set the crypto allow-lists.
    #[must_use]
    pub fn crypto(mut self, c: CryptoPolicy) -> Self {
        self.crypto = c;
        self
    }

    /// Select the concrete SSH2 backend.
    #[must_use]
    pub fn backend_kind(mut self, backend_kind: Ssh2BackendKind) -> Self {
        self.backend_kind = backend_kind;
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

    /// Override the underlying [`SessionConfiguration`] (banner, keepalive,
    /// timeout, etc.).
    #[must_use]
    pub fn session_config(mut self, c: SessionConfiguration) -> Self {
        self.config = c;
        self
    }

    /// Finalize the builder.
    #[must_use]
    pub fn build(self) -> Ssh2Protocol {
        Ssh2Protocol {
            backend_kind: self.backend_kind,
            crypto: self.crypto,
            trust: self.trust,
            hops: self.hops,
            backends: self.backends,
            config: self.config,
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

    fn backend_refs(&self) -> Vec<&dyn SecretBackend> {
        self.backends
            .iter()
            .map(std::convert::AsRef::as_ref)
            .collect()
    }

    /// Establish an SSH2 session and start the SFTP subsystem.
    ///
    /// This uses the pure-Rust `russh` backend. The legacy libssh2 backend
    /// still supports forwards, but SFTP is intentionally exposed through the
    /// production russh path first so CLI and policy surfaces do not grow a new
    /// libssh2 dependency contract.
    pub async fn connect_sftp(
        &self,
        endpoint: &Endpoint,
        auth_cfg: &AuthConfig,
    ) -> Result<SftpClient> {
        if self.backend_kind != Ssh2BackendKind::Russh {
            return Err(Error::UnsupportedPlatform(
                "SFTP over SSH2 is exposed through the russh backend; set capabilities.ssh2_backend = \"russh\"".into(),
            ));
        }
        let session = crate::russh_backend::connect(
            endpoint.clone(),
            auth_cfg.clone(),
            self.crypto.clone(),
            self.trust.clone(),
            self.backends.clone(),
            !self.hops.is_empty(),
        )
        .await?;
        session.open_sftp_client().await
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
        // Apply deprecated-algorithm warnings up-front.
        for w in self.crypto.deprecated_warnings() {
            warn!(target: "spt_ssh2::crypto", "{w}");
        }

        if self.backend_kind == Ssh2BackendKind::Russh {
            let endpoint = endpoint.clone();
            let auth_cfg = auth_cfg.clone();
            let crypto = self.crypto.clone();
            let trust = self.trust.clone();
            let backends = self.backends.clone();
            let has_hops = !self.hops.is_empty();
            let session = crate::russh_backend::connect(
                endpoint, auth_cfg, crypto, trust, backends, has_hops,
            )
            .await?;
            return Ok(Box::new(session));
        }

        // Single-hop case: open TCP, build session.
        if self.hops.is_empty() {
            let socket = open_tcp(&endpoint.host, endpoint.port).await?;
            let session = AsyncSession::new(socket, self.config.clone())
                .map_err(|e| from_async_ssh("AsyncSession::new", e))?;
            let info = self
                .finish_session(session, &endpoint.host, endpoint.port, auth_cfg)
                .await?;
            return Ok(info);
        }

        // Multi-hop chain: hop[0] is reached over a plain TCP socket;
        // each subsequent hop tunnels through the previous session.
        let first = &self.hops[0];
        let socket = open_tcp(&first.host, first.port).await?;
        let session = AsyncSession::new(socket, self.config.clone())
            .map_err(|e| from_async_ssh("AsyncSession::new", e))?;
        // For intermediate hops we still apply policy + handshake + auth +
        // host-key verification as a single uniform flow.
        let session = self
            .handshake_and_verify(session, &first.host, first.port, first.trust.as_ref())
            .await?;
        auth::run(
            &session,
            first.auth.as_ref().unwrap_or(auth_cfg),
            &self.backend_refs(),
        )
        .await?;

        let mut current = Arc::new(parking_lot::Mutex::new(session));
        for hop in self.hops.iter().skip(1) {
            let next = crate::multi_hop::open_chained_session(
                current.clone(),
                &hop.host,
                hop.port,
                self.config.clone(),
            )
            .await?;
            let next = self
                .handshake_and_verify(next, &hop.host, hop.port, hop.trust.as_ref())
                .await?;
            auth::run(
                &next,
                hop.auth.as_ref().unwrap_or(auth_cfg),
                &self.backend_refs(),
            )
            .await?;
            current = Arc::new(parking_lot::Mutex::new(next));
        }
        // Final leg to the endpoint.
        let final_session = crate::multi_hop::open_chained_session(
            current,
            &endpoint.host,
            endpoint.port,
            self.config.clone(),
        )
        .await?;
        let info = self
            .finish_session(final_session, &endpoint.host, endpoint.port, auth_cfg)
            .await?;
        Ok(info)
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh2()
    }

    fn name(&self) -> &'static str {
        "ssh2"
    }
}

impl Ssh2Protocol {
    async fn handshake_and_verify<S>(
        &self,
        mut session: AsyncSession<S>,
        host: &str,
        port: u16,
        trust: Option<&TrustPolicy>,
    ) -> Result<AsyncSession<S>>
    where
        S: async_ssh2_lite::session_stream::AsyncSessionStream + Send + Sync + 'static,
    {
        // Crypto policy
        for (m, prefs) in self.crypto.to_method_prefs() {
            apply_method_pref(&session, m, &prefs).await?;
        }
        session
            .handshake()
            .await
            .map_err(|e| from_async_ssh("handshake", e))?;
        // Verify host key
        let (blob, ty) = session
            .host_key()
            .ok_or_else(|| Error::TrustFailed("peer did not present a host key".into()))?;
        let pubkey = rebuild_public_key(blob, ty)?;
        trust.unwrap_or(&self.trust).verify(host, port, &pubkey)?;
        Ok(session)
    }

    async fn finish_session<S>(
        &self,
        mut session: AsyncSession<S>,
        host: &str,
        port: u16,
        auth_cfg: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>>
    where
        S: async_ssh2_lite::session_stream::AsyncSessionStream + Send + Sync + 'static,
    {
        // Crypto policy on the final session
        for (m, prefs) in self.crypto.to_method_prefs() {
            apply_method_pref(&session, m, &prefs).await?;
        }
        session
            .handshake()
            .await
            .map_err(|e| from_async_ssh("handshake", e))?;
        let (blob, ty) = session
            .host_key()
            .ok_or_else(|| Error::TrustFailed("peer did not present a host key".into()))?;
        let pubkey = rebuild_public_key(blob, ty)?;
        self.trust.verify(host, port, &pubkey)?;

        // Auth
        auth::run(&session, auth_cfg, &self.backend_refs()).await?;
        info!(target: "spt_ssh2", host, port, "session established");

        let info = SessionInfo {
            backend: "ssh2".into(),
            peer_version: session.banner().map(str::to_owned),
            negotiated: describe_negotiated(&session),
            established_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        Ok(Box::new(Ssh2Session::new(session, info)))
    }
}

async fn apply_method_pref<S>(session: &AsyncSession<S>, m: MethodType, prefs: &str) -> Result<()>
where
    S: async_ssh2_lite::session_stream::AsyncSessionStream + Send + Sync + 'static,
{
    session
        .method_pref(m, prefs)
        .await
        .map_err(|e| from_async_ssh("method_pref", e))
}

fn describe_negotiated<S>(session: &AsyncSession<S>) -> Option<String>
where
    S: async_ssh2_lite::session_stream::AsyncSessionStream + Send + Sync + 'static,
{
    let mut parts = Vec::new();
    for (label, m) in [
        ("kex", MethodType::Kex),
        ("hostkey", MethodType::HostKey),
        ("cipher_cs", MethodType::CryptCs),
        ("mac_cs", MethodType::MacCs),
    ] {
        if let Some(v) = session.methods(m) {
            parts.push(format!("{label}={v}"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

async fn open_tcp(host: &str, port: u16) -> Result<TcpStream> {
    // Resolve DNS off the hot path — `tokio::net::lookup_host` would also
    // work, but we accept a sync resolution here because libssh2 still calls
    // this on a per-connection basis.
    let mut last_err: Option<std::io::Error> = None;
    let addrs = match (host, port).to_socket_addrs() {
        Ok(it) => it.collect::<Vec<_>>(),
        Err(e) => {
            return Err(Error::DnsFailed(format!("resolve {host}:{port}: {e}")));
        }
    };
    for a in addrs {
        match TcpStream::connect(a).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(Error::NetworkUnreachable(format!(
        "connect to {host}:{port}: {}",
        last_err.map_or_else(|| "no addresses".into(), |e| e.to_string())
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sftp_requires_russh_backend() {
        let proto = Ssh2Protocol::builder()
            .backend_kind(Ssh2BackendKind::Libssh2)
            .build();
        let endpoint = Endpoint::new("127.0.0.1", 22);
        let auth = AuthConfig::new("alice", Vec::new());

        match proto.connect_sftp(&endpoint, &auth).await {
            Err(Error::UnsupportedPlatform(message)) => assert!(message.contains("russh")),
            other => panic!("expected unsupported platform, got {:?}", other.map(|_| ())),
        }
    }
}
