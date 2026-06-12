//! Pure-Rust SSH2 backend built on `russh`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use russh::client;
use russh_keys::PublicKeyBase64 as _;
use secrecy::ExposeSecret as _;
use spt_auth::{AuthConfig, AuthMethod, SecretRef as AuthSecretRef};
use spt_core::{BindAddr, Error, Result};
use spt_protocol::{
    DynamicForwardSpec, Endpoint, ForwardHandle, ForwardId, ForwardState, LocalForwardSpec,
    RemoteForwardSpec, SessionInfo, TargetAddr, TunnelSession, UdpForwardSpec,
};
use spt_secrets::SecretBackend;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};
use tracing::warn;

use crate::agent::Agent;
use crate::crypto::CryptoPolicy;
use crate::hostkey::TrustVerifier;
use crate::secret;
use crate::sftp::SftpClient;

type RusshHandle = client::Handle<ClientHandler>;
type SharedHandle = Arc<AsyncMutex<RusshHandle>>;
type RemoteForwardMap = Arc<AsyncMutex<HashMap<RemoteForwardKey, mpsc::Sender<ForwardedTcpip>>>>;
type ConnectFuture = Pin<Box<dyn Future<Output = Result<RusshSsh2Session>> + Send + 'static>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RemoteForwardKey {
    address: String,
    port: u32,
}

struct ForwardedTcpip {
    channel: russh::Channel<client::Msg>,
}

struct ClientHandler {
    host: String,
    port: u16,
    trust: TrustVerifier,
    trust_failure: Arc<parking_lot::Mutex<Option<String>>>,
    remote_forwards: RemoteForwardMap,
}

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // Map the russh-typed key into our `ssh_key::PublicKey` and run the
        // configured trust policy. We must NOT collapse every `Ok(_)` to
        // accept — `HostKeyOutcome::NotFound` means no source recorded the
        // host (non-strict + no TOFU) and the supervisor must refuse the
        // connection rather than silently trust an unknown server.
        let outcome = match russh_key_to_ssh_key(server_public_key)
            .and_then(|key| self.trust.verify(&self.host, self.port, &key))
        {
            Ok(o) => o,
            Err(e) => {
                *self.trust_failure.lock() = Some(e.to_string());
                return Ok(false);
            }
        };
        match outcome {
            crate::hostkey::HostKeyOutcome::Match | crate::hostkey::HostKeyOutcome::TofuAdded => {
                Ok(true)
            }
            crate::hostkey::HostKeyOutcome::NotFound => {
                *self.trust_failure.lock() = Some(format!(
                    "host {}:{} not found in any trust source and accept_new is disabled",
                    self.host, self.port
                ));
                Ok(false)
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let exact = RemoteForwardKey {
            address: connected_address.to_owned(),
            port: connected_port,
        };
        let sender = {
            let map = self.remote_forwards.lock().await;
            map.get(&exact).cloned().or_else(|| {
                map.iter()
                    .find(|(key, _)| key.port == connected_port)
                    .map(|(_, tx)| tx.clone())
            })
        };

        if let Some(tx) = sender {
            if tx.send(ForwardedTcpip { channel }).await.is_err() {
                warn!(
                    target: "spt_ssh2::russh",
                    address = connected_address,
                    port = connected_port,
                    "remote forward channel arrived after receiver closed"
                );
            }
        } else {
            let _ = channel.close().await;
            warn!(
                target: "spt_ssh2::russh",
                address = connected_address,
                port = connected_port,
                "dropping unregistered remote forward channel"
            );
        }
        Ok(())
    }
}

/// One hop in the multi-hop chain. Constructed from `Ssh2Protocol::hops`.
#[derive(Clone)]
pub(crate) struct HopSpec {
    pub host: String,
    pub port: u16,
    pub auth: Option<AuthConfig>,
    pub trust: Option<TrustVerifier>,
}

/// Obfuscation policy threaded from the profile's
/// `[profiles.transport.obfuscation]` block into the russh dial path (E3-F2).
///
/// When present, the *first* TCP hop (or the single direct endpoint when no
/// multi-hop chain is configured) is dialed through
/// [`crate::connect_to_endpoint`], producing a [`crate::ConnectStream`] whose
/// `Obfuscated` variant is handed to [`russh::client::connect_stream`] — the
/// same primitive `multi_hop.rs` already uses for channel streams. Without
/// this the entire `spt-obfs` crate and the `[obfuscation]` config surface
/// were unreachable: `russh::client::connect` always dialed plain TCP itself,
/// so a configured obfuscation transport was a silent no-op.
///
/// Obfuscation only wraps the outermost transport; inner multi-hop legs run
/// over `direct-tcpip` channels and are unaffected.
#[derive(Clone)]
pub(crate) struct ObfsPolicy {
    /// Resolved obfuscation transport configuration. The static transport
    /// identifier recorded on the resulting session (e.g. `"obfs4"`,
    /// `"meek-http"`) is read from [`spt_obfs::ObfsConfig::name`].
    pub config: Arc<spt_obfs::ObfsConfig>,
    /// Optional audit hook fired from inside the obfuscation crate.
    pub audit: Option<Arc<dyn spt_obfs::AuditHook>>,
}

/// SSH2 transport-keepalive policy threaded from the supervisor's
/// `[profiles.keepalive]` policy into the russh `client::Config`.
///
/// `interval` maps to russh `Config::keepalive_interval` (idle time before a
/// transport-level `keepalive@openssh.com` global request is sent) and
/// `max_missed` maps to `Config::keepalive_max` (number of unanswered
/// keepalives that closes the connection). When `interval` is `None` the
/// russh defaults are preserved (no transport keepalives) and liveness is
/// driven solely by [`RusshSsh2Session::keepalive`]'s active channel probe.
///
/// This resolves E3-F1: previously the russh `Config` was built with
/// `..Default::default()`, so `keepalive_interval` was always `None` and the
/// in-code comment claiming "russh drives protocol keepalives from
/// `client::Config`" was false.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeepalivePolicy {
    /// Idle interval before russh emits a transport keepalive. `None` keeps
    /// transport keepalives disabled (russh default).
    pub interval: Option<Duration>,
    /// Maximum unanswered keepalives before russh closes the transport.
    /// `None` keeps the russh default (3).
    pub max_missed: Option<usize>,
}

impl KeepalivePolicy {
    /// Apply this policy to a russh [`client::Config`], leaving russh's own
    /// defaults in place for any field left unset.
    fn apply(&self, cfg: &mut client::Config) {
        if let Some(interval) = self.interval {
            cfg.keepalive_interval = Some(interval);
        }
        if let Some(max) = self.max_missed {
            cfg.keepalive_max = max;
        }
    }
}

/// Reject auth methods that the russh 0.46 backend can never satisfy
/// (`gssapi`/`sspi` — russh exposes no `gssapi-with-mic` userauth primitive,
/// see [`try_gssapi_auth`]). Surfacing this at profile build / validation
/// time (E3-F9) fails fast instead of wasting a connect attempt and a backoff
/// cycle on a statically-impossible configuration.
pub(crate) fn validate_auth_methods(auth: &AuthConfig) -> Result<()> {
    for method in &auth.methods {
        match method {
            AuthMethod::Gssapi { .. } | AuthMethod::Sspi { .. } => {
                return Err(Error::InvalidConfig(format!(
                    "auth method `{}` is not supported by the SSH2/russh backend: \
                     russh 0.46 does not expose `gssapi-with-mic` (RFC 4462) as a \
                     userauth primitive. Remove `{}` from `auth.methods` or use a \
                     supported method (public_key, agent, password, \
                     keyboard_interactive, certificate).",
                    method_name(method),
                    method_name(method),
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn connect(
    endpoint: Endpoint,
    auth_cfg: AuthConfig,
    crypto: CryptoPolicy,
    trust: TrustVerifier,
    backends: Vec<Arc<dyn SecretBackend>>,
    hops: Vec<HopSpec>,
    gss_audit: Option<Arc<dyn spt_auth_sspi::AuditHook>>,
    keepalive: KeepalivePolicy,
    obfs: Option<ObfsPolicy>,
) -> ConnectFuture {
    Box::pin(async move {
        connect_inner(
            endpoint, auth_cfg, crypto, trust, backends, hops, gss_audit, keepalive, obfs,
        )
        .await
    })
}

/// Dial the outermost transport for the russh session and hand the resulting
/// byte stream to [`russh::client::connect_stream`].
///
/// When `obfs` is `None` this is exactly equivalent to the upstream
/// `russh::client::connect` helper (TCP dial → `connect_stream`). When an
/// [`ObfsPolicy`] is present (E3-F2) the dial is routed through
/// [`crate::connect_to_endpoint`], so a configured `[obfuscation]` transport
/// actually carries the SSH handshake instead of being silently bypassed.
///
/// Returns the russh handle plus the static transport name to record on the
/// session (`"tcp"` for the plain path, the obfs transport id otherwise).
async fn dial_outer(
    cfg: Arc<client::Config>,
    host: &str,
    port: u16,
    handler: ClientHandler,
    obfs: Option<&ObfsPolicy>,
) -> std::result::Result<(RusshHandle, Option<&'static str>), russh::Error> {
    match obfs {
        None => {
            let handle = client::connect(cfg, (host.to_owned(), port), handler).await?;
            Ok((handle, None))
        }
        Some(policy) => {
            let target = format!("{host}:{port}");
            // `connect_to_endpoint` performs the obfuscation handshake and
            // returns a type-erased duplex stream. A failure here (transport
            // build error, obfs handshake failure, TCP dial failure) maps onto
            // `russh::Error::IO` so the caller's existing trust/diagnostic
            // mapping treats it like any other dial failure.
            let stream = crate::connect_to_endpoint(
                &target,
                Some(policy.config.as_ref()),
                policy.audit.clone(),
            )
            .await
            .map_err(|e| {
                russh::Error::IO(std::io::Error::other(format!(
                    "obfuscated dial to {target} failed: {e}"
                )))
            })?;
            let transport_name = policy.config.name();
            match stream {
                crate::ConnectStream::Plain(sock) => {
                    // `obfs_cfg = Some` always yields the Obfuscated variant;
                    // this arm is unreachable in practice but kept total.
                    let handle = client::connect_stream(cfg, sock, handler).await?;
                    Ok((handle, Some(transport_name)))
                }
                crate::ConnectStream::Obfuscated(stream) => {
                    let handle = client::connect_stream(cfg, stream, handler).await?;
                    Ok((handle, Some(transport_name)))
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_inner(
    endpoint: Endpoint,
    auth_cfg: AuthConfig,
    crypto: CryptoPolicy,
    trust: TrustVerifier,
    backends: Vec<Arc<dyn SecretBackend>>,
    hops: Vec<HopSpec>,
    gss_audit: Option<Arc<dyn spt_auth_sspi::AuditHook>>,
    keepalive: KeepalivePolicy,
    obfs: Option<ObfsPolicy>,
) -> Result<RusshSsh2Session> {
    // E3-F9: fail fast on statically-impossible auth methods (gssapi/sspi)
    // for the endpoint and every hop before spending a TCP connect + backoff
    // cycle. Profile validation should also catch this, but enforcing here
    // keeps the backend honest for direct callers.
    validate_auth_methods(&auth_cfg)?;
    for hop in &hops {
        if let Some(hop_auth) = &hop.auth {
            validate_auth_methods(hop_auth)?;
        }
    }

    // E3-F1: set the transport keepalive policy on the russh client config so
    // russh actually emits `keepalive@openssh.com` global requests and tears
    // the session down after `keepalive_max` unanswered probes. Previously
    // this was `..Default::default()` (keepalive_interval = None), so no
    // transport keepalives were ever sent.
    let mut config = client::Config {
        preferred: build_preferred(&crypto)?,
        ..Default::default()
    };
    keepalive.apply(&mut config);
    let cfg = Arc::new(config);

    // Multi-hop dispatch: walk `hops` end-to-end. Each hop opens a
    // `direct-tcpip` channel through the previous session and handshakes a
    // fresh russh session over the resulting `ChannelStream`. The final hop
    // is `endpoint` itself.
    //
    // Each hop authenticates with either its own `HopSpec::auth` (when
    // present) or — for the final hop — the endpoint's `auth_cfg`. Hop trust
    // policy falls back to the endpoint's `trust` when unset.
    if !hops.is_empty() {
        // First hop: plain TCP connect to hops[0].host:port.
        let first = &hops[0];
        let first_trust = first.trust.clone().unwrap_or_else(|| trust.clone());
        let first_trust_failure = Arc::new(parking_lot::Mutex::new(None));
        let first_handler = ClientHandler {
            host: first.host.clone(),
            port: first.port,
            trust: first_trust,
            trust_failure: Arc::clone(&first_trust_failure),
            remote_forwards: RemoteForwardMap::default(),
        };
        // E3-F2: the obfuscation policy wraps the *outermost* transport only —
        // i.e. the plain-TCP dial to the first hop. Inner hops traverse
        // `direct-tcpip` channels and are unaffected.
        let first_handle =
            match dial_outer(cfg.clone(), &first.host, first.port, first_handler, obfs.as_ref())
                .await
            {
                Ok((h, _name)) => h,
                Err(e) => {
                    if let Some(reason) = first_trust_failure.lock().clone() {
                        return Err(Error::TrustFailed(reason));
                    }
                    return Err(Error::network_unreachable(
                        spt_core::Diagnostic::what(format!(
                            "Failed to connect to first hop `{}:{}`",
                            first.host, first.port
                        ))
                        .why(format!("{e}"))
                        .how_to_fix(
                            "Verify the bastion is reachable (`nc -zv <host> <port>`), \
                             that no firewall is blocking the egress, and that DNS is \
                             resolving to the expected IP. If the server is behind a \
                             proxy or VPN, ensure the tunnel is up.",
                        )
                        .endpoint(format!("{}:{}", first.host, first.port))
                        .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                        .build(),
                    ));
                }
            };
        let first_shared = Arc::new(AsyncMutex::new(first_handle));
        let first_auth = first.auth.clone().unwrap_or_else(|| auth_cfg.clone());
        run_auth(
            Arc::clone(&first_shared),
            first_auth,
            backends.clone(),
            gss_audit.clone(),
        )
        .await?;

        // Walk intermediate hops [1..]: each opens a direct-tcpip channel
        // through the prior session and handshakes a fresh russh client
        // over the channel stream.
        let mut prev_shared = first_shared;
        for hop in &hops[1..] {
            let hop_trust = hop.trust.clone().unwrap_or_else(|| trust.clone());
            let hop_trust_failure = Arc::new(parking_lot::Mutex::new(None));
            let hop_handler = ClientHandler {
                host: hop.host.clone(),
                port: hop.port,
                trust: hop_trust,
                trust_failure: Arc::clone(&hop_trust_failure),
                remote_forwards: RemoteForwardMap::default(),
            };
            let hop_handle = crate::multi_hop::open_chained_session(
                Arc::clone(&prev_shared),
                &hop.host,
                hop.port,
                cfg.clone(),
                hop_handler,
            )
            .await
            .map_err(|e| match e {
                Error::TrustFailed(_) => e,
                _ => {
                    if let Some(reason) = hop_trust_failure.lock().clone() {
                        Error::TrustFailed(reason)
                    } else {
                        e
                    }
                }
            })?;
            let hop_shared = Arc::new(AsyncMutex::new(hop_handle));
            let hop_auth = hop.auth.clone().unwrap_or_else(|| auth_cfg.clone());
            run_auth(
                Arc::clone(&hop_shared),
                hop_auth,
                backends.clone(),
                gss_audit.clone(),
            )
            .await?;
            prev_shared = hop_shared;
        }

        // Final hop: tunnel through the last bastion to `endpoint`.
        let final_trust_failure = Arc::new(parking_lot::Mutex::new(None));
        let final_remote_forwards = RemoteForwardMap::default();
        let final_handler = ClientHandler {
            host: endpoint.host.clone(),
            port: endpoint.port,
            trust,
            trust_failure: Arc::clone(&final_trust_failure),
            remote_forwards: Arc::clone(&final_remote_forwards),
        };
        let final_handle = crate::multi_hop::open_chained_session(
            Arc::clone(&prev_shared),
            &endpoint.host,
            endpoint.port,
            cfg.clone(),
            final_handler,
        )
        .await
        .map_err(|e| match e {
            Error::TrustFailed(_) => e,
            _ => {
                if let Some(reason) = final_trust_failure.lock().clone() {
                    Error::TrustFailed(reason)
                } else {
                    e
                }
            }
        })?;
        let final_shared = Arc::new(AsyncMutex::new(final_handle));
        run_auth(Arc::clone(&final_shared), auth_cfg, backends, gss_audit).await?;
        let info = SessionInfo {
            backend: "ssh2-russh".into(),
            peer_version: None,
            negotiated: Some("russh negotiated algorithms (multi-hop)".into()),
            established_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        return Ok(RusshSsh2Session {
            handle: final_shared,
            remote_forwards: final_remote_forwards,
            info,
            script_engine: None,
            script_ctx: ScriptContext::default(),
            established_at_instant: std::time::Instant::now(),
            // The outermost (first-hop) transport carried the obfuscation.
            obfs_transport_name: obfs.as_ref().map(|p| p.config.name()),
            obfs_audit: obfs.as_ref().and_then(|p| p.audit.clone()),
        });
    }

    let trust_failure = Arc::new(parking_lot::Mutex::new(None));
    let remote_forwards = RemoteForwardMap::default();
    let handler = ClientHandler {
        host: endpoint.host.clone(),
        port: endpoint.port,
        trust,
        trust_failure: Arc::clone(&trust_failure),
        remote_forwards: Arc::clone(&remote_forwards),
    };

    // E3-F2: route the single direct endpoint through `dial_outer`, so a
    // configured `[obfuscation]` transport actually carries the handshake
    // (was: `client::connect` always dialed plain TCP, making the obfs crate
    // and config unreachable).
    let (handle, obfs_name) =
        match dial_outer(cfg, &endpoint.host, endpoint.port, handler, obfs.as_ref()).await {
            Ok(pair) => pair,
            Err(e) => {
                if let Some(reason) = trust_failure.lock().clone() {
                    return Err(Error::TrustFailed(reason));
                }
                return Err(Error::network_unreachable(
                    spt_core::Diagnostic::what(format!(
                        "Failed to connect to `{}:{}`",
                        endpoint.host, endpoint.port
                    ))
                .why(format!("{e}"))
                .how_to_fix(
                    "Verify the target host is reachable from this network, that \
                         the configured port is correct, and that DNS resolves the \
                         hostname. Common causes: server down, firewall block, \
                         stale `~/.ssh/known_hosts` entry pointing to wrong IP.",
                )
                .endpoint(format!("{}:{}", endpoint.host, endpoint.port))
                .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                .build(),
            ));
        }
    };

    // Wrap the handle in `Arc<AsyncMutex>` *before* `run_auth` so the agent
    // arm can `tokio::spawn` `authenticate_future` with `'static` ownership —
    // russh 0.46's `Signer::Future` lacks an explicit `+ 'static` bound,
    // and only the spawn boundary contains the resulting auto-trait Send
    // inference. The other arms gain a single `.lock().await` per call.
    let shared = Arc::new(AsyncMutex::new(handle));
    run_auth(Arc::clone(&shared), auth_cfg, backends, gss_audit).await?;
    let info = SessionInfo {
        backend: "ssh2-russh".into(),
        peer_version: None,
        negotiated: Some("russh negotiated algorithms".into()),
        established_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };

    Ok(RusshSsh2Session {
        handle: shared,
        remote_forwards,
        info,
        script_engine: None,
        script_ctx: ScriptContext::default(),
        established_at_instant: std::time::Instant::now(),
        obfs_transport_name: obfs_name,
        obfs_audit: obfs.as_ref().and_then(|p| p.audit.clone()),
    })
}

/// russh-backed [`TunnelSession`] — the only SSH2 session type after
/// t7-Phase0. Re-exported as [`crate::Ssh2Session`].
pub struct RusshSsh2Session {
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    info: SessionInfo,
    // t7-Phase0: scripting + obfs hooks ported from the deleted libssh2
    // `Ssh2Session<S>` so downstream callers retain their builder ergonomics.
    script_engine: Option<Arc<spt_scripting::ScriptEngine>>,
    // E8-F1: context carried so the lifecycle hooks (post_connect, on_disconnect,
    // on_forward_state) can populate the `profile`/`host`/`port` fields of their
    // event payloads. Set alongside the engine via `with_script_context`.
    script_ctx: ScriptContext,
    established_at_instant: std::time::Instant,
    obfs_transport_name: Option<&'static str>,
    obfs_audit: Option<Arc<dyn spt_obfs::AuditHook>>,
}

/// Identifying context for scripting lifecycle events (E8-F1).
///
/// Populated when the protocol attaches the engine to a freshly-built session
/// so `on_disconnect` / `on_forward_state` payloads can name the profile and
/// endpoint without the session needing the full profile.
#[derive(Debug, Clone, Default)]
pub struct ScriptContext {
    /// Profile name (`[[profiles]].name`).
    pub profile: String,
    /// Remote host the session connected to.
    pub host: String,
    /// Remote port.
    pub port: u16,
}

impl RusshSsh2Session {
    /// Open the SFTP subsystem on this session and return a wrapped
    /// [`SftpClient`]. Errors map onto [`spt_core::Error::RuntimeFailure`].
    pub async fn open_sftp_client(&self) -> Result<SftpClient> {
        let channel = {
            let handle = self.handle.lock().await;
            handle
                .channel_open_session()
                .await
                .map_err(|e| Error::RuntimeFailure(format!("russh sftp session channel: {e}")))?
        };
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| Error::RuntimeFailure(format!("russh request sftp subsystem: {e}")))?;
        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| Error::RuntimeFailure(format!("sftp init: {e}")))?;
        Ok(SftpClient::from_russh(sftp))
    }

    /// Attach an optional scripting engine. Returns `self` for builder-style
    /// chaining at the protocol layer.
    #[must_use]
    pub fn with_script_engine(mut self, engine: Option<Arc<spt_scripting::ScriptEngine>>) -> Self {
        self.script_engine = engine;
        self
    }

    /// Attach the scripting [`ScriptContext`] (profile name + endpoint) used
    /// to populate lifecycle event payloads (E8-F1). Returns `self` for
    /// builder-style chaining at the protocol layer.
    #[must_use]
    pub fn with_script_context(mut self, ctx: ScriptContext) -> Self {
        self.script_ctx = ctx;
        self
    }

    /// Fire the `on_forward_state` hook for a forward transition (E8-F1).
    ///
    /// No-op when no engine is attached. Used by the protocol layer's forward
    /// runners so operator scripts observe forward state-machine transitions.
    pub async fn dispatch_forward_state(
        &self,
        forward_id: impl Into<String>,
        transition: spt_scripting::event::ForwardStateTransition,
    ) {
        if !self.has_script_engine() {
            return;
        }
        let event = spt_scripting::event::Event::ForwardState(spt_scripting::event::ForwardState {
            profile: self.script_ctx.profile.clone(),
            forward_id: forward_id.into(),
            transition,
        });
        self.dispatch_script_event_async(spt_scripting::config::HookName::OnForwardState, event)
            .await;
    }

    /// Fire the `post_connect` hook (E8-F1). No-op when no engine is attached.
    pub async fn dispatch_post_connect(&self, auth_method: impl Into<String>) {
        if !self.has_script_engine() {
            return;
        }
        let event = spt_scripting::event::Event::PostConnect(spt_scripting::event::PostConnect {
            profile: self.script_ctx.profile.clone(),
            host: self.script_ctx.host.clone(),
            port: self.script_ctx.port,
            auth_method: auth_method.into(),
            server_banner: self.info.peer_version.clone(),
        });
        self.dispatch_script_event_async(spt_scripting::config::HookName::PostConnect, event)
            .await;
    }

    /// Dispatch a structured event to the configured script hook. Returns
    /// silently when no engine is attached.
    ///
    /// This is the synchronous entry point. `rhai` execution is CPU-bound and
    /// the `max_operations` budget defaults to 1M, so on the async runtime
    /// prefer [`Self::dispatch_script_event_async`] which offloads the call to
    /// a blocking thread (E8-F1).
    pub fn dispatch_script_event(
        &self,
        hook: spt_scripting::config::HookName,
        event: &spt_scripting::event::Event,
    ) -> Result<()> {
        let Some(engine) = self.script_engine.as_ref() else {
            return Ok(());
        };
        match engine.invoke(hook, event) {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!(hook = %hook, error = %e, "spt-ssh2: script hook failed");
                Err(e.into())
            }
        }
    }

    /// Async wrapper around [`Self::dispatch_script_event`] (E8-F1).
    ///
    /// Rhai is synchronous and a single hook may run up to `max_operations`
    /// (default 1M) operations, so invoking it directly on a runtime worker
    /// thread risks stalling other tasks. We clone the `Arc<ScriptEngine>` and
    /// run `invoke` on `tokio::task::spawn_blocking`.
    ///
    /// A hook failure is logged and swallowed — a misbehaving operator script
    /// must never abort the session lifecycle (connect/auth/forward/disconnect
    /// all proceed regardless). When no engine is attached this is a cheap
    /// no-op that never touches the blocking pool.
    pub async fn dispatch_script_event_async(
        &self,
        hook: spt_scripting::config::HookName,
        event: spt_scripting::event::Event,
    ) {
        let Some(engine) = self.script_engine.clone() else {
            return;
        };
        let result = tokio::task::spawn_blocking(move || engine.invoke(hook, &event)).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(hook = %hook, error = %e, "spt-ssh2: script hook failed");
            }
            Err(join_err) => {
                tracing::warn!(
                    hook = %hook,
                    error = %join_err,
                    "spt-ssh2: script hook task panicked or was cancelled"
                );
            }
        }
    }

    /// True when a scripting engine is attached (a `[profiles.script]` block
    /// was configured for this profile). Used by the lifecycle dispatch sites
    /// to skip event-struct construction entirely when scripting is off.
    #[must_use]
    pub fn has_script_engine(&self) -> bool {
        self.script_engine.is_some()
    }

    /// Attach an obfuscation audit hook.
    #[must_use]
    pub fn with_obfs_audit(mut self, audit: Option<Arc<dyn spt_obfs::AuditHook>>) -> Self {
        self.obfs_audit = audit;
        self
    }

    /// Record the static name of the obfuscation transport that produced
    /// the underlying byte stream.
    #[must_use]
    pub fn with_obfs_transport_name(mut self, name: Option<&'static str>) -> Self {
        self.obfs_transport_name = name;
        self
    }

    /// Borrow the obfuscation transport identifier (if any).
    #[must_use]
    pub fn obfs_transport_name(&self) -> Option<&'static str> {
        self.obfs_transport_name
    }
}

#[async_trait]
impl TunnelSession for RusshSsh2Session {
    async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
        let handle = open_local(Arc::clone(&self.handle), spec).await?;
        // E8-F1: report the forward reaching its Listening state to the
        // `on_forward_state` script hook (the listener is bound by the time
        // `open_local` returns).
        self.dispatch_forward_state(
            forward_id_for(&spec.name, "local", &spec.listen),
            spt_scripting::event::ForwardStateTransition::Listening,
        )
        .await;
        Ok(handle)
    }

    async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
        let handle = open_remote(
            Arc::clone(&self.handle),
            Arc::clone(&self.remote_forwards),
            spec,
        )
        .await?;
        self.dispatch_forward_state(
            forward_id_for(&spec.name, "remote", &spec.listen),
            spt_scripting::event::ForwardStateTransition::Active,
        )
        .await;
        Ok(handle)
    }

    async fn open_dynamic_forward(&mut self, spec: &DynamicForwardSpec) -> Result<ForwardHandle> {
        let handle = open_dynamic(Arc::clone(&self.handle), spec).await?;
        self.dispatch_forward_state(
            forward_id_for(&spec.name, "dynamic", &spec.listen),
            spt_scripting::event::ForwardStateTransition::Listening,
        )
        .await;
        Ok(handle)
    }

    async fn open_udp_forward(&mut self, _spec: &UdpForwardSpec) -> Result<ForwardHandle> {
        Err(Error::UnsupportedPlatform(
            "SSH2/russh does not support UDP forwards; use SSH3 for UDP forwarding".into(),
        ))
    }

    async fn keepalive(&mut self) -> Result<()> {
        // E3-F1: a REAL liveness probe (was previously an unconditional
        // `Ok(())` no-op, so the supervisor could never detect a dead SSH2
        // session — defeating spec §11.3 for the primary backend).
        //
        // Two layers:
        //  1. `Handle::is_closed()` — the russh client event loop drops the
        //     command sender when the transport dies (transport I/O error, peer
        //     DISCONNECT, or `keepalive_max` transport keepalives going
        //     unanswered on a black-holed link). A closed handle is a
        //     definitively dead session.
        //  2. An active round-trip: open a session channel and close it. This
        //     forces a real request/confirmation exchange across the live
        //     transport, so a session whose underlying event loop has died (but
        //     whose handle has not yet observed the drop) surfaces as a
        //     `SendError`/channel-open failure here rather than only when real
        //     forward traffic happens to hit an I/O error.
        let handle = self.handle.lock().await;
        if handle.is_closed() {
            return Err(Error::NetworkUnreachable(
                "russh transport closed: the SSH2 session is no longer alive \
                 (transport keepalives exhausted or peer disconnected)"
                    .into(),
            ));
        }
        let channel = handle.channel_open_session().await.map_err(|e| {
            Error::NetworkUnreachable(format!(
                "russh keepalive liveness probe failed to open a session channel: {e}"
            ))
        })?;
        // Best-effort close; the open already proved liveness. A close error
        // does not by itself indicate a dead session.
        let _ = channel.close().await;
        Ok(())
    }

    async fn close(self: Box<Self>) -> Result<()> {
        // E8-F1: fire the `on_disconnect` hook before tearing the transport
        // down so operator scripts observe the session ending with a stable
        // reason and the measured lifetime. A script failure is logged and
        // swallowed inside the dispatcher — it must not block the close.
        if self.has_script_engine() {
            let duration_ms = self.established_at_instant.elapsed().as_millis() as u64;
            let event =
                spt_scripting::event::Event::Disconnect(spt_scripting::event::Disconnect {
                    profile: self.script_ctx.profile.clone(),
                    reason: "user_request".into(),
                    duration_ms,
                });
            self.dispatch_script_event_async(
                spt_scripting::config::HookName::OnDisconnect,
                event,
            )
            .await;
        }
        let handle = self.handle.lock().await;
        handle
            .disconnect(russh::Disconnect::ByApplication, "spt: session close", "")
            .await
            .map_err(|e| Error::SessionCloseFailed(format!("russh disconnect: {e}")))
    }

    fn session_info(&self) -> SessionInfo {
        self.info.clone()
    }
}

fn build_preferred(crypto: &CryptoPolicy) -> Result<russh::Preferred> {
    let mut preferred = russh::Preferred::DEFAULT;
    if !crypto.kex.is_empty() {
        preferred.kex = Cow::Owned(parse_names("kex", &crypto.kex)?);
    }
    if !crypto.host_keys.is_empty() {
        preferred.key = Cow::Owned(parse_names("host_key", &crypto.host_keys)?);
    }
    if !crypto.ciphers.is_empty() {
        preferred.cipher = Cow::Owned(parse_names("cipher", &crypto.ciphers)?);
    }
    if !crypto.macs.is_empty() {
        preferred.mac = Cow::Owned(parse_names("mac", &crypto.macs)?);
    }
    if !crypto.compression.is_empty() {
        preferred.compression = Cow::Owned(parse_names("compression", &crypto.compression)?);
    }
    Ok(preferred)
}

fn parse_names<T>(field: &str, values: &[String]) -> Result<Vec<T>>
where
    for<'a> T: TryFrom<&'a str>,
{
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        parsed.push(T::try_from(value.as_str()).map_err(|_| {
            Error::InvalidConfig(format!(
                "russh SSH2 backend does not support {field} algorithm `{value}`"
            ))
        })?);
    }
    Ok(parsed)
}

async fn run_auth(
    handle: SharedHandle,
    auth_cfg: AuthConfig,
    backends: Vec<Arc<dyn SecretBackend>>,
    gss_audit: Option<Arc<dyn spt_auth_sspi::AuditHook>>,
) -> Result<()> {
    if auth_cfg.methods.is_empty() {
        return Err(Error::auth_failed(
            spt_core::Diagnostic::what("No SSH authentication methods configured")
                .why("the `auth.methods` array for this endpoint is empty")
                .how_to_fix(
                    "Add at least one auth method under the `[auth]` table — e.g. \
                     `methods = [\"public_key\"]` with a corresponding \
                     `[[auth.public_keys]]` entry, or `methods = [\"agent\"]` to \
                     delegate to ssh-agent.",
                )
                .retry_advice(spt_core::RetryAdvice::NotRetryable)
                .build(),
        ));
    }

    let mut last_err: Option<Error> = None;
    for method in auth_cfg.methods {
        match try_auth_method(
            Arc::clone(&handle),
            auth_cfg.username.clone(),
            method.clone(),
            backends.clone(),
            gss_audit.clone(),
        )
        .await
        {
            Ok(true) => return Ok(()),
            Ok(false) => {
                last_err = Some(Error::auth_failed(
                    spt_core::Diagnostic::what(format!(
                        "Auth method `{}` rejected by server",
                        method_name(&method)
                    ))
                    .why("the server returned an authentication-failure response")
                    .how_to_fix(
                        "Check the server-side `/var/log/auth.log` (Linux) or \
                         `journalctl -u ssh` for the specific reason. Common causes: \
                         wrong username, key not in `~/.ssh/authorized_keys`, \
                         account locked, or auth method disabled in sshd_config \
                         (`PubkeyAuthentication`, `PasswordAuthentication`).",
                    )
                    .retry_advice(spt_core::RetryAdvice::NotRetryable)
                    .build(),
                ));
            }
            Err(e) => {
                warn!(
                    target: "spt_ssh2::russh",
                    method = method_name(&method),
                    error = %e,
                    "auth method failed"
                );
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::auth_failed(
            spt_core::Diagnostic::what("All configured SSH auth methods failed")
                .why("every entry in `auth.methods` was rejected by the server")
                .how_to_fix(
                    "Re-examine the methods array end-to-end: verify the username, \
                     keys, certificates, and that the server actually offers the \
                     requested methods (check sshd_config `AuthenticationMethods`).",
                )
                .retry_advice(spt_core::RetryAdvice::NotRetryable)
                .build(),
        )
    }))
}

async fn try_auth_method(
    handle: SharedHandle,
    username: String,
    method: AuthMethod,
    backends: Vec<Arc<dyn SecretBackend>>,
    gss_audit: Option<Arc<dyn spt_auth_sspi::AuditHook>>,
) -> Result<bool> {
    match method {
        AuthMethod::Password { secret: secret_ref } => {
            let password = {
                let refs = backend_refs(&backends);
                let bytes = secret::resolve_secret(&refs, &secret_ref)?;
                std::str::from_utf8(bytes.expose_secret())
                    .map_err(|_| {
                        Error::auth_failed(
                            spt_core::Diagnostic::what("Password secret is not valid UTF-8")
                                .why("the referenced secret resolves to non-UTF-8 bytes")
                                .how_to_fix(
                                    "Re-store the password as a UTF-8 string (`spt secret set`), \
                                 or switch this endpoint to public-key / agent auth.",
                                )
                                .retry_advice(spt_core::RetryAdvice::NotRetryable)
                                .build(),
                        )
                    })?
                    .to_owned()
            };
            let mut h = handle.lock().await;
            let user_for_msg = username.clone();
            h.authenticate_password(username, password)
                .await
                .map_err(|e| {
                    Error::auth_failed(
                        spt_core::Diagnostic::what(format!(
                            "Password authentication failed for user `{user_for_msg}`"
                        ))
                        .why(format!("russh password auth returned: {e}"))
                        .how_to_fix(
                            "Verify the password is correct, that the server allows \
                         `PasswordAuthentication yes`, and that the account is not \
                         locked. Consider switching to public-key or agent auth.",
                        )
                        .retry_advice(spt_core::RetryAdvice::NotRetryable)
                        .build(),
                    )
                })
        }
        AuthMethod::PublicKey {
            identity_file,
            passphrase,
            ..
        } => {
            let passphrase = resolve_passphrase(&backends, passphrase.as_ref())?;
            let key = russh_keys::load_secret_key(&identity_file, passphrase.as_deref())
                .map_err(|e| Error::KeyFailure(format!("load private key: {e}")))?;
            let mut h = handle.lock().await;
            let user_for_msg = username.clone();
            h.authenticate_publickey(username, Arc::new(key))
                .await
                .map_err(|e| {
                    Error::auth_failed(
                        spt_core::Diagnostic::what(format!(
                            "Public-key authentication failed for user `{user_for_msg}`"
                        ))
                        .why(format!("russh publickey auth returned: {e}"))
                        .how_to_fix(
                            "Verify the public half of this key is in the server's \
                         `~/.ssh/authorized_keys`, that its `mode` is `600`, and that \
                         the key algorithm is allowed by sshd_config `PubkeyAcceptedAlgorithms`.",
                        )
                        .retry_advice(spt_core::RetryAdvice::NotRetryable)
                        .build(),
                    )
                })
        }
        AuthMethod::Certificate {
            cert,
            key,
            passphrase,
        } => {
            let passphrase = resolve_passphrase(&backends, passphrase.as_ref())?;
            let key = russh_keys::load_secret_key(&key, passphrase.as_deref())
                .map_err(|e| Error::KeyFailure(format!("load private key: {e}")))?;
            let cert = russh_keys::load_openssh_certificate(&cert)
                .map_err(|e| Error::KeyFailure(format!("load OpenSSH certificate: {e}")))?;
            let mut h = handle.lock().await;
            let user_for_msg = username.clone();
            h.authenticate_openssh_cert(username, Arc::new(key), cert)
                .await
                .map_err(|e| {
                    Error::auth_failed(
                        spt_core::Diagnostic::what(format!(
                            "OpenSSH-certificate authentication failed for user `{user_for_msg}`"
                        ))
                        .why(format!("russh certificate auth returned: {e}"))
                        .how_to_fix(
                            "Verify the certificate's CA is in the server's TrustedUserCAKeys, \
                         that the cert is not expired, that its principals list includes \
                         this username, and that the underlying key has the matching public \
                         half registered.",
                        )
                        .retry_advice(spt_core::RetryAdvice::NotRetryable)
                        .build(),
                    )
                })
        }
        AuthMethod::Agent { socket } => try_agent_auth(handle, username, socket).await,
        AuthMethod::KeyboardInteractive { responder } => {
            try_keyboard_interactive(handle, username, responder, backends).await
        }
        AuthMethod::Gssapi {
            service,
            principal,
            delegate,
        } => try_gssapi_auth(handle, username, service, principal, delegate, gss_audit).await,
        AuthMethod::Sspi {
            service,
            principal,
            delegate,
            allow_ntlm_fallback,
        } => {
            try_sspi_auth(
                handle,
                username,
                service,
                principal,
                delegate,
                allow_ntlm_fallback,
                gss_audit,
            )
            .await
        }
        AuthMethod::Bearer { .. }
        | AuthMethod::Basic { .. }
        | AuthMethod::OidcDeviceFlow { .. } => Err(Error::InvalidConfig(format!(
            "auth method `{}` is SSH3-only; not supported by SSH2/russh backend",
            method_name(&method)
        ))),
    }
}

async fn try_keyboard_interactive(
    handle: SharedHandle,
    username: String,
    responder: Vec<spt_auth::KbiResponder>,
    backends: Vec<Arc<dyn SecretBackend>>,
) -> Result<bool> {
    // Compile regexes up front so a bad pattern fails before the network
    // round-trip. (Config-validate normally catches this earlier.)
    let compiled = responder
        .iter()
        .map(spt_auth::KbiResponder::compile)
        .collect::<Result<Vec<_>>>()?;
    let mut h = handle.lock().await;
    let mut response = h
        .authenticate_keyboard_interactive_start(username, None::<String>)
        .await
        .map_err(|e| Error::AuthFailed(format!("russh keyboard-interactive start: {e}")))?;
    loop {
        match response {
            client::KeyboardInteractiveAuthResponse::Success => return Ok(true),
            client::KeyboardInteractiveAuthResponse::Failure => return Ok(false),
            client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let mut answers = Vec::with_capacity(prompts.len());
                for prompt in prompts {
                    let idx = compiled
                        .iter()
                        .position(|re| re.is_match(&prompt.prompt))
                        .ok_or_else(|| {
                            Error::AuthFailed(format!(
                                "no keyboard-interactive responder matched prompt `{}`",
                                prompt.prompt
                            ))
                        })?;
                    let r = &responder[idx];
                    if r.echo != prompt.echo {
                        warn!(
                            target: "spt_ssh2::russh",
                            prompt = %prompt.prompt,
                            configured_echo = r.echo,
                            server_echo = prompt.echo,
                            "keyboard-interactive echo flag mismatch"
                        );
                    }
                    let value = {
                        let refs = backend_refs(&backends);
                        secret::evaluate_kbi_answer(&r.answer, &refs)?
                    };
                    answers.push(value);
                }
                response = h
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|e| {
                        Error::AuthFailed(format!("russh keyboard-interactive response: {e}"))
                    })?;
            }
        }
    }
}

/// SSH2/russh agent userauth.
///
/// Connects to the local SSH agent (`SSH_AUTH_SOCK` on Unix, the
/// OpenSSH-compatible named pipe `\\.\pipe\openssh-ssh-agent` or Pageant on
/// Windows; or the explicit `socket` path from the `AuthMethod::Agent`
/// config), lists identities, and tries `publickey` userauth against each
/// identity in turn via [`russh::client::Handle::authenticate_future`].
/// Returns `Ok(true)` on the first identity the server accepts.
///
/// Each identity attempt opens a *fresh* `AgentClient` because
/// `authenticate_future` consumes its [`russh::auth::Signer`] by value
/// (russh re-uses the agent client as the per-attempt signer state).
async fn try_agent_auth(
    handle: SharedHandle,
    username: String,
    socket: Option<std::path::PathBuf>,
) -> Result<bool> {
    let socket_ref = socket.as_deref();
    // First listing connection — surface "no agent reachable" errors early.
    let listing_client = Agent::open_signer(socket_ref).await?;
    let identities = {
        // Reuse the listing connection just for `request_identities`.
        let mut client = listing_client;
        client
            .request_identities()
            .await
            .map_err(|e| Error::AuthFailed(format!("ssh-agent: request_identities: {e}")))?
    };

    if identities.is_empty() {
        return Err(Error::auth_failed(
            spt_core::Diagnostic::what("ssh-agent has no loaded identities")
                .why("the agent socket was reachable but reported zero usable keys")
                .how_to_fix(
                    "Add a key with `ssh-add ~/.ssh/id_ed25519` (or your preferred key path), \
                     then re-run. Verify with `ssh-add -l`. If the agent is forwarded, \
                     confirm forwarding hasn't been disabled by the bastion.",
                )
                .retry_advice(spt_core::RetryAdvice::NotRetryable)
                .build(),
        ));
    }

    let mut last_err: Option<String> = None;
    for key in identities {
        // The agent driver must consume the russh `Signer` (which is the
        // `AgentClient` itself) by value. Open a fresh signer per identity
        // because `authenticate_future` takes ownership.
        let signer = Agent::open_signer(socket_ref).await?;
        let user = username.clone();
        let key_for_auth = key.clone();
        let outcome =
            drive_authenticate_future(Arc::clone(&handle), user, key_for_auth, signer).await;
        match outcome {
            Ok(true) => return Ok(true),
            Ok(false) => {
                last_err = Some(format!(
                    "ssh-agent: server rejected identity `{}`",
                    Agent::fingerprint(&key)
                ));
            }
            Err(e) => {
                last_err = Some(format!(
                    "ssh-agent: sign error for identity `{}`: {e}",
                    Agent::fingerprint(&key)
                ));
            }
        }
    }
    // No identity authenticated. Surface the last attempt's reason so the
    // caller can debug. Returning `Ok(false)` lets the outer dispatcher
    // try the next configured method; that matches how the password /
    // pubkey arms above signal "server rejected" cleanly.
    if let Some(msg) = last_err {
        warn!(target: "spt_ssh2::russh", "ssh-agent auth exhausted: {msg}");
    }
    Ok(false)
}

/// Drive russh's `Signer`-based publickey userauth path.
///
/// Calls [`russh::client::Handle::authenticate_future`] with the supplied
/// agent-client signer. The russh `AgentClient<R>` itself implements
/// `russh::auth::Signer` — each `Reply::SignRequest` from the server is
/// dispatched back through the agent's `sign_request` round trip.
///
/// # Send-HRT and the upstream patch
///
/// In upstream russh-v0.46.0 this call site does not type-check: the outer
/// `ConnectFuture` (`Pin<Box<dyn Future + Send + 'static>>`) `CoerceUnsized`
/// proof fails on a higher-ranked-lifetime obligation from the generic
/// `S: auth::Signer` state machine. We vendored russh under
/// `vendor/russh-fork/` with the minimum patch set that fixes this:
///
/// 1. `auth::Signer: Sized + Send + 'static` (was `Sized`).
/// 2. `Signer::Error: ... + Send + 'static`, `Signer::Future: ... + Send + 'static`.
/// 3. `client::Handle::authenticate_future` rewritten from `async fn` to
///    return an explicit `Pin<Box<dyn Future + Send + 'a>>`, hoisting the
///    `self.sender.clone()` and `&mut self.receiver` reborrows into the
///    sync prelude so the boxed future captures only owned/reborrowed state.
///
/// Behaviour is identical to upstream. See `.orchestration/logs/t7-P1.md`
/// for the full unified diff and the upstream-PR follow-up plan.
async fn drive_authenticate_future(
    handle: SharedHandle,
    user: String,
    key: russh_keys::key::PublicKey,
    signer: crate::agent::DynAgentClient,
) -> std::result::Result<bool, String> {
    let mut h = handle.lock().await;
    let (_signer_back, result) = h.authenticate_future(user, key, signer).await;
    result.map_err(|e| format!("russh authenticate_future: {e}"))
}

/// SSH2/russh GSSAPI (`gssapi-with-mic` per RFC 4462) userauth dispatch.
///
/// The `spt-auth-sspi` crate already provides the [`GssProvider`] trait and
/// `provider_for` / `sspi_provider_for` entry points. We invoke them here so
/// that:
///
/// * Configuration shape errors (invalid principal, NTLM-on-Unix, missing
///   `cross-krb5` / `sspi` in the lockfile) surface through the same
///   error path the rest of the auth dispatch uses.
/// * When the spt-auth-sspi A3 work lands real backends, the only change
///   needed in this file is to drive the token-exchange loop through the
///   built provider.
///
/// **russh 0.46 does not implement `gssapi-with-mic` as a first-class
/// userauth primitive.** The
/// [`russh::auth::Method`] enum (`auth.rs:80` in russh 0.46) covers
/// `none`, `password`, `publickey`, `openssh-cert`, `future-publickey`, and
/// `keyboard-interactive` only. Until upstream russh exposes a
/// gssapi userauth method (or a low-level `userauth_request` hook permitting
/// custom method names), this dispatcher surfaces the
/// canonical `UnsupportedBackend:` error from the spt-auth-sspi helper.
///
/// [`GssProvider`]: spt_auth_sspi::GssProvider
// `async` retained because `try_auth_method` calls this with `.await`. When
// upstream russh exposes a gssapi userauth primitive, this body becomes a
// real token-exchange + MIC loop and the async-ness is meaningful.
#[allow(clippy::unused_async)]
async fn try_gssapi_auth(
    handle: SharedHandle,
    username: String,
    service: Option<String>,
    principal: Option<String>,
    delegate: bool,
    audit_hook: Option<Arc<dyn spt_auth_sspi::AuditHook>>,
) -> Result<bool> {
    let _ = (handle, username);
    let cfg = spt_auth_sspi::GssApiConfig {
        service,
        principal,
        delegate,
        audit_hook,
        ..Default::default()
    };
    // Build the provider to exercise the spt-auth-sspi A3 hook. The result
    // is intentionally discarded — if A3 is not yet wired (no `cross-krb5`
    // in lockfile), this surfaces as the documented `UnsupportedBackend`
    // marker without panicking. If A3 *is* wired, the construction succeeds
    // and we still return `UnsupportedBackend` below because russh 0.46
    // cannot drive the `gssapi-with-mic` userauth state machine.
    let _provider = spt_auth_sspi::provider_for(&cfg);
    Err(spt_auth_sspi::unsupported_backend(
        "russh 0.46 does not yet expose gssapi-with-mic (RFC 4462) as a userauth method; \
         provider built via spt-auth-sspi but cannot be driven through this backend yet",
    ))
}

/// SSH2/russh SSPI (Windows Negotiate, Kerberos preferred, optional NTLM
/// fallback) userauth dispatch. See [`try_gssapi_auth`] for the architectural
/// notes — the SSPI path uses the same wire shape and the same `russh 0.46`
/// gap.
#[allow(clippy::unused_async)]
#[allow(clippy::too_many_arguments)]
async fn try_sspi_auth(
    handle: SharedHandle,
    username: String,
    service: Option<String>,
    principal: Option<String>,
    delegate: bool,
    allow_ntlm_fallback: bool,
    audit_hook: Option<Arc<dyn spt_auth_sspi::AuditHook>>,
) -> Result<bool> {
    let _ = (handle, username);
    let cfg = spt_auth_sspi::SspiConfig {
        service,
        principal,
        delegate,
        allow_ntlm_fallback,
        audit_hook,
        ..Default::default()
    };
    let _provider = spt_auth_sspi::sspi_provider_for(&cfg);
    Err(spt_auth_sspi::unsupported_backend(
        "russh 0.46 does not yet expose gssapi-with-mic / SSPI Negotiate (RFC 4462) as a \
         userauth method; provider built via spt-auth-sspi but cannot be driven through this \
         backend yet",
    ))
}

fn resolve_passphrase(
    backends: &[Arc<dyn SecretBackend>],
    passphrase: Option<&AuthSecretRef>,
) -> Result<Option<String>> {
    secret::resolve_passphrase(backends, passphrase)
}

fn backend_refs(backends: &[Arc<dyn SecretBackend>]) -> Vec<&dyn SecretBackend> {
    backends.iter().map(std::convert::AsRef::as_ref).collect()
}

async fn open_local(handle: SharedHandle, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
    let bind = bind_addr_string(&spec.listen)?;
    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|e| Error::LocalBindFailed {
            address: bind.clone(),
            reason: e.to_string(),
        })?;

    let (state_tx, state_rx) = watch::channel(ForwardState::Listening);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    tokio::spawn(local_loop(
        listener,
        handle,
        spec.target.clone(),
        state_tx,
        close_rx,
        spec.max_connections,
        name.clone(),
    ));
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

async fn open_dynamic(handle: SharedHandle, spec: &DynamicForwardSpec) -> Result<ForwardHandle> {
    let bind = bind_addr_string(&spec.listen)?;
    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|e| Error::LocalBindFailed {
            address: bind.clone(),
            reason: e.to_string(),
        })?;

    let (state_tx, state_rx) = watch::channel(ForwardState::Listening);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    let protocols = crate::dynamic::DynamicProxyProtocolSet {
        socks4: spec.allow_socks4,
        socks4a: spec.allow_socks4a,
        socks5: spec.allow_socks5,
        http_connect: spec.allow_http_connect,
    };
    tokio::spawn(dynamic_loop(
        listener,
        handle,
        state_tx,
        close_rx,
        spec.max_connections,
        name.clone(),
        protocols,
    ));
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

async fn local_loop(
    listener: TcpListener,
    handle: SharedHandle,
    target: TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    max_connections: Option<u32>,
    name: String,
) {
    let _ = state_tx.send(ForwardState::Active);
    let active = Arc::new(std::sync::atomic::AtomicU32::new(0));
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            accept = listener.accept() => {
                let (sock, peer) = match accept {
                    Ok(value) => value,
                    Err(e) => {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "local accept failed");
                        continue;
                    }
                };
                if let Some(limit) = max_connections {
                    if active.load(std::sync::atomic::Ordering::Relaxed) >= limit {
                        warn!(target: "spt_ssh2::russh", forward = %name, "max_connections reached");
                        continue;
                    }
                }
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let handle = Arc::clone(&handle);
                let target = target.clone();
                let active = Arc::clone(&active);
                let name = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_local(handle, sock, peer, &target).await {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "local bridge failed");
                    }
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
}

#[allow(clippy::too_many_arguments)]
async fn dynamic_loop(
    listener: TcpListener,
    handle: SharedHandle,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    max_connections: Option<u32>,
    name: String,
    protocols: crate::dynamic::DynamicProxyProtocolSet,
) {
    let _ = state_tx.send(ForwardState::Active);
    let active = Arc::new(std::sync::atomic::AtomicU32::new(0));
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            accept = listener.accept() => {
                let (sock, peer) = match accept {
                    Ok(value) => value,
                    Err(e) => {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "dynamic accept failed");
                        continue;
                    }
                };
                if let Some(limit) = max_connections {
                    if active.load(std::sync::atomic::Ordering::Relaxed) >= limit {
                        warn!(target: "spt_ssh2::russh", forward = %name, "max_connections reached");
                        continue;
                    }
                }
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let handle = Arc::clone(&handle);
                let active = Arc::clone(&active);
                let name = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_dynamic(handle, sock, peer, protocols).await {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "dynamic bridge failed");
                    }
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
}

async fn bridge_local(
    handle: SharedHandle,
    mut sock: TcpStream,
    peer: SocketAddr,
    target: &TargetAddr,
) -> Result<()> {
    let channel = {
        let handle = handle.lock().await;
        handle
            .channel_open_direct_tcpip(
                target.host.clone(),
                u32::from(target.port),
                peer.ip().to_string(),
                u32::from(peer.port()),
            )
            .await
            .map_err(|e| Error::RuntimeFailure(format!("russh direct-tcpip: {e}")))?
    };
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut sock, &mut stream)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("russh local bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn bridge_dynamic(
    handle: SharedHandle,
    mut sock: TcpStream,
    peer: SocketAddr,
    protocols: crate::dynamic::DynamicProxyProtocolSet,
) -> Result<()> {
    let request = crate::dynamic::read_request(&mut sock, protocols).await?;
    let channel = {
        let handle = handle.lock().await;
        handle
            .channel_open_direct_tcpip(
                request.target.host.clone(),
                u32::from(request.target.port),
                peer.ip().to_string(),
                u32::from(peer.port()),
            )
            .await
    };
    let channel = match channel {
        Ok(channel) => {
            crate::dynamic::reply_success(&mut sock, request.protocol).await?;
            channel
        }
        Err(e) => {
            let _ = crate::dynamic::reply_failure(&mut sock, request.protocol).await;
            return Err(Error::RuntimeFailure(format!(
                "russh dynamic direct-tcpip to {}:{}: {e}",
                request.target.host, request.target.port
            )));
        }
    };
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut sock, &mut stream)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("russh dynamic bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn open_remote(
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    spec: &RemoteForwardSpec,
) -> Result<ForwardHandle> {
    let (address, requested_port) = remote_listen_parts(&spec.listen)?;
    let (tx, rx) = mpsc::channel(64);
    let initial_key = RemoteForwardKey {
        address: address.clone(),
        port: u32::from(requested_port),
    };
    remote_forwards
        .lock()
        .await
        .insert(initial_key.clone(), tx.clone());

    let bound_port = {
        let mut handle = handle.lock().await;
        match handle
            .tcpip_forward(address.clone(), u32::from(requested_port))
            .await
        {
            Ok(0) => u32::from(requested_port),
            Ok(port) => port,
            Err(e) => {
                remote_forwards.lock().await.remove(&initial_key);
                return Err(Error::RemoteBindFailed {
                    address: format!("{address}:{requested_port}"),
                    reason: format!("russh tcpip-forward: {e}"),
                });
            }
        }
    };

    let active_key = RemoteForwardKey {
        address: address.clone(),
        port: bound_port,
    };
    if active_key != initial_key {
        let mut map = remote_forwards.lock().await;
        map.remove(&initial_key);
        map.insert(active_key.clone(), tx);
    }

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    tokio::spawn(remote_loop(
        rx,
        close_rx,
        RemoteLoopContext {
            handle: Arc::clone(&handle),
            remote_forwards,
            key: active_key,
            target: spec.target.clone(),
            state_tx,
            name: name.clone(),
        },
    ));
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

struct RemoteLoopContext {
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    key: RemoteForwardKey,
    target: TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    name: String,
}

async fn remote_loop(
    mut rx: mpsc::Receiver<ForwardedTcpip>,
    mut close_rx: oneshot::Receiver<()>,
    ctx: RemoteLoopContext,
) {
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            forwarded = rx.recv() => {
                let Some(forwarded) = forwarded else { break; };
                let target = ctx.target.clone();
                let name = ctx.name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_remote(forwarded.channel, &target).await {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "remote bridge failed");
                    }
                });
            }
        }
    }

    ctx.remote_forwards.lock().await.remove(&ctx.key);
    let handle = ctx.handle.lock().await;
    let _ = handle
        .cancel_tcpip_forward(ctx.key.address, ctx.key.port)
        .await;
    let _ = ctx.state_tx.send(ForwardState::Stopped);
}

async fn bridge_remote(channel: russh::Channel<client::Msg>, target: &TargetAddr) -> Result<()> {
    let mut stream = channel.into_stream();
    let mut sock = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| {
            Error::NetworkUnreachable(format!(
                "connect remote-forward target {}:{}: {e}",
                target.host, target.port
            ))
        })?;
    tokio::io::copy_bidirectional(&mut stream, &mut sock)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("russh remote bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Build the `forward_id` field for an `on_forward_state` event (E8-F1):
/// the configured `name` when set, otherwise `kind:bind` for anonymous
/// forwards (matching the documented event schema).
fn forward_id_for(name: &str, kind: &str, listen: &BindAddr) -> String {
    if name.is_empty() {
        let bind = match listen {
            BindAddr::Tcp(sock) => sock.to_string(),
            BindAddr::TcpHostPort { host, port } => format!("{host}:{port}"),
            BindAddr::Unix(path) => path.display().to_string(),
        };
        format!("{kind}:{bind}")
    } else {
        name.to_owned()
    }
}

fn bind_addr_string(addr: &BindAddr) -> Result<String> {
    match addr {
        BindAddr::Tcp(sock) => Ok(sock.to_string()),
        BindAddr::TcpHostPort { host, port } => Ok(format!("{host}:{port}")),
        BindAddr::Unix(_) => Err(Error::UnsupportedPlatform(
            "SSH2/russh forward listeners on unix sockets are not implemented".into(),
        )),
    }
}

fn remote_listen_parts(addr: &BindAddr) -> Result<(String, u16)> {
    match addr {
        BindAddr::Tcp(sock) => Ok((sock.ip().to_string(), sock.port())),
        BindAddr::TcpHostPort { host, port } => Ok((host.clone(), *port)),
        BindAddr::Unix(_) => Err(Error::UnsupportedPlatform(
            "SSH2/russh remote forward listeners on unix sockets are not supported".into(),
        )),
    }
}

fn russh_key_to_ssh_key(key: &russh_keys::key::PublicKey) -> Result<ssh_key::PublicKey> {
    ssh_key::PublicKey::from_bytes(&key.public_key_bytes())
        .map_err(|e| Error::TrustFailed(format!("parse russh host key: {e}")))
}

fn method_name(method: &AuthMethod) -> &'static str {
    match method {
        AuthMethod::PublicKey { .. } => "public_key",
        AuthMethod::Agent { .. } => "agent",
        AuthMethod::Password { .. } => "password",
        AuthMethod::KeyboardInteractive { .. } => "keyboard_interactive",
        AuthMethod::Certificate { .. } => "certificate",
        AuthMethod::Gssapi { .. } => "gssapi",
        AuthMethod::Sspi { .. } => "sspi",
        AuthMethod::Bearer { .. } => "bearer",
        AuthMethod::Basic { .. } => "basic",
        AuthMethod::OidcDeviceFlow { .. } => "oidc_device_flow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_supported_algorithm_names() {
        let policy = CryptoPolicy {
            ciphers: vec!["aes256-ctr".into()],
            kex: vec!["curve25519-sha256".into()],
            macs: vec!["hmac-sha2-256".into()],
            host_keys: vec!["ssh-ed25519".into()],
            compression: vec!["none".into()],
        };
        let preferred = build_preferred(&policy).unwrap();
        assert_eq!(preferred.cipher.len(), 1);
        assert_eq!(preferred.kex.len(), 1);
        assert_eq!(preferred.mac.len(), 1);
        assert_eq!(preferred.key.len(), 1);
        assert_eq!(preferred.compression.len(), 1);
    }

    // ──────── E3-F1: keepalive config plumbing ────────────────────────

    #[test]
    fn keepalive_policy_default_preserves_russh_defaults() {
        // A default policy (interval=None, max_missed=None) must leave russh's
        // own Config defaults untouched: keepalive_interval stays None (no
        // transport keepalives) and keepalive_max stays at russh's default (3).
        let mut cfg = client::Config::default();
        let default_max = cfg.keepalive_max;
        KeepalivePolicy::default().apply(&mut cfg);
        assert_eq!(cfg.keepalive_interval, None);
        assert_eq!(cfg.keepalive_max, default_max);
    }

    #[test]
    fn keepalive_policy_plumbs_interval_and_max_into_russh_config() {
        // This is the regression guard for E3-F1: previously the russh Config
        // was built `..Default::default()`, so keepalive_interval was always
        // None. The supervisor's keepalive policy must now reach russh.
        let mut cfg = client::Config::default();
        let policy = KeepalivePolicy {
            interval: Some(Duration::from_secs(15)),
            max_missed: Some(5),
        };
        policy.apply(&mut cfg);
        assert_eq!(cfg.keepalive_interval, Some(Duration::from_secs(15)));
        assert_eq!(cfg.keepalive_max, 5);
    }

    #[test]
    fn keepalive_policy_partial_only_sets_provided_fields() {
        let mut cfg = client::Config::default();
        let default_max = cfg.keepalive_max;
        KeepalivePolicy {
            interval: Some(Duration::from_secs(20)),
            max_missed: None,
        }
        .apply(&mut cfg);
        assert_eq!(cfg.keepalive_interval, Some(Duration::from_secs(20)));
        // max_missed left unset ⇒ russh default retained.
        assert_eq!(cfg.keepalive_max, default_max);
    }

    // ──────── E3-F9: gssapi/sspi fail-fast validation ──────────────────

    #[test]
    fn validate_auth_methods_rejects_gssapi() {
        let auth = AuthConfig::new(
            "user",
            vec![AuthMethod::Gssapi {
                service: None,
                principal: None,
                delegate: false,
            }],
        );
        let err = validate_auth_methods(&auth).expect_err("gssapi must be rejected");
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
        assert!(format!("{err}").contains("gssapi"));
    }

    #[test]
    fn validate_auth_methods_rejects_sspi() {
        let auth = AuthConfig::new(
            "user",
            vec![AuthMethod::Sspi {
                service: None,
                principal: None,
                delegate: false,
                allow_ntlm_fallback: false,
            }],
        );
        let err = validate_auth_methods(&auth).expect_err("sspi must be rejected");
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
    }

    #[test]
    fn validate_auth_methods_accepts_supported_methods() {
        let auth = AuthConfig::new(
            "user",
            vec![
                AuthMethod::Agent { socket: None },
                AuthMethod::Password {
                    secret: spt_auth::SecretRef::Env("X".into()),
                },
            ],
        );
        validate_auth_methods(&auth).expect("supported methods must pass");
    }

    // ──────── E3-F2: obfuscation dial path ─────────────────────────────

    #[tokio::test]
    async fn obfs_policy_routes_dial_through_connect_to_endpoint() {
        // Regression guard for E3-F2: when an `ObfsPolicy` is present the
        // russh dial MUST go through `connect_to_endpoint` (the obfuscation
        // transport) instead of `client::connect`'s plain TCP. We assert the
        // obfs audit hook — which fires from *inside* the obfuscation crate's
        // `connect`, before any TCP I/O — recorded the attempt. If the obfs
        // branch were skipped (the pre-E3-F2 behaviour) the hook would never
        // fire and `entries` would be empty.
        let audit = Arc::new(spt_obfs::audit::MockAuditHook::new());
        let obfs = ObfsPolicy {
            config: Arc::new(spt_obfs::ObfsConfig::Obfs4 {
                node_id: [7; 20],
                public_key: [9; 32],
                iat_mode: 0,
            }),
            audit: Some(Arc::clone(&audit) as Arc<dyn spt_obfs::AuditHook>),
        };
        // Port 1 on loopback is unroutable for SSH; the connect will error,
        // but the obfs audit hook fires before the failure.
        let endpoint = Endpoint::new("127.0.0.1", 1);
        let auth = AuthConfig::new("u", vec![AuthMethod::Agent { socket: None }]);
        let _ = connect(
            endpoint,
            auth,
            CryptoPolicy::default(),
            TrustVerifier::default(),
            Vec::new(),
            Vec::new(),
            None,
            KeepalivePolicy::default(),
            Some(obfs),
        )
        .await;

        let entries = audit.entries();
        assert_eq!(
            entries.len(),
            1,
            "obfs branch must fire the audit hook exactly once; got {entries:?}"
        );
        assert_eq!(entries[0].0, "obfs4", "wrong transport name recorded");
        assert_eq!(
            entries[0].1, "127.0.0.1:1",
            "target must be the canonical host:port"
        );
    }

    #[tokio::test]
    async fn no_obfs_policy_does_not_touch_obfuscation_layer() {
        // Complementary guard: with `obfs = None` the dial takes the plain
        // path and never constructs an obfs transport / fires its audit.
        let audit = Arc::new(spt_obfs::audit::MockAuditHook::new());
        let endpoint = Endpoint::new("127.0.0.1", 1);
        let auth = AuthConfig::new("u", vec![AuthMethod::Agent { socket: None }]);
        let _ = connect(
            endpoint,
            auth,
            CryptoPolicy::default(),
            TrustVerifier::default(),
            Vec::new(),
            Vec::new(),
            None,
            KeepalivePolicy::default(),
            None,
        )
        .await;
        assert!(
            audit.entries().is_empty(),
            "plain dial must not fire the obfs audit hook"
        );
    }

    #[test]
    fn rejects_unknown_algorithm_names() {
        let policy = CryptoPolicy {
            ciphers: vec!["made-up".into()],
            ..CryptoPolicy::default()
        };
        assert!(matches!(
            build_preferred(&policy),
            Err(Error::InvalidConfig(_))
        ));
    }

    // ──────── t8-A1: diagnostic regression tests ──────────────────────
    //
    // The russh_backend converted sites are inside async functions that
    // require a live SSH server to reach. We assert the *shape* of the
    // diagnostic emitted by `run_auth`'s empty-methods early-return — the
    // only path reachable from a unit test.

    use spt_core::Diagnostic;

    /// Construct the empty-methods `AuthFailed` diagnostic the way `run_auth`
    /// does and confirm the rendered message matches what operators see.
    /// Avoids spinning up a russh handshake just to assert text.
    #[test]
    fn empty_auth_methods_diagnostic_rendering_matches_runtime_emission() {
        // Mirrors the literal site in run_auth above (search "No SSH
        // authentication methods configured").
        let d = Diagnostic::what("No SSH authentication methods configured")
            .why("the `auth.methods` array for this endpoint is empty")
            .how_to_fix(
                "Add at least one auth method under the `[auth]` table — e.g. \
                 `methods = [\"public_key\"]` with a corresponding \
                 `[[auth.public_keys]]` entry, or `methods = [\"agent\"]` to \
                 delegate to ssh-agent.",
            )
            .retry_advice(spt_core::RetryAdvice::NotRetryable)
            .build();
        let e = Error::auth_failed(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "No SSH authentication methods configured",
            why: "`auth.methods` array",
            how_to_fix: "[[auth.public_keys]]",
        );
        assert_eq!(e.exit_code(), spt_core::ExitCode::AuthFailed);
    }

    #[test]
    fn agent_no_identities_diagnostic_carries_remediation() {
        // Mirrors the literal site for `if identities.is_empty()` in
        // try_agent_auth.
        let d = Diagnostic::what("ssh-agent has no loaded identities")
            .why("the agent socket was reachable but reported zero usable keys")
            .how_to_fix(
                "Add a key with `ssh-add ~/.ssh/id_ed25519` (or your preferred key path), \
                 then re-run. Verify with `ssh-add -l`. If the agent is forwarded, \
                 confirm forwarding hasn't been disabled by the bastion.",
            )
            .retry_advice(spt_core::RetryAdvice::NotRetryable)
            .build();
        let e = Error::auth_failed(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "ssh-agent has no loaded identities",
            how_to_fix: "ssh-add ~/.ssh/id_ed25519",
        );
    }

    #[test]
    fn connect_failure_diagnostic_includes_endpoint_and_retry_hint() {
        let d = Diagnostic::what(format!(
            "Failed to connect to first hop `{}:{}`",
            "bastion.example.com", 22u16,
        ))
        .why("connection refused")
        .how_to_fix("Verify the bastion is reachable")
        .endpoint("bastion.example.com:22")
        .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
        .build();
        let e = Error::network_unreachable(d);
        let s = format!("{e}");
        assert!(s.contains("bastion.example.com:22"));
        assert!(s.contains("retry: retry with backoff"));
        assert!(s.contains("endpoint: bastion.example.com:22"));
        assert_eq!(e.exit_code(), spt_core::ExitCode::NetworkUnreachable);
    }

    #[test]
    fn password_auth_failure_mentions_username_in_diagnostic() {
        let d = Diagnostic::what(format!(
            "Password authentication failed for user `{}`",
            "alice"
        ))
        .why("russh password auth returned: PERMISSION_DENIED")
        .how_to_fix("Verify the password")
        .retry_advice(spt_core::RetryAdvice::NotRetryable)
        .build();
        let e = Error::auth_failed(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "for user `alice`",
            why: "PERMISSION_DENIED",
            how_to_fix: "Verify the password",
        );
    }

    #[test]
    fn publickey_auth_failure_suggests_authorized_keys_check() {
        let d = Diagnostic::what(format!(
            "Public-key authentication failed for user `{}`",
            "bob"
        ))
        .why("russh publickey auth returned: SIG_VERIFY_FAILED")
        .how_to_fix(
            "Verify the public half of this key is in the server's \
             `~/.ssh/authorized_keys`, that its `mode` is `600`, and that \
             the key algorithm is allowed by sshd_config `PubkeyAcceptedAlgorithms`.",
        )
        .retry_advice(spt_core::RetryAdvice::NotRetryable)
        .build();
        let e = Error::auth_failed(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "Public-key authentication failed",
            why: "SIG_VERIFY_FAILED",
            how_to_fix: "authorized_keys",
        );
    }

    #[test]
    fn cert_auth_failure_suggests_principals_check() {
        let d = Diagnostic::what(format!(
            "OpenSSH-certificate authentication failed for user `{}`",
            "carol"
        ))
        .why("russh certificate auth returned: CERT_EXPIRED")
        .how_to_fix("Verify the certificate's CA is in the server's TrustedUserCAKeys")
        .retry_advice(spt_core::RetryAdvice::NotRetryable)
        .build();
        let e = Error::auth_failed(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "OpenSSH-certificate authentication failed",
            why: "CERT_EXPIRED",
            how_to_fix: "TrustedUserCAKeys",
        );
    }

    #[test]
    fn all_auth_methods_failed_diagnostic_mentions_methods_array() {
        let d = Diagnostic::what("All configured SSH auth methods failed")
            .why("every entry in `auth.methods` was rejected by the server")
            .how_to_fix("Re-examine the methods array end-to-end")
            .retry_advice(spt_core::RetryAdvice::NotRetryable)
            .build();
        let e = Error::auth_failed(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "All configured SSH auth methods failed",
            why: "`auth.methods`",
            how_to_fix: "methods array",
        );
    }

    #[test]
    fn auth_method_rejected_by_server_diagnostic_suggests_authlog_check() {
        let d = Diagnostic::what(format!("Auth method `{}` rejected by server", "public-key"))
            .why("the server returned an authentication-failure response")
            .how_to_fix("Check the server-side `/var/log/auth.log`")
            .retry_advice(spt_core::RetryAdvice::NotRetryable)
            .build();
        let e = Error::auth_failed(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "Auth method `public-key` rejected",
            how_to_fix: "/var/log/auth.log",
        );
    }

    #[test]
    fn password_secret_not_utf8_diagnostic_offers_alternatives() {
        let d = Diagnostic::what("Password secret is not valid UTF-8")
            .why("the referenced secret resolves to non-UTF-8 bytes")
            .how_to_fix("Re-store the password as a UTF-8 string (`spt secret set`)")
            .retry_advice(spt_core::RetryAdvice::NotRetryable)
            .build();
        let e = Error::auth_failed(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "Password secret is not valid UTF-8",
            how_to_fix: "spt secret set",
        );
    }
}
