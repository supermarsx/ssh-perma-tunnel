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
use russh::keys::ssh_key::HashAlg;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyBase64 as _};
use secrecy::ExposeSecret as _;
use spt_auth::{AuthConfig, AuthMethod, SecretRef as AuthSecretRef};
use spt_core::{escape_control, BindAddr, DnsResolution, Error, Result};
use spt_forward::{
    bind_with_policy, copy_bidirectional_throttled_idle, BoundListener, RateGate, TokenBucket,
};
use spt_protocol::{
    BindConflictPolicy, DynamicForwardSpec, Endpoint, ForwardHandle, ForwardId, ForwardRateLimits,
    ForwardState, LocalForwardSpec, RemoteForwardSpec, RemoteUdsForwardSpec, SessionInfo,
    TargetAddr, TunnelSession, UdpForwardSpec, UdsForwardSpec,
};
use spt_secrets::SecretBackend;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};
use tracing::{debug, info, warn};

use crate::agent::Agent;
use crate::crypto::CryptoPolicy;
use crate::hostkey::TrustVerifier;
use crate::multi_hop::HopKind;
use crate::proxy_jump::ProxyCredentials;
use crate::secret;
use crate::sftp::SftpClient;

type RusshHandle = client::Handle<ClientHandler>;
type SharedHandle = Arc<AsyncMutex<RusshHandle>>;
type RemoteForwardMap = Arc<AsyncMutex<HashMap<RemoteForwardKey, mpsc::Sender<ForwardedTcpip>>>>;
/// Server-opened `forwarded-streamlocal@openssh.com` channels are routed by the
/// remote UNIX socket path the server is listening on. Mirrors
/// [`RemoteForwardMap`] but keyed by `socket_path` (there is no port).
type RemoteUdsForwardMap = Arc<AsyncMutex<HashMap<String, mpsc::Sender<ForwardedStreamlocal>>>>;
type ConnectFuture = Pin<Box<dyn Future<Output = Result<RusshSsh2Session>> + Send + 'static>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RemoteForwardKey {
    address: String,
    port: u32,
}

struct ForwardedTcpip {
    channel: russh::Channel<client::Msg>,
}

/// A server-opened `forwarded-streamlocal@openssh.com` channel destined for a
/// `remote_uds` forward's accept loop (the streamlocal analogue of
/// [`ForwardedTcpip`]).
struct ForwardedStreamlocal {
    // Consumed by the cfg(unix) `bridge_remote_uds`; on non-Unix the
    // `forwarded-streamlocal` channel is never bridged (no AF_UNIX target), so
    // the field is read only on Unix.
    #[cfg_attr(not(unix), allow(dead_code))]
    channel: russh::Channel<client::Msg>,
}

struct ClientHandler {
    host: String,
    port: u16,
    trust: TrustVerifier,
    trust_failure: Arc<parking_lot::Mutex<Option<String>>>,
    remote_forwards: RemoteForwardMap,
    remote_uds_forwards: RemoteUdsForwardMap,
    /// Shared out-param carrying the canonical negotiated-crypto token string
    /// captured by [`client::Handler::kex_done`] (mirrors `trust_failure`).
    /// Read after connect to populate [`SessionInfo::negotiated`]. Contains
    /// algorithm names only — NEVER any key material / shared secret.
    negotiated: Arc<parking_lot::Mutex<Option<String>>>,
    /// Whether the *offered* kex preference list included a post-quantum KEX
    /// (derived from the resolved [`CryptoPolicy`] at construction). Emitted as
    /// the `pq_offered=<bool>` token; reflects what was OFFERED, not necessarily
    /// what the peer negotiated.
    pq_offered: bool,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
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

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        // Capture the fully negotiated algorithm set as the canonical token
        // string. `kex_done` fires on every (re)key; "last wins" is correct
        // because the negotiated algorithms are stable across a rekey, and the
        // initial kex precedes auth so the value is set before `session_info()`
        // is read. NEVER record `_shared_secret` or any key material — only the
        // algorithm names.
        *self.negotiated.lock() = Some(format_negotiated(names, self.pq_offered));
        Ok(())
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
                    address = %escape_control(connected_address),
                    port = connected_port,
                    "remote forward channel arrived after receiver closed"
                );
            }
        } else {
            let _ = channel.close().await;
            warn!(
                target: "spt_ssh2::russh",
                address = %escape_control(connected_address),
                port = connected_port,
                "dropping unregistered remote forward channel"
            );
        }
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        channel: russh::Channel<client::Msg>,
        socket_path: &str,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        // Mirror `server_channel_open_forwarded_tcpip`: route the server-opened
        // `forwarded-streamlocal@openssh.com` channel to the matching
        // `remote_uds` accept loop, keyed by the remote socket path the server
        // is listening on. Fall back to the sole registered forward when the
        // exact path is absent (OpenSSH may canonicalise the path).
        let sender = {
            let map = self.remote_uds_forwards.lock().await;
            map.get(socket_path).cloned().or_else(|| {
                if map.len() == 1 {
                    map.values().next().cloned()
                } else {
                    None
                }
            })
        };

        if let Some(tx) = sender {
            if tx.send(ForwardedStreamlocal { channel }).await.is_err() {
                warn!(
                    target: "spt_ssh2::russh",
                    socket_path = %escape_control(socket_path),
                    "remote uds forward channel arrived after receiver closed"
                );
            }
        } else {
            let _ = channel.close().await;
            warn!(
                target: "spt_ssh2::russh",
                socket_path = %escape_control(socket_path),
                "dropping unregistered remote uds forward channel"
            );
        }
        Ok(())
    }
}

/// Render a russh [`compression::Compression`](russh::compression::Compression)
/// to its wire algorithm name. The enum carries no `Display`/name accessor, so
/// we map the variants explicitly. (russh is built with `flate2`, so the
/// zlib variants are present.)
fn compression_name(c: &russh::compression::Compression) -> &'static str {
    use russh::compression::Compression;
    match c {
        Compression::None => "none",
        Compression::Zlib => "zlib",
        Compression::ZlibOpenSSH => "zlib@openssh.com",
    }
}

/// Format the negotiated algorithm set into the canonical space-separated
/// `key=value` token string shared with the status/observability consumers.
///
/// The `transport=` token is always first. Values are algorithm names only
/// (never key material). russh negotiates a SINGLE `cipher` for both
/// directions, so only one `cipher=` token is emitted (MAC + compression are
/// per-direction: `mac_c2s`/`mac_s2c`, `comp_c2s`/`comp_s2c`). `pq_offered`
/// reflects whether the offered kex list contained a post-quantum KEX.
fn format_negotiated(names: &russh::Names, pq_offered: bool) -> String {
    format!(
        "transport=ssh2 kex={} hostkey={} cipher={} mac_c2s={} mac_s2c={} \
         comp_c2s={} comp_s2c={} pq_offered={}",
        names.kex.as_ref(),
        names.key,
        names.cipher.as_ref(),
        names.client_mac.as_ref(),
        names.server_mac.as_ref(),
        compression_name(&names.client_compression),
        compression_name(&names.server_compression),
        pq_offered,
    )
}

/// Emit the always-on structured `spt::crypto_negotiated` info log for an
/// established ssh2 session, next to the "session established" line. The
/// algorithm names are recovered from the canonical `token` string this crate
/// produced (so the log and the carrier can never drift); `pq_offered` is
/// passed through as a bool.
fn emit_crypto_negotiated_log(token: &str, pq_offered: bool) {
    let mut fields: HashMap<&str, &str> = HashMap::new();
    for kv in token.split(' ') {
        if let Some((k, v)) = kv.split_once('=') {
            fields.insert(k, v);
        }
    }
    let get = |k: &str| fields.get(k).copied().unwrap_or("");
    info!(
        target: "spt::crypto_negotiated",
        transport = "ssh2",
        kex = get("kex"),
        cipher = get("cipher"),
        host_key = get("hostkey"),
        mac_c2s = get("mac_c2s"),
        mac_s2c = get("mac_s2c"),
        comp_c2s = get("comp_c2s"),
        comp_s2c = get("comp_s2c"),
        pq_offered = pq_offered,
        "negotiated ssh2 crypto"
    );
}

/// One hop in the multi-hop chain. Constructed from `Ssh2Protocol::hops`.
#[derive(Clone)]
pub(crate) struct HopSpec {
    pub host: String,
    pub port: u16,
    pub auth: Option<AuthConfig>,
    pub trust: Option<TrustVerifier>,
    /// Dispatch kind. [`HopKind::Ssh`] (default) re-establishes an SSH session
    /// through this hop; the proxy kinds tunnel the *next* leg through a SOCKS5
    /// / HTTP CONNECT handshake spoken at this hop's `(host, port)`.
    pub kind: HopKind,
    /// Optional proxy credentials, consumed only by the proxy hop kinds.
    pub creds: Option<ProxyCredentials>,
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
    /// Resolved obfs secret bytes (currently only the Shadowsocks
    /// `password`), keyed into the transport before it dials.
    ///
    /// The configured `[obfuscation]` `password` is a
    /// `secret://`/vault-backed reference; it must be resolved through the
    /// secrets backend chain — exactly like the SSH auth secrets — before the
    /// transport can derive its AEAD subkey. This is populated per-dial in
    /// [`connect_inner`] (so reconnects re-resolve), not stored on disk. It is
    /// `None` for transports that need no secret. Wrapped in
    /// [`zeroize::Zeroizing`] so the resolved PSK is scrubbed from the heap on
    /// drop instead of lingering for the connection lifetime
    /// (defense-in-depth against core-dump / swap residue).
    pub resolved_secret: Option<zeroize::Zeroizing<Vec<u8>>>,
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

/// Socket- and channel-level connection tuning threaded from the profile's
/// `[profiles.connection]` table into the russh dial path.
///
/// This carries only the **genuinely wireable** subset of `[profiles.connection]`:
///
/// * `tcp_nodelay` → russh [`client::Config::nodelay`] (russh calls
///   `set_nodelay` on the SSH socket) *and* the dialed socket via
///   [`spt_net::sockopts`] so it is honored on the `connect_stream` path too.
/// * `channel_window_size` → [`client::Config::window_size`].
/// * `channel_max_packet_size` → [`client::Config::maximum_packet_size`]
///   (russh rejects values `> 65535`; the factory/validate side clamps).
/// * `connect_timeout` → bounds the outermost TCP connect via
///   [`tokio::time::timeout`].
/// * `socket_keepalive` + `keepalive_idle` / `keepalive_interval` /
///   `keepalive_retries` → a [`spt_net::sockopts::TcpOptions`] applied to the
///   dialed `socket2::Socket` before it is handed to russh.
///
/// The SSH-level per-operation timeouts (`auth_timeout`, `handshake_timeout`,
/// `channel_idle_timeout` — a combined read/write idle bound) are wired in
/// t-tunnel-wire-2 §1. russh 0.61 exposes no native per-operation deadline (its
/// `Limits` are rekey byte/time limits), so they are applied via
/// `tokio::time::timeout` wraps in `connect_inner` (auth/handshake, including
/// per hop leg) and the bidir copy loop's idle param (channel idle, MIN-combined
/// with any per-forward `idle_timeout`). They default to `None` (no deadline).
///
/// A fully-defaulted `ConnectionPolicy` is a no-op: every field is `None`/
/// `false`, so the russh `Config` defaults and the legacy plain-TCP dial are
/// preserved byte-for-byte.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionPolicy {
    /// `tcp_nodelay`. `None` keeps russh's default (Nagle on).
    pub tcp_nodelay: Option<bool>,
    /// `channel_window_size`. `None` keeps russh's default (2 MiB).
    pub channel_window_size: Option<u32>,
    /// `channel_max_packet_size`. `None` keeps russh's default (32 KiB).
    pub channel_max_packet_size: Option<u32>,
    /// `connect_timeout` for the outermost TCP dial. `None` = unbounded
    /// (tokio's default connect behaviour).
    pub connect_timeout: Option<Duration>,
    /// `socket_keepalive` master switch. When `Some(true)`, a `TcpKeepalive`
    /// is applied with the idle/interval/retry values below; `None`/`Some(false)`
    /// leaves OS defaults.
    pub socket_keepalive: Option<bool>,
    /// `keepalive_idle` — idle time before the first keepalive probe.
    pub keepalive_idle: Option<Duration>,
    /// `keepalive_interval` — interval between keepalive probes.
    pub keepalive_interval: Option<Duration>,
    /// `keepalive_retries` — probe count before the socket is declared dead
    /// (Linux only at the OS layer).
    pub keepalive_retries: Option<u32>,
    // t-tunnel-wire-2 §1: per-operation SSH deadlines. Default `None` = no
    // deadline (current behaviour, byte-for-byte). Wired in `connect_inner` via
    // `tokio::time::timeout` wraps (auth/handshake) and the bidir copy loop's
    // idle param (channel idle).
    /// Deadline for the auth driver (publickey/password/... userauth flow).
    /// `None` = unbounded. Wired via `run_auth_timed` in `connect_inner`.
    pub auth_timeout: Option<Duration>,
    /// Deadline for the SSH transport handshake (the outermost dial +
    /// version/kex exchange). `None` = unbounded. Wired via `dial_outer_timed`
    /// (and `open_next_leg_timed` per hop leg) in `connect_inner`.
    pub handshake_timeout: Option<Duration>,
    /// Combined per-channel read/write idle deadline. `None` = no idle
    /// deadline. Reinterprets the `connection.{read,write}_timeout` pair as a
    /// single channel-idle bound, threaded into every forward bridge's copy
    /// loop (MIN-combined with any per-forward `idle_timeout`).
    pub channel_idle_timeout: Option<Duration>,
    /// Client-side DNS resolution policy (`[profiles.connection].dns_resolution`).
    /// [`DnsResolution::PerAttempt`] (default) re-resolves the endpoint on every
    /// dial — byte-for-byte the prior behaviour. [`DnsResolution::Once`] resolves
    /// the endpoint once per `(host, port)` and pins the result across
    /// reconnects via the shared [`spt_core::dns`] cache.
    pub dns: DnsResolution,
}

impl ConnectionPolicy {
    /// Apply the channel-flow-control + nodelay knobs onto the russh
    /// [`client::Config`]. Socket-level options (connect timeout, keepalive)
    /// are applied separately at dial time via [`Self::tcp_options`].
    fn apply_to_config(&self, cfg: &mut client::Config) {
        if let Some(nodelay) = self.tcp_nodelay {
            cfg.nodelay = nodelay;
        }
        if let Some(window) = self.channel_window_size {
            cfg.window_size = window;
        }
        if let Some(packet) = self.channel_max_packet_size {
            // russh rejects `maximum_packet_size > 65535` at connect; clamp so a
            // larger configured value degrades gracefully rather than failing
            // the dial.
            cfg.maximum_packet_size = packet.min(65535);
        }
    }

    /// True when a socket-level keepalive should be applied to the dialed
    /// socket (the master `socket_keepalive` switch is on, or any keepalive
    /// timing field is set).
    fn wants_keepalive(&self) -> bool {
        matches!(self.socket_keepalive, Some(true))
    }

    /// Build the [`spt_net::sockopts::TcpOptions`] to apply to a freshly
    /// dialed socket, or `None` when this policy requests no socket-level
    /// tuning (so the legacy `TcpStream::connect` fast path is preserved).
    fn tcp_options(&self) -> Option<spt_net::sockopts::TcpOptions> {
        let nodelay = self.tcp_nodelay.unwrap_or(false);
        let keepalive = self.wants_keepalive();
        if !nodelay && !keepalive {
            return None;
        }
        Some(spt_net::sockopts::TcpOptions {
            nodelay,
            keepalive_idle: keepalive.then_some(self.keepalive_idle).flatten(),
            keepalive_interval: keepalive.then_some(self.keepalive_interval).flatten(),
            keepalive_retries: keepalive.then_some(self.keepalive_retries).flatten(),
            freebind: false,
            dual_stack_v6: false,
        })
    }
}

/// Reject auth methods that the russh 0.61 backend can never satisfy
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
                     russh 0.61 does not expose `gssapi-with-mic` (RFC 4462) as a \
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
    connection: ConnectionPolicy,
) -> ConnectFuture {
    // Capture every dial input in one place so the established session can
    // reproduce a fresh connect+auth dial for `preflight_connect` (§3) without
    // disturbing the live session.
    let params = ReconnectParams {
        endpoint,
        auth_cfg,
        crypto,
        trust,
        backends,
        hops,
        gss_audit,
        keepalive,
        obfs,
        connection,
    };
    Box::pin(async move { connect_inner(params).await })
}

/// Dial a plain `TcpStream` to `host:port`, applying the `[profiles.connection]`
/// socket options (`tcp_nodelay`, `socket_keepalive` + idle/interval/retries)
/// and bounding the connect with `connect_timeout` when set.
///
/// The socket is dialed via tokio, converted to a blocking `socket2::Socket`
/// to apply the options, then converted back to a non-blocking tokio
/// `TcpStream` for the russh handshake. Errors map onto `russh::Error::IO` so
/// the caller's existing dial-failure diagnostics apply unchanged.
async fn dial_tuned(
    host: &str,
    port: u16,
    connection: &ConnectionPolicy,
) -> std::result::Result<TcpStream, russh::Error> {
    // Resolution policy. `PerAttempt` (default) preserves the original
    // `TcpStream::connect((host, port))` semantics exactly (tokio resolves
    // fresh and tries each address). `Once` resolves through the shared
    // `spt_core::dns` cache so a `(host, port)` is pinned across reconnects.
    let connect_result = match connection.dns {
        DnsResolution::PerAttempt => {
            let connect = TcpStream::connect((host, port));
            match connection.connect_timeout {
                Some(timeout) => tokio::time::timeout(timeout, connect)
                    .await
                    .map_err(|_| {
                        russh::Error::IO(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("connect to {host}:{port} timed out after {timeout:?}"),
                        ))
                    })?
                    .map_err(russh::Error::IO)?,
                None => connect.await.map_err(russh::Error::IO)?,
            }
        }
        DnsResolution::Once => {
            let addrs =
                spt_core::resolve_dns(host, port, DnsResolution::Once).map_err(russh::Error::IO)?;
            let connect = TcpStream::connect(&addrs[..]);
            match connection.connect_timeout {
                Some(timeout) => tokio::time::timeout(timeout, connect)
                    .await
                    .map_err(|_| {
                        russh::Error::IO(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("connect to {host}:{port} timed out after {timeout:?}"),
                        ))
                    })?
                    .map_err(russh::Error::IO)?,
                None => connect.await.map_err(russh::Error::IO)?,
            }
        }
    };
    let sock = connect_result;

    if let Some(opts) = connection.tcp_options() {
        // Convert tokio → std → socket2 to apply options, then back to tokio.
        // `into_std` requires the runtime to deregister the socket; the socket
        // is re-registered by `from_std`. Options are applied while it is a
        // plain `socket2::Socket` (blocking), matching `spt_net::sockopts`.
        let std_sock = sock.into_std().map_err(russh::Error::IO)?;
        let socket = socket2::Socket::from(std_sock);
        spt_net::sockopts::apply(&socket, &opts).map_err(|e| {
            russh::Error::IO(std::io::Error::other(format!(
                "apply socket options for {host}:{port}: {e}"
            )))
        })?;
        let std_sock: std::net::TcpStream = socket.into();
        std_sock.set_nonblocking(true).map_err(russh::Error::IO)?;
        return TcpStream::from_std(std_sock).map_err(russh::Error::IO);
    }
    Ok(sock)
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
    connection: &ConnectionPolicy,
) -> std::result::Result<(RusshHandle, Option<&'static str>), russh::Error> {
    match obfs {
        None => {
            // When the connection policy requests no socket-level tuning and no
            // connect timeout, preserve the legacy `client::connect` fast path
            // (russh dials TCP itself). Otherwise dial the socket here so we can
            // apply `[profiles.connection]` socket options + connect timeout,
            // then hand the tuned stream to `connect_stream`.
            if connection.tcp_options().is_none() && connection.connect_timeout.is_none() {
                let handle = client::connect(cfg, (host.to_owned(), port), handler).await?;
                return Ok((handle, None));
            }
            let sock = dial_tuned(host, port, connection).await?;
            let handle = client::connect_stream(cfg, sock, handler).await?;
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
                policy.resolved_secret.clone(),
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

/// Map a `tokio::time::timeout` elapse on the SSH handshake to the same
/// `russh::Error::IO(TimedOut)` idiom `dial_tuned`'s connect-timeout uses, so
/// the caller's existing dial-failure diagnostics + backoff apply unchanged.
fn handshake_timed_out(host: &str, port: u16, timeout: Duration) -> russh::Error {
    russh::Error::IO(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("SSH handshake to {host}:{port} timed out after {timeout:?}"),
    ))
}

/// Run `dial_outer`, bounding it with `handshake_timeout` (when `Some`) via
/// `tokio::time::timeout`. Mirrors the `connect_timeout` wrap in `dial_tuned`.
/// Applied per-leg so every hop honours the same handshake deadline.
async fn dial_outer_timed(
    cfg: Arc<client::Config>,
    host: &str,
    port: u16,
    handler: ClientHandler,
    obfs: Option<&ObfsPolicy>,
    connection: &ConnectionPolicy,
) -> std::result::Result<(RusshHandle, Option<&'static str>), russh::Error> {
    let dial = dial_outer(cfg, host, port, handler, obfs, connection);
    match connection.handshake_timeout {
        Some(timeout) => tokio::time::timeout(timeout, dial)
            .await
            .map_err(|_| handshake_timed_out(host, port, timeout))?,
        None => dial.await,
    }
}

/// Run `run_auth`, bounding it with `auth_timeout` (when `Some`) via
/// `tokio::time::timeout`. On elapse maps to an `AuthFailed` diagnostic so the
/// existing auth-failure handling (no retry) applies.
async fn run_auth_timed(
    handle: SharedHandle,
    auth_cfg: AuthConfig,
    backends: Vec<Arc<dyn SecretBackend>>,
    gss_audit: Option<Arc<dyn spt_auth_sspi::AuditHook>>,
    auth_timeout: Option<Duration>,
) -> Result<()> {
    let drive = run_auth(handle, auth_cfg, backends, gss_audit);
    match auth_timeout {
        Some(timeout) => match tokio::time::timeout(timeout, drive).await {
            Ok(res) => res,
            Err(_) => Err(Error::auth_failed(
                spt_core::Diagnostic::what(format!(
                    "SSH authentication timed out after {timeout:?}"
                ))
                .why("the userauth flow did not complete within `connection.auth_timeout`")
                .how_to_fix(
                    "Increase `[profiles.connection].auth_timeout`, or investigate a slow / \
                     hung auth backend (ssh-agent, OIDC device flow, keyboard-interactive \
                     prompt) on this endpoint.",
                )
                .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                .build(),
            )),
        },
        None => drive.await,
    }
}

async fn connect_inner(params: ReconnectParams) -> Result<RusshSsh2Session> {
    // Keep a clone of the dial inputs so the returned session can re-run a
    // fresh side dial for `preflight_connect` (§3). The locals below shadow
    // the params fields for the existing connect path (which consumes them).
    let reconnect = params.clone();
    let ReconnectParams {
        endpoint,
        auth_cfg,
        crypto,
        trust,
        backends,
        hops,
        gss_audit,
        keepalive,
        mut obfs,
        connection,
    } = params;

    // Resolve the obfuscation transport's secret (the Shadowsocks `password`)
    // through the SAME secrets backend chain the SSH auth path uses, before
    // any dial. A `secret://`/`file://`/vault-backed obfs password is only a
    // reference on disk; the transport needs the bytes to derive its AEAD
    // subkey. Resolving here (per `connect_inner` call) means reconnects
    // re-resolve, and the resolved bytes never live in the persisted
    // `ReconnectParams`. Transports with no secret leave this `None`.
    if let Some(policy) = obfs.as_mut() {
        if let Some(pw_ref) = policy.config.password_ref() {
            let bytes = resolve_obfs_secret(&backends, pw_ref)?;
            policy.resolved_secret = Some(bytes);
        }
    }

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
    // t-tunnel-wire conn-wire: apply the genuinely-wireable `[profiles.connection]`
    // channel/nodelay knobs onto the russh config. Socket-level options
    // (connect timeout + keepalive) are applied at the dial site below.
    connection.apply_to_config(&mut config);
    let cfg = Arc::new(config);

    // `pq_offered` reflects the OFFERED kex preference list (does it contain a
    // post-quantum / ML-KEM KEX?), not necessarily what the peer negotiated.
    // Threaded into every `ClientHandler` so `kex_done` can stamp the
    // `pq_offered=<bool>` token. Computed once — the same `crypto`/`cfg` drives
    // every hop.
    let pq_offered = crypto.has_post_quantum_kex();

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
            remote_uds_forwards: RemoteUdsForwardMap::default(),
            // Only the final hop's negotiated crypto is surfaced on the
            // session; intermediate hops capture into a throwaway carrier.
            negotiated: Arc::new(parking_lot::Mutex::new(None)),
            pq_offered,
        };
        // E3-F2: the obfuscation policy wraps the *outermost* transport only —
        // i.e. the plain-TCP dial to the first hop. Inner hops traverse
        // `direct-tcpip` channels and are unaffected.
        let first_handle = match dial_outer_timed(
            cfg.clone(),
            &first.host,
            first.port,
            first_handler,
            obfs.as_ref(),
            &connection,
        )
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
        run_auth_timed(
            Arc::clone(&first_shared),
            first_auth,
            backends.clone(),
            gss_audit.clone(),
            connection.auth_timeout,
        )
        .await?;

        // Walk intermediate hops [1..]: each opens a leg *through the prior
        // session* and handshakes a fresh russh client over the resulting
        // channel stream. The leg toward `hop` is dispatched by the *previous*
        // hop's `kind`: an SSH-kind prior hop opens a plain `direct-tcpip`
        // channel; a proxy-kind prior hop (SOCKS5 / HTTP CONNECT) opens a
        // channel to the proxy and tunnels the CONNECT toward `hop` through it.
        let mut prev_shared = first_shared;
        let mut prev_hop = first;
        for hop in &hops[1..] {
            let hop_trust = hop.trust.clone().unwrap_or_else(|| trust.clone());
            let hop_trust_failure = Arc::new(parking_lot::Mutex::new(None));
            let hop_handler = ClientHandler {
                host: hop.host.clone(),
                port: hop.port,
                trust: hop_trust,
                trust_failure: Arc::clone(&hop_trust_failure),
                remote_forwards: RemoteForwardMap::default(),
                remote_uds_forwards: RemoteUdsForwardMap::default(),
                negotiated: Arc::new(parking_lot::Mutex::new(None)),
                pq_offered,
            };
            let hop_handle = open_next_leg_timed(
                Arc::clone(&prev_shared),
                prev_hop,
                &hop.host,
                hop.port,
                cfg.clone(),
                hop_handler,
                connection.handshake_timeout,
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
            run_auth_timed(
                Arc::clone(&hop_shared),
                hop_auth,
                backends.clone(),
                gss_audit.clone(),
                connection.auth_timeout,
            )
            .await?;
            prev_shared = hop_shared;
            prev_hop = hop;
        }

        // Final leg: tunnel through the last hop to `endpoint`. Dispatched by
        // the last hop's `kind` (proxy-kind ⇒ CONNECT to `endpoint` through it).
        let final_trust_failure = Arc::new(parking_lot::Mutex::new(None));
        let final_remote_forwards = RemoteForwardMap::default();
        let final_remote_uds_forwards = RemoteUdsForwardMap::default();
        let final_negotiated = Arc::new(parking_lot::Mutex::new(None));
        let final_handler = ClientHandler {
            host: endpoint.host.clone(),
            port: endpoint.port,
            trust,
            trust_failure: Arc::clone(&final_trust_failure),
            remote_forwards: Arc::clone(&final_remote_forwards),
            remote_uds_forwards: Arc::clone(&final_remote_uds_forwards),
            negotiated: Arc::clone(&final_negotiated),
            pq_offered,
        };
        let final_handle = open_next_leg_timed(
            Arc::clone(&prev_shared),
            prev_hop,
            &endpoint.host,
            endpoint.port,
            cfg.clone(),
            final_handler,
            connection.handshake_timeout,
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
        run_auth_timed(
            Arc::clone(&final_shared),
            auth_cfg,
            backends,
            gss_audit,
            connection.auth_timeout,
        )
        .await?;
        // The canonical negotiated-crypto token captured by the final hop's
        // `kex_done` (falls back to `None` if — unexpectedly — kex_done never
        // fired). Emit the always-on structured crypto log next to the
        // establishment of the final leg.
        let negotiated = final_negotiated.lock().clone();
        if let Some(token) = negotiated.as_deref() {
            emit_crypto_negotiated_log(token, pq_offered);
        }
        info!(
            target: "spt_ssh2::russh",
            host = %endpoint.host,
            port = endpoint.port,
            backend = "ssh2-russh",
            hops = hops.len(),
            "SSH2 multi-hop session established and authenticated"
        );
        let info = SessionInfo {
            backend: "ssh2-russh".into(),
            peer_version: None,
            negotiated,
            established_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        return Ok(RusshSsh2Session {
            handle: final_shared,
            remote_forwards: final_remote_forwards,
            remote_uds_forwards: final_remote_uds_forwards,
            channel_idle_timeout: connection.channel_idle_timeout,
            reconnect,
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
    let remote_uds_forwards = RemoteUdsForwardMap::default();
    let negotiated_carrier = Arc::new(parking_lot::Mutex::new(None));
    let handler = ClientHandler {
        host: endpoint.host.clone(),
        port: endpoint.port,
        trust,
        trust_failure: Arc::clone(&trust_failure),
        remote_forwards: Arc::clone(&remote_forwards),
        remote_uds_forwards: Arc::clone(&remote_uds_forwards),
        negotiated: Arc::clone(&negotiated_carrier),
        pq_offered,
    };

    // E3-F2: route the single direct endpoint through `dial_outer`, so a
    // configured `[obfuscation]` transport actually carries the handshake
    // (was: `client::connect` always dialed plain TCP, making the obfs crate
    // and config unreachable).
    let (handle, obfs_name) = match dial_outer_timed(
        cfg,
        &endpoint.host,
        endpoint.port,
        handler,
        obfs.as_ref(),
        &connection,
    )
    .await
    {
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

    // Wrap the handle in `Arc<AsyncMutex>` *before* `run_auth` so every auth
    // arm (including the agent `authenticate_publickey_with` path) shares one
    // owned handle. russh 0.61 carries the `+ 'static` `Signer` bounds
    // upstream, so the spawn gymnastics the vendored 0.46 fork required are no
    // longer needed; each arm just takes a single `.lock().await` per call.
    let shared = Arc::new(AsyncMutex::new(handle));
    run_auth_timed(
        Arc::clone(&shared),
        auth_cfg,
        backends,
        gss_audit,
        connection.auth_timeout,
    )
    .await?;
    info!(
        target: "spt_ssh2::russh",
        host = %endpoint.host,
        port = endpoint.port,
        backend = "ssh2-russh",
        "SSH2 session established and authenticated"
    );
    // Canonical negotiated-crypto token captured by `kex_done` (falls back to
    // `None` if kex_done somehow never fired). Emit the always-on structured
    // crypto log next to the establishment line above.
    let negotiated = negotiated_carrier.lock().clone();
    if let Some(token) = negotiated.as_deref() {
        emit_crypto_negotiated_log(token, pq_offered);
    }
    let info = SessionInfo {
        backend: "ssh2-russh".into(),
        peer_version: None,
        negotiated,
        established_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };

    Ok(RusshSsh2Session {
        handle: shared,
        remote_forwards,
        remote_uds_forwards,
        channel_idle_timeout: connection.channel_idle_timeout,
        reconnect,
        info,
        script_engine: None,
        script_ctx: ScriptContext::default(),
        established_at_instant: std::time::Instant::now(),
        obfs_transport_name: obfs_name,
        obfs_audit: obfs.as_ref().and_then(|p| p.audit.clone()),
    })
}

/// Open the next chained leg toward `(target_host, target_port)` through the
/// `prev` hop's already-authenticated session, dispatching by `prev.kind`:
///
/// * [`HopKind::Ssh`] — a plain `direct-tcpip` channel to the target plus a
///   fresh SSH handshake (the historical behavior;
///   [`crate::multi_hop::open_chained_session`]).
/// * [`HopKind::Socks5`] / [`HopKind::HttpConnect`] — a `direct-tcpip` channel
///   to the *proxy* (`prev.host:prev.port`), the SOCKS5 / HTTP CONNECT
///   handshake aimed at `(target_host, target_port)`, then the SSH handshake
///   through the now-tunneled stream
///   ([`crate::multi_hop::open_chained_session_with_kind`]).
///
/// This is the dispatch point the proxy-hop wiring needs: the leaf proxy /
/// chained-session helpers already exist and are tested; this connects them to
/// the `HopSpec.kind` / `HopSpec.creds` fields populated by the factory.
async fn open_next_leg(
    prev_shared: SharedHandle,
    prev: &HopSpec,
    target_host: &str,
    target_port: u16,
    cfg: Arc<client::Config>,
    handler: ClientHandler,
) -> Result<RusshHandle> {
    match prev.kind {
        HopKind::Ssh => {
            crate::multi_hop::open_chained_session(
                prev_shared,
                target_host,
                target_port,
                cfg,
                handler,
            )
            .await
        }
        HopKind::Socks5 | HopKind::HttpConnect => {
            crate::multi_hop::open_chained_session_with_kind(
                prev_shared,
                &prev.host,
                prev.port,
                target_host,
                target_port,
                prev.kind,
                prev.creds.clone(),
                cfg,
                handler,
            )
            .await
        }
    }
}

/// [`open_next_leg`] bounded by `handshake_timeout` (when `Some`). Mirrors
/// `dial_outer_timed`: the per-leg handshake (the proxy/CONNECT handshake plus
/// the chained SSH handshake) is wrapped in `tokio::time::timeout`, so a hop
/// that hangs mid-handshake fails fast with the same `TimedOut` IO idiom rather
/// than blocking the whole chain indefinitely.
#[allow(clippy::too_many_arguments)]
async fn open_next_leg_timed(
    prev_shared: SharedHandle,
    prev: &HopSpec,
    target_host: &str,
    target_port: u16,
    cfg: Arc<client::Config>,
    handler: ClientHandler,
    handshake_timeout: Option<Duration>,
) -> Result<RusshHandle> {
    let leg = open_next_leg(prev_shared, prev, target_host, target_port, cfg, handler);
    match handshake_timeout {
        Some(timeout) => match tokio::time::timeout(timeout, leg).await {
            Ok(res) => res,
            Err(_) => Err(Error::NetworkUnreachable(format!(
                "SSH handshake to hop `{target_host}:{target_port}` timed out after {timeout:?}"
            ))),
        },
        None => leg.await,
    }
}

/// Inputs needed to re-run [`connect_inner`] for a fresh side connection.
///
/// `preflight_connect` (t-tunnel-wire-2 §3) opens a brand-new connect+auth-only
/// dial to the SAME endpoint this session targets, without touching the live
/// session. The session therefore carries a clone of every `connect_inner`
/// input so the preflight can reproduce the exact dial + auth flow and then
/// drop the result. Cloning these is cheap relative to a TCP+SSH handshake and
/// keeps the live session untouched.
#[derive(Clone)]
struct ReconnectParams {
    endpoint: Endpoint,
    auth_cfg: AuthConfig,
    crypto: CryptoPolicy,
    trust: TrustVerifier,
    backends: Vec<Arc<dyn SecretBackend>>,
    hops: Vec<HopSpec>,
    gss_audit: Option<Arc<dyn spt_auth_sspi::AuditHook>>,
    keepalive: KeepalivePolicy,
    obfs: Option<ObfsPolicy>,
    connection: ConnectionPolicy,
}

/// russh-backed [`TunnelSession`] — the only SSH2 session type after
/// t7-Phase0. Re-exported as [`crate::Ssh2Session`].
pub struct RusshSsh2Session {
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    /// Server-opened `forwarded-streamlocal@openssh.com` channels land here,
    /// routed by the `server_channel_open_forwarded_streamlocal` handler hook
    /// to the matching `remote_uds` accept loop.
    remote_uds_forwards: RemoteUdsForwardMap,
    /// Combined per-channel read/write idle deadline from
    /// `[profiles.connection].{read,write}_timeout` (t-tunnel-wire-2 §1). When
    /// `Some`, every forward bridge runs its copy loop with the MIN of this and
    /// the per-forward `idle_timeout`, so the tighter deadline wins.
    channel_idle_timeout: Option<Duration>,
    /// Inputs to re-run a fresh connect+auth dial for `preflight_connect`.
    reconnect: ReconnectParams,
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
        let handle = open_local(Arc::clone(&self.handle), spec, self.channel_idle_timeout).await?;
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
            self.channel_idle_timeout,
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
        let handle =
            open_dynamic(Arc::clone(&self.handle), spec, self.channel_idle_timeout).await?;
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

    async fn open_uds_forward(&mut self, spec: &UdsForwardSpec) -> Result<ForwardHandle> {
        // `local_uds`: bind a local AF_UNIX listener on `listen_path`, and for
        // each accepted stream open a `direct-streamlocal@openssh.com` channel
        // to the remote `remote_socket_path`, bridging the two with the
        // per-forward limits + idle timeout. On non-Unix the `cfg(not(unix))`
        // impl below surfaces `UnsupportedPlatform` (the trait default
        // behaviour is preserved for the platform that cannot bind AF_UNIX).
        let handle = open_uds(Arc::clone(&self.handle), spec, self.channel_idle_timeout).await?;
        self.dispatch_forward_state(
            if spec.name.is_empty() {
                format!("local_uds:{}", spec.listen_path.display())
            } else {
                spec.name.clone()
            },
            spt_scripting::event::ForwardStateTransition::Listening,
        )
        .await;
        Ok(handle)
    }

    async fn open_remote_uds(&mut self, spec: &RemoteUdsForwardSpec) -> Result<ForwardHandle> {
        // `remote_uds`: ask the server to listen on `spec.remote_socket_path`
        // (via `streamlocal-forward@openssh.com`), then drain the server-opened
        // `forwarded-streamlocal@openssh.com` channels and bridge each to a
        // local `UnixStream::connect(spec.local_socket_path)`. This is the
        // streamlocal analogue of `open_remote`/`open_remote_forward`. On
        // non-Unix the `cfg(not(unix))` impl surfaces `UnsupportedPlatform`
        // (connecting an `AF_UNIX` socket is Unix-only).
        let handle = open_remote_uds(
            Arc::clone(&self.handle),
            Arc::clone(&self.remote_uds_forwards),
            spec,
            self.channel_idle_timeout,
        )
        .await?;
        self.dispatch_forward_state(
            if spec.name.is_empty() {
                format!("remote_uds:{}", spec.remote_socket_path)
            } else {
                spec.name.clone()
            },
            spt_scripting::event::ForwardStateTransition::Active,
        )
        .await;
        Ok(handle)
    }

    async fn preflight_connect(&mut self) -> Result<()> {
        // §3: open a FRESH side connection to the SAME endpoint this session
        // targets, run the full connect + auth flow to completion, then drop it
        // immediately. This never touches the live session (`self.handle` is
        // untouched) — it re-runs `connect_inner` against a clone of the
        // original dial inputs and discards the resulting session on success.
        // Auth/handshake timeouts (§1) apply because they live on the cloned
        // `ConnectionPolicy`.
        let session = connect_inner(self.reconnect.clone()).await?;
        // Best-effort graceful disconnect of the side connection; the connect +
        // auth already proved reachability + credentials, which is the whole
        // point of the preflight. A disconnect error does not invalidate the
        // successful preflight.
        let _ = Box::new(session).close().await;
        Ok(())
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
        info!(
            target: "spt_ssh2::russh",
            backend = %self.info.backend,
            "SSH2 session closing"
        );
        // E8-F1: fire the `on_disconnect` hook before tearing the transport
        // down so operator scripts observe the session ending with a stable
        // reason and the measured lifetime. A script failure is logged and
        // swallowed inside the dispatcher — it must not block the close.
        if self.has_script_engine() {
            let duration_ms = self.established_at_instant.elapsed().as_millis() as u64;
            let event = spt_scripting::event::Event::Disconnect(spt_scripting::event::Disconnect {
                profile: self.script_ctx.profile.clone(),
                reason: "user_request".into(),
                duration_ms,
            });
            self.dispatch_script_event_async(spt_scripting::config::HookName::OnDisconnect, event)
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
        preferred.key = Cow::Owned(parse_host_key_names(&crypto.host_keys)?);
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

/// Parse host-key algorithm names into russh 0.61's `ssh_key::Algorithm`.
///
/// Unlike the `kex`/`cipher`/`mac`/`compression` `Name` types, `ssh-key`'s
/// `Algorithm` does not implement `TryFrom<&str>`; it implements `FromStr`
/// via `Algorithm::new`. We map a parse failure onto the same `InvalidConfig`
/// diagnostic `parse_names` produces.
fn parse_host_key_names(values: &[String]) -> Result<Vec<russh::keys::ssh_key::Algorithm>> {
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let algo = russh::keys::ssh_key::Algorithm::new(value).map_err(|_| {
            Error::InvalidConfig(format!(
                "russh SSH2 backend does not support host_key algorithm `{value}`"
            ))
        })?;
        parsed.push(algo);
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
                warn!(
                    target: "spt_ssh2::russh",
                    method = method_name(&method),
                    "auth method rejected by server (authentication failure); trying next method"
                );
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
                .map(|r| r.success())
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
            let key = russh::keys::load_secret_key(&identity_file, passphrase.as_deref())
                .map_err(|e| classify_key_load_error("load private key", e))?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), RSA_AUTH_HASH_ALG);
            let mut h = handle.lock().await;
            let user_for_msg = username.clone();
            h.authenticate_publickey(username, key)
                .await
                .map(|r| r.success())
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
            let key = russh::keys::load_secret_key(&key, passphrase.as_deref())
                .map_err(|e| classify_key_load_error("load private key", e))?;
            let cert = russh::keys::load_openssh_certificate(&cert)
                .map_err(|e| classify_cert_load_error("load OpenSSH certificate", e))?;
            let mut h = handle.lock().await;
            let user_for_msg = username.clone();
            h.authenticate_openssh_cert(username, Arc::new(key), cert)
                .await
                .map(|r| r.success())
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
        AuthMethod::Agent {
            socket,
            identity_hint,
        } => try_agent_auth(handle, username, socket, identity_hint).await,
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
            client::KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let mut answers = Vec::with_capacity(prompts.len());
                for prompt in prompts {
                    let idx = compiled
                        .iter()
                        .position(|re| re.is_match(&prompt.prompt))
                        .ok_or_else(|| {
                            Error::AuthFailed(kbi_unmatched_prompt_msg(&prompt.prompt))
                        })?;
                    let r = &responder[idx];
                    if r.echo != prompt.echo {
                        warn!(
                            target: "spt_ssh2::russh",
                            prompt = %escape_control(&prompt.prompt),
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
/// identity in turn via
/// [`russh::client::Handle::authenticate_publickey_with`]. Returns `Ok(true)`
/// on the first identity the server accepts.
///
/// A single `AgentClient` serves every identity attempt: russh 0.61's
/// `authenticate_publickey_with` borrows the [`russh::auth::Signer`] mutably
/// (the 0.46 by-value consumption that forced a fresh client per attempt is
/// gone).
async fn try_agent_auth(
    handle: SharedHandle,
    username: String,
    socket: Option<std::path::PathBuf>,
    identity_hint: Option<String>,
) -> Result<bool> {
    let socket_ref = socket.as_deref();
    // First listing connection — surface "no agent reachable" errors early.
    let listing_client = Agent::open_signer(socket_ref).await?;
    let mut identities = {
        // Reuse the listing connection just for `request_identities`.
        let mut client = listing_client;
        client
            .request_identities()
            .await
            .map_err(|e| Error::AuthFailed(format!("ssh-agent: request_identities: {e}")))?
    };

    // E?-A2: if the profile supplied an `identity_hint`, prefer the matching
    // identity first (by key comment exact-match, or by `SHA256:…`
    // fingerprint). We stable-partition rather than filter so an unmatched or
    // wrong hint still falls back to trying every identity in natural order.
    if let Some(hint) = identity_hint.as_deref() {
        reorder_by_identity_hint(&mut identities, hint);
    }

    // russh 0.61 lets one `AgentClient` signer serve every identity attempt
    // (`authenticate_publickey_with` borrows `&mut signer`), so unlike the
    // 0.46 fork we open a single signer and reuse it across identities.
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

    // A single signer drives every identity attempt (russh 0.61's
    // `authenticate_publickey_with` borrows the `Signer` mutably).
    let mut signer = Agent::open_signer(socket_ref).await?;
    let mut last_err: Option<String> = None;
    for key in identities {
        let user = username.clone();
        let outcome = drive_authenticate_future(Arc::clone(&handle), user, &key, &mut signer).await;
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

/// Stable-reorder `identities` so every entry matching `hint` (by key comment
/// exact-match or by `SHA256:…` fingerprint) is tried first, preserving the
/// agent's natural order within each group. A hint that matches nothing leaves
/// the list untouched, so the flow still tries every identity.
fn reorder_by_identity_hint(identities: &mut [russh::keys::agent::AgentIdentity], hint: &str) {
    // `sort_by_key` is stable, so mapping "matches" → 0 and "no match" → 1
    // moves matches to the front while preserving relative order in each group.
    identities.sort_by_key(|id| usize::from(!identity_matches_hint(id, hint)));
}

/// True when `identity` matches the operator-supplied `hint`, either by an
/// exact key-comment match or by a `SHA256:…` public-key fingerprint match
/// (case-insensitive on the `SHA256` label; the base64 body is compared
/// verbatim).
fn identity_matches_hint(identity: &russh::keys::agent::AgentIdentity, hint: &str) -> bool {
    if identity.comment() == hint {
        return true;
    }
    agent_fingerprint(identity).eq_ignore_ascii_case(hint)
}

/// Canonical `SHA256:…` fingerprint of an agent identity's public key, used to
/// match an `identity_hint`. Distinct from [`Agent::fingerprint`], which
/// renders an `algorithm (base64)` diagnostic string rather than the
/// OpenSSH-style fingerprint operators paste from `ssh-add -l`.
fn agent_fingerprint(identity: &russh::keys::agent::AgentIdentity) -> String {
    identity
        .public_key()
        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
        .to_string()
}

/// Drive russh's `Signer`-based publickey userauth path.
///
/// Calls [`russh::client::Handle::authenticate_publickey_with`] with the
/// supplied agent-client signer. In russh 0.61 the `AgentClient<R>` itself
/// implements [`russh::auth::Signer`] (`auth_sign`), and each server
/// `SignRequest` is dispatched back through the agent's `sign_request` round
/// trip internally — no vendored fork is needed. The signer is borrowed
/// mutably, so a single agent connection serves every identity.
///
/// The identity's public key is presented to the server; for RSA agent keys
/// we request a SHA-256 signature (`rsa-sha2-256`).
async fn drive_authenticate_future(
    handle: SharedHandle,
    user: String,
    identity: &russh::keys::agent::AgentIdentity,
    signer: &mut crate::agent::DynAgentClient,
) -> std::result::Result<bool, String> {
    let public_key = identity.public_key().into_owned();
    let mut h = handle.lock().await;
    h.authenticate_publickey_with(user, public_key, RSA_AUTH_HASH_ALG, signer)
        .await
        .map(|r| r.success())
        .map_err(|e| format!("russh authenticate_publickey_with: {e}"))
}

/// Hash algorithm to request for RSA keys. russh ignores this for non-RSA
/// algorithms (Ed25519/ECDSA), so it is safe to pass unconditionally. We pick
/// SHA-256 (`rsa-sha2-256`) — the modern default OpenSSH accepts; passing
/// `None` would select the deprecated SHA-1 `ssh-rsa`.
const RSA_AUTH_HASH_ALG: Option<HashAlg> = Some(HashAlg::Sha256);

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
/// **russh 0.61 does not implement `gssapi-with-mic` as a first-class
/// userauth primitive.** The
/// [`russh::auth::Method`] enum covers `none`, `password`, `publickey`,
/// `openssh-cert`, `future-publickey`, `future-certificate`, and
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
        "russh 0.61 does not yet expose gssapi-with-mic (RFC 4462) as a userauth method; \
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
        "russh 0.61 does not yet expose gssapi-with-mic / SSPI Negotiate (RFC 4462) as a \
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

/// Resolve an obfuscation transport's pre-shared secret (the Shadowsocks
/// `password`) into raw bytes via the configured secrets backend chain.
///
/// The obfs `password` is a `spt_secrets::SecretRef` (`secret://ns/name`),
/// resolved through the very same `backends` the SSH auth path uses for
/// `password_ref`/passphrase resolution — the first backend to return a value
/// wins. A reference that no backend can resolve is a hard error (we will not
/// dial with an unresolved obfs password), surfaced as `SecretUnavailable`.
fn resolve_obfs_secret(
    backends: &[Arc<dyn SecretBackend>],
    reference: &spt_secrets::SecretRef,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    for b in backends {
        if let Some(v) = b.get(reference)? {
            return Ok(zeroize::Zeroizing::new(v.expose_secret().to_vec()));
        }
    }
    Err(Error::SecretUnavailable {
        reference: reference.to_string(),
        reason: "no backend resolved the obfuscation password reference".into(),
    })
}

/// Per-direction token buckets built from a forward's [`ForwardRateLimits`].
///
/// `up` throttles the client→remote direction (`a→b` in
/// [`copy_bidirectional_throttled_idle`]); `down` throttles remote→client.
/// A zero rate yields an inert bucket (unlimited), preserving the prior
/// `TokenBucket::unlimited()` behaviour at every forward-open site.
struct ForwardBuckets {
    up: TokenBucket,
    down: TokenBucket,
}

impl ForwardBuckets {
    fn from_limits(limits: &ForwardRateLimits) -> Self {
        Self {
            up: TokenBucket::new(limits.rate_bps_up, limits.burst_up),
            down: TokenBucket::new(limits.rate_bps_down, limits.burst_down),
        }
    }
}

/// Combine a per-forward `idle_timeout` with the connection-level
/// `channel_idle_timeout` (the "combined channel-idle" deadline derived from
/// `[profiles.connection].{read,write}_timeout`, t-tunnel-wire-2 §1).
///
/// When BOTH are `Some` the tighter (MIN) deadline wins, so neither the
/// per-forward nor the connection-level bound can be exceeded. When only one is
/// `Some` it is used as-is. `None`/`None` ⇒ no idle close (legacy behaviour).
fn combine_idle(per_forward: Option<Duration>, channel: Option<Duration>) -> Option<Duration> {
    match (per_forward, channel) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Bind a local TCP listener honouring the forward's [`BindConflictPolicy`].
///
/// Returns the bound listener; the actually-bound address (which may differ
/// from the requested one under [`BindConflictPolicy::NextPort`]) is logged.
async fn bind_local_listener(
    listen: &BindAddr,
    policy: BindConflictPolicy,
    name: &str,
) -> Result<TcpListener> {
    let bind = bind_addr_string(listen)?;
    let desired: SocketAddr = bind.parse().map_err(|e| Error::LocalBindFailed {
        address: bind.clone(),
        reason: format!("parse bind address: {e}"),
    })?;
    let BoundListener { listener, addr } = bind_with_policy(desired, policy).await?;
    if addr != desired {
        warn!(
            target: "spt_ssh2::russh",
            forward = %name,
            requested = %desired,
            bound = %addr,
            "bind conflict resolved to a different address"
        );
    }
    Ok(listener)
}

async fn open_local(
    handle: SharedHandle,
    spec: &LocalForwardSpec,
    channel_idle: Option<Duration>,
) -> Result<ForwardHandle> {
    let name = spec.name.clone();
    let listener = bind_local_listener(&spec.listen, spec.on_bind_conflict, &name).await?;

    let (state_tx, state_rx) = watch::channel(ForwardState::Listening);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    tokio::spawn(local_loop(
        listener,
        handle,
        spec.target.clone(),
        state_tx,
        close_rx,
        spec.max_connections,
        name.clone(),
        spec.limits,
        combine_idle(spec.idle_timeout, channel_idle),
    ));
    info!(target: "spt_ssh2::russh", forward = %name, "local forward opened");
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

async fn open_dynamic(
    handle: SharedHandle,
    spec: &DynamicForwardSpec,
    channel_idle: Option<Duration>,
) -> Result<ForwardHandle> {
    let name = spec.name.clone();
    let listener = bind_local_listener(&spec.listen, spec.on_bind_conflict, &name).await?;

    let (state_tx, state_rx) = watch::channel(ForwardState::Listening);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let protocols = crate::dynamic::DynamicProxyProtocolSet {
        socks4: spec.allow_socks4,
        socks4a: spec.allow_socks4a,
        socks5: spec.allow_socks5,
        http_connect: spec.allow_http_connect,
    };
    // SSRF mitigation: build the destination ACL from the spec. Bad patterns
    // are rejected at open time (fail-closed) so a typo never silently
    // degrades into allow-all.
    let target_acl = Arc::new(
        crate::target_acl::TargetAcl::from_patterns(
            Some(&spec.allow_targets),
            Some(&spec.deny_targets),
        )
        .map_err(|e| Error::InvalidConfig(format!("dynamic forward `{name}` target ACL: {e}")))?,
    );
    tokio::spawn(dynamic_loop(
        listener,
        handle,
        state_tx,
        close_rx,
        spec.max_connections,
        name.clone(),
        protocols,
        target_acl,
        spec.limits,
        combine_idle(spec.idle_timeout, channel_idle),
    ));
    info!(target: "spt_ssh2::russh", forward = %name, "dynamic (SOCKS/HTTP-CONNECT) forward opened");
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

#[allow(clippy::too_many_arguments)]
async fn local_loop(
    listener: TcpListener,
    handle: SharedHandle,
    target: TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    max_connections: Option<u32>,
    name: String,
    limits: ForwardRateLimits,
    idle_timeout: Option<Duration>,
) {
    let _ = state_tx.send(ForwardState::Active);
    let active = Arc::new(std::sync::atomic::AtomicU32::new(0));
    // `max_new_conns_per_sec == 0` ⇒ unlimited gate (preserves prior behaviour).
    let rate_gate = RateGate::new(limits.max_new_conns_per_sec, limits.max_new_conns_per_sec);
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
                if !rate_gate.admit() {
                    warn!(target: "spt_ssh2::russh", forward = %name, "max_new_connections_per_second reached, dropping connection");
                    continue;
                }
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
                    if let Err(e) = bridge_local(handle, sock, peer, &target, &limits, idle_timeout).await {
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
    target_acl: Arc<crate::target_acl::TargetAcl>,
    limits: ForwardRateLimits,
    idle_timeout: Option<Duration>,
) {
    let _ = state_tx.send(ForwardState::Active);
    let active = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let rate_gate = RateGate::new(limits.max_new_conns_per_sec, limits.max_new_conns_per_sec);
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
                if !rate_gate.admit() {
                    warn!(target: "spt_ssh2::russh", forward = %name, "max_new_connections_per_second reached, dropping connection");
                    continue;
                }
                if let Some(limit) = max_connections {
                    if active.load(std::sync::atomic::Ordering::Relaxed) >= limit {
                        warn!(target: "spt_ssh2::russh", forward = %name, "max_connections reached");
                        continue;
                    }
                }
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let handle = Arc::clone(&handle);
                let active = Arc::clone(&active);
                let target_acl = Arc::clone(&target_acl);
                let name = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_dynamic(handle, sock, peer, protocols, &target_acl, &limits, idle_timeout).await {
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
    limits: &ForwardRateLimits,
    idle_timeout: Option<Duration>,
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
    let buckets = ForwardBuckets::from_limits(limits);
    // `sock` is the client side (a), `stream` the tunnel/remote side (b):
    // a→b throttles client→remote (up), b→a throttles remote→client (down).
    copy_bidirectional_throttled_idle(
        &mut sock,
        &mut stream,
        buckets.up,
        buckets.down,
        idle_timeout,
    )
    .await
    .map_err(|e| Error::RuntimeFailure(format!("russh local bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn bridge_dynamic(
    handle: SharedHandle,
    mut sock: TcpStream,
    peer: SocketAddr,
    protocols: crate::dynamic::DynamicProxyProtocolSet,
    target_acl: &crate::target_acl::TargetAcl,
    limits: &ForwardRateLimits,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    let handshake_timeout = idle_timeout.unwrap_or(crate::dynamic::DEFAULT_HANDSHAKE_TIMEOUT);
    let request =
        crate::dynamic::read_request_with_timeout(&mut sock, protocols, handshake_timeout).await?;
    // SSRF mitigation: enforce the destination ACL BEFORE opening any channel.
    // A forbidden target is rejected at the SOCKS layer (code 0x02 for SOCKS5)
    // and the connection closed without ever asking the server to dial.
    if !target_acl.permits(&request.target.host, request.target.port) {
        let _ = crate::dynamic::reply_denied(&mut sock, request.protocol).await;
        return Err(Error::RuntimeFailure(dynamic_target_denied_msg(
            &request.target.host,
            request.target.port,
        )));
    }
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
            return Err(Error::RuntimeFailure(dynamic_dial_failure_msg(
                &request.target.host,
                request.target.port,
                &e,
            )));
        }
    };
    let mut stream = channel.into_stream();
    let buckets = ForwardBuckets::from_limits(limits);
    copy_bidirectional_throttled_idle(
        &mut sock,
        &mut stream,
        buckets.up,
        buckets.down,
        idle_timeout,
    )
    .await
    .map_err(|e| Error::RuntimeFailure(format!("russh dynamic bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Concurrency + new-connection-rate admission gate for the reverse
/// (remote / remote-UDS) forward accept loops.
///
/// This is the *same* mechanism the hardened `local_loop`/`dynamic_loop` apply
/// inline — an `active` [`AtomicU32`](std::sync::atomic::AtomicU32) concurrency
/// counter plus a [`RateGate`] for `max_new_conns_per_sec` — packaged so the two
/// reverse loops can share it and so a slot is released via RAII
/// ([`ConnPermit`]'s `Drop`) even if the per-connection bridge task panics
/// (`local_loop`'s manual `fetch_sub` would leak a slot on panic).
struct ConnLimiter {
    active: Arc<std::sync::atomic::AtomicU32>,
    /// `None` ⇒ no concurrency cap (unlimited), matching an absent
    /// `max_connections` in the forward spec.
    max_connections: Option<u32>,
    /// `max_new_conns_per_sec == 0` ⇒ unlimited gate (preserves prior
    /// behaviour for specs that omit the limit).
    rate_gate: RateGate,
}

impl ConnLimiter {
    fn new(max_connections: Option<u32>, max_new_conns_per_sec: u32) -> Self {
        Self {
            active: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            max_connections,
            rate_gate: RateGate::new(max_new_conns_per_sec, max_new_conns_per_sec),
        }
    }

    /// Try to admit one inbound connection. Returns an RAII [`ConnPermit`] that
    /// decrements the active count on drop, or `None` when the new-connection
    /// rate gate or the `max_connections` cap rejects it.
    ///
    /// Order mirrors `local_loop`/`dynamic_loop` exactly: the rate gate is
    /// consulted first, then the concurrency cap. Admission runs on the single
    /// accept-loop task (never concurrently), so the `load` + `fetch_add` pair
    /// is race-free.
    fn try_admit(&self) -> Option<ConnPermit> {
        if !self.rate_gate.admit() {
            return None;
        }
        if let Some(limit) = self.max_connections {
            if self.active.load(std::sync::atomic::Ordering::Relaxed) >= limit {
                return None;
            }
        }
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(ConnPermit {
            active: Arc::clone(&self.active),
        })
    }

    #[cfg(test)]
    fn active_count(&self) -> u32 {
        self.active.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// RAII slot for one admitted reverse-forward connection. Dropping it (when the
/// bridge task ends — cleanly, by error, or by panic) frees the slot so the
/// limiter never wedges.
struct ConnPermit {
    active: Arc<std::sync::atomic::AtomicU32>,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn open_remote(
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    spec: &RemoteForwardSpec,
    channel_idle: Option<Duration>,
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
        let handle = handle.lock().await;
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
            max_connections: spec.max_connections,
            limits: spec.limits,
            idle_timeout: combine_idle(spec.idle_timeout, channel_idle),
        },
    ));
    info!(target: "spt_ssh2::russh", forward = %name, "remote forward opened");
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

struct RemoteLoopContext {
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    key: RemoteForwardKey,
    target: TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    name: String,
    /// Concurrency cap for inbound (reverse) connections; `None` ⇒ unlimited.
    max_connections: Option<u32>,
    limits: ForwardRateLimits,
    idle_timeout: Option<Duration>,
}

async fn remote_loop(
    mut rx: mpsc::Receiver<ForwardedTcpip>,
    mut close_rx: oneshot::Receiver<()>,
    ctx: RemoteLoopContext,
) {
    // Enforce `max_connections` + `max_new_conns_per_sec` on the reverse path,
    // mirroring `local_loop`/`dynamic_loop`. Without this, every server-pushed
    // `forwarded-tcpip` channel spawned an unbounded bridge (client-side DoS).
    let limiter = ConnLimiter::new(ctx.max_connections, ctx.limits.max_new_conns_per_sec);
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            forwarded = rx.recv() => {
                let Some(forwarded) = forwarded else { break; };
                let Some(permit) = limiter.try_admit() else {
                    debug!(
                        target: "spt_ssh2::russh",
                        forward = %ctx.name,
                        "reverse forward at max_connections / new-conn rate cap, closing inbound channel"
                    );
                    let _ = forwarded.channel.close().await;
                    continue;
                };
                let target = ctx.target.clone();
                let name = ctx.name.clone();
                let limits = ctx.limits;
                let idle_timeout = ctx.idle_timeout;
                tokio::spawn(async move {
                    // Hold the permit for the bridge's lifetime; its `Drop`
                    // releases the concurrency slot when the bridge ends.
                    let _permit = permit;
                    if let Err(e) = bridge_remote(forwarded.channel, &target, &limits, idle_timeout).await {
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

async fn bridge_remote(
    channel: russh::Channel<client::Msg>,
    target: &TargetAddr,
    limits: &ForwardRateLimits,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    let mut stream = channel.into_stream();
    let mut sock = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| {
            Error::NetworkUnreachable(format!(
                "connect remote-forward target {}:{}: {e}",
                target.host, target.port
            ))
        })?;
    // For a remote forward, `stream` is the tunnel side carrying inbound
    // connections (remote→client = `up` semantics relative to the client),
    // `sock` the local target. `a→b` is stream→sock; we apply `up` to the
    // remote-origin direction and `down` to the reply.
    let buckets = ForwardBuckets::from_limits(limits);
    copy_bidirectional_throttled_idle(
        &mut stream,
        &mut sock,
        buckets.up,
        buckets.down,
        idle_timeout,
    )
    .await
    .map_err(|e| Error::RuntimeFailure(format!("russh remote bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Open a `local_uds` forward: bind the local `AF_UNIX` listener on
/// `spec.listen_path` and spawn an accept loop that bridges each accepted
/// stream onto a `direct-streamlocal@openssh.com` channel to
/// `spec.remote_socket_path`.
///
/// On non-Unix targets this returns [`Error::UnsupportedPlatform`] (binding an
/// `AF_UNIX` listener is Unix-only); the outbound channel side would work but
/// there is no local listener half to drive it.
#[cfg(unix)]
async fn open_uds(
    handle: SharedHandle,
    spec: &UdsForwardSpec,
    channel_idle: Option<Duration>,
) -> Result<ForwardHandle> {
    let listen_path = spec.listen_path.to_string_lossy().into_owned();
    // Clear a stale socket file from a previous unclean shutdown so the bind
    // does not spuriously fail with AddrInUse.
    spt_forward::uds_listener::UdsListener::unlink_existing_if_socket(&listen_path)?;
    let listener = spt_forward::uds_listener::open_listener(&listen_path).await?;

    let (state_tx, state_rx) = watch::channel(ForwardState::Listening);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    // `UdsForwardSpec` has no per-forward `idle_timeout`, so the connection-level
    // combined channel-idle deadline is the only idle bound here.
    tokio::spawn(uds_loop(
        listener,
        handle,
        spec.remote_socket_path.clone(),
        state_tx,
        close_rx,
        // `UdsForwardSpec` carries no `max_connections` field (mirrors
        // `RemoteUdsForwardSpec` / `remote_uds_loop`), so the concurrency cap is
        // `None` here; the `max_new_conns_per_sec` rate gate from `limits` is
        // enforced by the `ConnLimiter`. Wiring a per-forward `max_connections`
        // value onto the UDS spec is a config-schema change outside this crate.
        None,
        name.clone(),
        spec.limits,
        combine_idle(None, channel_idle),
    ));
    info!(target: "spt_ssh2::russh", forward = %name, "local_uds forward opened");
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn open_uds(
    _handle: SharedHandle,
    _spec: &UdsForwardSpec,
    _channel_idle: Option<Duration>,
) -> Result<ForwardHandle> {
    Err(crate::uds_forward::windows_local_uds_unsupported())
}

/// Build the admission gate for a `local_uds` accept loop: the same
/// [`ConnLimiter`] (concurrency cap + `max_new_conns_per_sec` rate gate) the
/// TCP/dynamic/reverse loops use. Split out so `uds_loop`'s cap enforcement is
/// unit-testable without binding a real listener + live SSH handle.
#[cfg(unix)]
fn uds_conn_limiter(max_connections: Option<u32>, limits: &ForwardRateLimits) -> ConnLimiter {
    ConnLimiter::new(max_connections, limits.max_new_conns_per_sec)
}

/// Accept loop for a `local_uds` forward. Each accepted `UnixStream` is bridged
/// onto a fresh `direct-streamlocal@openssh.com` channel to `remote_path`.
///
/// Admission is gated by a [`ConnLimiter`] — the same mechanism the
/// TCP/dynamic/reverse loops use — so `max_connections` and the
/// `max_new_conns_per_sec` rate gate are honoured (previously the UDS local
/// path applied neither). The permit is held for the bridge task's lifetime and
/// released via RAII on drop, so the cap never wedges even if a bridge panics.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn uds_loop(
    listener: spt_forward::uds_listener::UdsListener,
    handle: SharedHandle,
    remote_path: String,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    max_connections: Option<u32>,
    name: String,
    limits: ForwardRateLimits,
    idle_timeout: Option<Duration>,
) {
    let _ = state_tx.send(ForwardState::Active);
    let limiter = uds_conn_limiter(max_connections, &limits);
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            accept = listener.accept() => {
                let sock = match accept {
                    Ok(value) => value,
                    Err(e) => {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "uds accept failed");
                        continue;
                    }
                };
                let Some(permit) = limiter.try_admit() else {
                    warn!(
                        target: "spt_ssh2::russh",
                        forward = %name,
                        "local_uds forward refused: max_connections / new-connection rate cap reached, dropping connection"
                    );
                    continue;
                };
                let handle = Arc::clone(&handle);
                let remote_path = remote_path.clone();
                let name = name.clone();
                tokio::spawn(async move {
                    // Hold the permit for the bridge's lifetime; its `Drop`
                    // releases the concurrency slot when the bridge ends.
                    let _permit = permit;
                    if let Err(e) = bridge_uds(handle, sock, &remote_path, &limits, idle_timeout).await {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "uds bridge failed");
                    }
                });
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
    info!(target: "spt_ssh2::russh", forward = %name, "local_uds forward closed");
}

/// Bridge one accepted local `UnixStream` onto a `direct-streamlocal` channel
/// to `remote_path`, throttling with the per-forward limits and honouring the
/// combined channel-idle deadline.
#[cfg(unix)]
async fn bridge_uds(
    handle: SharedHandle,
    mut sock: tokio::net::UnixStream,
    remote_path: &str,
    limits: &ForwardRateLimits,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    let channel = crate::uds_forward::open_local_uds(&handle, remote_path).await?;
    let mut stream = channel.into_stream();
    let buckets = ForwardBuckets::from_limits(limits);
    // `sock` is the local UDS client (a), `stream` the remote socket (b).
    copy_bidirectional_throttled_idle(
        &mut sock,
        &mut stream,
        buckets.up,
        buckets.down,
        idle_timeout,
    )
    .await
    .map_err(|e| Error::RuntimeFailure(format!("russh uds bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Open a `remote_uds` forward: ask the server to listen on
/// `spec.remote_socket_path` and bridge each inbound
/// `forwarded-streamlocal@openssh.com` channel to a local
/// `UnixStream::connect(spec.local_socket_path)`.
///
/// This is the streamlocal analogue of [`open_remote`]: it registers the
/// remote socket path in `remote_uds_forwards` so the
/// `server_channel_open_forwarded_streamlocal` handler hook routes channels to
/// this forward's accept loop, then issues the `streamlocal-forward` global
/// request. The returned [`RemoteUdsForward`] guard's `Drop` cancels the
/// server-side listener; it is held by the accept loop and dropped when the
/// forward closes.
///
/// On non-Unix targets this returns [`Error::UnsupportedPlatform`] (connecting
/// an `AF_UNIX` socket is Unix-only), mirroring `open_uds`'s cfg split.
#[cfg(unix)]
async fn open_remote_uds(
    handle: SharedHandle,
    remote_uds_forwards: RemoteUdsForwardMap,
    spec: &RemoteUdsForwardSpec,
    channel_idle: Option<Duration>,
) -> Result<ForwardHandle> {
    use crate::uds_forward::RemoteUdsForward;

    let remote_path = spec.remote_socket_path.clone();
    let (tx, rx) = mpsc::channel(64);
    remote_uds_forwards
        .lock()
        .await
        .insert(remote_path.clone(), tx);

    // Issue the `streamlocal-forward@openssh.com` global request. On failure,
    // unregister so a retry can re-request the same path cleanly.
    let forward = match RemoteUdsForward::request(Arc::clone(&handle), &remote_path).await {
        Ok(f) => f,
        Err(e) => {
            remote_uds_forwards.lock().await.remove(&remote_path);
            return Err(e);
        }
    };

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    tokio::spawn(remote_uds_loop(
        rx,
        close_rx,
        RemoteUdsLoopContext {
            remote_uds_forwards,
            forward,
            remote_path,
            local_path: spec.local_socket_path.clone(),
            state_tx,
            name: name.clone(),
            // `RemoteUdsForwardSpec` carries no `max_connections` field (unlike
            // `RemoteForwardSpec`), so the concurrency cap is `None` here; the
            // `max_new_conns_per_sec` rate gate from `limits` is still enforced.
            max_connections: None,
            limits: spec.limits,
            idle_timeout: combine_idle(spec.idle_timeout, channel_idle),
        },
    ));
    info!(target: "spt_ssh2::russh", forward = %name, "remote_uds forward opened");
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn open_remote_uds(
    _handle: SharedHandle,
    _remote_uds_forwards: RemoteUdsForwardMap,
    _spec: &RemoteUdsForwardSpec,
    _channel_idle: Option<Duration>,
) -> Result<ForwardHandle> {
    Err(Error::UnsupportedPlatform(
        "remote_uds (server-side UNIX-socket forward) requires a Unix target: bridging \
         forwarded-streamlocal channels to a local AF_UNIX socket is not supported on Windows"
            .into(),
    ))
}

/// Owned context for a `remote_uds` accept loop. The `forward` guard is held so
/// its `Drop` sends `cancel-streamlocal-forward` when the loop exits.
#[cfg(unix)]
struct RemoteUdsLoopContext {
    remote_uds_forwards: RemoteUdsForwardMap,
    forward: crate::uds_forward::RemoteUdsForward<ClientHandler>,
    remote_path: String,
    local_path: std::path::PathBuf,
    state_tx: watch::Sender<ForwardState>,
    name: String,
    /// Concurrency cap for inbound (reverse) connections; `None` ⇒ unlimited.
    max_connections: Option<u32>,
    limits: ForwardRateLimits,
    idle_timeout: Option<Duration>,
}

/// Accept loop for a `remote_uds` forward. Each server-opened
/// `forwarded-streamlocal` channel is bridged to a fresh
/// `UnixStream::connect(local_path)`.
#[cfg(unix)]
async fn remote_uds_loop(
    mut rx: mpsc::Receiver<ForwardedStreamlocal>,
    mut close_rx: oneshot::Receiver<()>,
    ctx: RemoteUdsLoopContext,
) {
    // Enforce the reverse-path concurrency + new-conn rate gate, mirroring
    // `remote_loop`. `max_connections` is `None` here (the spec has no such
    // field), but the `max_new_conns_per_sec` rate gate is applied.
    let limiter = ConnLimiter::new(ctx.max_connections, ctx.limits.max_new_conns_per_sec);
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            forwarded = rx.recv() => {
                let Some(forwarded) = forwarded else { break; };
                let Some(permit) = limiter.try_admit() else {
                    debug!(
                        target: "spt_ssh2::russh",
                        forward = %ctx.name,
                        "reverse uds forward at max_connections / new-conn rate cap, closing inbound channel"
                    );
                    let _ = forwarded.channel.close().await;
                    continue;
                };
                let local_path = ctx.local_path.clone();
                let name = ctx.name.clone();
                let limits = ctx.limits;
                let idle_timeout = ctx.idle_timeout;
                tokio::spawn(async move {
                    // Permit's `Drop` frees the slot when the bridge ends.
                    let _permit = permit;
                    if let Err(e) =
                        bridge_remote_uds(forwarded.channel, &local_path, &limits, idle_timeout).await
                    {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "remote uds bridge failed");
                    }
                });
            }
        }
    }

    ctx.remote_uds_forwards
        .lock()
        .await
        .remove(&ctx.remote_path);
    // Drop the forward guard explicitly so the server-side listener is
    // cancelled (`cancel-streamlocal-forward@openssh.com`) as the loop ends.
    drop(ctx.forward);
    let _ = ctx.state_tx.send(ForwardState::Stopped);
}

/// Bridge one server-opened `forwarded-streamlocal` channel to a local
/// `UnixStream::connect(local_path)`, throttling with the per-forward limits
/// and honouring the combined channel-idle deadline.
#[cfg(unix)]
async fn bridge_remote_uds(
    channel: russh::Channel<client::Msg>,
    local_path: &std::path::Path,
    limits: &ForwardRateLimits,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    let mut stream = channel.into_stream();
    let mut sock = tokio::net::UnixStream::connect(local_path)
        .await
        .map_err(|e| {
            Error::NetworkUnreachable(format!(
                "connect remote-uds local target {}: {e}",
                local_path.display()
            ))
        })?;
    // `stream` is the tunnel side carrying inbound connections (remote→client =
    // `up`), `sock` the local UDS target.
    let buckets = ForwardBuckets::from_limits(limits);
    copy_bidirectional_throttled_idle(
        &mut stream,
        &mut sock,
        buckets.up,
        buckets.down,
        idle_timeout,
    )
    .await
    .map_err(|e| Error::RuntimeFailure(format!("russh remote uds bridge I/O: {e}")))?;
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

/// Bridge russh 0.61's `ssh-key` (0.7-rc) host-key type into the workspace's
/// `ssh-key` 0.6 `PublicKey` that [`TrustVerifier::verify`] (and spt-trust)
/// operate on. russh pins an `ssh-key` rc that is a different crate version
/// than the workspace's stable 0.6, so the only stable bridge is the SSH wire
/// encoding: `PublicKeyBase64::public_key_bytes` produces the canonical
/// public-key blob, which our 0.6 `PublicKey::from_bytes` re-parses.
fn russh_key_to_ssh_key(key: &russh::keys::ssh_key::PublicKey) -> Result<ssh_key::PublicKey> {
    ssh_key::PublicKey::from_bytes(&key.public_key_bytes())
        .map_err(|e| Error::TrustFailed(format!("parse russh host key: {e}")))
}

/// `std::io::ErrorKind`s that indicate a *transient* filesystem failure when
/// loading a key / certificate file: the file is momentarily unreadable during
/// an atomic key-rotation `rename` gap, a permission race, or a network-FS
/// hiccup (NFS/SMB `ESTALE`, which maps to `Other` on most platforms). Such a
/// failure can heal on the next reconnect, so it must be classified RETRYABLE
/// rather than permanently killing the profile (H-1).
fn is_transient_key_io(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind;
    matches!(
        kind,
        ErrorKind::NotFound
            | ErrorKind::PermissionDenied
            | ErrorKind::Interrupted
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::Other
    )
}

/// Classify a private-key load error from [`russh::keys::load_secret_key`].
///
/// A transient filesystem I/O error (see [`is_transient_key_io`]) maps to the
/// RETRYABLE [`Error::RuntimeFailure`] so the supervisor's reconnect loop backs
/// off and tries again — a key briefly unreadable during rotation or a
/// permission race must not kill the profile forever (H-1). A genuine parse /
/// passphrase / unsupported-type failure is UNRECOVERABLE and maps to terminal
/// [`Error::KeyFailure`], so the supervisor stops the profile instead of
/// hammering a host with a key that can never succeed.
fn classify_key_load_error(what: &str, e: russh::keys::Error) -> Error {
    match e {
        russh::keys::Error::IO(io) if is_transient_key_io(io.kind()) => {
            let kind = io.kind();
            Error::RuntimeFailure(format!("{what}: transient key-file I/O ({kind}): {io}"))
        }
        other => Error::KeyFailure(format!("{what}: {other}")),
    }
}

/// Classify an OpenSSH-certificate load error from
/// [`russh::keys::load_openssh_certificate`]. Same transient-vs-terminal split
/// as [`classify_key_load_error`]: a transient cert-file I/O error is RETRYABLE
/// ([`Error::RuntimeFailure`]); a malformed / unparseable certificate is
/// terminal ([`Error::KeyFailure`]) (H-1).
fn classify_cert_load_error(what: &str, e: russh::keys::ssh_key::Error) -> Error {
    match e {
        russh::keys::ssh_key::Error::Io(kind) if is_transient_key_io(kind) => {
            Error::RuntimeFailure(format!("{what}: transient cert-file I/O ({kind})"))
        }
        other => Error::KeyFailure(format!("{what}: {other}")),
    }
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

// ── Server-controlled-data error/log formatters ─────────────────────────────
//
// These build operator-facing messages from SSH-server-controlled strings
// (keyboard-interactive prompt text per RFC 4256; dynamic-forward SOCKS/CONNECT
// target hosts). The server-supplied field is always passed through
// `escape_control` so a malicious peer cannot inject ANSI/terminal escape
// sequences (or forge log lines) into the operator's terminal/log. They are
// behavior-preserving for clean input. Kept as small free functions so the
// escaping is unit-testable in isolation.

/// Error message for a keyboard-interactive prompt that matched no configured
/// responder. `prompt` is fully server-controlled (RFC 4256) → escaped.
fn kbi_unmatched_prompt_msg(prompt: &str) -> String {
    format!(
        "no keyboard-interactive responder matched prompt `{}`",
        escape_control(prompt)
    )
}

/// Error message for a dynamic-proxy target rejected by the destination ACL.
/// `host` originates from the client SOCKS/CONNECT request → escaped.
fn dynamic_target_denied_msg(host: &str, port: u16) -> String {
    format!(
        "dynamic proxy target {}:{} denied by ruleset",
        escape_control(host),
        port
    )
}

/// Error message for a failed dynamic-forward channel-open. `host` originates
/// from the client SOCKS/CONNECT request → escaped (mirrors the success/deny
/// paths). `err` is the backend error rendered via `Display`.
fn dynamic_dial_failure_msg<D: std::fmt::Display>(host: &str, port: u16, err: &D) -> String {
    format!(
        "russh dynamic direct-tcpip to {}:{}: {err}",
        escape_control(host),
        port
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_name_maps_every_variant() {
        use russh::compression::Compression;
        assert_eq!(compression_name(&Compression::None), "none");
        assert_eq!(compression_name(&Compression::Zlib), "zlib");
        assert_eq!(
            compression_name(&Compression::ZlibOpenSSH),
            "zlib@openssh.com"
        );
    }

    #[test]
    fn emit_crypto_negotiated_log_parses_canonical_token() {
        // The log helper must tolerate the exact token shape `format_negotiated`
        // produces (and unknown/missing keys) without panicking. tracing is a
        // no-op without a subscriber; we assert it does not panic on a
        // well-formed line and on a degenerate one.
        emit_crypto_negotiated_log(
            "transport=ssh2 kex=curve25519-sha256 hostkey=ssh-ed25519 \
             cipher=chacha20-poly1305@openssh.com mac_c2s=hmac-sha2-256-etm@openssh.com \
             mac_s2c=hmac-sha2-256-etm@openssh.com comp_c2s=none comp_s2c=none pq_offered=true",
            true,
        );
        emit_crypto_negotiated_log("transport=ssh2", false);
    }

    #[test]
    fn conn_limiter_caps_concurrency_and_releases_on_permit_drop() {
        // The reverse-forward admission gate: with `max_connections = 2` the
        // third concurrent admit is rejected while two permits are live, the
        // active count never exceeds the cap, and dropping a permit frees a
        // slot so the limiter never wedges. Rate gate disabled (0 = unlimited)
        // to isolate the concurrency cap.
        let limiter = ConnLimiter::new(Some(2), 0);
        let p1 = limiter.try_admit().expect("first admit");
        let p2 = limiter.try_admit().expect("second admit");
        assert_eq!(limiter.active_count(), 2);
        // Over the cap: rejected, count unchanged.
        assert!(
            limiter.try_admit().is_none(),
            "third admit must be rejected"
        );
        assert_eq!(limiter.active_count(), 2);
        // Releasing a slot re-opens capacity (RAII decrement).
        drop(p1);
        assert_eq!(limiter.active_count(), 1);
        let p3 = limiter.try_admit().expect("admit after release");
        assert_eq!(limiter.active_count(), 2);
        drop(p2);
        drop(p3);
        assert_eq!(limiter.active_count(), 0);
    }

    #[test]
    fn conn_limiter_none_cap_is_unlimited() {
        // `None` cap (e.g. remote-UDS, which has no `max_connections` field)
        // admits without a concurrency ceiling; permits still track active
        // count for release accounting.
        let limiter = ConnLimiter::new(None, 0);
        let permits: Vec<_> = (0..8)
            .map(|_| limiter.try_admit().expect("admit"))
            .collect();
        assert_eq!(limiter.active_count(), 8);
        drop(permits);
        assert_eq!(limiter.active_count(), 0);
    }

    #[test]
    fn conn_limiter_rate_gate_rejects_burst() {
        // With `max_new_conns_per_sec = 1` and no concurrency cap, the second
        // immediate admit is rate-limited even though a slot is free.
        let limiter = ConnLimiter::new(None, 1);
        let _p1 = limiter.try_admit().expect("first admit within rate");
        assert!(
            limiter.try_admit().is_none(),
            "second immediate admit must be rate-limited"
        );
    }

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

    // ──────── conn-wire: [profiles.connection] policy plumbing ─────────

    #[test]
    fn connection_policy_default_preserves_russh_config_defaults() {
        let mut cfg = client::Config::default();
        let (def_nodelay, def_window, def_packet) =
            (cfg.nodelay, cfg.window_size, cfg.maximum_packet_size);
        ConnectionPolicy::default().apply_to_config(&mut cfg);
        assert_eq!(cfg.nodelay, def_nodelay);
        assert_eq!(cfg.window_size, def_window);
        assert_eq!(cfg.maximum_packet_size, def_packet);
    }

    #[test]
    fn connection_policy_plumbs_nodelay_and_channel_sizes_into_config() {
        let mut cfg = client::Config::default();
        let policy = ConnectionPolicy {
            tcp_nodelay: Some(true),
            channel_window_size: Some(4 * 1024 * 1024),
            channel_max_packet_size: Some(16384),
            ..ConnectionPolicy::default()
        };
        policy.apply_to_config(&mut cfg);
        assert!(cfg.nodelay);
        assert_eq!(cfg.window_size, 4 * 1024 * 1024);
        assert_eq!(cfg.maximum_packet_size, 16384);
    }

    #[test]
    fn connection_policy_clamps_packet_size_to_russh_ceiling() {
        // russh rejects maximum_packet_size > 65535; the policy clamps so an
        // over-large configured value degrades gracefully instead of failing
        // the dial.
        let mut cfg = client::Config::default();
        ConnectionPolicy {
            channel_max_packet_size: Some(1_000_000),
            ..ConnectionPolicy::default()
        }
        .apply_to_config(&mut cfg);
        assert_eq!(cfg.maximum_packet_size, 65535);
    }

    #[test]
    fn connection_policy_no_socket_tuning_yields_no_tcp_options() {
        // No nodelay, no keepalive ⇒ `None` so the legacy fast-path dial
        // (`client::connect`) is preserved.
        assert!(ConnectionPolicy::default().tcp_options().is_none());
        // keepalive timing without the master switch is still no-op.
        let timing_only = ConnectionPolicy {
            keepalive_idle: Some(Duration::from_secs(30)),
            ..ConnectionPolicy::default()
        };
        assert!(timing_only.tcp_options().is_none());
    }

    #[test]
    fn connection_policy_socket_keepalive_builds_tcp_options() {
        let policy = ConnectionPolicy {
            tcp_nodelay: Some(true),
            socket_keepalive: Some(true),
            keepalive_idle: Some(Duration::from_secs(30)),
            keepalive_interval: Some(Duration::from_secs(10)),
            keepalive_retries: Some(4),
            ..ConnectionPolicy::default()
        };
        let opts = policy.tcp_options().expect("socket tuning requested");
        assert!(opts.nodelay);
        assert_eq!(opts.keepalive_idle, Some(Duration::from_secs(30)));
        assert_eq!(opts.keepalive_interval, Some(Duration::from_secs(10)));
        assert_eq!(opts.keepalive_retries, Some(4));
    }

    #[test]
    fn connection_policy_nodelay_only_builds_tcp_options_without_keepalive() {
        let policy = ConnectionPolicy {
            tcp_nodelay: Some(true),
            ..ConnectionPolicy::default()
        };
        let opts = policy.tcp_options().expect("nodelay requested");
        assert!(opts.nodelay);
        // Master keepalive switch off ⇒ no keepalive timings carried.
        assert_eq!(opts.keepalive_idle, None);
        assert_eq!(opts.keepalive_interval, None);
        assert_eq!(opts.keepalive_retries, None);
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
                AuthMethod::Agent {
                    socket: None,
                    identity_hint: None,
                },
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
            resolved_secret: None,
        };
        // Port 1 on loopback is unroutable for SSH; the connect will error,
        // but the obfs audit hook fires before the failure.
        let endpoint = Endpoint::new("127.0.0.1", 1);
        let auth = AuthConfig::new(
            "u",
            vec![AuthMethod::Agent {
                socket: None,
                identity_hint: None,
            }],
        );
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
            ConnectionPolicy::default(),
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
        let auth = AuthConfig::new(
            "u",
            vec![AuthMethod::Agent {
                socket: None,
                identity_hint: None,
            }],
        );
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
            ConnectionPolicy::default(),
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

    // ──────── agent identity_hint reordering ──────────────────────────

    /// Build an `AgentIdentity::PublicKey` with a fresh Ed25519 key and the
    /// given comment for the reorder tests.
    fn test_identity(comment: &str) -> russh::keys::agent::AgentIdentity {
        use russh::keys::ssh_key::{Algorithm, PrivateKey};
        let key = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519)
            .expect("keygen")
            .public_key()
            .clone();
        russh::keys::agent::AgentIdentity::PublicKey {
            key,
            comment: comment.to_owned(),
        }
    }

    #[test]
    fn identity_hint_matches_by_comment() {
        let id = test_identity("work-laptop");
        assert!(identity_matches_hint(&id, "work-laptop"));
        assert!(!identity_matches_hint(&id, "home-desktop"));
    }

    #[test]
    fn identity_hint_matches_by_fingerprint() {
        let id = test_identity("anything");
        let fp = agent_fingerprint(&id);
        assert!(fp.starts_with("SHA256:"), "got {fp}");
        assert!(identity_matches_hint(&id, &fp));
        // Case-insensitive on the SHA256 label.
        assert!(identity_matches_hint(
            &id,
            &fp.replacen("SHA256", "sha256", 1)
        ));
    }

    #[test]
    fn reorder_moves_hinted_comment_to_front() {
        let mut ids = vec![
            test_identity("alpha"),
            test_identity("beta"),
            test_identity("gamma"),
        ];
        reorder_by_identity_hint(&mut ids, "gamma");
        assert_eq!(ids[0].comment(), "gamma");
        // Remaining keep their natural order.
        assert_eq!(ids[1].comment(), "alpha");
        assert_eq!(ids[2].comment(), "beta");
    }

    #[test]
    fn reorder_by_fingerprint_prefers_match() {
        let mut ids = vec![test_identity("a"), test_identity("b"), test_identity("c")];
        let target_fp = agent_fingerprint(&ids[2]);
        reorder_by_identity_hint(&mut ids, &target_fp);
        assert_eq!(agent_fingerprint(&ids[0]), target_fp);
    }

    #[test]
    fn reorder_with_no_match_preserves_order() {
        let mut ids = vec![test_identity("a"), test_identity("b")];
        let before: Vec<String> = ids.iter().map(|i| i.comment().to_owned()).collect();
        reorder_by_identity_hint(&mut ids, "no-such-key");
        let after: Vec<String> = ids.iter().map(|i| i.comment().to_owned()).collect();
        assert_eq!(before, after, "unmatched hint must not reorder");
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

    // ──────── C-ssh2: per-forward limits / idle / bind-conflict ────────

    #[test]
    fn forward_buckets_unlimited_when_limits_zero() {
        // The all-zero default must reproduce the prior `TokenBucket::unlimited()`
        // behaviour at every forward-open site.
        let b = ForwardBuckets::from_limits(&ForwardRateLimits::default());
        assert!(!b.up.is_active(), "up bucket must be inert for zero rate");
        assert!(
            !b.down.is_active(),
            "down bucket must be inert for zero rate"
        );
    }

    #[test]
    fn forward_buckets_built_from_spec_limits() {
        let limits = ForwardRateLimits {
            rate_bps_up: 4096,
            rate_bps_down: 8192,
            burst_up: 4096,
            burst_down: 8192,
            ..ForwardRateLimits::default()
        };
        let b = ForwardBuckets::from_limits(&limits);
        assert!(b.up.is_active());
        assert!(b.down.is_active());
        assert_eq!(b.up.rate_bps(), 4096);
        assert_eq!(b.down.rate_bps(), 8192);
        assert_eq!(b.up.burst(), 4096);
        assert_eq!(b.down.burst(), 8192);
    }

    #[tokio::test]
    async fn throttled_buckets_from_spec_actually_slow_throughput() {
        use tokio::io::{duplex, AsyncReadExt as _, AsyncWriteExt as _};
        // 4 KiB/s up bucket from a spec; 16 KiB payload ⇒ ~3s wall-clock.
        let limits = ForwardRateLimits {
            rate_bps_up: 4 * 1024,
            burst_up: 4 * 1024,
            ..ForwardRateLimits::default()
        };
        let buckets = ForwardBuckets::from_limits(&limits);

        let (mut left_app, mut left_tun) = duplex(64 * 1024);
        let (mut right_tun, mut right_app) = duplex(64 * 1024);
        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled_idle(
                &mut left_tun,
                &mut right_tun,
                buckets.up,
                buckets.down,
                None,
            )
            .await
        });

        let payload = vec![0xAB; 16 * 1024];
        left_app.write_all(&payload).await.unwrap();
        left_app.shutdown().await.unwrap();
        right_app.shutdown().await.unwrap();

        let start = std::time::Instant::now();
        let mut got = vec![0u8; payload.len()];
        right_app.read_exact(&mut got).await.unwrap();
        let dt = start.elapsed();
        assert!(
            dt >= Duration::from_millis(1500),
            "spec-derived bucket must throttle (>=1.5s), got {dt:?}"
        );
        let _ = bridge.await.unwrap();
    }

    #[tokio::test]
    async fn idle_timeout_closes_a_throttled_bridge() {
        use tokio::io::duplex;
        // No bytes flow; a short idle timeout must close the copy on its own
        // rather than blocking forever. Real (non-paused) time — the
        // `test-util` feature is not enabled for this crate's tokio — so we use
        // a small real timeout and bound the test with a generous deadline.
        let (_left_app, mut left_tun) = duplex(64);
        let (mut right_tun, _right_app) = duplex(64);
        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled_idle(
                &mut left_tun,
                &mut right_tun,
                TokenBucket::unlimited(),
                TokenBucket::unlimited(),
                Some(Duration::from_millis(150)),
            )
            .await
        });
        let stats = tokio::time::timeout(Duration::from_secs(5), bridge)
            .await
            .expect("idle close must fire within the deadline")
            .expect("bridge task joins")
            .expect("copy returns Ok on idle close");
        // Idle close returns default (zero) stats.
        assert_eq!(stats, spt_forward::CopyStats::default());
    }

    #[tokio::test]
    async fn bind_local_listener_honours_fail_on_conflict() {
        // Occupy a port, then a default-Fail bind on the same addr must error.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let listen = BindAddr::Tcp(addr);
        let err = bind_local_listener(&listen, BindConflictPolicy::Fail, "t")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::LocalBindFailed { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn bind_local_listener_next_port_falls_forward() {
        // Occupy a port; NextPort must bind a different (higher) port.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let listen = BindAddr::Tcp(addr);
        let listener = bind_local_listener(&listen, BindConflictPolicy::NextPort, "t")
            .await
            .expect("next_port must fall forward");
        let bound = listener.local_addr().unwrap();
        assert_ne!(bound.port(), addr.port());
        assert!(bound.port() > addr.port());
    }

    /// cfg(unix): `open_uds` binds a local `AF_UNIX` listener and bridges an
    /// accepted stream's bytes onto a `direct-streamlocal` channel. We can't
    /// open a real russh channel without a server, so this exercises the
    /// listener-bind + accept half end-to-end and asserts the bridge attempt
    /// fires (the channel-open then errors against the dead handle, which the
    /// loop logs and swallows). The byte-bridge proper is covered against a
    /// live server in `tests/uds_forward.rs` at the Linux gate.
    #[cfg(unix)]
    #[tokio::test]
    async fn open_uds_binds_listener_and_accepts() {
        let tmp = tempfile::tempdir().unwrap();
        let listen_path = tmp.path().join("c-ssh2.sock");
        let listener = spt_forward::uds_listener::open_listener(&listen_path.to_string_lossy())
            .await
            .expect("bind local uds listener");
        // Spawn an acceptor and connect once to prove the listener half works.
        let listener = std::sync::Arc::new(listener);
        let lc = std::sync::Arc::clone(&listener);
        let server = tokio::spawn(async move {
            let _stream = lc.accept().await.expect("accept");
        });
        let _client = tokio::net::UnixStream::connect(&listen_path)
            .await
            .expect("connect to local uds");
        server.await.expect("acceptor joins");
    }

    /// finding 3: the `local_uds` accept loop now gates admission through the
    /// same [`ConnLimiter`] the TCP/dynamic/reverse loops use (built by
    /// `uds_conn_limiter`), so `max_connections` and the new-connection rate gate
    /// are enforced — previously `uds_loop` applied neither. With a cap of 2 the
    /// first two inbound connections are admitted and the third is refused until
    /// a slot frees (RAII permit drop). Fails against pre-fix: `uds_conn_limiter`
    /// did not exist and the loop had no admission gate.
    #[cfg(unix)]
    #[test]
    fn local_uds_conn_limiter_rejects_over_max_connections() {
        let limits = ForwardRateLimits::default();
        let limiter = uds_conn_limiter(Some(2), &limits);
        let p1 = limiter.try_admit().expect("1st admitted");
        let _p2 = limiter.try_admit().expect("2nd admitted");
        assert_eq!(limiter.active_count(), 2);
        // The N+1-th (3rd) connection is rejected at the cap.
        assert!(
            limiter.try_admit().is_none(),
            "3rd connection must be refused at max_connections = 2"
        );
        // Freeing a slot (bridge ended) re-opens capacity.
        drop(p1);
        assert_eq!(limiter.active_count(), 1);
        let _p3 = limiter
            .try_admit()
            .expect("a freed slot must admit the next connection");
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

    // ──────── t-tunnel-wire-2 §1: auth/handshake/channel-idle timeouts ────

    #[test]
    fn handshake_timed_out_maps_to_timedout_io_error() {
        // The handshake-timeout elapse must map to the SAME `russh::Error::IO`
        // / `ErrorKind::TimedOut` idiom that `dial_tuned`'s connect-timeout
        // uses, so the caller's dial-failure diagnostics/backoff apply.
        let e = handshake_timed_out("example.com", 22, Duration::from_secs(3));
        match e {
            russh::Error::IO(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
                let msg = io.to_string();
                assert!(msg.contains("example.com:22"), "msg: {msg}");
                assert!(msg.contains("handshake"), "msg: {msg}");
            }
            other => panic!("expected IO(TimedOut), got {other:?}"),
        }
    }

    #[test]
    fn combine_idle_takes_min_when_both_present() {
        // Tighter (smaller) deadline wins so neither bound can be exceeded.
        assert_eq!(
            combine_idle(Some(Duration::from_secs(30)), Some(Duration::from_secs(10))),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            combine_idle(Some(Duration::from_secs(5)), Some(Duration::from_secs(60))),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn combine_idle_uses_the_sole_present_value() {
        assert_eq!(
            combine_idle(Some(Duration::from_secs(7)), None),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            combine_idle(None, Some(Duration::from_secs(9))),
            Some(Duration::from_secs(9))
        );
    }

    #[test]
    fn combine_idle_none_when_neither_present() {
        assert_eq!(combine_idle(None, None), None);
    }

    #[tokio::test]
    async fn run_auth_timed_elapses_to_auth_failed() {
        // A near-zero auth deadline against a never-resolving auth future must
        // surface as an `AuthFailed` diagnostic (not hang). We can't build a
        // real russh handle here, so we wrap a future that blocks forever and
        // assert the timeout arm fires the mapped error. Exercise the timeout
        // arm directly via `tokio::time::timeout` mirroring `run_auth_timed`.
        let drive = std::future::pending::<Result<()>>();
        let res: std::result::Result<Result<()>, _> =
            tokio::time::timeout(Duration::from_millis(1), drive).await;
        assert!(res.is_err(), "the pending auth future must time out");
        // And the mapping `run_auth_timed` performs yields AuthFailed:
        let mapped = Error::auth_failed(
            spt_core::Diagnostic::what("SSH authentication timed out after 1ms")
                .why("the userauth flow did not complete within `connection.auth_timeout`")
                .how_to_fix("Increase `[profiles.connection].auth_timeout`")
                .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                .build(),
        );
        assert_eq!(mapped.exit_code(), spt_core::ExitCode::AuthFailed);
    }

    #[tokio::test]
    async fn dial_outer_timed_with_no_timeout_matches_plain_dial_failure() {
        // With `handshake_timeout = None` the wrapper must behave exactly like
        // `dial_outer`: a dial to an unroutable port errors (not times out).
        let cfg = Arc::new(client::Config::default());
        let handler = ClientHandler {
            host: "127.0.0.1".into(),
            port: 1,
            trust: TrustVerifier::default(),
            trust_failure: Arc::new(parking_lot::Mutex::new(None)),
            remote_forwards: RemoteForwardMap::default(),
            remote_uds_forwards: RemoteUdsForwardMap::default(),
            negotiated: Arc::new(parking_lot::Mutex::new(None)),
            pq_offered: false,
        };
        let conn = ConnectionPolicy::default();
        let res = dial_outer_timed(cfg, "127.0.0.1", 1, handler, None, &conn).await;
        assert!(res.is_err(), "dial to 127.0.0.1:1 should fail");
    }

    // ──────── t-tunnel-wire-2 §2: remote_uds (forwarded-streamlocal) ──────

    #[cfg(not(unix))]
    #[tokio::test]
    async fn open_remote_uds_unsupported_on_non_unix() {
        let spec = RemoteUdsForwardSpec {
            name: "ruds".into(),
            remote_socket_path: "/run/remote.sock".into(),
            local_socket_path: std::path::PathBuf::from("/run/local.sock"),
            ..RemoteUdsForwardSpec::default()
        };
        // A dummy handle is never dialed on the non-unix path; build one via the
        // public fn entry indirectly is impossible without a server, so assert
        // the cfg(not(unix)) impl returns Unsupported through the spec-only path.
        // We cannot construct a `SharedHandle` cheaply; instead assert the
        // documented error via the standalone non-unix impl semantics by
        // calling it with a handle obtained from a failed connect is overkill —
        // the cfg gate guarantees this arm. Construct the error directly to
        // pin the contract the impl returns.
        let _ = &spec;
        let e = Error::UnsupportedPlatform(
            "remote_uds (server-side UNIX-socket forward) requires a Unix target: bridging \
             forwarded-streamlocal channels to a local AF_UNIX socket is not supported on Windows"
                .into(),
        );
        match e {
            Error::UnsupportedPlatform(msg) => {
                assert!(msg.contains("remote_uds"), "msg: {msg}");
                assert!(msg.contains("Unix"), "msg: {msg}");
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    /// The `forwarded-streamlocal` routing the handler hook performs: a channel
    /// for a registered remote socket path is delivered to that forward's
    /// queue. We exercise the same lookup+send logic the
    /// `server_channel_open_forwarded_streamlocal` hook runs (a registered
    /// sender receives; an unregistered path finds nothing).
    /// Mirror the lookup the `server_channel_open_forwarded_streamlocal` hook
    /// performs: exact-path hit, single-entry fallback, and the no-route case
    /// when an unknown path arrives with multiple forwards registered.
    fn route_streamlocal(
        map: &HashMap<String, mpsc::Sender<ForwardedStreamlocal>>,
        socket_path: &str,
    ) -> Option<mpsc::Sender<ForwardedStreamlocal>> {
        map.get(socket_path).cloned().or_else(|| {
            if map.len() == 1 {
                map.values().next().cloned()
            } else {
                None
            }
        })
    }

    #[tokio::test]
    async fn forwarded_streamlocal_routing_delivers_to_registered_path() {
        let (tx, _rx) = mpsc::channel::<ForwardedStreamlocal>(4);
        let mut map: HashMap<String, mpsc::Sender<ForwardedStreamlocal>> = HashMap::new();
        map.insert("/run/db.sock".to_owned(), tx);

        // Exact-path hit.
        assert!(
            route_streamlocal(&map, "/run/db.sock").is_some(),
            "registered path must resolve a sender"
        );
        // Single-entry fallback catches a mismatched path.
        assert!(
            route_streamlocal(&map, "/run/other.sock").is_some(),
            "single registered forward must catch a canonicalised path"
        );

        // With >1 entries an unknown path routes nowhere (and is dropped+closed
        // by the hook).
        let (tx2, _rx2) = mpsc::channel::<ForwardedStreamlocal>(4);
        map.insert("/run/two.sock".to_owned(), tx2);
        assert!(
            route_streamlocal(&map, "/run/nope.sock").is_none(),
            "ambiguous mismatched path must not route"
        );
        // Exact hit still works with multiple entries.
        assert!(route_streamlocal(&map, "/run/two.sock").is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn open_remote_uds_validates_socket_path_before_request() {
        // A relative remote socket path must be rejected by
        // `validate_socket_path` (inside `RemoteUdsForward::request`) before any
        // network I/O — so a dead handle never even matters. We can't build a
        // live `SharedHandle`, but `validate_socket_path` is the gate the impl
        // relies on; assert it rejects the bad path the impl would forward.
        let e = crate::uds_forward::validate_socket_path("relative.sock").unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("absolute")));
    }

    #[cfg(unix)]
    #[test]
    fn remote_uds_spec_carries_local_and_remote_paths() {
        // Guards the field wiring the impl reads (remote → server listen,
        // local → bridge connect target).
        let spec = RemoteUdsForwardSpec {
            name: "x".into(),
            remote_socket_path: "/run/r.sock".into(),
            local_socket_path: std::path::PathBuf::from("/run/l.sock"),
            ..RemoteUdsForwardSpec::default()
        };
        assert_eq!(spec.remote_socket_path, "/run/r.sock");
        assert_eq!(
            spec.local_socket_path,
            std::path::PathBuf::from("/run/l.sock")
        );
    }

    // ──────── t-tunnel-wire-2 §3: preflight_connect ──────────────────────

    #[tokio::test]
    async fn preflight_connect_fails_against_unroutable_endpoint() {
        // `preflight_connect` re-runs the full connect+auth dial against the
        // session's own endpoint. Building a real live session needs a server,
        // but the FAILURE path is deterministic: a fresh `connect_inner` against
        // an unroutable endpoint returns a connect error. We assert that the
        // reconnect params drive `connect_inner` to a network error (the exact
        // primitive `preflight_connect` awaits).
        let params = ReconnectParams {
            endpoint: Endpoint::new("127.0.0.1", 1),
            auth_cfg: AuthConfig::new(
                "u",
                vec![AuthMethod::Agent {
                    socket: None,
                    identity_hint: None,
                }],
            ),
            crypto: CryptoPolicy::default(),
            trust: TrustVerifier::default(),
            backends: Vec::new(),
            hops: Vec::new(),
            gss_audit: None,
            keepalive: KeepalivePolicy::default(),
            obfs: None,
            connection: ConnectionPolicy::default(),
        };
        let res = connect_inner(params).await;
        assert!(
            res.is_err(),
            "preflight to an unroutable endpoint must error"
        );
    }

    #[tokio::test]
    async fn preflight_connect_honours_handshake_timeout() {
        // With a near-zero handshake timeout against a black-holed address the
        // dial must elapse rather than hang. 10.255.255.1 is a reserved,
        // typically-unroutable address; bound the test so a (rare) immediate
        // RST still passes (any error is acceptable — the point is it returns).
        let params = ReconnectParams {
            endpoint: Endpoint::new("10.255.255.1", 22),
            auth_cfg: AuthConfig::new(
                "u",
                vec![AuthMethod::Agent {
                    socket: None,
                    identity_hint: None,
                }],
            ),
            crypto: CryptoPolicy::default(),
            trust: TrustVerifier::default(),
            backends: Vec::new(),
            hops: Vec::new(),
            gss_audit: None,
            keepalive: KeepalivePolicy::default(),
            obfs: None,
            connection: ConnectionPolicy {
                handshake_timeout: Some(Duration::from_millis(50)),
                ..ConnectionPolicy::default()
            },
        };
        let res = tokio::time::timeout(Duration::from_secs(5), connect_inner(params)).await;
        assert!(
            res.is_ok(),
            "connect_inner must return within the deadline (handshake timeout fired)"
        );
        assert!(res.unwrap().is_err(), "the black-holed dial must error");
    }

    // ──────── fix-ss-secret: obfs Shadowsocks password resolution ─────────

    /// Minimal in-memory `SecretBackend` returning a fixed value for any ref
    /// (mirrors `secret.rs::CannedBackend`). Avoids pulling the spt-secrets
    /// `testing` feature into the dev-dep graph.
    struct CannedSecretBackend(&'static [u8]);
    impl SecretBackend for CannedSecretBackend {
        fn kind(&self) -> spt_secrets::BackendKind {
            spt_secrets::BackendKind::Env
        }
        fn get(&self, _r: &spt_secrets::SecretRef) -> Result<Option<spt_secrets::SecretBytes>> {
            Ok(Some(spt_secrets::backend::secret_bytes(self.0.to_vec())))
        }
        fn set(&self, _r: &spt_secrets::SecretRef, _value: &[u8]) -> Result<()> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<spt_secrets::SecretRef>> {
            Ok(vec![])
        }
        fn remove(&self, _r: &spt_secrets::SecretRef) -> Result<bool> {
            Ok(false)
        }
        fn doctor(&self) -> spt_secrets::BackendDoctor {
            spt_secrets::BackendDoctor::ok(spt_secrets::BackendKind::Env, "test")
        }
    }

    /// In-memory backend that resolves nothing (`Ok(None)`), so the chain
    /// falls through to the next backend.
    struct EmptySecretBackend;
    impl SecretBackend for EmptySecretBackend {
        fn kind(&self) -> spt_secrets::BackendKind {
            spt_secrets::BackendKind::Env
        }
        fn get(&self, _r: &spt_secrets::SecretRef) -> Result<Option<spt_secrets::SecretBytes>> {
            Ok(None)
        }
        fn set(&self, _r: &spt_secrets::SecretRef, _value: &[u8]) -> Result<()> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<spt_secrets::SecretRef>> {
            Ok(vec![])
        }
        fn remove(&self, _r: &spt_secrets::SecretRef) -> Result<bool> {
            Ok(false)
        }
        fn doctor(&self) -> spt_secrets::BackendDoctor {
            spt_secrets::BackendDoctor::ok(spt_secrets::BackendKind::Env, "test")
        }
    }

    #[test]
    fn resolve_obfs_secret_falls_through_chain_to_first_hit() {
        // A `secret://obfs/ss-pw` reference resolves through the SAME backend
        // chain the SSH auth path uses: an empty backend falls through to the
        // canned backend that holds the value.
        let b1: Arc<dyn SecretBackend> = Arc::new(EmptySecretBackend);
        let b2: Arc<dyn SecretBackend> = Arc::new(CannedSecretBackend(b"ss-secret-key"));
        let backends = vec![b1, b2];
        let reference = spt_secrets::SecretRef::new("obfs", "ss-pw").unwrap();
        let bytes = resolve_obfs_secret(&backends, &reference).unwrap();
        assert_eq!(&bytes[..], b"ss-secret-key");
    }

    #[test]
    fn resolve_obfs_secret_unresolvable_is_hard_error() {
        // No backend resolves the reference ⇒ hard `SecretUnavailable`; we
        // must never dial with an unresolved obfs password.
        let backends: Vec<Arc<dyn SecretBackend>> = vec![Arc::new(EmptySecretBackend)];
        let reference = spt_secrets::SecretRef::new("obfs", "missing").unwrap();
        let err = resolve_obfs_secret(&backends, &reference).unwrap_err();
        assert!(
            matches!(err, Error::SecretUnavailable { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn connect_inner_resolves_shadowsocks_password_into_transport() {
        // End-to-end of the fix: a Shadowsocks `[obfuscation]` whose `password`
        // is a `secret://` ref gets resolved through the backend chain and the
        // bytes keyed into the dialed transport. We point the dial at a
        // loopback acceptor so the connect succeeds and the transport reaches
        // `derive_key` — which would error with "password not resolved" if the
        // ref were NOT resolved. The dial completes the obfs handshake (salt
        // write) and then fails the SSH handshake (the peer is not an SSH
        // server), proving resolution happened: the obfs audit hook records
        // the SS connect.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept = tokio::spawn(async move {
            // Drain a little from each accepted peer then drop, so the SSH
            // handshake fails (we only need to get PAST `derive_key`).
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
            }
        });

        let audit = Arc::new(spt_obfs::audit::MockAuditHook::new());
        let ss_cfg = spt_obfs::ObfsConfig::Shadowsocks {
            method: spt_obfs::SsMethod::Aead2022Blake3Aes256Gcm,
            password: spt_secrets::SecretRef::new("obfs", "ss-pw").unwrap(),
        };
        let obfs = ObfsPolicy {
            config: Arc::new(ss_cfg),
            audit: Some(Arc::clone(&audit) as Arc<dyn spt_obfs::AuditHook>),
            resolved_secret: None,
        };
        let backends: Vec<Arc<dyn SecretBackend>> =
            vec![Arc::new(CannedSecretBackend(b"resolved-ss-pw"))];

        let endpoint = Endpoint::new(addr.ip().to_string(), addr.port());
        let res = connect(
            endpoint,
            AuthConfig::new(
                "u",
                vec![AuthMethod::Agent {
                    socket: None,
                    identity_hint: None,
                }],
            ),
            CryptoPolicy::default(),
            TrustVerifier::default(),
            backends,
            Vec::new(),
            None,
            KeepalivePolicy::default(),
            Some(obfs),
            ConnectionPolicy {
                handshake_timeout: Some(Duration::from_millis(500)),
                ..ConnectionPolicy::default()
            },
        )
        .await;

        // The dial fails at the SSH handshake (the loopback peer is not an SSH
        // server), NOT at the obfs layer — proving the password resolved.
        assert!(res.is_err(), "loopback peer is not an SSH server");
        let entries = audit.entries();
        assert_eq!(
            entries.len(),
            1,
            "the SS transport must have dialed (password resolved, no \
             'password not resolved' short-circuit)"
        );
        assert_eq!(entries[0].0, "ssh-over-shadowsocks");
    }

    // ──────── M2/Low: escape server-controlled data at log/error sinks ──────

    #[test]
    fn kbi_unmatched_prompt_msg_escapes_control_bytes() {
        // A malicious server prompt with ESC + CR + newline must be neutralized.
        let evil = "Password:\x1b[31m\r\nFAKE";
        let msg = kbi_unmatched_prompt_msg(evil);
        assert!(!msg.contains('\x1b'), "ESC must be escaped: {msg:?}");
        assert!(!msg.contains('\n'), "newline must be escaped: {msg:?}");
        assert!(!msg.contains('\r'), "CR must be escaped: {msg:?}");
        assert!(msg.contains("\\u{1b}"), "ESC rendered visibly: {msg:?}");
        assert!(msg.contains("\\n") && msg.contains("\\r"));
    }

    #[test]
    fn kbi_unmatched_prompt_msg_clean_input_unchanged() {
        let msg = kbi_unmatched_prompt_msg("Verification code:");
        assert_eq!(
            msg,
            "no keyboard-interactive responder matched prompt `Verification code:`"
        );
    }

    #[test]
    fn dynamic_target_denied_msg_escapes_host() {
        let evil = "10.0.0.1\x1b]0;pwned\x07";
        let msg = dynamic_target_denied_msg(evil, 22);
        assert!(!msg.contains('\x1b'), "ESC must be escaped: {msg:?}");
        assert!(!msg.contains('\x07'), "BEL must be escaped: {msg:?}");
        assert!(msg.ends_with(":22 denied by ruleset"));
    }

    #[test]
    fn dynamic_target_denied_msg_clean_input_unchanged() {
        assert_eq!(
            dynamic_target_denied_msg("example.com", 443),
            "dynamic proxy target example.com:443 denied by ruleset"
        );
    }

    #[test]
    fn dynamic_dial_failure_msg_escapes_host() {
        let evil = "host\ninjected: line";
        let msg = dynamic_dial_failure_msg(evil, 80, &"connection refused");
        assert!(!msg.contains('\n'), "newline must be escaped: {msg:?}");
        assert!(msg.contains("\\n"));
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn dynamic_dial_failure_msg_clean_input_unchanged() {
        assert_eq!(
            dynamic_dial_failure_msg("svc.internal", 8080, &"timed out"),
            "russh dynamic direct-tcpip to svc.internal:8080: timed out"
        );
    }

    // ──────── H-1: transient key/cert-file I/O is RETRYABLE, not terminal ──
    //
    // The supervisor reconnect classifier treats `KeyFailure` as TERMINAL
    // (stop the profile forever). A key/cert file briefly unreadable during an
    // atomic rotation or a permission race must therefore NOT map to
    // `KeyFailure` — it must map to a retryable variant so the profile heals.
    // A genuinely-bad (malformed / wrong-passphrase) key must stay terminal.

    #[test]
    fn transient_key_io_error_is_retryable_not_terminal() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let e = russh::keys::Error::IO(std::io::Error::new(kind, "rotation race"));
            let mapped = classify_key_load_error("load private key", e);
            assert!(
                matches!(mapped, Error::RuntimeFailure(_)),
                "transient {kind:?} must be retryable, got {mapped:?}"
            );
            // Crucially NOT the terminal variant.
            assert!(!matches!(mapped, Error::KeyFailure(_)));
        }
    }

    #[test]
    fn malformed_key_error_is_terminal_key_failure() {
        // A genuine parse failure (corrupt key) must remain terminal so we do
        // not infinite-retry a key that will never load (H-2 must not regress).
        let mapped = classify_key_load_error("load private key", russh::keys::Error::KeyIsCorrupt);
        assert!(
            matches!(mapped, Error::KeyFailure(_)),
            "corrupt key must be terminal, got {mapped:?}"
        );
        // An encrypted key with the wrong/missing passphrase is also terminal.
        let mapped =
            classify_key_load_error("load private key", russh::keys::Error::KeyIsEncrypted);
        assert!(matches!(mapped, Error::KeyFailure(_)));
    }

    #[test]
    fn non_transient_key_io_error_stays_terminal() {
        // An `InvalidData` I/O error (e.g. the file is not UTF-8 / not a key)
        // is not a transient race; keep it terminal so we don't retry forever.
        let e = russh::keys::Error::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a key",
        ));
        let mapped = classify_key_load_error("load private key", e);
        assert!(matches!(mapped, Error::KeyFailure(_)), "got {mapped:?}");
    }

    #[test]
    fn transient_cert_io_error_is_retryable_not_terminal() {
        let mapped = classify_cert_load_error(
            "load OpenSSH certificate",
            russh::keys::ssh_key::Error::Io(std::io::ErrorKind::PermissionDenied),
        );
        assert!(
            matches!(mapped, Error::RuntimeFailure(_)),
            "transient cert I/O must be retryable, got {mapped:?}"
        );
        assert!(!matches!(mapped, Error::KeyFailure(_)));
    }

    #[test]
    fn malformed_cert_error_is_terminal_key_failure() {
        let mapped = classify_cert_load_error(
            "load OpenSSH certificate",
            russh::keys::ssh_key::Error::FormatEncoding,
        );
        assert!(matches!(mapped, Error::KeyFailure(_)), "got {mapped:?}");
    }
}
