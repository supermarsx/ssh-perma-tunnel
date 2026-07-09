//! In-repo SSH3 **server end** — the responder half of an spt↔spt tunnel.
//!
//! ## Status & scope
//!
//! This is the glue that promotes the per-helper server primitives in
//! [`crate::forward`] (`serve_local_tcp_acceptor`, `serve_datagram_demux`,
//! `serve_remote_udp_forwards`) and [`crate::transport::accept_control_stream`]
//! into a single reusable responder, [`Ssh3Server::run`], so a real
//! end-to-end forward test (and, in a later wave, a real `spt ssh3-serve`
//! subcommand) can stand up a server over a loopback
//! [`quinn::Endpoint::server`] and tunnel against a live [`crate::Ssh3Session`]
//! opened via the full HTTP/3 Extended-CONNECT [`crate::bootstrap`] path.
//!
//! It is gated behind the `server` cargo feature (also implied by `testing`).
//! The base `server` feature adds no new external dependency — the
//! `spt ssh3-serve` subcommand builds its [`quinn::ServerConfig`] from
//! operator-supplied cert+key PEM via [`crate::tls::build_server_config`].
//! Dev-mode self-signed certificates ([`crate::tls::self_signed_server_config`])
//! live behind the separate `server-selfsigned` feature so production server
//! builds never link `rcgen`.
//!
//! ## Responder flow
//!
//! Mirrors the client [`crate::bootstrap`] order exactly:
//!
//! 1. **HTTP/3 Extended-CONNECT** — the client opens its first bidi stream and
//!    writes a `:protocol = <token>` HEADERS frame (see [`crate::h3_raw`]). The
//!    server decodes it, optionally checks the `:protocol` token + an
//!    `authorization` header against the [`Ssh3ServerAcl`], and replies with a
//!    `:status 200` (or `:status 401`) HEADERS frame. The client drops this
//!    bidi immediately after reading the status; so does the server.
//! 2. **Control stream** — the client opens its second bidi and exchanges
//!    [`crate::frame::Ssh3FrameKind::Settings`] frames
//!    ([`crate::transport::accept_control_stream`]). The server's advertised
//!    [`Ssh3Settings`] gate which forward kinds it will serve.
//! 3. **Forwards** — every subsequent inbound bidi is a `direct-tcp` open
//!    (local-TCP forward); QUIC datagrams carry UDP-forward traffic; and
//!    `RemoteUdpForwardRequest` control frames request server-side UDP
//!    listeners. The server serves all three by wiring the existing
//!    `serve_*` helpers against one shared [`crate::forward::SessionState`].

#![cfg(any(test, feature = "server"))]

use std::sync::Arc;
use std::time::Duration;

use spt_core::{Error, Result};
use spt_protocol::endpoint::TargetAddr;
use tokio::sync::Mutex as AsyncMutex;
use tracing::debug;

use crate::forward::{
    serve_datagram_demux, serve_inbound_opens, serve_remote_udp_forwards, SessionState,
};
use crate::frame::{ChannelOpenPayload, Ssh3Settings};
use crate::h3_raw::{build_headers_frame, qpack_decode, qpack_encode, read_frame_typed};
use crate::transport::accept_control_stream;

/// HTTP/3 HEADERS frame type (RFC 9114 §7.2.2).
const FRAME_HEADERS: u64 = 0x01;

/// Generous default deadline for the server-side accept→CONNECT→control-ready
/// handshake. A half-open peer (stalled CONNECT, or an endless stream of
/// non-HEADERS frames that defeats the idle timeout) cannot pin the
/// per-connection task past this bound; a legit slow-but-progressing handshake
/// completes well within it. Matches the client-side CONNECT timeout (30s).
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolver/authorizer for a peer-requested `direct-tcp` open: maps the open to
/// a dial target, or `None` to deny.
type TargetResolver = Arc<dyn Fn(&ChannelOpenPayload) -> Option<TargetAddr> + Send + Sync>;

/// CONNECT-time authorizer: given the `:protocol` token and the `Authorization`
/// header value (if any), returns `true` to accept (HTTP 200) or `false` to
/// reject (HTTP 401).
type ConnectAuthorizer = Arc<dyn Fn(&str, Option<&str>) -> bool + Send + Sync>;

/// UDS path authorizer: returns `true` to allow a peer-requested unix socket
/// path to be connected or bound by the server.
type UdsPathAuthorizer = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Access-control + target-resolution policy for an [`Ssh3Server`].
///
/// The resolver maps a peer-requested `direct-tcp` open ([`ChannelOpenPayload`])
/// to the [`TargetAddr`] the server should actually dial — returning `None`
/// denies the open. This is the seam an operator-facing server uses to enforce
/// an allow-list; the loopback test rig uses it to pin every open to one echo
/// target.
///
/// Cheaply cloneable — the resolver/authorizer are `Arc`-wrapped, so a single
/// configured ACL can be cloned per accepted connection (as
/// [`serve`] does).
#[derive(Clone)]
pub struct Ssh3ServerAcl {
    /// Resolve (and authorize) a `direct-tcp` open to a dial target. `None`
    /// rejects the open.
    pub resolve_target: TargetResolver,
    /// Authorize peer-requested Unix-domain socket paths. The default denies
    /// all UDS paths so TCP target ACLs cannot be bypassed by UDS forwards.
    pub authorize_uds_path: UdsPathAuthorizer,
    /// Optional CONNECT-time authorization check. Given the request's
    /// `:protocol` token and `Authorization` header value (if present), return
    /// `true` to accept (HTTP 200) or `false` to reject (HTTP 401). When
    /// `None`, every CONNECT with a recognized `:protocol` token is accepted.
    pub authorize_connect: Option<ConnectAuthorizer>,
    /// The `:protocol` token the server requires on the CONNECT (default
    /// `ssh3`). A mismatch is rejected with HTTP 421 (Misdirected Request).
    pub protocol_token: String,
}

impl Ssh3ServerAcl {
    /// Build an ACL that resolves every open with `resolve_target` and accepts
    /// every CONNECT bearing the default `ssh3` protocol token.
    #[must_use]
    pub fn new(
        resolve_target: impl Fn(&ChannelOpenPayload) -> Option<TargetAddr> + Send + Sync + 'static,
    ) -> Self {
        Self {
            resolve_target: Arc::new(resolve_target),
            authorize_uds_path: Arc::new(|_path| false),
            authorize_connect: None,
            protocol_token: crate::config::DEFAULT_PROTOCOL_TOKEN.to_string(),
        }
    }

    /// Pin a single fixed dial target for every accepted open (the common
    /// loopback-test case).
    #[must_use]
    pub fn fixed_target(target: TargetAddr) -> Self {
        Self::new(move |_open| Some(target.clone()))
    }

    /// Set a UDS path authorization callback for local and remote UDS forwards.
    #[must_use]
    pub fn with_authorize_uds_path(
        mut self,
        f: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.authorize_uds_path = Arc::new(f);
        self
    }

    /// Set a CONNECT-time authorization callback.
    #[must_use]
    pub fn with_authorize_connect(
        mut self,
        f: impl Fn(&str, Option<&str>) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.authorize_connect = Some(Arc::new(f));
        self
    }

    /// Override the required `:protocol` token (default `ssh3`).
    #[must_use]
    pub fn with_protocol_token(mut self, token: impl Into<String>) -> Self {
        self.protocol_token = token.into();
        self
    }
}

impl std::fmt::Debug for Ssh3ServerAcl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssh3ServerAcl")
            .field("protocol_token", &self.protocol_token)
            .field("has_authorize_connect", &self.authorize_connect.is_some())
            .finish_non_exhaustive()
    }
}

/// The reusable SSH3 responder. Pair one [`Ssh3Server`] with one accepted
/// [`quinn::Connection`].
#[derive(Debug)]
pub struct Ssh3Server {
    /// Capabilities advertised to the client on the control stream. Gates which
    /// forward kinds the client will attempt.
    settings: Ssh3Settings,
    /// Deadline for the accept→CONNECT→control-ready handshake.
    handshake_timeout: Duration,
}

impl Default for Ssh3Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Ssh3Server {
    /// Build a server advertising a full TCP + UDP capability set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: Ssh3Settings {
                direct_tcp: true,
                remote_tcp: true,
                udp_datagrams: true,
                agent_forwarding: false,
                max_forwards: Some(64),
                version: Some(concat!("spt-ssh3-server/", env!("CARGO_PKG_VERSION")).to_string()),
                extras: Vec::new(),
            },
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Override the advertised [`Ssh3Settings`].
    #[must_use]
    pub fn with_settings(mut self, settings: Ssh3Settings) -> Self {
        self.settings = settings;
        self
    }

    /// Override the accept→CONNECT→control-ready handshake deadline (default
    /// 30s). Primarily a test hook for asserting the stalled-peer timeout
    /// fires quickly.
    #[must_use]
    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    /// Run the responder loop for one accepted QUIC connection until it closes.
    ///
    /// Order matches the client [`crate::bootstrap`] sequence: CONNECT bidi →
    /// control bidi → forward bidis + datagrams. Returns when the connection is
    /// closed (cleanly or by error) after all spawned sub-tasks have been
    /// dropped.
    pub async fn run(self, connection: quinn::Connection, acl: Ssh3ServerAcl) -> Result<()> {
        let acl = Arc::new(acl);

        // Steps 0–2 form the server-side handshake. Wrap them in a deadline so a
        // half-open peer (stalled CONNECT, or endless non-HEADERS frames that
        // defeat the idle timeout) cannot pin this per-connection task forever
        // (M6). `_h3_control` must outlive the handshake (held for the
        // connection's lifetime), so it is returned from the timed block and
        // bound in the outer scope.
        let settings = self.settings.clone();
        let handshake = async {
            // 0. Open the server-side HTTP/3 control stream + SETTINGS so the
            // client's h3 driver (`poll_close`) observes a live peer and does
            // NOT tear the QUIC connection down when its driver task drops. The
            // real francoismichel/ssh3 server provides this implicitly (it is a
            // full h3 server).
            let h3_control = crate::h3_raw::write_server_control_stream(&connection).await?;

            // 1. HTTP/3 Extended-CONNECT bootstrap bidi (client's first bidi).
            self.handle_connect(&connection, &acl).await?;

            // 2. Control stream (client's second bidi): exchange Settings.
            let (control_send, control_recv, _peer) =
                accept_control_stream(&connection, settings).await?;
            Ok::<_, Error>((h3_control, control_send, control_recv))
        };
        let (_h3_control, control_send, control_recv) =
            match tokio::time::timeout(self.handshake_timeout, handshake).await {
                Ok(Ok(parts)) => parts,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(Error::RuntimeFailure(
                        "ssh3 server: handshake timed out".into(),
                    ))
                }
            };
        let control_send = Arc::new(AsyncMutex::new(control_send));

        // Shared per-connection state — one SessionState wires the local-TCP
        // acceptor, the datagram demux, and the remote-UDP acceptor together.
        let state = Arc::new(SessionState::with_max_forwards(self.settings.max_forwards));

        // 3a. Remote-UDP control acceptor: reads RemoteUdpForwardRequest frames
        // off the control stream and binds server-side UDP listeners.
        let ru_conn = connection.clone();
        let ru_state = state.clone();
        let ru_ctl = control_send.clone();
        let acl_for_remote_uds = acl.clone();
        let remote_udp = tokio::spawn(async move {
            serve_remote_udp_forwards(ru_conn, control_recv, ru_ctl, ru_state, move |path| {
                (acl_for_remote_uds.authorize_uds_path)(path)
            })
            .await;
        });

        // 3b. Datagram demux: routes inbound QUIC datagrams by flow-id into the
        // shared state. This keeps the server-side `udp_flows` map (populated by
        // `serve_remote_udp_forwards`) fed with client replies. The local-UDP
        // *server* side (handling a client `UdpAssociate` that asks the server
        // to dial a target per datagram) is not wired here — the A4 e2e test
        // covers local-TCP + remote-UDP; local-UDP server support is a
        // follow-up once a `serve_udp_associate` helper exists in `forward.rs`.
        let dg_conn = connection.clone();
        let dg_state = state.clone();
        let datagram = tokio::spawn(async move {
            serve_datagram_demux(dg_conn, dg_state).await;
        });

        // 4. Inbound-open acceptor: every remaining inbound bidi is either a
        // `direct-tcp` open (resolved via the ACL and bridged to a TCP target)
        // or, on `cfg(unix)`, a `uds` open authorized by the ACL before the
        // server connects to the requested socket path.
        let acl_for_tcp = acl.clone();
        let acl_for_uds = acl.clone();
        serve_inbound_opens(
            connection.clone(),
            move |open| (acl_for_tcp.resolve_target)(open),
            move |path| (acl_for_uds.authorize_uds_path)(path),
        )
        .await;

        // The acceptor returns when the connection closes; tear the rest down.
        remote_udp.abort();
        datagram.abort();
        Ok(())
    }

    /// Handle the HTTP/3 Extended-CONNECT bootstrap bidi: decode the request
    /// HEADERS, authorize, and write a `:status` HEADERS response.
    async fn handle_connect(
        &self,
        connection: &quinn::Connection,
        acl: &Ssh3ServerAcl,
    ) -> Result<()> {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| Error::RuntimeFailure(format!("ssh3 server: accept CONNECT bidi: {e}")))?;
        let payload = read_frame_typed(&mut recv, FRAME_HEADERS).await?;
        let fields = qpack_decode(&payload)?;

        let by_name = |key: &[u8]| -> Option<Vec<u8>> {
            fields
                .iter()
                .find(|(n, _)| n.as_slice() == key)
                .map(|(_, v)| v.clone())
        };

        let protocol = by_name(b":protocol").unwrap_or_default();
        let protocol_str = String::from_utf8_lossy(&protocol);
        let authz = by_name(b"authorization");
        let authz_str = authz
            .as_ref()
            .map(|v| String::from_utf8_lossy(v).to_string());

        let status: &[u8] = if protocol_str != acl.protocol_token {
            debug!(
                target: "spt_ssh3::server",
                got = %protocol_str, want = %acl.protocol_token,
                "CONNECT :protocol token mismatch — rejecting 421"
            );
            b"421"
        } else if let Some(check) = acl.authorize_connect.as_ref() {
            if check(&protocol_str, authz_str.as_deref()) {
                b"200"
            } else {
                b"401"
            }
        } else {
            b"200"
        };

        let resp = qpack_encode(&[(b":status", status), (b"server", b"spt-ssh3")]);
        let frame = build_headers_frame(&resp);
        send.write_all(&frame).await.map_err(|e| {
            Error::RuntimeFailure(format!("ssh3 server: write CONNECT status: {e}"))
        })?;
        send.finish()
            .map_err(|e| Error::RuntimeFailure(format!("ssh3 server: finish CONNECT: {e}")))?;

        if status != b"200" {
            return Err(Error::AuthFailed(format!(
                "ssh3 server: CONNECT rejected with HTTP {}",
                String::from_utf8_lossy(status)
            )));
        }
        Ok(())
    }
}

/// Bind a [`quinn::Endpoint::server`] on `listen` with `server_cfg`, then accept
/// connections in a loop, spawning one [`Ssh3Server::run`] task per accepted
/// connection (each gets a clone of `acl`). The loop runs until the `shutdown`
/// future resolves, at which point the endpoint is closed cleanly and the call
/// awaits in-flight connections going idle.
///
/// This is the engine behind the `spt ssh3-serve` subcommand; it owns all
/// `quinn` server plumbing so callers (e.g. `spt-bin`) need not depend on
/// `quinn` directly. Connect/disconnect/error events are logged via `tracing`.
///
/// `listen` is a concrete [`std::net::SocketAddr`]; the caller resolves any
/// host string first.
#[cfg(any(test, feature = "server"))]
pub async fn serve<F>(
    listen: std::net::SocketAddr,
    server_cfg: quinn::ServerConfig,
    acl: Ssh3ServerAcl,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send,
{
    use tracing::{info, warn};

    let endpoint = quinn::Endpoint::server(server_cfg, listen)
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 server: bind {listen}: {e}")))?;
    let bound = endpoint
        .local_addr()
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 server: local_addr: {e}")))?;
    info!(
        target: "spt_ssh3::server",
        listen = %bound, protocol_token = %acl.protocol_token,
        "ssh3 server: listening for SSH3 (QUIC + HTTP/3) connections"
    );

    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => {
                info!(target: "spt_ssh3::server", "ssh3 server: shutdown requested — stopping accept loop");
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let remote = incoming.remote_address();
                let conn_acl = acl.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(target: "spt_ssh3::server", peer = %remote, error = %e, "ssh3 server: handshake failed");
                            return;
                        }
                    };
                    info!(target: "spt_ssh3::server", peer = %remote, "ssh3 server: connection established");
                    match Ssh3Server::new().run(conn, conn_acl).await {
                        Ok(()) => info!(target: "spt_ssh3::server", peer = %remote, "ssh3 server: connection closed"),
                        Err(e) => warn!(target: "spt_ssh3::server", peer = %remote, error = %e, "ssh3 server: connection error"),
                    }
                });
            }
        }
    }

    endpoint.close(0u32.into(), b"ssh3 server shutting down");
    endpoint.wait_idle().await;
    info!(target: "spt_ssh3::server", "ssh3 server: endpoint closed");
    Ok(())
}
