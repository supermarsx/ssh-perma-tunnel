//! Per-forward channel framing on top of the SSH3 QUIC connection.
//!
//! ## Wire contract (spt↔spt only)
//!
//! Each forward channel = one bidi QUIC stream. Frames on a stream use the
//! [`crate::frame::Ssh3Frame`] layout (`[kind:u8][len:u32_be][payload…]`),
//! with the following semantics:
//!
//! * **Local TCP forward** (initiator → peer): the client opens a fresh bidi
//!   stream and writes one [`Ssh3FrameKind::DirectTcpRequest`] frame whose
//!   payload is a [`crate::frame::ChannelOpenPayload`] (`host:port`). The peer
//!   responds with an [`Ssh3FrameKind::ForwardOpenResponse`]; if `ok = true`
//!   the stream becomes a raw byte pipe (no further framing) until either side
//!   half-closes.
//!
//! * **Remote TCP forward** (initiator → peer, via control stream): the
//!   client sends a [`Ssh3FrameKind::DirectTcpRequest`] frame **on the control
//!   stream** with `kind = TcpipForward` semantics — the peer interprets this
//!   as a request to listen on the supplied `host:port` and forward inbound
//!   connections back as `forwarded-tcp` channels. (We reuse
//!   [`Ssh3FrameKind::DirectTcpRequest`] for both directions of the channel
//!   open; the *direction* is implied by which end opened the stream.) The
//!   peer responds with [`Ssh3FrameKind::ForwardOpenResponse`] on the control
//!   stream. On each inbound connection on the server side, the server opens
//!   a fresh bidi stream **toward the client**, sending its own
//!   [`Ssh3FrameKind::DirectTcpRequest`] frame; the client dispatches that
//!   stream onto the matching remote forward.
//!
//! * **UDP forward**: see `udp_forward` below — flow-id is allocated via a
//!   [`Ssh3FrameKind::UdpAssociate`] control frame, then datagrams are sent
//!   over QUIC datagrams with a `[u32_be flow_id][payload…]` prefix.
//!
//! These constants are NOT bit-compatible with the francoismichel/ssh3
//! reference (which uses an SSH-style `string + uint32` encoding); the task
//! explicitly authorizes the spt↔spt-only escape hatch. Real-server interop
//! is gated on the `SPT_SSH3_TEST_SERVER` integration test.
//!
//! TODO(spec-clarify): when the upstream SSH3 wire spec stabilizes, replace
//! this framing with a bit-compatible encoder.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use quinn::{Connection, RecvStream, SendStream};
use spt_core::{BindAddr, Error, Result};
use spt_forward::{
    bind_with_policy, copy_bidirectional_throttled_idle, BoundListener, ConnectionGate,
    ConnectionPermit, RateGate, TokenBucket, UdpFlowKey, UdpFlowTable, UdpFlowTableConfig,
};
use spt_protocol::endpoint::TargetAddr;
use spt_protocol::forward::{
    BindConflictPolicy, ForwardDirection, ForwardRateLimits, ForwardState, LocalForwardSpec,
    RemoteForwardSpec, UdpForwardSpec,
};
use spt_protocol::handle::{ForwardHandle, ForwardId};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Semaphore};
use tracing::{debug, error, info, warn};

use crate::frame::{
    ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, UdpAssociatePayload,
};
// `UdsChannelOpenPayload` is only referenced from `cfg(unix)` UDS paths; on
// non-unix the import would be dead.
#[cfg(unix)]
use crate::frame::UdsChannelOpenPayload;

/// Channel-open timeout (peer must answer the open frame within this).
const OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Hard ceiling on the number of concurrent accepted inbound forwards when the
/// peer's `Settings` did not advertise a `max_forwards` value. The advertised
/// value (when present) takes precedence; this is only the fallback bound so an
/// unbounded peer cannot flood us into unbounded task/socket growth (E3-F3).
const DEFAULT_MAX_INBOUND_FORWARDS: u32 = 256;

/// Cap on the number of in-flight remote-UDP per-datagram dial tasks across all
/// flows on a session. The remote-UDP path spawns a short-lived task per
/// inbound datagram (each binding a socket + a 64 KiB buffer); without a bound a
/// datagram flood translates directly into unbounded socket/memory growth
/// (E3-F3). Bounded fan-out drops excess datagrams instead.
const MAX_REMOTE_UDP_INFLIGHT: usize = 1024;

/// Bound on each per-flow inbound UDP datagram queue (`udp_flows`).
///
/// M1: the session datagram demux loop (`session.rs` / [`serve_datagram_demux`])
/// `try_send`s every inbound QUIC datagram into the matching flow's channel and
/// DROPS on a full queue, matching UDP's inherently lossy semantics. A bounded
/// channel ensures a fast or hostile peer that outruns the local socket-send
/// path cannot drive unbounded memory growth (the prior `unbounded_channel`
/// grew without limit). Sized to absorb transient bursts while the consumer
/// drains, consistent with how the UDP flow table caps elsewhere.
const UDP_INBOUND_CHANNEL_CAP: usize = 1024;

/// Default maximum UDP datagram size (bytes) enforced on the ssh3 UDP forward
/// path. `UdpForwardSpec` currently has **no** `max_datagram_size` field in the
/// config schema (flagged for the coordinator to add in Wave 8 — see
/// `.orchestration/logs/w3-ssh3fwd.md`), so we apply this conservative default
/// (the maximum well-formed UDP payload); oversized datagrams are dropped and
/// counted. When the schema field lands this becomes the per-forward configured
/// value. Chosen so it is behaviour-preserving (a normal datagram is never
/// rejected) while still bounding a malformed/oversized datagram.
const DEFAULT_MAX_DATAGRAM_SIZE: u32 = 65_535;

/// Fallback per-flow idle timeout for a UDP forward whose spec sets
/// `idle_timeout_secs = 0` (interpreted as "unset").
const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(60);

/// Build the `(up, down)` byte-rate token buckets for a forward from its rate
/// limits, mirroring the ssh2 backend's `ForwardBuckets` (a zero rate yields an
/// inert/unlimited bucket, preserving prior behaviour). `up` throttles the
/// client→peer direction, `down` the peer→client direction.
fn forward_buckets(limits: &ForwardRateLimits) -> (TokenBucket, TokenBucket) {
    (
        TokenBucket::new(limits.rate_bps_up, limits.burst_up),
        TokenBucket::new(limits.rate_bps_down, limits.burst_down),
    )
}

/// Resolve the effective per-forward UDP flow-table config from a
/// [`UdpForwardSpec`]: the config `max_flows` (NOT a hard-coded 1024 — falling
/// back to [`UdpFlowTableConfig`]'s generous-but-finite default when unset), the
/// per-flow idle timeout from `idle_timeout_secs`, and the (currently
/// schema-less) max-datagram-size default.
fn udp_flow_config(spec: &UdpForwardSpec) -> UdpFlowTableConfig {
    let idle_timeout = if spec.idle_timeout_secs == 0 {
        DEFAULT_UDP_IDLE
    } else {
        Duration::from_secs(u64::from(spec.idle_timeout_secs))
    };
    UdpFlowTableConfig {
        idle_timeout,
        max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
        // `UdpForwardSpec.max_flows` is the config `max_connections` remapped by
        // the runner. `Some(n)` ⇒ that cap; `None` ⇒ the table's finite default
        // (never the old hard-coded 1024 channel cap).
        max_flows: spec
            .max_flows
            .unwrap_or(UdpFlowTableConfig::default().max_flows),
    }
}

/// What the inbound-bidi dispatcher hands off to the remote-forward loop once
/// it has accepted an inbound `forwarded-tcp` open *and* successfully dialed
/// the local target (E3-F8): the already-connected local socket plus the QUIC
/// stream halves to bridge it against, and a concurrency permit whose lifetime
/// bounds the forward (E3-F3).
pub(crate) struct InboundForward {
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
    pub(crate) local: TcpStream,
    /// Held for the lifetime of the bridged connection so the session-wide
    /// negotiated `max_forwards` semaphore reflects live forwards, not merely
    /// accepted opens.
    pub(crate) _permit: tokio::sync::OwnedSemaphorePermit,
    /// Per-forward config `max_connections` permit (M-W3): held alongside the
    /// negotiated permit so an inbound remote forward is bounded by
    /// `min(config max_connections, negotiated max_forwards)`. `None` when the
    /// forward set no `max_connections` (unlimited gate).
    pub(crate) _conn_permit: Option<ConnectionPermit>,
    /// Per-forward byte-rate buckets + idle timeout applied by [`bridge_remote`].
    pub(crate) limits: ForwardRateLimits,
    pub(crate) idle_timeout: Option<Duration>,
}

/// Per-remote-forward registration: the local target to dial on each inbound
/// open and the channel that delivers dialed-and-accepted inbound forwards to
/// the forward's bridge loop.
pub(crate) struct RemoteForwardEntry {
    pub(crate) target: TargetAddr,
    pub(crate) tx: mpsc::UnboundedSender<InboundForward>,
    /// Per-forward connection cap from the config `max_connections` (M-W3).
    /// `cap == 0` ⇒ unlimited; the session-wide negotiated `max_forwards`
    /// semaphore still applies, so the effective cap is the min of the two.
    pub(crate) conn_gate: ConnectionGate,
    /// Per-forward byte-rate limits + idle timeout, applied per bridged conn.
    pub(crate) limits: ForwardRateLimits,
    pub(crate) idle_timeout: Option<Duration>,
}

/// Transient state shared between the session and its dispatch loop.
///
/// * `udp_flows` maps a flow-id (allocated either by a local UDP forward or by
///   the peer's `UdpAssociate` frame) to a sender that receives inbound
///   datagram payloads (sans flow-id prefix).
/// * `remote_forwards` maps a `(host, port)` listening address to the target +
///   sender that receives dialed inbound forwards from the peer for that
///   listener.
/// * `inbound_forward_limit` bounds the number of concurrently-accepted inbound
///   forwards (`max_forwards` enforcement, E3-F3).
/// * `remote_udp_inflight` bounds the per-datagram remote-UDP dial fan-out
///   (E3-F3).
pub struct SessionState {
    pub(crate) udp_flows: DashMap<u32, mpsc::Sender<Bytes>>,
    pub(crate) remote_forwards: DashMap<(String, u16), RemoteForwardEntry>,
    /// Registered remote-UDS forwards, keyed by the *remote bind path* the peer
    /// listens on. The peer back-channels each accepted connection as a
    /// [`Ssh3FrameKind::UdsForwardRequest`] whose payload path is this key; the
    /// inbound dispatcher looks it up to find the *local* socket path to
    /// `UnixStream::connect` and bridge against (`cfg(unix)`).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) remote_uds_forwards: DashMap<String, RemoteUdsEntry>,
    pub(crate) inbound_forward_limit: Arc<Semaphore>,
    pub(crate) remote_udp_inflight: Arc<Semaphore>,
}

/// Per-remote-UDS-forward registration: the local unix socket path the client
/// dials on each inbound back-channel the peer opens for this forward.
pub(crate) struct RemoteUdsEntry {
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) local_path: std::path::PathBuf,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::with_max_forwards(None)
    }
}

impl SessionState {
    /// Build session state with the inbound-forward concurrency cap taken from
    /// the peer's advertised `max_forwards` (falling back to
    /// [`DEFAULT_MAX_INBOUND_FORWARDS`] when the peer advertises none, and
    /// clamping `0`/absurd values into a sane range).
    #[must_use]
    pub fn with_max_forwards(max_forwards: Option<u32>) -> Self {
        let cap = match max_forwards {
            Some(0) | None => DEFAULT_MAX_INBOUND_FORWARDS,
            Some(n) => n,
        };
        // Semaphore permits are `usize`; on 16-bit targets a huge advertised
        // cap would overflow, so clamp to a generous ceiling.
        let cap = usize::try_from(cap).unwrap_or(usize::MAX).min(1 << 20);
        Self {
            udp_flows: DashMap::new(),
            remote_forwards: DashMap::new(),
            remote_uds_forwards: DashMap::new(),
            inbound_forward_limit: Arc::new(Semaphore::new(cap)),
            remote_udp_inflight: Arc::new(Semaphore::new(MAX_REMOTE_UDP_INFLIGHT)),
        }
    }
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("udp_flows", &self.udp_flows.len())
            .field("remote_forwards", &self.remote_forwards.len())
            .field("remote_uds_forwards", &self.remote_uds_forwards.len())
            .field(
                "inbound_forward_permits_available",
                &self.inbound_forward_limit.available_permits(),
            )
            .field(
                "remote_udp_inflight_available",
                &self.remote_udp_inflight.available_permits(),
            )
            .finish()
    }
}

/// Render a `BindAddr` into the `host:port` form `tokio::net::TcpListener`
/// accepts.
fn bind_addr_string(addr: &BindAddr) -> Result<String> {
    match addr {
        BindAddr::Tcp(sock) => Ok(sock.to_string()),
        BindAddr::TcpHostPort { host, port } => Ok(format!("{host}:{port}")),
        BindAddr::Unix(_) => Err(Error::UnsupportedPlatform(
            "ssh3 forward listeners on unix sockets are not implemented".into(),
        )),
    }
}

/// Extract the `(host, port)` of a [`BindAddr`].
fn bind_host_port(addr: &BindAddr) -> Result<(String, u16)> {
    match addr {
        BindAddr::Tcp(sock) => Ok((sock.ip().to_string(), sock.port())),
        BindAddr::TcpHostPort { host, port } => Ok((host.clone(), *port)),
        BindAddr::Unix(_) => Err(Error::UnsupportedPlatform(
            "ssh3 forward listeners on unix sockets are not implemented".into(),
        )),
    }
}

/// Open a channel-open exchange on a fresh bidi stream and return the
/// resulting send/recv halves on success.
async fn open_channel(conn: &Connection, target: &TargetAddr) -> Result<(SendStream, RecvStream)> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 open_bi: {e}")))?;
    let req = Ssh3Frame::new(
        Ssh3FrameKind::DirectTcpRequest,
        ChannelOpenPayload {
            host: target.host.clone(),
            port: target.port,
        }
        .encode(),
    );
    req.write_async(&mut send).await?;

    let resp = tokio::time::timeout(OPEN_TIMEOUT, Ssh3Frame::read_async(&mut recv))
        .await
        .map_err(|_| {
            Error::RuntimeFailure("ssh3 channel-open: timeout waiting for response".into())
        })??;
    if resp.kind != Ssh3FrameKind::ForwardOpenResponse {
        return Err(Error::RuntimeFailure(format!(
            "ssh3 channel-open: expected ForwardOpenResponse, got {:?}",
            resp.kind
        )));
    }
    let parsed = ForwardOpenResponse::decode(resp.payload)?;
    if !parsed.ok {
        return Err(Error::NetworkUnreachable(format!(
            "ssh3 channel-open rejected by peer: {}",
            parsed.reason
        )));
    }
    Ok((send, recv))
}

/// Bind a local TCP listener honouring the forward's [`BindConflictPolicy`]
/// (M-W3). Mirrors the ssh2 backend's `bind_local_listener`: instead of a bare
/// `TcpListener::bind`, a bind conflict is resolved per the configured policy
/// (fail / retry / next-port), and a fell-forward bind is logged.
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
            target: "spt_ssh3::forward",
            forward = %name,
            requested = %desired,
            bound = %addr,
            "bind conflict resolved to a different address"
        );
    }
    Ok(listener)
}

/// Open a TCP local forward.
pub async fn open_local(conn: Connection, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
    let name = spec.name.clone();
    let listener = bind_local_listener(&spec.listen, spec.on_bind_conflict, &name).await?;
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();

    let (state_tx, state_rx) = watch::channel(ForwardState::Listening);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let target = spec.target.clone();

    info!(
        target: "spt_ssh3::forward",
        forward = %name,
        listen = %bound,
        target = %format!("{}:{}", target.host, target.port),
        max_connections = ?spec.max_connections,
        "ssh3 local forward opened"
    );

    tokio::spawn(local_loop(
        conn,
        listener,
        target,
        state_tx,
        close_rx,
        spec.max_connections,
        name.clone(),
        spec.limits,
        spec.idle_timeout,
    ));

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

#[allow(clippy::too_many_arguments)]
async fn local_loop(
    conn: Connection,
    listener: TcpListener,
    target: TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    max: Option<u32>,
    name: String,
    limits: ForwardRateLimits,
    idle_timeout: Option<Duration>,
) {
    let _ = state_tx.send(ForwardState::Active);
    // LOW-6: enforce `max_connections` with a proper semaphore gate rather than
    // a racy load-then-increment. `try_acquire` reserves a slot atomically, so N
    // concurrent accepts can never overshoot the cap; the RAII permit is held
    // for the bridged connection's lifetime and released on completion. `0`
    // (⇐ `max == None`) ⇒ unlimited (mirrors the ConnectionGate used by the
    // remote-forward/inbound-bidi paths).
    let conn_gate = ConnectionGate::new(max.unwrap_or(0));
    // M-W3: honour `max_new_connections_per_second` — a per-accept admission
    // gate. `0` ⇒ unlimited (preserves prior behaviour).
    let rate_gate = RateGate::new(limits.max_new_conns_per_sec, limits.max_new_conns_per_sec);
    loop {
        tokio::select! {
            _ = &mut close_rx => {
                debug!(target: "spt_ssh3::forward", forward = %name, "local forward shutdown signal");
                break;
            }
            accept = listener.accept() => {
                let (sock, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        error!(target: "spt_ssh3::forward", forward = %name, error = %e, "accept failed");
                        continue;
                    }
                };
                // M-W3: new-connection rate cap (checked before the conn cap so a
                // flood is shed cheaply).
                if !rate_gate.admit() {
                    warn!(target: "spt_ssh3::forward", forward = %name, ?peer, "max_new_connections_per_second reached, dropping connection");
                    continue;
                }
                // LOW-6: atomically reserve a connection slot. When the gate is
                // exhausted the freshly-accepted socket is dropped (no overshoot).
                let Some(permit) = conn_gate.try_acquire() else {
                    warn!(target: "spt_ssh3::forward", forward = %name, ?peer, limit = max, "max_connections reached, dropping incoming");
                    continue;
                };
                let target = target.clone();
                let conn = conn.clone();
                let name_t = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_local(conn, sock, &target, &limits, idle_timeout).await {
                        warn!(target: "spt_ssh3::forward", forward = %name_t, error = %e, "local conn failed");
                    }
                    // Release the connection slot only after the bridge returns.
                    drop(permit);
                });
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
}

async fn bridge_local(
    conn: Connection,
    mut sock: TcpStream,
    target: &TargetAddr,
    limits: &ForwardRateLimits,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    let (send, recv) = open_channel(&conn, target).await?;
    // M-W3: throttle + idle-close identically to the ssh2 local bridge. The
    // QUIC channel's (recv, send) halves are joined into one duplex so the
    // shared bidirectional copy can drive both directions. `sock` is the client
    // side (a); the joined QUIC stream is the peer side (b): a→b throttles
    // client→peer (`up`), b→a throttles peer→client (`down`).
    let (up, down) = forward_buckets(limits);
    let mut quic = tokio::io::join(recv, send);
    let res = copy_bidirectional_throttled_idle(&mut sock, &mut quic, up, down, idle_timeout).await;
    // Finish the QUIC send half regardless of outcome so the peer sees EOF.
    let _ = quic.shutdown().await;
    let _ = sock.shutdown().await;
    res.map_err(|e| Error::RuntimeFailure(format!("ssh3 local bridge I/O: {e}")))?;
    Ok(())
}

/// Open a TCP remote forward.
///
/// Sends a `tcpip-forward`-style request on the **control stream** and
/// installs a per-forward inbound dispatch entry. Inbound bidi streams from
/// the peer matching the listening address are accepted and bridged to a
/// fresh local TCP connection to `spec.target`.
#[allow(clippy::too_many_arguments)]
pub async fn open_remote(
    conn: Connection,
    state: Arc<SessionState>,
    control_send: Arc<AsyncMutex<SendStream>>,
    control_recv: Arc<AsyncMutex<RecvStream>>,
    control_request: Arc<AsyncMutex<()>>,
    spec: &RemoteForwardSpec,
    peer_supports_remote: bool,
) -> Result<ForwardHandle> {
    if !peer_supports_remote {
        return Err(Error::UnsupportedPlatform(
            "ssh3 peer does not advertise remote_tcp capability".into(),
        ));
    }
    let (host, port) = bind_host_port(&spec.listen)?;

    // E3-F5: hold the control-request lock across the write-request /
    // read-response exchange so two concurrent `open_remote` calls can't have
    // their `ForwardOpenResponse` frames mis-routed to each other on the
    // shared, un-correlated control stream.
    let _ctl_guard = control_request.lock().await;

    // Register the inbound dispatch entry *before* sending the request so a
    // peer that races to open `forwarded-tcp` streams the moment it ACKs
    // doesn't lose the first connection. The entry carries the local target so
    // the dispatcher can dial it *before* ACKing the open (E3-F8).
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<InboundForward>();
    state.remote_forwards.insert(
        (host.clone(), port),
        RemoteForwardEntry {
            target: spec.target.clone(),
            tx: inbound_tx,
            // M-W3: enforce the CONFIG `max_connections` in addition to the
            // session-wide negotiated `max_forwards` cap (effective = min).
            // `None`/`0` ⇒ unlimited gate.
            conn_gate: ConnectionGate::new(spec.max_connections.unwrap_or(0)),
            limits: spec.limits,
            idle_timeout: spec.idle_timeout,
        },
    );

    let req = Ssh3Frame::new(
        Ssh3FrameKind::DirectTcpRequest,
        ChannelOpenPayload {
            host: host.clone(),
            port,
        }
        .encode(),
    );
    let send_result = async {
        let mut g = control_send.lock().await;
        req.write_async(&mut *g).await
    }
    .await;
    if let Err(e) = send_result {
        state.remote_forwards.remove(&(host.clone(), port));
        return Err(e);
    }
    let resp = {
        let mut g = control_recv.lock().await;
        tokio::time::timeout(OPEN_TIMEOUT, Ssh3Frame::read_async(&mut *g))
            .await
            .map_err(|_| Error::RuntimeFailure("ssh3 tcpip-forward: timeout".into()))?
    };
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            state.remote_forwards.remove(&(host.clone(), port));
            return Err(e);
        }
    };
    if resp.kind != Ssh3FrameKind::ForwardOpenResponse {
        state.remote_forwards.remove(&(host.clone(), port));
        return Err(Error::RuntimeFailure(format!(
            "ssh3 tcpip-forward: unexpected kind {:?}",
            resp.kind
        )));
    }
    let parsed = ForwardOpenResponse::decode(resp.payload)?;
    if !parsed.ok {
        state.remote_forwards.remove(&(host.clone(), port));
        return Err(Error::RemoteBindFailed {
            address: format!("{host}:{port}"),
            reason: parsed.reason,
        });
    }

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();

    info!(
        target: "spt_ssh3::forward",
        forward = %name,
        listen = %format!("{host}:{port}"),
        max_connections = ?spec.max_connections,
        "ssh3 remote forward opened"
    );

    tokio::spawn(remote_loop(
        conn,
        state.clone(),
        inbound_rx,
        state_tx,
        close_rx,
        name.clone(),
        host,
        port,
    ));

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

#[allow(clippy::too_many_arguments)]
async fn remote_loop(
    _conn: Connection,
    state: Arc<SessionState>,
    mut inbound_rx: mpsc::UnboundedReceiver<InboundForward>,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    name: String,
    host: String,
    port: u16,
) {
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            inbound = inbound_rx.recv() => {
                match inbound {
                    Some(inbound) => {
                        let name_t = name.clone();
                        tokio::spawn(async move {
                            if let Err(e) = bridge_remote(inbound).await {
                                warn!(target: "spt_ssh3::forward", forward = %name_t, error = %e, "remote conn failed");
                            }
                        });
                    }
                    None => break,
                }
            }
        }
    }
    state.remote_forwards.remove(&(host, port));
    let _ = state_tx.send(ForwardState::Stopped);
}

/// Bridge an already-dialed inbound remote forward. The dispatcher has already
/// consumed the channel-open frame, dialed the local target, and acked the peer
/// with `ok:true` *only because* the dial succeeded (E3-F8); here we just splice
/// the QUIC stream against the connected socket. The concurrency permit inside
/// [`InboundForward`] is released when this future (and the moved socket/stream)
/// drops.
async fn bridge_remote(inbound: InboundForward) -> Result<()> {
    let InboundForward {
        send,
        recv,
        mut local,
        _permit,
        _conn_permit,
        limits,
        idle_timeout,
    } = inbound;
    // M-W3: throttle + idle-close the bridged remote forward. `local` is the
    // client-side dialed socket (a); the joined QUIC stream is the peer side
    // (b). For a remote forward the tunnel-side traffic (peer→local) is the
    // "down"/inbound direction and local→peer is "up".
    let (up, down) = forward_buckets(&limits);
    let mut quic = tokio::io::join(recv, send);
    let res =
        copy_bidirectional_throttled_idle(&mut local, &mut quic, up, down, idle_timeout).await;
    let _ = quic.shutdown().await;
    let _ = local.shutdown().await;
    res.map_err(|e| Error::RuntimeFailure(format!("ssh3 remote bridge I/O: {e}")))?;
    Ok(())
}

/// Per-client return-path route for a local UDP forward (MED-4).
///
/// Created lazily on the first datagram from a *new* client source address and
/// stored as the [`UdpFlowTable`] value (keyed by that client addr). It owns the
/// per-client `flow_id`, so a reply datagram — routed by the session demux into
/// `state.udp_flows[flow_id]` — is delivered back to the *correct* client rather
/// than a shared "last peer". Dropping the route (idle eviction or forward
/// teardown) unregisters the flow-id and stops the client's reply pump, keeping
/// `state.udp_flows` and the spawned task set bounded by `max_flows`.
struct UdpFlowRoute {
    flow_id: u32,
    state: Arc<SessionState>,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for UdpFlowRoute {
    fn drop(&mut self) {
        self.state.udp_flows.remove(&self.flow_id);
        self.pump.abort();
    }
}

/// Spawn the per-client reply pump: drain `rx` (fed by the session datagram
/// demux for this client's `flow_id`) and deliver each reply back to exactly
/// `peer`. The shared per-direction `down_bucket` throttles byte-rate (UDP is
/// lossy — an over-budget datagram is dropped, never blocked).
fn spawn_udp_reply_pump(
    mut rx: mpsc::Receiver<Bytes>,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    down_bucket: TokenBucket,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            if down_bucket.is_active() && down_bucket.try_acquire(payload.len() as u64).is_some() {
                debug!(target: "spt_ssh3::forward", ?peer, "udp down byte-rate cap — dropping datagram");
                continue;
            }
            if let Err(e) = socket.send_to(&payload, peer).await {
                warn!(target: "spt_ssh3::forward", error = %e, ?peer, "udp send_to client failed");
            }
        }
    })
}

/// Parameters for [`local_udp_pump`], the local-UDP forward data-plane task.
/// Bundled into one struct so the pump can be driven directly from tests with a
/// caller-bound socket (whose ephemeral port is then known) without an
/// unwieldy argument list.
struct LocalUdpPump {
    conn: Connection,
    state: Arc<SessionState>,
    control_send: Arc<AsyncMutex<SendStream>>,
    next_flow_id: Arc<std::sync::atomic::AtomicU32>,
    socket: Arc<UdpSocket>,
    target: TargetAddr,
    flow_table: Arc<UdpFlowTable<UdpFlowKey, UdpFlowRoute>>,
    up_bucket: TokenBucket,
    down_bucket: TokenBucket,
    idle: Duration,
    name: String,
}

/// Data-plane loop for a local UDP forward.
///
/// Outbound (`socket` → QUIC): each datagram is admitted against the pps /
/// datagram-size / max-flows / byte-rate limits, then sent with a 4-byte
/// big-endian `flow_id` prefix. Crucially, every *distinct* client source
/// address gets its *own* `flow_id` (allocated lazily and announced with a
/// [`Ssh3FrameKind::UdpAssociate`] frame), so return datagrams are demultiplexed
/// per-client and never cross-talk (MED-4).
///
/// Inbound (QUIC → `socket`): handled by the per-client reply pumps spawned in
/// [`spawn_udp_reply_pump`]; the session demux routes each reply into the
/// originating client's channel by `flow_id`.
async fn local_udp_pump(
    pump: LocalUdpPump,
    mut close_rx: oneshot::Receiver<()>,
    state_tx: watch::Sender<ForwardState>,
) {
    let LocalUdpPump {
        conn,
        state,
        control_send,
        next_flow_id,
        socket,
        target,
        flow_table,
        up_bucket,
        down_bucket,
        idle,
        name,
    } = pump;

    let flow_table_evict = flow_table.clone();
    let name_e = name.clone();

    let outbound = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(target: "spt_ssh3::forward", error = %e, "udp recv_from failed");
                    return;
                }
            };
            // packets-per-second cap.
            if !flow_table.admit_packet() {
                warn!(target: "spt_ssh3::forward", forward = %name, ?peer, "udp max_packets_per_second reached — dropping datagram");
                continue;
            }
            // max_datagram_size reject (oversized dropped + counted).
            if !flow_table.admit_size(n) {
                warn!(target: "spt_ssh3::forward", forward = %name, ?peer, bytes = n, "udp datagram exceeds max_datagram_size — dropping");
                continue;
            }
            // Resolve (or lazily create) this client's flow. `touch_or_insert`
            // bumps last_seen for an existing flow and atomically inserts a new
            // one under the `max_flows` cap — so concurrent clients cannot
            // overshoot it. On insert we allocate a fresh per-client `flow_id`,
            // register its reply channel + pump, and remember (via `created`)
            // that we must announce it below.
            let mut created: Option<u32> = None;
            let admitted = flow_table.touch_or_insert(peer, || {
                let fid = next_flow_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (tx, rx) = mpsc::channel::<Bytes>(UDP_INBOUND_CHANNEL_CAP);
                state.udp_flows.insert(fid, tx);
                let pump = spawn_udp_reply_pump(rx, socket.clone(), peer, down_bucket.clone());
                created = Some(fid);
                UdpFlowRoute {
                    flow_id: fid,
                    state: state.clone(),
                    pump,
                }
            });
            if !admitted {
                warn!(target: "spt_ssh3::forward", forward = %name, ?peer, "udp max_flows reached — dropping datagram");
                continue;
            }
            let flow_id = if let Some(fid) = created {
                // New client flow: announce the association so the peer opens a
                // dedicated per-client mapping toward the target.
                let assoc = Ssh3Frame::new(
                    Ssh3FrameKind::UdpAssociate,
                    UdpAssociatePayload {
                        flow_id: fid,
                        host: target.host.clone(),
                        port: target.port,
                    }
                    .encode(),
                );
                let mut g = control_send.lock().await;
                if let Err(e) = assoc.write_async(&mut *g).await {
                    warn!(target: "spt_ssh3::forward", error = %e, ?peer, "udp associate write failed");
                }
                drop(g);
                fid
            } else {
                // Existing flow: read back its flow_id. (A concurrent eviction
                // between the touch and this read is possible but improbable —
                // we just bumped last_seen; if it did happen, drop the datagram.)
                let mut fid = None;
                flow_table.with_value(&peer, |r: &UdpFlowRoute| fid = Some(r.flow_id));
                let Some(fid) = fid else {
                    continue;
                };
                fid
            };
            // Byte-rate (up): drop when over rate (UDP is lossy — never block
            // the datagram pump).
            if up_bucket.is_active() && up_bucket.try_acquire(n as u64).is_some() {
                debug!(target: "spt_ssh3::forward", forward = %name, ?peer, "udp up byte-rate cap — dropping datagram");
                continue;
            }
            let mut payload = Vec::with_capacity(4 + n);
            payload.extend_from_slice(&flow_id.to_be_bytes());
            payload.extend_from_slice(&buf[..n]);
            if let Err(e) = conn.send_datagram(Bytes::from(payload)) {
                warn!(target: "spt_ssh3::forward", error = %e, "udp send_datagram failed");
            }
        }
    };

    // Idle-flow evictor: prune per-client flows quiescent for `idle`. Dropping
    // an evicted `UdpFlowRoute` value tears down its channel + reply pump.
    let evict = async move {
        let mut ticker = tokio::time::interval(idle.max(Duration::from_secs(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let n = flow_table_evict.evict_idle();
            if n > 0 {
                debug!(target: "spt_ssh3::forward", forward = %name_e, evicted = n, "udp idle flows evicted");
            }
        }
    };

    #[allow(clippy::ignored_unit_patterns)]
    {
        tokio::select! {
            _ = &mut close_rx => {}
            _ = outbound => {}
            _ = evict => {}
        }
    }
    // Dropping `flow_table` here drops every `UdpFlowRoute`, which unregisters
    // each flow-id from `state.udp_flows` and aborts its reply pump.
    debug!(target: "spt_ssh3::forward", forward = %name, "udp forward stopped");
    let _ = state_tx.send(ForwardState::Stopped);
}

/// Open a UDP forward.
///
/// Binds a local `UdpSocket` and bridges it to the QUIC datagram channel. Each
/// datagram is prefixed with a 4-byte big-endian `flow_id`; every distinct local
/// client source address is assigned its *own* `flow_id` (announced with a
/// [`Ssh3FrameKind::UdpAssociate`] frame) so replies are demultiplexed back to
/// the client that originated the flow (MED-4) and concurrent clients never
/// receive each other's traffic.
pub async fn open_udp(
    conn: Connection,
    state: Arc<SessionState>,
    control_send: Arc<AsyncMutex<SendStream>>,
    next_flow_id: Arc<std::sync::atomic::AtomicU32>,
    spec: &UdpForwardSpec,
    peer_supports_udp: bool,
) -> Result<ForwardHandle> {
    if !peer_supports_udp {
        return Err(Error::UnsupportedPlatform(
            "ssh3 peer does not advertise udp_datagrams capability".into(),
        ));
    }
    if spec.direction == ForwardDirection::Remote {
        return open_remote_udp(conn, state, control_send, next_flow_id, spec).await;
    }
    if conn.max_datagram_size().is_none() {
        return Err(Error::UnsupportedPlatform(
            "ssh3 QUIC peer disabled datagrams (negotiated)".into(),
        ));
    }

    let bind = bind_addr_string(&spec.listen)?;
    let socket = UdpSocket::bind(&bind)
        .await
        .map_err(|e| Error::LocalBindFailed {
            address: bind.clone(),
            reason: e.to_string(),
        })?;

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();

    // M-W3: enforce the full UDP per-forward limit surface. `flow_table` bounds
    // concurrent client-source flows (config `max_flows`, NOT the old hard-coded
    // 1024), the packets-per-second gate (`max_packets_per_sec`), and the
    // max-datagram-size drop; the token buckets throttle byte-rate per
    // direction; idle flows are evicted at the configured idle cadence.
    let flow_cfg = udp_flow_config(spec);
    let idle = flow_cfg.idle_timeout;
    let flow_table: Arc<UdpFlowTable<UdpFlowKey, UdpFlowRoute>> = Arc::new(UdpFlowTable::with_pps(
        flow_cfg,
        spec.limits.max_packets_per_sec,
    ));
    let (up_bucket, down_bucket) = forward_buckets(&spec.limits);

    info!(
        target: "spt_ssh3::forward",
        forward = %name,
        listen = %bind,
        target = %format!("{}:{}", spec.target.host, spec.target.port),
        max_flows = flow_cfg.max_flows,
        max_packets_per_sec = spec.limits.max_packets_per_sec,
        idle_secs = idle.as_secs(),
        "ssh3 udp forward opened"
    );

    let pump = LocalUdpPump {
        conn,
        state,
        control_send,
        next_flow_id,
        socket: Arc::new(socket),
        target: spec.target.clone(),
        flow_table,
        up_bucket,
        down_bucket,
        idle,
        name: name.clone(),
    };
    tokio::spawn(local_udp_pump(pump, close_rx, state_tx));

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

/// Serve a peer-opened *keepalive* stream (F-R2): the peer opened a dedicated
/// bidi whose first frame is an [`Ssh3FrameKind::AppPing`]. We echo that ping
/// and every subsequent ping straight back so the peer's keepalive reader can
/// confirm our application layer is still draining streams — not merely that
/// QUIC is up. Runs until the stream is reset / closed or a write fails.
async fn serve_keepalive_stream(mut send: SendStream, mut recv: RecvStream, first: Ssh3Frame) {
    if first.write_async(&mut send).await.is_err() {
        return;
    }
    loop {
        match Ssh3Frame::read_async(&mut recv).await {
            Ok(frame) => {
                if frame.write_async(&mut send).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Send a `ForwardOpenResponse { ok: false, reason }` and half-close `send`.
async fn reject_inbound(mut send: SendStream, reason: &str) {
    let _ = Ssh3Frame::new(
        Ssh3FrameKind::ForwardOpenResponse,
        ForwardOpenResponse {
            ok: false,
            reason: reason.to_string(),
        }
        .encode(),
    )
    .write_async(&mut send)
    .await;
    let _ = send.finish();
}

/// Dispatch one inbound bidi stream from the peer.
///
/// Reads the channel-open frame, looks up a matching remote-forward, **dials the
/// local target**, and only on a successful dial sends `ok:true` and hands the
/// connected forward off (E3-F8). On capacity-exhaustion, no-match, dial
/// failure, or any protocol error it sends `ok:false` with a reason and drops
/// the stream. A `max_forwards` permit (E3-F3) is acquired before the dial and
/// held for the lifetime of the bridged connection; if no permit is available
/// the open is rejected immediately rather than queued.
pub(crate) async fn dispatch_inbound_bidi(
    state: Arc<SessionState>,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    let frame = match Ssh3Frame::read_async(&mut recv).await {
        Ok(f) => f,
        Err(e) => {
            warn!(target: "spt_ssh3::forward", error = %e, "inbound bidi: read open frame failed");
            return;
        }
    };
    // F-R2: a peer-opened keepalive stream — echo pings so the peer can verify
    // our application layer is live (not just the QUIC transport).
    if frame.kind == Ssh3FrameKind::AppPing {
        serve_keepalive_stream(send, recv, frame).await;
        return;
    }
    // A peer-opened bidi carrying a UDS forward back-channel (remote-UDS:
    // the *server* accepted a connection on its remote unix listener and is
    // opening a stream back to us, the requester, to be bridged to our local
    // unix socket). `cfg(unix)` only — the path is meaningless on Windows.
    if frame.kind == Ssh3FrameKind::UdsForwardRequest {
        dispatch_inbound_uds(state, send, recv, frame.payload).await;
        return;
    }
    if frame.kind != Ssh3FrameKind::DirectTcpRequest {
        warn!(
            target: "spt_ssh3::forward",
            kind = ?frame.kind,
            "inbound bidi: unexpected first frame"
        );
        reject_inbound(send, "unexpected open frame").await;
        return;
    }
    let open = match ChannelOpenPayload::decode(frame.payload) {
        Ok(o) => o,
        Err(e) => {
            warn!(target: "spt_ssh3::forward", error = %e, "inbound bidi: bad open payload");
            return;
        }
    };

    let key = (open.host.clone(), open.port);
    let (target, tx, conn_gate, limits, idle_timeout) = {
        let Some(entry) = state.remote_forwards.get(&key) else {
            debug!(
                target: "spt_ssh3::forward",
                host = %open.host, port = open.port,
                "inbound bidi: no matching remote forward — rejecting"
            );
            reject_inbound(send, "no remote forward registered for that bind").await;
            return;
        };
        (
            entry.target.clone(),
            entry.tx.clone(),
            entry.conn_gate.clone(),
            entry.limits,
            entry.idle_timeout,
        )
    };

    // E3-F3: bound concurrent inbound forwards by the negotiated `max_forwards`
    // cap. `try_acquire_owned` fails immediately when at capacity so a flood of
    // opens is rejected (not queued, which would itself be an unbounded buffer).
    let Ok(permit) = state.inbound_forward_limit.clone().try_acquire_owned() else {
        warn!(
            target: "spt_ssh3::forward",
            host = %open.host, port = open.port,
            "inbound bidi: max_forwards reached — rejecting"
        );
        reject_inbound(send, "max_forwards reached").await;
        return;
    };
    // M-W3: additionally enforce the per-forward CONFIG `max_connections`
    // (effective cap = min of this and the negotiated `max_forwards` above).
    // `None`/`0` ⇒ unlimited gate that always yields a permit.
    let conn_permit = if conn_gate.cap() == 0 {
        None
    } else {
        match conn_gate.try_acquire() {
            Some(p) => Some(p),
            None => {
                warn!(
                    target: "spt_ssh3::forward",
                    host = %open.host, port = open.port, cap = conn_gate.cap(),
                    "inbound bidi: max_connections reached — rejecting"
                );
                reject_inbound(send, "max_connections reached").await;
                return;
            }
        }
    };

    // E3-F8: dial the local target *before* ACKing so the peer never sees a
    // success for a forward whose downstream is unreachable.
    let local = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(s) => s,
        Err(e) => {
            debug!(
                target: "spt_ssh3::forward",
                target = %format!("{}:{}", target.host, target.port),
                error = %e,
                "inbound bidi: local dial failed — rejecting"
            );
            reject_inbound(send, &format!("local dial failed: {e}")).await;
            return;
        }
    };

    if Ssh3Frame::new(
        Ssh3FrameKind::ForwardOpenResponse,
        ForwardOpenResponse {
            ok: true,
            reason: String::new(),
        }
        .encode(),
    )
    .write_async(&mut send)
    .await
    .is_err()
    {
        return;
    }
    let _ = tx.send(InboundForward {
        send,
        recv,
        local,
        _permit: permit,
        _conn_permit: conn_permit,
        limits,
        idle_timeout,
    });
}

/// Dispatch one inbound bidi stream the peer opened as a UDS forward
/// back-channel (remote-UDS: the server accepted a connection on its remote
/// unix listener and is bridging it back to our local unix socket).
///
/// Looks up the remote-UDS forward by the `remote bind path` the peer echoes in
/// the [`UdsChannelOpenPayload`], `UnixStream::connect`s the registered local
/// path, ACKs `ok:true` on success, and bridges the QUIC stream against the
/// local socket. On no-match / dial failure it rejects with `ok:false`.
#[cfg(unix)]
async fn dispatch_inbound_uds(
    state: Arc<SessionState>,
    mut send: SendStream,
    mut recv: RecvStream,
    payload: Bytes,
) {
    let open = match UdsChannelOpenPayload::decode(payload) {
        Ok(o) => o,
        Err(e) => {
            warn!(target: "spt_ssh3::forward", error = %e, "inbound uds: bad open payload");
            return;
        }
    };
    let Some(entry) = state.remote_uds_forwards.get(&open.path) else {
        debug!(
            target: "spt_ssh3::forward",
            path = %open.path,
            "inbound uds: no matching remote-uds forward — rejecting"
        );
        reject_inbound(send, "no remote-uds forward registered for that path").await;
        return;
    };
    let local_path = entry.local_path.clone();
    drop(entry);

    let Ok(permit) = state.inbound_forward_limit.clone().try_acquire_owned() else {
        warn!(target: "spt_ssh3::forward", path = %open.path, "inbound uds: max_forwards reached — rejecting");
        reject_inbound(send, "max_forwards reached").await;
        return;
    };

    let mut local = match tokio::net::UnixStream::connect(&local_path).await {
        Ok(s) => s,
        Err(e) => {
            debug!(
                target: "spt_ssh3::forward",
                path = %local_path.display(), error = %e,
                "inbound uds: local dial failed — rejecting"
            );
            reject_inbound(send, &format!("local uds dial failed: {e}")).await;
            return;
        }
    };

    if Ssh3Frame::new(
        Ssh3FrameKind::ForwardOpenResponse,
        ForwardOpenResponse {
            ok: true,
            reason: String::new(),
        }
        .encode(),
    )
    .write_async(&mut send)
    .await
    .is_err()
    {
        return;
    }

    // Bridge the QUIC stream (remote→client) against the local unix socket.
    let _permit = permit;
    let (mut sr, mut sw) = local.split();
    let to_local = async {
        let _ = tokio::io::copy(&mut recv, &mut sw).await;
        let _ = sw.shutdown().await;
    };
    let from_local = async {
        let _ = tokio::io::copy(&mut sr, &mut send).await;
        let _ = send.finish();
    };
    tokio::join!(to_local, from_local);
}

#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn dispatch_inbound_uds(
    _state: Arc<SessionState>,
    send: SendStream,
    _recv: RecvStream,
    _payload: Bytes,
) {
    // UDS forwarding is Unix-only; a peer should never open a UDS back-channel
    // to a Windows requester (we never advertise/register one), but reject
    // defensively rather than leak the stream.
    reject_inbound(send, "uds forwards are not supported on this platform").await;
}

/// Open a `local_uds` forward (`cfg(unix)`): bind a client-side
/// [`tokio::net::UnixListener`] on `spec.listen_path` and, for each accepted
/// connection, open a fresh bidi QUIC stream carrying a
/// [`Ssh3FrameKind::UdsForwardRequest`] frame whose payload is the *remote*
/// unix socket path; the peer `UnixStream::connect`s it and the two are bridged.
///
/// Mirrors the russh `open_uds` contract (`russh_backend.rs:2509`). On
/// `cfg(not(unix))` returns [`Error::UnsupportedPlatform`] (binding `AF_UNIX` is
/// Unix-only).
///
/// `async` is kept for signature symmetry with the non-unix stub and the trait
/// method (`tokio::net::UnixListener::bind` is itself synchronous, so the body
/// has no `await`).
#[cfg(unix)]
#[allow(clippy::unused_async)]
pub async fn open_uds(
    conn: Connection,
    spec: &spt_protocol::forward::UdsForwardSpec,
) -> Result<ForwardHandle> {
    let listen_path = spec.listen_path.clone();
    unlink_existing_socket(&listen_path);
    let listener =
        tokio::net::UnixListener::bind(&listen_path).map_err(|e| Error::LocalBindFailed {
            address: listen_path.display().to_string(),
            reason: e.to_string(),
        })?;

    let (state_tx, state_rx) = watch::channel(ForwardState::Listening);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    let remote_path = spec.remote_socket_path.clone();

    tokio::spawn(uds_local_loop(
        conn,
        listener,
        remote_path,
        state_tx,
        close_rx,
        name.clone(),
    ));

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

/// `cfg(not(unix))` stub for [`open_uds`]: binding an `AF_UNIX` listener is
/// Unix-only, so this surfaces [`Error::UnsupportedPlatform`] (mirrors russh).
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
pub async fn open_uds(
    _conn: Connection,
    _spec: &spt_protocol::forward::UdsForwardSpec,
) -> Result<ForwardHandle> {
    Err(Error::UnsupportedPlatform(
        "ssh3 local UNIX-socket forward requires a Unix target: binding an \
         AF_UNIX listener is not supported on this platform"
            .into(),
    ))
}

/// Best-effort: remove a stale socket file left by an unclean shutdown so the
/// bind does not spuriously fail with `AddrInUse`. Only unlinks paths that are
/// actually sockets.
#[cfg(unix)]
fn unlink_existing_socket(path: &std::path::Path) {
    use std::os::unix::fs::FileTypeExt;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_socket() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
async fn uds_local_loop(
    conn: Connection,
    listener: tokio::net::UnixListener,
    remote_path: String,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    name: String,
) {
    let _ = state_tx.send(ForwardState::Active);
    loop {
        tokio::select! {
            _ = &mut close_rx => {
                debug!(target: "spt_ssh3::forward", forward = %name, "local uds forward shutdown signal");
                break;
            }
            accept = listener.accept() => {
                let (sock, _addr) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        error!(target: "spt_ssh3::forward", forward = %name, error = %e, "uds accept failed");
                        continue;
                    }
                };
                let conn = conn.clone();
                let remote_path = remote_path.clone();
                let name_t = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_local_uds(conn, sock, &remote_path).await {
                        warn!(target: "spt_ssh3::forward", forward = %name_t, error = %e, "local uds conn failed");
                    }
                });
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
}

/// Bridge one accepted local `UnixStream` onto a fresh UDS channel to
/// `remote_path` on the peer.
#[cfg(unix)]
async fn bridge_local_uds(
    conn: Connection,
    mut sock: tokio::net::UnixStream,
    remote_path: &str,
) -> Result<()> {
    let (mut send, mut recv) = open_uds_channel(&conn, remote_path).await?;
    let (mut sock_r, mut sock_w) = sock.split();
    let to_peer = async {
        let n = tokio::io::copy(&mut sock_r, &mut send).await;
        let _ = send.finish();
        n
    };
    let from_peer = async {
        let n = tokio::io::copy(&mut recv, &mut sock_w).await;
        let _ = sock_w.shutdown().await;
        n
    };
    let (a, b) = tokio::join!(to_peer, from_peer);
    a.map_err(|e| Error::RuntimeFailure(format!("ssh3 local-uds→peer copy: {e}")))?;
    b.map_err(|e| Error::RuntimeFailure(format!("ssh3 peer→local-uds copy: {e}")))?;
    Ok(())
}

/// Open a UDS channel-open exchange on a fresh bidi stream (the UDS analogue of
/// [`open_channel`]): write a [`Ssh3FrameKind::UdsForwardRequest`] frame
/// carrying `path` and await the peer's [`Ssh3FrameKind::ForwardOpenResponse`].
#[cfg(unix)]
async fn open_uds_channel(conn: &Connection, path: &str) -> Result<(SendStream, RecvStream)> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 open_bi (uds): {e}")))?;
    let req = Ssh3Frame::new(
        Ssh3FrameKind::UdsForwardRequest,
        UdsChannelOpenPayload {
            path: path.to_string(),
        }
        .encode(),
    );
    req.write_async(&mut send).await?;

    let resp = tokio::time::timeout(OPEN_TIMEOUT, Ssh3Frame::read_async(&mut recv))
        .await
        .map_err(|_| {
            Error::RuntimeFailure("ssh3 uds channel-open: timeout waiting for response".into())
        })??;
    if resp.kind != Ssh3FrameKind::ForwardOpenResponse {
        return Err(Error::RuntimeFailure(format!(
            "ssh3 uds channel-open: expected ForwardOpenResponse, got {:?}",
            resp.kind
        )));
    }
    let parsed = ForwardOpenResponse::decode(resp.payload)?;
    if !parsed.ok {
        return Err(Error::NetworkUnreachable(format!(
            "ssh3 uds channel-open rejected by peer: {}",
            parsed.reason
        )));
    }
    Ok((send, recv))
}

/// Open a `remote_uds` forward (`cfg(unix)`): ask the peer (via a
/// [`Ssh3FrameKind::RemoteUdsForwardRequest`] control frame) to bind a unix
/// listener on `spec.remote_socket_path`, register an inbound entry so the peer
/// can back-channel each accepted connection as a
/// [`Ssh3FrameKind::UdsForwardRequest`] bidi (handled by
/// [`dispatch_inbound_uds`]), and bridge each back-channel to a local
/// `UnixStream::connect(spec.local_socket_path)`.
///
/// Mirrors the russh `open_remote_uds` contract (`russh_backend.rs:2633`). On
/// `cfg(not(unix))` returns [`Error::UnsupportedPlatform`].
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub async fn open_remote_uds(
    state: Arc<SessionState>,
    control_send: Arc<AsyncMutex<SendStream>>,
    control_recv: Arc<AsyncMutex<RecvStream>>,
    control_request: Arc<AsyncMutex<()>>,
    spec: &spt_protocol::forward::RemoteUdsForwardSpec,
    peer_supports_remote: bool,
) -> Result<ForwardHandle> {
    if !peer_supports_remote {
        return Err(Error::UnsupportedPlatform(
            "ssh3 peer does not advertise remote_tcp capability (required for remote-uds)".into(),
        ));
    }
    let remote_path = spec.remote_socket_path.clone();

    // E3-F5: serialize the control-stream request/response exchange.
    let _ctl_guard = control_request.lock().await;

    // Register the inbound dispatch entry *before* sending the request so a
    // peer that races to open back-channels the moment it ACKs is not lost.
    state.remote_uds_forwards.insert(
        remote_path.clone(),
        RemoteUdsEntry {
            local_path: spec.local_socket_path.clone(),
        },
    );

    let req = Ssh3Frame::new(
        Ssh3FrameKind::RemoteUdsForwardRequest,
        UdsChannelOpenPayload {
            path: remote_path.clone(),
        }
        .encode(),
    );
    let send_result = async {
        let mut g = control_send.lock().await;
        req.write_async(&mut *g).await
    }
    .await;
    if let Err(e) = send_result {
        state.remote_uds_forwards.remove(&remote_path);
        return Err(e);
    }
    let resp = {
        let mut g = control_recv.lock().await;
        tokio::time::timeout(OPEN_TIMEOUT, Ssh3Frame::read_async(&mut *g))
            .await
            .map_err(|_| Error::RuntimeFailure("ssh3 remote-uds: timeout".into()))?
    };
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            state.remote_uds_forwards.remove(&remote_path);
            return Err(e);
        }
    };
    if resp.kind != Ssh3FrameKind::ForwardOpenResponse {
        state.remote_uds_forwards.remove(&remote_path);
        return Err(Error::RuntimeFailure(format!(
            "ssh3 remote-uds: unexpected kind {:?}",
            resp.kind
        )));
    }
    let parsed = ForwardOpenResponse::decode(resp.payload)?;
    if !parsed.ok {
        state.remote_uds_forwards.remove(&remote_path);
        return Err(Error::RemoteBindFailed {
            address: remote_path,
            reason: parsed.reason,
        });
    }

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();

    tokio::spawn(remote_uds_loop(
        state.clone(),
        close_rx,
        state_tx,
        name.clone(),
        remote_path,
    ));

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

/// `cfg(not(unix))` stub for [`open_remote_uds`]: connecting an `AF_UNIX` socket
/// is Unix-only, so this surfaces [`Error::UnsupportedPlatform`] (mirrors
/// russh).
#[cfg(not(unix))]
#[allow(clippy::unused_async, clippy::too_many_arguments)]
pub async fn open_remote_uds(
    _state: Arc<SessionState>,
    _control_send: Arc<AsyncMutex<SendStream>>,
    _control_recv: Arc<AsyncMutex<RecvStream>>,
    _control_request: Arc<AsyncMutex<()>>,
    _spec: &spt_protocol::forward::RemoteUdsForwardSpec,
    _peer_supports_remote: bool,
) -> Result<ForwardHandle> {
    Err(Error::UnsupportedPlatform(
        "ssh3 remote UNIX-socket forward requires a Unix target: bridging \
         inbound UDS channels to a local AF_UNIX socket is not supported on this platform"
            .into(),
    ))
}

/// Lifecycle loop for a `remote_uds` forward: holds the inbound registration
/// alive until close, then deregisters it. The actual per-connection bridging
/// happens in [`dispatch_inbound_uds`] (driven by the session's inbound-bidi
/// accept loop), exactly as remote-TCP bridging happens in the inbound
/// dispatcher rather than this loop.
#[cfg(unix)]
async fn remote_uds_loop(
    state: Arc<SessionState>,
    close_rx: oneshot::Receiver<()>,
    state_tx: watch::Sender<ForwardState>,
    name: String,
    remote_path: String,
) {
    let _ = close_rx.await;
    debug!(target: "spt_ssh3::forward", forward = %name, "remote uds forward shutdown signal");
    state.remote_uds_forwards.remove(&remote_path);
    let _ = state_tx.send(ForwardState::Stopped);
}

/// Server-side helper (`cfg(unix)`): drain inbound `UdsForwardRequest` opens on
/// freshly-accepted bidi streams that are *local-uds* opens (client → server,
/// the server `UnixStream::connect`s the requested path) and bridge them.
///
/// This is the UDS analogue of [`serve_local_tcp_acceptor`]; the
/// [`crate::server::Ssh3Server`] dispatches inbound bidis by their first frame
/// kind, routing `UdsForwardRequest` here.
#[cfg(unix)]
pub async fn serve_local_uds_open(mut send: SendStream, mut recv: RecvStream, payload: Bytes) {
    let open = match UdsChannelOpenPayload::decode(payload) {
        Ok(o) => o,
        Err(e) => {
            warn!(target: "spt_ssh3::forward", error = %e, "server uds: bad open payload");
            return;
        }
    };
    let mut sock = match tokio::net::UnixStream::connect(&open.path).await {
        Ok(s) => s,
        Err(e) => {
            let _ = Ssh3Frame::new(
                Ssh3FrameKind::ForwardOpenResponse,
                ForwardOpenResponse {
                    ok: false,
                    reason: format!("uds dial {}: {e}", open.path),
                }
                .encode(),
            )
            .write_async(&mut send)
            .await;
            return;
        }
    };
    if Ssh3Frame::new(
        Ssh3FrameKind::ForwardOpenResponse,
        ForwardOpenResponse {
            ok: true,
            reason: String::new(),
        }
        .encode(),
    )
    .write_async(&mut send)
    .await
    .is_err()
    {
        return;
    }
    let (mut sr, mut sw) = sock.split();
    let a = async {
        let _ = tokio::io::copy(&mut recv, &mut sw).await;
        let _ = sw.shutdown().await;
    };
    let b = async {
        let _ = tokio::io::copy(&mut sr, &mut send).await;
        let _ = send.finish();
    };
    tokio::join!(a, b);
}

/// Server-side helper (`cfg(unix)`): handle a client's
/// [`Ssh3FrameKind::RemoteUdsForwardRequest`] control frame by binding a unix
/// listener on the requested path and opening one
/// [`Ssh3FrameKind::UdsForwardRequest`] back-channel toward the client per
/// accepted connection. ACKs the request (`ok:true`/`ok:false`) on
/// `control_send`.
///
/// `bind_path` is the remote path the client asked the server to listen on;
/// it is also the key the back-channel echoes so the client can map the
/// inbound stream to its local socket. The listener runs until `conn` closes.
#[cfg(unix)]
pub async fn serve_remote_uds_request(
    conn: Connection,
    control_send: Arc<AsyncMutex<SendStream>>,
    bind_path: String,
    // Held for the listener's lifetime so the `inbound_forward_limit` cap
    // reflects this live remote-UDS forward (M5); released on return.
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    unlink_existing_socket(std::path::Path::new(&bind_path));
    let listener = match tokio::net::UnixListener::bind(&bind_path) {
        Ok(l) => l,
        Err(e) => {
            let _ = async {
                let mut g = control_send.lock().await;
                Ssh3Frame::new(
                    Ssh3FrameKind::ForwardOpenResponse,
                    ForwardOpenResponse {
                        ok: false,
                        reason: format!("remote-uds bind {bind_path}: {e}"),
                    }
                    .encode(),
                )
                .write_async(&mut *g)
                .await
            }
            .await;
            return;
        }
    };
    // ACK success on the control stream.
    if async {
        let mut g = control_send.lock().await;
        Ssh3Frame::new(
            Ssh3FrameKind::ForwardOpenResponse,
            ForwardOpenResponse {
                ok: true,
                reason: String::new(),
            }
            .encode(),
        )
        .write_async(&mut *g)
        .await
    }
    .await
    .is_err()
    {
        return;
    }

    loop {
        let (sock, _addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!(target: "spt_ssh3::forward", error = %e, "server remote-uds accept ended");
                break;
            }
        };
        let conn = conn.clone();
        let bind_path = bind_path.clone();
        tokio::spawn(async move {
            if let Err(e) = bridge_server_remote_uds(conn, sock, &bind_path).await {
                warn!(target: "spt_ssh3::forward", error = %e, "server remote-uds bridge failed");
            }
        });
    }
}

/// Bridge one server-accepted `UnixStream` back to the client over a fresh bidi
/// UDS back-channel keyed by `bind_path`.
#[cfg(unix)]
async fn bridge_server_remote_uds(
    conn: Connection,
    mut sock: tokio::net::UnixStream,
    bind_path: &str,
) -> Result<()> {
    // The back-channel echoes the *remote bind path* so the client's inbound
    // dispatcher can map it to the registered local socket path.
    let (mut send, mut recv) = open_uds_channel(&conn, bind_path).await?;
    let (mut sr, mut sw) = sock.split();
    let to_client = async {
        let n = tokio::io::copy(&mut sr, &mut send).await;
        let _ = send.finish();
        n
    };
    let from_client = async {
        let n = tokio::io::copy(&mut recv, &mut sw).await;
        let _ = sw.shutdown().await;
        n
    };
    let (a, b) = tokio::join!(to_client, from_client);
    a.map_err(|e| Error::RuntimeFailure(format!("ssh3 server-uds→client copy: {e}")))?;
    b.map_err(|e| Error::RuntimeFailure(format!("ssh3 client→server-uds copy: {e}")))?;
    Ok(())
}

/// Server-side helper: accept inbound bidi streams that are local-tcp opens
/// (initiator → peer) and bridge to a local TCP target. Used by the test
/// harness "fake server" — and would be the entry point for an spt instance
/// running as the server end of an SSH3 tunnel.
pub async fn serve_local_tcp_acceptor(
    conn: Connection,
    target_resolver: impl Fn(&ChannelOpenPayload) -> Option<TargetAddr> + Send + Sync + 'static,
) {
    let resolver = Arc::new(target_resolver);
    loop {
        let Ok((send, mut recv)) = conn.accept_bi().await else {
            break;
        };
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let Ok(frame) = Ssh3Frame::read_async(&mut recv).await else {
                return;
            };
            if frame.kind != Ssh3FrameKind::DirectTcpRequest {
                return;
            }
            serve_tcp_open(send, recv, frame.payload, &*resolver).await;
        });
    }
}

/// Server-side acceptor that handles BOTH local-TCP (`DirectTcpRequest`) and,
/// on `cfg(unix)`, local-UDS (`UdsForwardRequest`) inbound bidi opens by
/// reading the first frame and routing accordingly. TCP opens resolve their
/// target via `target_resolver`; UDS opens `UnixStream::connect` the path the
/// client supplied (path-based ACL is the caller's responsibility — the server
/// only dials paths the client sent).
///
/// This is the superset of [`serve_local_tcp_acceptor`] the
/// [`crate::server::Ssh3Server`] uses so a single accept loop serves both
/// forward kinds.
pub async fn serve_inbound_opens(
    conn: Connection,
    target_resolver: impl Fn(&ChannelOpenPayload) -> Option<TargetAddr> + Send + Sync + 'static,
) {
    let resolver = Arc::new(target_resolver);
    loop {
        let Ok((send, mut recv)) = conn.accept_bi().await else {
            break;
        };
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let Ok(frame) = Ssh3Frame::read_async(&mut recv).await else {
                return;
            };
            match frame.kind {
                Ssh3FrameKind::DirectTcpRequest => {
                    serve_tcp_open(send, recv, frame.payload, &*resolver).await;
                }
                #[cfg(unix)]
                Ssh3FrameKind::UdsForwardRequest => {
                    serve_local_uds_open(send, recv, frame.payload).await;
                }
                // F-R2: echo keepalive pings so the client's liveness reader
                // sees our application layer is still draining streams.
                Ssh3FrameKind::AppPing => {
                    serve_keepalive_stream(send, recv, frame).await;
                }
                _ => {
                    reject_inbound(send, "unexpected open frame").await;
                }
            }
        });
    }
}

/// Serve one already-read local-TCP open frame: resolve the target, dial it,
/// and bridge. Shared by [`serve_inbound_opens`] and
/// [`serve_local_tcp_acceptor`].
async fn serve_tcp_open(
    mut send: SendStream,
    mut recv: RecvStream,
    payload: Bytes,
    resolver: &(impl Fn(&ChannelOpenPayload) -> Option<TargetAddr> + Send + Sync),
) {
    let Ok(open) = ChannelOpenPayload::decode(payload) else {
        return;
    };
    let Some(target) = resolver(&open) else {
        reject_inbound(send, "denied by acl").await;
        return;
    };
    let mut sock = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(s) => s,
        Err(e) => {
            reject_inbound(send, &format!("dial: {e}")).await;
            return;
        }
    };
    if Ssh3Frame::new(
        Ssh3FrameKind::ForwardOpenResponse,
        ForwardOpenResponse {
            ok: true,
            reason: String::new(),
        }
        .encode(),
    )
    .write_async(&mut send)
    .await
    .is_err()
    {
        return;
    }
    let (mut sr, mut sw) = sock.split();
    let a = async {
        let _ = tokio::io::copy(&mut recv, &mut sw).await;
        let _ = sw.shutdown().await;
    };
    let b = async {
        let _ = tokio::io::copy(&mut sr, &mut send).await;
        let _ = send.finish();
    };
    tokio::join!(a, b);
}

/// Pull a one-shot ack frame off `recv` (used after writing a control frame
/// and waiting for `ForwardOpenResponse`). Public for test harness use.
pub async fn read_one_frame(recv: &mut RecvStream) -> Result<Ssh3Frame> {
    Ssh3Frame::read_async(recv).await
}

/// Open a remote UDP forward.
///
/// Symmetric to [`open_udp`] for the local case. The flow:
///
/// 1. Allocate a fresh `flow_id`.
/// 2. Send a [`Ssh3FrameKind::RemoteUdpForwardRequest`] frame on the control
///    stream carrying `(flow_id, bind_host, bind_port)`.
/// 3. (The peer's control-stream reader — see
///    [`serve_remote_udp_forwards`] — binds a UDP socket on `bind` and
///    starts proxying inbound datagrams as `[u32_be flow_id][bytes]` QUIC
///    datagrams toward us.)
/// 4. Local datagram dispatch (`session.rs::read_datagram` loop) routes
///    incoming traffic by `flow_id` into our `state.udp_flows` map; we
///    forward each payload to `spec.target` over a fresh local
///    [`UdpSocket`] and reflect any reply back over QUIC.
async fn open_remote_udp(
    conn: Connection,
    state: Arc<SessionState>,
    control_send: Arc<AsyncMutex<SendStream>>,
    next_flow_id: Arc<std::sync::atomic::AtomicU32>,
    spec: &UdpForwardSpec,
) -> Result<ForwardHandle> {
    if conn.max_datagram_size().is_none() {
        return Err(Error::UnsupportedPlatform(
            "ssh3 QUIC peer disabled datagrams (negotiated)".into(),
        ));
    }
    let (bind_host, bind_port) = bind_host_port(&spec.listen)?;
    let flow_id = next_flow_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let req = Ssh3Frame::new(
        Ssh3FrameKind::RemoteUdpForwardRequest,
        UdpAssociatePayload {
            flow_id,
            host: bind_host.clone(),
            port: bind_port,
        }
        .encode(),
    );
    {
        let mut g = control_send.lock().await;
        req.write_async(&mut *g).await?;
    }

    // Register flow demux entry so any datagrams the peer races to deliver
    // before our response arrives aren't dropped.
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Bytes>(UDP_INBOUND_CHANNEL_CAP);
    state.udp_flows.insert(flow_id, inbound_tx);

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, mut close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    let target = spec.target.clone();
    let state_clone = state.clone();
    let inflight = state.remote_udp_inflight.clone();
    let name_t = name.clone();

    // MED/LOW-5: keep ONE persistent local socket per flow (connected to the
    // target) alive for the flow's idle window and relay *every* reply datagram,
    // instead of binding a fresh socket per datagram and reading a single reply.
    // This matches normal UDP-forward semantics for multi-response / stateful
    // protocols (DNS retries, QUIC, TFTP): all replies get through and the
    // target sees a stable source port. Bounded: at most one socket + one relay
    // task per remote-UDP forward (the in-flight permit is held for the socket's
    // lifetime, not per datagram), reclaimed after `idle` with no traffic.
    let idle = udp_flow_config(spec).idle_timeout;
    tokio::spawn(async move {
        let dial_target = format!("{}:{}", target.host, target.port);
        // Lazily-(re)created persistent socket and its reply-relay task.
        let mut sock: Option<Arc<UdpSocket>> = None;
        let mut relay_task: Option<tokio::task::JoinHandle<()>> = None;
        loop {
            tokio::select! {
                _ = &mut close_rx => break,
                res = tokio::time::timeout(idle, inbound_rx.recv()) => {
                    match res {
                        // Idle window elapsed with no datagram: reclaim the
                        // socket + relay task (releases the in-flight permit).
                        Err(_) => {
                            if let Some(t) = relay_task.take() {
                                t.abort();
                            }
                            sock = None;
                        }
                        // Demux channel closed (forward dropped).
                        Ok(None) => break,
                        Ok(Some(payload)) => {
                            // (Re)establish the persistent socket + relay on the
                            // first datagram of an active window.
                            if sock.is_none() {
                                // Hold one in-flight permit for the socket's
                                // lifetime so concurrent remote-UDP forwards stay
                                // bounded (E3-F3).
                                let Ok(permit) = inflight.clone().try_acquire_owned() else {
                                    warn!(target: "spt_ssh3::forward", target = %dial_target, "remote-udp in-flight cap reached — dropping datagram");
                                    continue;
                                };
                                let s = match UdpSocket::bind(("0.0.0.0", 0)).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        warn!(target: "spt_ssh3::forward", error = %e, "remote-udp local bind failed");
                                        continue;
                                    }
                                };
                                if let Err(e) = s.connect(&dial_target).await {
                                    warn!(target: "spt_ssh3::forward", error = %e, target = %dial_target, "remote-udp connect to target failed");
                                    continue;
                                }
                                let s = Arc::new(s);
                                let relay_sock = s.clone();
                                let relay_conn = conn.clone();
                                relay_task = Some(tokio::spawn(async move {
                                    // Permit released when this relay task ends.
                                    let _permit = permit;
                                    let mut buf = vec![0u8; 64 * 1024];
                                    loop {
                                        match relay_sock.recv(&mut buf).await {
                                            Ok(n) => {
                                                let mut out = Vec::with_capacity(4 + n);
                                                out.extend_from_slice(&flow_id.to_be_bytes());
                                                out.extend_from_slice(&buf[..n]);
                                                if relay_conn.send_datagram(Bytes::from(out)).is_err() {
                                                    return;
                                                }
                                            }
                                            Err(e) => {
                                                warn!(target: "spt_ssh3::forward", error = %e, "remote-udp reply recv failed");
                                                return;
                                            }
                                        }
                                    }
                                }));
                                sock = Some(s);
                            }
                            if let Some(s) = sock.as_ref() {
                                if let Err(e) = s.send(&payload).await {
                                    warn!(target: "spt_ssh3::forward", error = %e, target = %dial_target, "remote-udp send to target failed");
                                    // Socket may be wedged; tear down so the next
                                    // datagram rebinds a fresh one.
                                    if let Some(t) = relay_task.take() {
                                        t.abort();
                                    }
                                    sock = None;
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(t) = relay_task.take() {
            t.abort();
        }
        state_clone.udp_flows.remove(&flow_id);
        debug!(target: "spt_ssh3::forward", forward = %name_t, "remote-udp forward stopped");
        let _ = state_tx.send(ForwardState::Stopped);
    });

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

/// Server-side datagram dispatcher: reads QUIC datagrams from `conn` and
/// routes them by their 4-byte big-endian `flow_id` prefix into
/// `state.udp_flows`. Symmetric to the client-side dispatch loop in
/// [`crate::session::Ssh3Session::from_parts`]. Used by the test harness.
pub async fn serve_datagram_demux(conn: Connection, state: Arc<SessionState>) {
    while let Ok(payload) = conn.read_datagram().await {
        if payload.len() < 4 {
            continue;
        }
        let flow_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let body = payload.slice(4..);
        if let Some(tx) = state.udp_flows.get(&flow_id) {
            // M1: bounded channel; `try_send` drops on a full queue (UDP is
            // lossy) so a flooding peer cannot grow memory without bound. The
            // DashMap `Ref` is held only across this non-blocking send.
            let _ = tx.value().try_send(body);
        }
    }
}

/// Server-side acceptor: drains the control stream, and for each
/// [`Ssh3FrameKind::RemoteUdpForwardRequest`] the peer sends, binds a UDP
/// listener on the requested address and pumps inbound datagrams as
/// `[flow_id][bytes]` QUIC datagrams back toward the requester. Replies
/// (received over `state.udp_flows[flow_id]`) are sent to the most recent
/// external source.
///
/// Used by the test harness "fake server" and by an spt instance running
/// as the server end of an SSH3 tunnel. Pair with
/// [`serve_datagram_demux`] on the same `state` so server-side
/// `udp_flows` entries actually receive client replies.
pub async fn serve_remote_udp_forwards(
    conn: Connection,
    mut control_recv: RecvStream,
    control_send: Arc<AsyncMutex<SendStream>>,
    state: Arc<SessionState>,
) {
    loop {
        let frame = match Ssh3Frame::read_async(&mut control_recv).await {
            Ok(f) => f,
            Err(e) => {
                debug!(target: "spt_ssh3::forward", error = %e, "remote-udp acceptor: control stream closed");
                return;
            }
        };
        // Remote-UDS request: bind a server-side unix listener and back-channel
        // each accepted connection toward the client (`cfg(unix)`).
        #[cfg(unix)]
        if frame.kind == Ssh3FrameKind::RemoteUdsForwardRequest {
            let path = match UdsChannelOpenPayload::decode(frame.payload) {
                Ok(p) => p.path,
                Err(e) => {
                    warn!(target: "spt_ssh3::forward", error = %e, "remote-uds: bad payload");
                    continue;
                }
            };
            // M5: gate remote-UDS forward listeners behind the same
            // `inbound_forward_limit` semaphore that bounds the matched-forward
            // TCP path, so a peer flooding RemoteUdsForwardRequest frames cannot
            // spawn unbounded listeners/tasks. The permit is held for the
            // listener's lifetime and released when `serve_remote_uds_request`
            // returns.
            let Ok(permit) = state.inbound_forward_limit.clone().try_acquire_owned() else {
                warn!(target: "spt_ssh3::forward", path = %path, "remote-uds: max_forwards reached — rejecting");
                // The client awaits a ForwardOpenResponse ACK, so reject
                // explicitly rather than letting it time out.
                let mut g = control_send.lock().await;
                let _ = Ssh3Frame::new(
                    Ssh3FrameKind::ForwardOpenResponse,
                    ForwardOpenResponse {
                        ok: false,
                        reason: "max_forwards reached".into(),
                    }
                    .encode(),
                )
                .write_async(&mut *g)
                .await;
                continue;
            };
            let conn = conn.clone();
            let ctl = control_send.clone();
            tokio::spawn(serve_remote_uds_request(conn, ctl, path, permit));
            continue;
        }
        if frame.kind != Ssh3FrameKind::RemoteUdpForwardRequest {
            // Ignore other control frames here (e.g. AppPing keepalives, or a
            // RemoteUdsForwardRequest on a non-unix server which cannot honour
            // it).
            continue;
        }
        let payload = match UdpAssociatePayload::decode(frame.payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(target: "spt_ssh3::forward", error = %e, "remote-udp: bad payload");
                continue;
            }
        };
        // M5: gate remote-UDP forward listeners behind the same
        // `inbound_forward_limit` semaphore that bounds the matched-forward TCP
        // path. Acquire BEFORE binding so a flood of RemoteUdpForwardRequest
        // frames cannot even open sockets. The client does not await an ACK on
        // this path (see `open_remote_udp`), so an over-cap request is dropped
        // with a warning. The permit is held for the listener's lifetime.
        let Ok(permit) = state.inbound_forward_limit.clone().try_acquire_owned() else {
            warn!(
                target: "spt_ssh3::forward",
                bind = %format!("{}:{}", payload.host, payload.port),
                "remote-udp: max_forwards reached — dropping request"
            );
            continue;
        };
        let socket = match UdpSocket::bind((payload.host.as_str(), payload.port)).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    target: "spt_ssh3::forward",
                    error = %e,
                    bind = %format!("{}:{}", payload.host, payload.port),
                    "remote-udp: bind failed"
                );
                continue;
            }
        };
        let conn = conn.clone();
        let state = state.clone();
        let _ctl = control_send.clone();
        tokio::spawn(server_remote_udp_loop(
            socket,
            conn,
            state,
            payload.flow_id,
            permit,
        ));
    }
}

async fn server_remote_udp_loop(
    socket: UdpSocket,
    conn: Connection,
    state: Arc<SessionState>,
    flow_id: u32,
    // Held for the loop's lifetime so the `inbound_forward_limit` cap reflects
    // this live remote-UDP forward (M5); released on return.
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let socket = Arc::new(socket);
    // Track the most recent external source so replies can be delivered.
    let last_peer: Arc<AsyncMutex<Option<std::net::SocketAddr>>> = Arc::new(AsyncMutex::new(None));

    // Register an inbound channel so the session-level datagram dispatch
    // can deliver replies (if the client sends back via the same flow_id).
    let (reply_tx, mut reply_rx) = mpsc::channel::<Bytes>(UDP_INBOUND_CHANNEL_CAP);
    state.udp_flows.insert(flow_id, reply_tx);

    // External → QUIC.
    let outbound_socket = socket.clone();
    let outbound_peer = last_peer.clone();
    let outbound_conn = conn.clone();
    let outbound = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, peer) = match outbound_socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(target: "spt_ssh3::forward", error = %e, "remote-udp: server recv_from failed");
                    return;
                }
            };
            {
                let mut g = outbound_peer.lock().await;
                *g = Some(peer);
            }
            let mut out = Vec::with_capacity(4 + n);
            out.extend_from_slice(&flow_id.to_be_bytes());
            out.extend_from_slice(&buf[..n]);
            if let Err(e) = outbound_conn.send_datagram(Bytes::from(out)) {
                warn!(target: "spt_ssh3::forward", error = %e, "remote-udp: server send_datagram failed");
            }
        }
    };

    // QUIC reply → external.
    let inbound_peer = last_peer.clone();
    let inbound_socket = socket.clone();
    let inbound = async move {
        while let Some(payload) = reply_rx.recv().await {
            let peer = {
                let g = inbound_peer.lock().await;
                *g
            };
            if let Some(peer) = peer {
                if let Err(e) = inbound_socket.send_to(&payload, peer).await {
                    warn!(target: "spt_ssh3::forward", error = %e, "remote-udp: server send_to external failed");
                }
            }
        }
    };

    #[allow(clippy::ignored_unit_patterns)]
    {
        tokio::select! {
            _ = outbound => {}
            _ = inbound => {}
        }
    }
    state.udp_flows.remove(&flow_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "testing")]
    use crate::testing::test_support::connected_pair_public;

    #[test]
    fn bind_addr_string_tcp() {
        let s = bind_addr_string(&BindAddr::TcpHostPort {
            host: "127.0.0.1".into(),
            port: 7777,
        })
        .unwrap();
        assert_eq!(s, "127.0.0.1:7777");
    }

    #[test]
    fn bind_addr_string_unix_unsupported() {
        let err =
            bind_addr_string(&BindAddr::Unix(std::path::PathBuf::from("/tmp/x"))).unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[test]
    fn bind_host_port_tcp() {
        let (h, p) = bind_host_port(&BindAddr::TcpHostPort {
            host: "::1".into(),
            port: 8888,
        })
        .unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 8888);
    }

    #[test]
    fn bind_addr_string_socketaddr_v4() {
        let s = bind_addr_string(&BindAddr::Tcp("127.0.0.1:9090".parse().unwrap())).unwrap();
        assert_eq!(s, "127.0.0.1:9090");
    }

    #[test]
    fn bind_addr_string_socketaddr_v6() {
        let s = bind_addr_string(&BindAddr::Tcp("[::1]:9091".parse().unwrap())).unwrap();
        assert!(s.contains("[::1]"));
        assert!(s.ends_with(":9091"));
    }

    #[test]
    fn bind_host_port_socketaddr_v4() {
        let (h, p) = bind_host_port(&BindAddr::Tcp("10.0.0.1:7000".parse().unwrap())).unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 7000);
    }

    #[test]
    fn bind_host_port_unix_unsupported() {
        let err = bind_host_port(&BindAddr::Unix(std::path::PathBuf::from("/tmp/y"))).unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[test]
    fn session_state_default_is_empty() {
        let s = SessionState::default();
        assert_eq!(s.udp_flows.len(), 0);
        assert_eq!(s.remote_forwards.len(), 0);
    }

    #[test]
    fn session_state_debug_includes_field_names() {
        let s = SessionState::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("udp_flows"));
        assert!(dbg.contains("remote_forwards"));
    }

    /// M1: the per-flow inbound UDP channel is BOUNDED. Mirroring the datagram
    /// demux producer (`state.udp_flows.get(flow).try_send(body)`), a flood that
    /// outruns the (here: never-draining) consumer is dropped once the queue is
    /// full — memory cannot grow without bound.
    #[test]
    fn udp_flows_try_send_is_bounded_and_drops_on_flood() {
        let state = SessionState::default();
        let (tx, _rx) = mpsc::channel::<Bytes>(UDP_INBOUND_CHANNEL_CAP);
        state.udp_flows.insert(7, tx);

        let mut accepted = 0usize;
        let mut dropped = 0usize;
        // Flood far beyond the cap without ever draining `_rx`.
        for _ in 0..(UDP_INBOUND_CHANNEL_CAP * 4) {
            if let Some(s) = state.udp_flows.get(&7) {
                match s.value().try_send(Bytes::from(vec![0u8; 16])) {
                    Ok(()) => accepted += 1,
                    Err(_) => dropped += 1,
                }
            }
        }
        // The queue accepts at most its capacity, then drops the rest.
        assert_eq!(
            accepted, UDP_INBOUND_CHANNEL_CAP,
            "bounded channel must cap buffered datagrams at its capacity"
        );
        assert_eq!(accepted + dropped, UDP_INBOUND_CHANNEL_CAP * 4);
        assert!(
            dropped >= UDP_INBOUND_CHANNEL_CAP * 3,
            "excess must be dropped"
        );
    }

    /// M1 (end-to-end demux): `serve_datagram_demux` routes inbound QUIC
    /// datagrams into the per-flow bounded channel via `try_send`; a peer that
    /// floods a flow whose consumer never drains cannot push the buffered count
    /// past the channel capacity.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn serve_datagram_demux_flood_stays_bounded() {
        use crate::testing::test_support::connected_pair_public;

        let (client, server) = connected_pair_public().await;
        let state = Arc::new(SessionState::default());
        let flow_id: u32 = 42;
        let (tx, mut rx) = mpsc::channel::<Bytes>(UDP_INBOUND_CHANNEL_CAP);
        state.udp_flows.insert(flow_id, tx);

        // Run the real demux against the server side; never drain `rx`.
        let demux = tokio::spawn(serve_datagram_demux(server.clone(), state.clone()));

        // Flood many more datagrams than the channel cap from the client.
        let flood = UDP_INBOUND_CHANNEL_CAP * 8;
        for _ in 0..flood {
            let mut payload = Vec::with_capacity(4 + 16);
            payload.extend_from_slice(&flow_id.to_be_bytes());
            payload.extend_from_slice(&[1u8; 16]);
            // Best-effort: QUIC may drop datagrams under load — irrelevant, we
            // only assert the buffered count never exceeds the cap.
            let _ = client.send_datagram(Bytes::from(payload));
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Drain and count: a bounded channel can never hold more than its cap.
        let mut buffered = 0usize;
        while rx.try_recv().is_ok() {
            buffered += 1;
        }
        assert!(
            buffered <= UDP_INBOUND_CHANNEL_CAP,
            "buffered datagrams {buffered} exceeded bounded cap {UDP_INBOUND_CHANNEL_CAP}"
        );

        demux.abort();
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    }

    #[test]
    fn dispatch_inbound_bidi_rejection_payload_round_trips() {
        // Mirror the rejection-response shape dispatch_inbound_bidi sends
        // when no matching remote forward is registered.
        let open = ChannelOpenPayload {
            host: "unknown.invalid".into(),
            port: 5555,
        };
        let de = ChannelOpenPayload::decode(open.encode()).unwrap();
        assert_eq!(de.host, "unknown.invalid");
        assert_eq!(de.port, 5555);

        let resp = ForwardOpenResponse {
            ok: false,
            reason: "no remote forward registered for that bind".into(),
        };
        let de = ForwardOpenResponse::decode(resp.encode()).unwrap();
        assert!(!de.ok);
        assert!(de.reason.contains("no remote forward registered"));
    }

    #[test]
    fn open_timeout_constant_is_15s() {
        assert_eq!(OPEN_TIMEOUT.as_secs(), 15);
    }

    // ---------------------------------------------------------------------
    // M-W3: per-forward limit enforcement (Wave 3). Each of the following
    // targets a knob that was DEAD before this wave (rate/idle/bind on the
    // local path, config max_flows on UDP) and therefore FAILS against the
    // pre-fix code.
    // ---------------------------------------------------------------------

    /// A full [`UdpForwardSpec`] used by the UDP-config tests.
    #[cfg(test)]
    fn make_udp_spec(max_flows: Option<u32>, pps: u32, idle_secs: u32) -> UdpForwardSpec {
        UdpForwardSpec {
            name: "u".into(),
            direction: ForwardDirection::Local,
            listen: BindAddr::TcpHostPort {
                host: "127.0.0.1".into(),
                port: 0,
            },
            target: TargetAddr::new("127.0.0.1", 9),
            idle_timeout_secs: idle_secs,
            max_flows,
            limits: ForwardRateLimits {
                max_packets_per_sec: pps,
                ..Default::default()
            },
        }
    }

    /// The UDP flow table is sized from the CONFIG `max_flows`, NOT the old
    /// hard-coded `UDP_INBOUND_CHANNEL_CAP = 1024`. The full limit surface
    /// (`max_flows` / `max_datagram_size` / packets-per-second) is live on the
    /// table `open_udp` builds.
    #[test]
    fn udp_flow_config_uses_config_max_flows_and_enforces_surface() {
        let spec = make_udp_spec(Some(3), 5, 30);
        let cfg = udp_flow_config(&spec);
        assert_eq!(
            cfg.max_flows, 3,
            "must use config max_flows, not a hard-coded 1024"
        );
        assert_ne!(cfg.max_flows, 1024);
        assert_eq!(cfg.idle_timeout, Duration::from_secs(30));

        // Build the table exactly as `open_udp` does and assert enforcement.
        let table: UdpFlowTable<UdpFlowKey, ()> =
            UdpFlowTable::with_pps(cfg, spec.limits.max_packets_per_sec);
        let a = |p: u16| std::net::SocketAddr::from(([127, 0, 0, 1], p));
        assert!(table.touch_or_insert(a(1), || ()));
        assert!(table.touch_or_insert(a(2), || ()));
        assert!(table.touch_or_insert(a(3), || ()));
        assert!(
            !table.touch_or_insert(a(4), || ()),
            "config max_flows=3 must reject the 4th distinct flow"
        );
        // Oversized-datagram reject.
        assert!(table.admit_size(1000));
        assert!(!table.admit_size(DEFAULT_MAX_DATAGRAM_SIZE as usize + 1));
        assert_eq!(table.oversized_count(), 1);
        // packets-per-second: burst 5 then drop.
        for _ in 0..5 {
            assert!(table.admit_packet());
        }
        assert!(
            !table.admit_packet(),
            "pps cap must drop the 6th packet in the burst window"
        );
    }

    /// When `max_flows` is unset the table falls back to the finite default
    /// (never the old 1024 channel cap, and never unbounded).
    #[test]
    fn udp_flow_config_default_max_flows_is_finite_not_1024() {
        let cfg = udp_flow_config(&make_udp_spec(None, 0, 0));
        assert_eq!(cfg.max_flows, UdpFlowTableConfig::default().max_flows);
        assert_ne!(cfg.max_flows, 1024);
        assert_ne!(cfg.max_flows, 0, "unset must NOT mean unbounded");
        // idle_timeout_secs = 0 ⇒ the safe default idle window.
        assert_eq!(cfg.idle_timeout, DEFAULT_UDP_IDLE);
    }

    /// `on_bind_conflict` is honoured: a `Fail` policy on an occupied address
    /// errors (the pre-fix bare-`TcpListener::bind` behaviour), while
    /// `NextPort` falls forward to a free port instead of failing.
    #[tokio::test]
    async fn local_forward_honors_bind_conflict_policy() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let listen = BindAddr::TcpHostPort {
            host: addr.ip().to_string(),
            port: addr.port(),
        };

        let err = bind_local_listener(&listen, BindConflictPolicy::Fail, "bc")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::LocalBindFailed { .. }));

        let l = bind_local_listener(&listen, BindConflictPolicy::NextPort, "bc")
            .await
            .expect("NextPort must fall forward to a free port");
        assert_ne!(
            l.local_addr().unwrap().port(),
            addr.port(),
            "NextPort must bind a different port"
        );
    }

    /// Spin up a TCP target that counts accepted connections and echoes bytes.
    #[cfg(feature = "testing")]
    async fn counting_echo_target() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicU32>) {
        use std::sync::atomic::{AtomicU32, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicU32::new(0));
        let c = count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                c.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.into_split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        (addr, count)
    }

    /// The local forward honours `max_new_connections_per_second`: of two rapid
    /// connections only the first is bridged to the peer, and the refusal is
    /// logged at WARN. Pre-fix (`bridge_local` used a plain `copy` with no rate
    /// gate) both connections reached the target.
    #[cfg(feature = "testing")]
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn local_forward_rate_limits_new_connections_and_warns() {
        use std::sync::atomic::Ordering;
        use tokio::io::AsyncWriteExt as _;

        let (client, server) = connected_pair_public().await;
        let (target_addr, count) = counting_echo_target().await;
        let resolver = move |_o: &ChannelOpenPayload| {
            Some(TargetAddr::new(
                target_addr.ip().to_string(),
                target_addr.port(),
            ))
        };
        tokio::spawn(serve_local_tcp_acceptor(server.clone(), resolver));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lport = listener.local_addr().unwrap().port();
        let (state_tx, _state_rx) = watch::channel(ForwardState::Listening);
        let (_close_tx, close_rx) = oneshot::channel();
        let limits = ForwardRateLimits {
            max_new_conns_per_sec: 1,
            ..Default::default()
        };
        tokio::spawn(local_loop(
            client,
            listener,
            TargetAddr::new("unused", 0),
            state_tx,
            close_rx,
            None,
            "rl".into(),
            limits,
            None,
        ));

        for _ in 0..2 {
            let mut s = TcpStream::connect(("127.0.0.1", lport)).await.unwrap();
            let _ = s.write_all(b"x").await;
            let _ = s.shutdown().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(600)).await;

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "rate gate must bridge only the first of two rapid connections"
        );
        assert!(
            logs_contain("max_new_connections_per_second reached"),
            "a rate-refused forward must log a WARN"
        );

        server.close(0u32.into(), b"done");
    }

    /// The local forward honours a per-forward `idle_timeout`: a connection over
    /// which no bytes flow is closed after the idle window, so the client sees
    /// EOF. Pre-fix the plain `copy` never closed an idle connection, so the
    /// read below would block until the outer timeout fired (test failure).
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_forward_idle_timeout_drops_connection() {
        use tokio::io::AsyncReadExt as _;

        let (client, server) = connected_pair_public().await;
        let (target_addr, _count) = counting_echo_target().await;
        let resolver = move |_o: &ChannelOpenPayload| {
            Some(TargetAddr::new(
                target_addr.ip().to_string(),
                target_addr.port(),
            ))
        };
        tokio::spawn(serve_local_tcp_acceptor(server.clone(), resolver));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lport = listener.local_addr().unwrap().port();
        let (state_tx, _state_rx) = watch::channel(ForwardState::Listening);
        let (_close_tx, close_rx) = oneshot::channel();
        tokio::spawn(local_loop(
            client,
            listener,
            TargetAddr::new("unused", 0),
            state_tx,
            close_rx,
            None,
            "idle".into(),
            ForwardRateLimits::default(),
            Some(Duration::from_millis(300)),
        ));

        let mut s = TcpStream::connect(("127.0.0.1", lport)).await.unwrap();
        // Never send anything; the only closure cause is the idle timeout.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await;
        // `Err(_)` from the outer timeout = the connection stayed open past the
        // idle window (the pre-fix unenforced behaviour) → test failure. An
        // inner `Ok(0)` (EOF) or an inner reset both mean the idle-close fired.
        let inner = read.expect(
            "idle timeout did not close the idle connection within 3s (pre-fix unenforced behaviour)",
        );
        match inner {
            Ok(0) | Err(_) => {} // idle-close EOF or reset — the wired behaviour.
            Ok(n) => panic!("expected idle EOF, got {n} bytes"),
        }

        server.close(0u32.into(), b"done");
    }

    // ---------------------------------------------------------------------
    // MED-4 / MED-LOW-5 / LOW-6: ssh3 UDP data-plane demux + cap fixes.
    // ---------------------------------------------------------------------

    /// MED-4 (key regression): two concurrent local UDP clients each receive
    /// ONLY their own replies. Each distinct client source address gets its own
    /// `flow_id`, so the session demux routes each reply back to the client that
    /// originated the flow — never a shared "last peer". Pre-fix (single
    /// `flow_id` + one shared `last_peer`) client A could receive client B's
    /// reply.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_udp_concurrent_clients_no_reply_cross_talk() {
        use std::sync::atomic::AtomicU32;

        // Each client tags its datagrams with its own marker byte and asserts
        // every reply it gets back carries THAT marker (never the other's).
        async fn run_client(marker: u8, fwd_addr: std::net::SocketAddr) -> (usize, bool) {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sock.connect(fwd_addr).await.unwrap();
            let mut got = 0usize;
            let mut clean = true;
            for i in 0..40u8 {
                let _ = sock.send(&[marker, i]).await;
                let mut buf = [0u8; 64];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(50), sock.recv(&mut buf)).await
                {
                    if n >= 1 {
                        got += 1;
                        if buf[0] != marker {
                            clean = false;
                        }
                    }
                }
            }
            // Drain any stragglers.
            loop {
                let mut buf = [0u8; 64];
                match tokio::time::timeout(Duration::from_millis(150), sock.recv(&mut buf)).await {
                    Ok(Ok(n)) if n >= 1 => {
                        got += 1;
                        if buf[0] != marker {
                            clean = false;
                        }
                    }
                    _ => break,
                }
            }
            (got, clean)
        }

        let (client, server) = connected_pair_public().await;
        let state = Arc::new(SessionState::default());

        // Client-side inbound demux: route server→client datagrams by flow_id
        // into `state.udp_flows` (the per-client reply pumps drain these).
        let demux = tokio::spawn(serve_datagram_demux(client.clone(), state.clone()));

        // Server "target": reflect each datagram back verbatim (flow_id prefix
        // preserved), i.e. an echo of what the client sent.
        let server_echo = server.clone();
        let echo = tokio::spawn(async move {
            while let Ok(payload) = server_echo.read_datagram().await {
                if payload.len() < 4 {
                    continue;
                }
                let _ = server_echo.send_datagram(payload);
            }
        });

        // Control stream for the (per-client) UdpAssociate frames.
        let (csend, _crecv) = client.open_bi().await.unwrap();
        let control_send = Arc::new(AsyncMutex::new(csend));

        // Forward socket bound to a known port (so the test clients can reach it).
        let fwd_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fwd_addr = fwd_sock.local_addr().unwrap();

        let flow_cfg = UdpFlowTableConfig {
            max_flows: 64,
            ..Default::default()
        };
        let flow_table = Arc::new(UdpFlowTable::with_pps(flow_cfg, 0));
        let (state_tx, _state_rx) = watch::channel(ForwardState::Active);
        let (_close_tx, close_rx) = oneshot::channel();
        let pump = LocalUdpPump {
            conn: client.clone(),
            state: state.clone(),
            control_send,
            next_flow_id: Arc::new(AtomicU32::new(1)),
            socket: fwd_sock,
            target: TargetAddr::new("127.0.0.1", 9),
            flow_table,
            up_bucket: TokenBucket::unlimited(),
            down_bucket: TokenBucket::unlimited(),
            idle: Duration::from_secs(60),
            name: "u".into(),
        };
        tokio::spawn(local_udp_pump(pump, close_rx, state_tx));

        let a = tokio::spawn(run_client(b'A', fwd_addr));
        let b = tokio::spawn(run_client(b'B', fwd_addr));
        let (a_got, a_clean) = a.await.unwrap();
        let (b_got, b_clean) = b.await.unwrap();

        assert!(
            a_clean,
            "client A received a datagram belonging to another client (cross-talk)"
        );
        assert!(
            b_clean,
            "client B received a datagram belonging to another client (cross-talk)"
        );
        assert!(
            a_got > 0,
            "client A must receive at least one of its own replies"
        );
        assert!(
            b_got > 0,
            "client B must receive at least one of its own replies"
        );
        assert!(
            state.udp_flows.len() >= 2,
            "each distinct client must be assigned its own flow-id"
        );

        demux.abort();
        echo.abort();
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    }

    /// MED/LOW-5: a remote UDP forward relays *every* reply datagram for a flow
    /// (multi-response / stateful UDP), not just the first. The persistent
    /// per-flow socket stays alive for the idle window. Pre-fix (fresh socket +
    /// single `recv` per inbound datagram) only the first of N replies survived.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_udp_relays_all_reply_datagrams() {
        use std::sync::atomic::AtomicU32;

        const REPLIES: u8 = 5;

        let (client, server) = connected_pair_public().await;
        let state = Arc::new(SessionState::default());

        // Client-side demux: route the test's injected `[flow_id][req]` datagrams
        // into `state.udp_flows[flow_id]` so the remote-udp inbound loop dials
        // the target.
        let demux = tokio::spawn(serve_datagram_demux(client.clone(), state.clone()));

        // UDP target: on each request, fire back REPLIES reply datagrams.
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok((_n, from)) = target.recv_from(&mut buf).await {
                for i in 0..REPLIES {
                    let _ = target.send_to(&[b'R', i], from).await;
                }
            }
        });

        // Control stream for the RemoteUdpForwardRequest frame.
        let (csend, _crecv) = client.open_bi().await.unwrap();
        let control_send = Arc::new(AsyncMutex::new(csend));

        let spec = UdpForwardSpec {
            name: "ru".into(),
            direction: ForwardDirection::Remote,
            listen: BindAddr::TcpHostPort {
                host: "127.0.0.1".into(),
                port: 0,
            },
            target: TargetAddr::new(target_addr.ip().to_string(), target_addr.port()),
            idle_timeout_secs: 0,
            max_flows: None,
            limits: ForwardRateLimits::default(),
        };
        // next_flow_id starts at 1 ⇒ this forward gets flow_id = 1.
        let _handle = open_remote_udp(
            client.clone(),
            state.clone(),
            control_send,
            Arc::new(AtomicU32::new(1)),
            &spec,
        )
        .await
        .expect("open_remote_udp");
        let flow_id: u32 = 1;

        // Inject one request datagram as if the peer forwarded it to us.
        let mut req = Vec::new();
        req.extend_from_slice(&flow_id.to_be_bytes());
        req.extend_from_slice(b"ping");
        server.send_datagram(Bytes::from(req)).unwrap();

        // Collect relayed replies off the QUIC channel.
        let mut relayed = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while relayed < REPLIES as usize && tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(300), server.read_datagram()).await {
                Ok(Ok(p)) if p.len() >= 5 => {
                    let fid = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
                    if fid == flow_id && p[4] == b'R' {
                        relayed += 1;
                    }
                }
                Ok(Ok(_)) => {}
                _ => break,
            }
        }

        assert!(
            relayed >= 2,
            "remote-udp must relay MULTIPLE reply datagrams per request (got {relayed}); \
             pre-fix relayed only the first"
        );

        demux.abort();
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    }

    /// LOW-6: the local forward's `max_connections` cap is enforced with a
    /// semaphore gate and is never overshot, even when many clients connect at
    /// once. The peer accepts the bridge channels but never responds, so each
    /// admitted bridge holds its slot; every connection beyond the cap is
    /// dropped at the gate (its channel is never opened toward the peer).
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_forward_max_connections_not_overshot() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncWriteExt as _;

        const CAP: u32 = 2;
        const CLIENTS: usize = 8;

        let (client, server) = connected_pair_public().await;

        // Server: accept bridge channels, count them, and hold them open WITHOUT
        // responding (so each admitted bridge keeps its connection slot).
        let opened = Arc::new(AtomicUsize::new(0));
        let o = opened.clone();
        let srv = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((send, recv)) = server.accept_bi().await {
                o.fetch_add(1, Ordering::SeqCst);
                held.push((send, recv));
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lport = listener.local_addr().unwrap().port();
        let (state_tx, _state_rx) = watch::channel(ForwardState::Listening);
        let (_close_tx, close_rx) = oneshot::channel();
        tokio::spawn(local_loop(
            client,
            listener,
            TargetAddr::new("127.0.0.1", 9),
            state_tx,
            close_rx,
            Some(CAP),
            "cap".into(),
            ForwardRateLimits::default(),
            None,
        ));

        // Fire CLIENTS concurrent connections and keep them all open.
        let mut socks = Vec::new();
        for _ in 0..CLIENTS {
            let mut s = TcpStream::connect(("127.0.0.1", lport)).await.unwrap();
            let _ = s.write_all(b"x").await;
            socks.push(s);
        }

        // Wait for the admitted bridges' channels to reach the peer.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while opened.load(Ordering::SeqCst) < CAP as usize && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Settle: give any (erroneously) over-admitted bridge time to appear.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let n = opened.load(Ordering::SeqCst);
        assert!(
            n <= CAP as usize,
            "max_connections overshot: {n} channels opened for cap {CAP}"
        );
        assert!(
            n >= 1,
            "the gate must still admit up to the cap (opened {n})"
        );

        srv.abort();
        drop(socks);
    }
}
