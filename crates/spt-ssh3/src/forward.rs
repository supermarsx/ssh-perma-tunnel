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

use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use quinn::{Connection, RecvStream, SendStream};
use spt_core::{BindAddr, Error, Result};
use spt_protocol::endpoint::TargetAddr;
use spt_protocol::forward::{
    ForwardDirection, ForwardState, LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec,
};
use spt_protocol::handle::{ForwardHandle, ForwardId};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};
use tracing::{debug, error, warn};

use crate::frame::{
    ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, UdpAssociatePayload,
};

/// Channel-open timeout (peer must answer the open frame within this).
const OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Transient state shared between the session and its dispatch loop.
///
/// * `udp_flows` maps a flow-id (allocated either by a local UDP forward or by
///   the peer's `UdpAssociate` frame) to a sender that receives inbound
///   datagram payloads (sans flow-id prefix).
/// * `remote_forwards` maps a `(host, port)` listening address to a sender
///   that receives inbound bidi streams from the peer for that listener.
#[derive(Default)]
pub struct SessionState {
    pub(crate) udp_flows: DashMap<u32, mpsc::UnboundedSender<Bytes>>,
    pub(crate) remote_forwards:
        DashMap<(String, u16), mpsc::UnboundedSender<(SendStream, RecvStream)>>,
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("udp_flows", &self.udp_flows.len())
            .field("remote_forwards", &self.remote_forwards.len())
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

/// Open a TCP local forward.
pub async fn open_local(conn: Connection, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
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
    let target = spec.target.clone();
    let max = spec.max_connections;

    tokio::spawn(local_loop(
        conn,
        listener,
        target,
        state_tx,
        close_rx,
        max,
        name.clone(),
    ));

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

async fn local_loop(
    conn: Connection,
    listener: TcpListener,
    target: TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    max: Option<u32>,
    name: String,
) {
    let _ = state_tx.send(ForwardState::Active);
    let active = Arc::new(std::sync::atomic::AtomicU32::new(0));
    loop {
        tokio::select! {
            _ = &mut close_rx => {
                debug!(target: "spt_ssh3::forward", forward = %name, "local forward shutdown signal");
                break;
            }
            accept = listener.accept() => {
                let (sock, _peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        error!(target: "spt_ssh3::forward", forward = %name, error = %e, "accept failed");
                        continue;
                    }
                };
                if let Some(limit) = max {
                    if active.load(std::sync::atomic::Ordering::Relaxed) >= limit {
                        warn!(target: "spt_ssh3::forward", forward = %name, "max_connections reached, dropping incoming");
                        continue;
                    }
                }
                let target = target.clone();
                let conn = conn.clone();
                let active = active.clone();
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let name_t = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_local(conn, sock, &target).await {
                        warn!(target: "spt_ssh3::forward", forward = %name_t, error = %e, "local conn failed");
                    }
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
}

async fn bridge_local(conn: Connection, mut sock: TcpStream, target: &TargetAddr) -> Result<()> {
    let (mut send, mut recv) = open_channel(&conn, target).await?;
    let (mut sock_r, mut sock_w) = sock.split();
    let to_peer = async {
        let n = tokio::io::copy(&mut sock_r, &mut send).await;
        let _ = send.finish();
        n
    };
    let from_peer = async {
        let n = tokio::io::copy(&mut recv, &mut sock_w).await;
        // Half-close the local socket so the application sees EOF cleanly
        // before we drop the stream (otherwise Windows can RST the conn).
        let _ = sock_w.shutdown().await;
        n
    };
    let (a, b) = tokio::join!(to_peer, from_peer);
    a.map_err(|e| Error::RuntimeFailure(format!("ssh3 local→peer copy: {e}")))?;
    b.map_err(|e| Error::RuntimeFailure(format!("ssh3 peer→local copy: {e}")))?;
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
    spec: &RemoteForwardSpec,
    peer_supports_remote: bool,
) -> Result<ForwardHandle> {
    if !peer_supports_remote {
        return Err(Error::UnsupportedPlatform(
            "ssh3 peer does not advertise remote_tcp capability".into(),
        ));
    }
    let (host, port) = bind_host_port(&spec.listen)?;

    // Register the inbound dispatch entry *before* sending the request so a
    // peer that races to open `forwarded-tcp` streams the moment it ACKs
    // doesn't lose the first connection.
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<(SendStream, RecvStream)>();
    state
        .remote_forwards
        .insert((host.clone(), port), inbound_tx);

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
    let target = spec.target.clone();

    tokio::spawn(remote_loop(
        conn,
        state.clone(),
        inbound_rx,
        target,
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
    mut inbound_rx: mpsc::UnboundedReceiver<(SendStream, RecvStream)>,
    target: TargetAddr,
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
                    Some((send, recv)) => {
                        let target = target.clone();
                        let name_t = name.clone();
                        tokio::spawn(async move {
                            if let Err(e) = bridge_remote(send, recv, &target).await {
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

async fn bridge_remote(
    mut send: SendStream,
    mut recv: RecvStream,
    target: &TargetAddr,
) -> Result<()> {
    // Inbound stream already past its channel-open frame (the dispatcher
    // consumed and validated it). Dial the local target and bridge raw.
    let mut sock = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| {
            // Best-effort error response; the dispatcher already sent OK.
            Error::NetworkUnreachable(format!(
                "ssh3 remote-forward dial {}:{}: {e}",
                target.host, target.port
            ))
        })?;
    let (mut sr, mut sw) = sock.split();
    let to_local = async {
        let n = tokio::io::copy(&mut recv, &mut sw).await;
        let _ = sw.shutdown().await;
        n
    };
    let from_local = async {
        let n = tokio::io::copy(&mut sr, &mut send).await;
        let _ = send.finish();
        n
    };
    let (a, b) = tokio::join!(to_local, from_local);
    a.map_err(|e| Error::RuntimeFailure(format!("ssh3 remote→local copy: {e}")))?;
    b.map_err(|e| Error::RuntimeFailure(format!("ssh3 local→remote copy: {e}")))?;
    Ok(())
}

/// Open a UDP forward.
///
/// Allocates a fresh `flow_id`, sends a [`Ssh3FrameKind::UdpAssociate`] frame
/// on the control stream, then bridges between a local `UdpSocket` and the
/// QUIC datagram channel. Each datagram is prefixed with the 4-byte big-endian
/// `flow_id` so multiple UDP forwards on one session can be demultiplexed.
#[allow(clippy::too_many_arguments)]
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

    let flow_id = next_flow_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let assoc = Ssh3Frame::new(
        Ssh3FrameKind::UdpAssociate,
        UdpAssociatePayload {
            flow_id,
            host: spec.target.host.clone(),
            port: spec.target.port,
        }
        .encode(),
    );
    {
        let mut g = control_send.lock().await;
        assoc.write_async(&mut *g).await?;
    }

    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Bytes>();
    state.udp_flows.insert(flow_id, inbound_tx);

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, mut close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();

    let socket = Arc::new(socket);
    let conn_dgrm = conn.clone();
    let socket_send = socket.clone();
    let state_clone = state.clone();
    let name_t = name.clone();
    tokio::spawn(async move {
        // Track last peer addr so we can deliver server→client datagrams.
        let last_peer: Arc<AsyncMutex<Option<std::net::SocketAddr>>> =
            Arc::new(AsyncMutex::new(None));

        // Outbound: socket → quic datagram (with flow-id prefix).
        let outbound_socket = socket.clone();
        let outbound_conn = conn_dgrm.clone();
        let outbound_peer = last_peer.clone();
        let outbound = async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let (n, peer) = match outbound_socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(target: "spt_ssh3::forward", error = %e, "udp recv_from failed");
                        return;
                    }
                };
                {
                    let mut g = outbound_peer.lock().await;
                    *g = Some(peer);
                }
                let mut payload = Vec::with_capacity(4 + n);
                payload.extend_from_slice(&flow_id.to_be_bytes());
                payload.extend_from_slice(&buf[..n]);
                if let Err(e) = outbound_conn.send_datagram(Bytes::from(payload)) {
                    warn!(target: "spt_ssh3::forward", error = %e, "udp send_datagram failed");
                }
            }
        };

        // Inbound: dispatched datagrams (from session loop) → socket.
        let inbound_peer = last_peer.clone();
        let inbound = async move {
            while let Some(payload) = inbound_rx.recv().await {
                let peer = {
                    let g = inbound_peer.lock().await;
                    *g
                };
                if let Some(peer) = peer {
                    if let Err(e) = socket_send.send_to(&payload, peer).await {
                        warn!(target: "spt_ssh3::forward", error = %e, "udp send_to client failed");
                    }
                } else {
                    debug!(target: "spt_ssh3::forward", "udp inbound dropped — no client peer yet");
                }
            }
        };

        #[allow(clippy::ignored_unit_patterns)]
        {
            tokio::select! {
                _ = &mut close_rx => {}
                _ = outbound => {}
                _ = inbound => {}
            }
        }
        state_clone.udp_flows.remove(&flow_id);
        debug!(target: "spt_ssh3::forward", forward = %name_t, "udp forward stopped");
        let _ = state_tx.send(ForwardState::Stopped);
    });

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

/// Dispatch one inbound bidi stream from the peer.
///
/// Reads the channel-open frame, looks up a matching remote-forward, and on
/// match sends an OK response and hands the stream off. On no-match (or any
/// error) sends a rejection and drops the stream.
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
    if frame.kind != Ssh3FrameKind::DirectTcpRequest {
        warn!(
            target: "spt_ssh3::forward",
            kind = ?frame.kind,
            "inbound bidi: unexpected first frame"
        );
        let _ = Ssh3Frame::new(
            Ssh3FrameKind::ForwardOpenResponse,
            ForwardOpenResponse {
                ok: false,
                reason: "unexpected open frame".into(),
            }
            .encode(),
        )
        .write_async(&mut send)
        .await;
        let _ = send.finish();
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
    let Some(entry) = state.remote_forwards.get(&key) else {
        debug!(
            target: "spt_ssh3::forward",
            host = %open.host, port = open.port,
            "inbound bidi: no matching remote forward — rejecting"
        );
        let _ = Ssh3Frame::new(
            Ssh3FrameKind::ForwardOpenResponse,
            ForwardOpenResponse {
                ok: false,
                reason: "no remote forward registered for that bind".into(),
            }
            .encode(),
        )
        .write_async(&mut send)
        .await;
        let _ = send.finish();
        return;
    };
    let tx = entry.value().clone();
    drop(entry);

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
    let _ = tx.send((send, recv));
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
        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
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
            let Ok(open) = ChannelOpenPayload::decode(frame.payload) else {
                return;
            };
            let Some(target) = resolver(&open) else {
                let _ = Ssh3Frame::new(
                    Ssh3FrameKind::ForwardOpenResponse,
                    ForwardOpenResponse {
                        ok: false,
                        reason: "denied by acl".into(),
                    }
                    .encode(),
                )
                .write_async(&mut send)
                .await;
                return;
            };
            let mut sock = match TcpStream::connect((target.host.as_str(), target.port)).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = Ssh3Frame::new(
                        Ssh3FrameKind::ForwardOpenResponse,
                        ForwardOpenResponse {
                            ok: false,
                            reason: format!("dial: {e}"),
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
        });
    }
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
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Bytes>();
    state.udp_flows.insert(flow_id, inbound_tx);

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, mut close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    let target = spec.target.clone();
    let state_clone = state.clone();
    let name_t = name.clone();

    // For each inbound datagram, dial target; reflect replies back over the
    // QUIC datagram channel.
    tokio::spawn(async move {
        let dial_target = format!("{}:{}", target.host, target.port);
        let inbound_loop = async {
            while let Some(payload) = inbound_rx.recv().await {
                // Resolve + connect a fresh local UDP socket per inbound
                // datagram (stateless mapping). For long-lived flows the
                // caller can layer a connection-tracking table on top.
                let sock = match UdpSocket::bind(("0.0.0.0", 0)).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(
                            target: "spt_ssh3::forward",
                            error = %e,
                            "remote-udp local bind failed"
                        );
                        continue;
                    }
                };
                if let Err(e) = sock.send_to(&payload, &dial_target).await {
                    warn!(
                        target: "spt_ssh3::forward",
                        error = %e,
                        target = %dial_target,
                        "remote-udp send_to local target failed"
                    );
                    continue;
                }
                // Best-effort: read one reply with a short timeout, send back.
                let mut buf = vec![0u8; 64 * 1024];
                let conn_clone = conn.clone();
                tokio::spawn(async move {
                    let r = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        sock.recv(&mut buf),
                    )
                    .await;
                    if let Ok(Ok(n)) = r {
                        let mut out = Vec::with_capacity(4 + n);
                        out.extend_from_slice(&flow_id.to_be_bytes());
                        out.extend_from_slice(&buf[..n]);
                        let _ = conn_clone.send_datagram(Bytes::from(out));
                    }
                });
            }
        };
        #[allow(clippy::ignored_unit_patterns)]
        {
            tokio::select! {
                _ = &mut close_rx => {}
                _ = inbound_loop => {}
            }
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
            let _ = tx.value().send(body);
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
        if frame.kind != Ssh3FrameKind::RemoteUdpForwardRequest {
            // Ignore other control frames here; the test harness only cares
            // about the remote-UDP path.
            continue;
        }
        let payload = match UdpAssociatePayload::decode(frame.payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(target: "spt_ssh3::forward", error = %e, "remote-udp: bad payload");
                continue;
            }
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
        tokio::spawn(server_remote_udp_loop(socket, conn, state, payload.flow_id));
    }
}

async fn server_remote_udp_loop(
    socket: UdpSocket,
    conn: Connection,
    state: Arc<SessionState>,
    flow_id: u32,
) {
    let socket = Arc::new(socket);
    // Track the most recent external source so replies can be delivered.
    let last_peer: Arc<AsyncMutex<Option<std::net::SocketAddr>>> = Arc::new(AsyncMutex::new(None));

    // Register an inbound channel so the session-level datagram dispatch
    // can deliver replies (if the client sends back via the same flow_id).
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<Bytes>();
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
}
