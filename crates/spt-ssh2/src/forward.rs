//! TCP forward listener tasks (local + remote) for SSH2 sessions.
//!
//! Local forwards: spawn a `tokio::net::TcpListener` on the configured
//! `BindAddr`. Each accepted connection opens a `direct-tcpip` channel via
//! libssh2 and bridges bytes both ways with `tokio::io::copy_bidirectional`.
//!
//! Remote forwards: issue `channel_forward_listen`, then in an accept loop
//! receive `forwarded-tcpip` channels and dial the configured target.

use std::sync::Arc;

use async_ssh2_lite::session_stream::AsyncSessionStream;
use async_ssh2_lite::{AsyncChannel, AsyncSession};
use parking_lot::Mutex;
use spt_core::{Error, Result};
use spt_protocol::forward::{ForwardState, LocalForwardSpec, RemoteForwardSpec};
use spt_protocol::handle::{ForwardHandle, ForwardId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tracing::{debug, error, warn};

use crate::errors::from_async_ssh;

/// Render a `BindAddr` into the `host:port` form `tokio::net::TcpListener` accepts.
fn bind_addr_string(addr: &spt_core::BindAddr) -> Result<String> {
    use spt_core::address::BindAddr as B;
    match addr {
        B::Tcp(sock) => Ok(sock.to_string()),
        B::TcpHostPort { host, port } => Ok(format!("{host}:{port}")),
        B::Unix(_) => Err(Error::UnsupportedPlatform(
            "SSH2 forward listeners on unix sockets are not implemented".into(),
        )),
    }
}

/// Open a local TCP forward whose listener lives on the client side.
///
/// Spawns a tokio task that accepts connections and bridges each to a fresh
/// `direct-tcpip` channel.
pub async fn open_local<S>(
    session: Arc<Mutex<AsyncSession<S>>>,
    spec: &LocalForwardSpec,
) -> Result<ForwardHandle>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    let bind = bind_addr_string(&spec.listen)?;
    let listener = TcpListener::bind(&bind).await.map_err(|e| Error::LocalBindFailed {
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
        listener, session, target, state_tx, close_rx, max, name.clone(),
    ));

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

async fn local_loop<S>(
    listener: TcpListener,
    session: Arc<Mutex<AsyncSession<S>>>,
    target: spt_protocol::TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    max: Option<u32>,
    name: String,
) where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    let _ = state_tx.send(ForwardState::Active);
    let active = Arc::new(std::sync::atomic::AtomicU32::new(0));
    loop {
        tokio::select! {
            _ = &mut close_rx => {
                debug!(target: "spt_ssh2::forward", forward = %name, "local forward shutdown signal");
                break;
            }
            accept = listener.accept() => {
                let (sock, _peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        error!(target: "spt_ssh2::forward", forward = %name, error = %e, "accept failed");
                        continue;
                    }
                };
                if let Some(limit) = max {
                    if active.load(std::sync::atomic::Ordering::Relaxed) >= limit {
                        warn!(target: "spt_ssh2::forward", forward = %name, "max_connections reached, dropping incoming");
                        continue;
                    }
                }
                let target = target.clone();
                let session = session.clone();
                let active = active.clone();
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let name_t = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_local(session, sock, &target).await {
                        warn!(target: "spt_ssh2::forward", forward = %name_t, error = %e, "local conn failed");
                    }
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
}

async fn bridge_local<S>(
    session: Arc<Mutex<AsyncSession<S>>>,
    mut sock: TcpStream,
    target: &spt_protocol::TargetAddr,
) -> Result<()>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    // Open the channel under the session lock; the AsyncChannel itself is
    // independent for I/O, so we release the lock immediately.
    let mut channel = {
        let s = session.lock().clone();
        // drop guard before await
        s.channel_direct_tcpip(&target.host, target.port, None)
            .await
            .map_err(|e| from_async_ssh("channel_direct_tcpip", e))?
    };

    let (mut sock_r, mut sock_w) = sock.split();
    let mut buf_in = vec![0u8; 32 * 1024];
    let mut buf_out = vec![0u8; 32 * 1024];

    loop {
        tokio::select! {
            n = sock_r.read(&mut buf_in) => {
                match n {
                    Ok(0) => break,
                    Ok(n) => {
                        channel.write_all(&buf_in[..n]).await.map_err(|e| {
                            Error::RuntimeFailure(format!("channel write: {e}"))
                        })?;
                    }
                    Err(e) => return Err(Error::RuntimeFailure(format!("sock read: {e}"))),
                }
            }
            n = channel.read(&mut buf_out) => {
                match n {
                    Ok(0) => break,
                    Ok(n) => {
                        sock_w.write_all(&buf_out[..n]).await.map_err(|e| {
                            Error::RuntimeFailure(format!("sock write: {e}"))
                        })?;
                    }
                    Err(e) => return Err(Error::RuntimeFailure(format!("channel read: {e}"))),
                }
            }
        }
    }
    let _ = channel.send_eof().await;
    let _ = channel.close().await;
    Ok(())
}

/// Open a remote TCP forward — request a server-side listener via
/// `tcpip-forward` and bridge each inbound `forwarded-tcpip` channel to the
/// configured target.
pub async fn open_remote<S>(
    session: Arc<Mutex<AsyncSession<S>>>,
    spec: &RemoteForwardSpec,
) -> Result<ForwardHandle>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    let (host_str, port) = match &spec.listen {
        spt_core::BindAddr::Tcp(sock) => (Some(sock.ip().to_string()), sock.port()),
        spt_core::BindAddr::TcpHostPort { host, port } => (Some(host.clone()), *port),
        spt_core::BindAddr::Unix(_) => {
            return Err(Error::UnsupportedPlatform(
                "SSH2 remote forward listeners on unix sockets are not supported".into(),
            ));
        }
    };

    let listener_pair = {
        let s = session.lock().clone();
        s.channel_forward_listen(port, host_str.as_deref(), None)
            .await
            .map_err(|e| match e {
                async_ssh2_lite::Error::Ssh2(_) => Error::RemoteBindFailed {
                    address: format!("{}:{}", host_str.as_deref().unwrap_or(""), port),
                    reason: from_async_ssh("channel_forward_listen", e).to_string(),
                },
                other => from_async_ssh("channel_forward_listen", other),
            })?
    };
    let (listener, _bound_port) = listener_pair;

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    let target = spec.target.clone();

    tokio::spawn(remote_loop(
        listener, target, state_tx, close_rx, name.clone(),
    ));

    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

async fn remote_loop<S>(
    mut listener: async_ssh2_lite::AsyncListener<S>,
    target: spt_protocol::TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    name: String,
) where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            ch = listener.accept() => {
                match ch {
                    Ok(channel) => {
                        let target = target.clone();
                        let name_t = name.clone();
                        tokio::spawn(async move {
                            if let Err(e) = bridge_remote(channel, &target).await {
                                warn!(target: "spt_ssh2::forward", forward = %name_t, error = %e, "remote conn failed");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(target: "spt_ssh2::forward", forward = %name, error = ?e, "remote accept failed");
                    }
                }
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
}

async fn bridge_remote<S>(
    mut channel: AsyncChannel<S>,
    target: &spt_protocol::TargetAddr,
) -> Result<()>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    let mut sock = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| Error::NetworkUnreachable(format!(
            "dial remote-forward target {}:{}: {e}",
            target.host, target.port
        )))?;
    let (mut sr, mut sw) = sock.split();
    let mut bi = vec![0u8; 32 * 1024];
    let mut bo = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            n = channel.read(&mut bi) => match n {
                Ok(0) => break,
                Ok(n) => sw.write_all(&bi[..n]).await
                    .map_err(|e| Error::RuntimeFailure(format!("sock write: {e}")))?,
                Err(e) => return Err(Error::RuntimeFailure(format!("channel read: {e}"))),
            },
            n = sr.read(&mut bo) => match n {
                Ok(0) => break,
                Ok(n) => channel.write_all(&bo[..n]).await
                    .map_err(|e| Error::RuntimeFailure(format!("channel write: {e}")))?,
                Err(e) => return Err(Error::RuntimeFailure(format!("sock read: {e}"))),
            }
        }
    }
    let _ = channel.send_eof().await;
    let _ = channel.close().await;
    Ok(())
}
