//! Multi-hop chains via nested `direct-tcpip` channels.
//!
//! `async-ssh2-lite::AsyncSession::new` requires `S: AsRawFd` (Unix) /
//! `AsRawSocket` (Windows) — neither of which an `AsyncChannel` exposes,
//! because the channel is a logical SSH stream rather than an OS socket. As a
//! result libssh2 cannot natively run a session over a Tokio-driven stream
//! that lacks a raw OS handle.
//!
//! For multi-hop chains we therefore use the *socketpair* trick: bind a
//! loopback `TcpListener`, accept one connection (becoming the SSH session's
//! socket), and pump bytes between the channel and the loopback peer.
//! libssh2 sees a real OS socket; the bytes traverse the prior hop's
//! `direct-tcpip` channel transparently.

use std::sync::Arc;

use async_ssh2_lite::session_stream::AsyncSessionStream;
use async_ssh2_lite::{AsyncChannel, AsyncSession, SessionConfiguration};
use parking_lot::Mutex;
use spt_core::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

use crate::errors::from_async_ssh;

/// Open a `direct-tcpip` channel through `outer` to `(host, port)` and wrap
/// it in a fresh `AsyncSession` (handshake + auth happen at the caller's
/// level after this function returns).
pub async fn open_chained_session<S>(
    outer: Arc<Mutex<AsyncSession<S>>>,
    host: &str,
    port: u16,
) -> Result<AsyncSession<TcpStream>>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    let channel = {
        let s = outer.lock().clone();
        s.channel_direct_tcpip(host, port, None)
            .await
            .map_err(|e| from_async_ssh("multi-hop direct-tcpip", e))?
    };

    // Loopback socketpair: bind, accept, connect.
    let lis = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| Error::RuntimeFailure(format!("bind multi-hop loopback: {e}")))?;
    let local_addr = lis.local_addr().map_err(|e| {
        Error::RuntimeFailure(format!("local_addr on multi-hop loopback: {e}"))
    })?;

    let (accept_res, connect_res) =
        tokio::join!(lis.accept(), TcpStream::connect(local_addr));
    let (server_side, _peer) =
        accept_res.map_err(|e| Error::RuntimeFailure(format!("accept multi-hop: {e}")))?;
    let client_side =
        connect_res.map_err(|e| Error::RuntimeFailure(format!("connect multi-hop: {e}")))?;

    // Spawn the byte pump bridging server_side <-> channel.
    tokio::spawn(pump(server_side, channel));

    // libssh2's session reads/writes from the OS socket = `client_side`.
    let session = AsyncSession::new(client_side, SessionConfiguration::default())
        .map_err(|e| from_async_ssh("AsyncSession::new (multi-hop)", e))?;
    Ok(session)
}

async fn pump<S>(mut sock: TcpStream, mut channel: AsyncChannel<S>)
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    let (mut sr, mut sw) = sock.split();
    let mut a = vec![0u8; 32 * 1024];
    let mut b = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            n = sr.read(&mut a) => match n {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = channel.write_all(&a[..n]).await {
                        warn!(target: "spt_ssh2::multi_hop", "channel write: {e}"); break;
                    }
                }
                Err(e) => { warn!(target: "spt_ssh2::multi_hop", "sock read: {e}"); break; }
            },
            n = channel.read(&mut b) => match n {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = sw.write_all(&b[..n]).await {
                        warn!(target: "spt_ssh2::multi_hop", "sock write: {e}"); break;
                    }
                }
                Err(e) => { warn!(target: "spt_ssh2::multi_hop", "channel read: {e}"); break; }
            }
        }
    }
    let _ = channel.send_eof().await;
    let _ = channel.close().await;
}
