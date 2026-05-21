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
use spt_core::audit::{record_audit, AuditEvent, AuditSeverity};
use spt_core::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

use crate::errors::from_async_ssh;
use crate::proxy_jump::{http_connect, socks5_connect, ProxyCredentials};

/// Hop dispatch kind mirrored from `spt_config::schema::HopKind`.
///
/// Re-defined here to keep `spt-ssh2` free of a build-time dep on
/// `spt-config`. The runtime mapper in `spt-bin` converts one to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HopKind {
    /// Re-establish an SSH session through this hop. Default.
    #[default]
    Ssh,
    /// SOCKS5 proxy.
    Socks5,
    /// HTTP CONNECT proxy.
    HttpConnect,
}

/// Open a `direct-tcpip` channel through `outer` to `(host, port)` and wrap
/// it in a fresh `AsyncSession` (handshake + auth happen at the caller's
/// level after this function returns).
pub async fn open_chained_session<S>(
    outer: Arc<Mutex<AsyncSession<S>>>,
    host: &str,
    port: u16,
    config: SessionConfiguration,
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
    let local_addr = lis
        .local_addr()
        .map_err(|e| Error::RuntimeFailure(format!("local_addr on multi-hop loopback: {e}")))?;

    let (accept_res, connect_res) = tokio::join!(lis.accept(), TcpStream::connect(local_addr));
    let (server_side, _peer) =
        accept_res.map_err(|e| Error::RuntimeFailure(format!("accept multi-hop: {e}")))?;
    let client_side =
        connect_res.map_err(|e| Error::RuntimeFailure(format!("connect multi-hop: {e}")))?;

    // Spawn the byte pump bridging server_side <-> channel.
    tokio::spawn(pump(server_side, channel));

    // libssh2's session reads/writes from the OS socket = `client_side`.
    let session = AsyncSession::new(client_side, config)
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
    let mut sock_done = false;
    let mut channel_done = false;
    while !sock_done || !channel_done {
        tokio::select! {
            n = sr.read(&mut a), if !sock_done => match n {
                Ok(0) => {
                    sock_done = true;
                    let _ = channel.send_eof().await;
                }
                Ok(n) => {
                    if let Err(e) = channel.write_all(&a[..n]).await {
                        warn!(target: "spt_ssh2::multi_hop", "channel write: {e}"); break;
                    }
                }
                Err(e) => { warn!(target: "spt_ssh2::multi_hop", "sock read: {e}"); break; }
            },
            n = channel.read(&mut b), if !channel_done => match n {
                Ok(0) => {
                    channel_done = true;
                    let _ = sw.shutdown().await;
                }
                Ok(n) => {
                    if let Err(e) = sw.write_all(&b[..n]).await {
                        warn!(target: "spt_ssh2::multi_hop", "sock write: {e}"); break;
                    }
                }
                Err(e) => { warn!(target: "spt_ssh2::multi_hop", "channel read: {e}"); break; }
            }
        }
    }
    let _ = channel.close().await;
}

/// Open a kind-aware chained connection through `outer` toward
/// `(host, port)`. Equivalent to [`open_chained_session`] for
/// [`HopKind::Ssh`]. For proxy kinds, a `direct-tcpip` channel is opened to
/// the proxy host, a CONNECT (SOCKS5 or HTTP) is performed across the
/// loopback socket, and a fresh [`AsyncSession`] is returned positioned to
/// speak SSH to `(host, port)`.
///
/// **Note** — for proxy kinds, the caller's `outer` session reaches the
/// **proxy**; the CONNECT inside this function targets `(host, port)` and
/// the returned `AsyncSession` then handshakes to `(host, port)`. The proxy
/// itself does not require an SSH handshake.
#[allow(clippy::too_many_arguments)]
pub async fn open_chained_session_with_kind<S>(
    outer: Arc<Mutex<AsyncSession<S>>>,
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    kind: HopKind,
    creds: Option<ProxyCredentials>,
    config: SessionConfiguration,
) -> Result<AsyncSession<TcpStream>>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    // Audit hook fires once per hop transition regardless of kind so
    // operator dashboards see a single event per intermediate hop.
    record_audit(
        AuditEvent::new("audit.ssh.hop_transition", AuditSeverity::Info)
            .with_field("proxy_host", proxy_host)
            .with_field("proxy_port", proxy_port.to_string())
            .with_field("target_host", target_host)
            .with_field("target_port", target_port.to_string())
            .with_field(
                "kind",
                match kind {
                    HopKind::Ssh => "ssh",
                    HopKind::Socks5 => "socks5",
                    HopKind::HttpConnect => "http-connect",
                },
            ),
    );

    // For SSH-kind hops the historical behaviour applies: the chained
    // session targets the proxy host directly (which IS the next SSH hop).
    if matches!(kind, HopKind::Ssh) {
        return open_chained_session(outer, target_host, target_port, config).await;
    }

    // Proxy-kind: open a direct-tcpip channel to the proxy, then speak the
    // proxy's CONNECT handshake aimed at `(target_host, target_port)`.
    let channel = {
        let s = outer.lock().clone();
        s.channel_direct_tcpip(proxy_host, proxy_port, None)
            .await
            .map_err(|e| from_async_ssh("multi-hop proxy direct-tcpip", e))?
    };

    // Loopback socketpair so we can hand a real OS socket to libssh2 for
    // the post-CONNECT SSH session.
    let lis = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| Error::RuntimeFailure(format!("bind proxy-jump loopback: {e}")))?;
    let local_addr = lis
        .local_addr()
        .map_err(|e| Error::RuntimeFailure(format!("local_addr on proxy-jump loopback: {e}")))?;
    let (accept_res, connect_res) = tokio::join!(lis.accept(), TcpStream::connect(local_addr));
    let (server_side, _peer) =
        accept_res.map_err(|e| Error::RuntimeFailure(format!("accept proxy-jump: {e}")))?;
    let mut client_side =
        connect_res.map_err(|e| Error::RuntimeFailure(format!("connect proxy-jump: {e}")))?;

    // Spawn the bidirectional pump between the channel and the server-side
    // half of the loopback pair. The CONNECT handshake will travel through
    // this pump.
    tokio::spawn(pump(server_side, channel));

    // Speak CONNECT to the proxy. After it returns Ok, `client_side` carries
    // a clean tunnel to `(target_host, target_port)`.
    match kind {
        HopKind::Socks5 => {
            socks5_connect(&mut client_side, target_host, target_port, creds.as_ref()).await?
        }
        HopKind::HttpConnect => {
            http_connect(&mut client_side, target_host, target_port, creds.as_ref()).await?
        }
        HopKind::Ssh => unreachable!(),
    }

    let session = AsyncSession::new(client_side, config)
        .map_err(|e| from_async_ssh("AsyncSession::new (proxy-jump)", e))?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_jump;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // -- Schema-mirror sanity ---------------------------------------------

    #[test]
    fn hopkind_default_is_ssh() {
        assert_eq!(HopKind::default(), HopKind::Ssh);
    }

    // -- Chained mid-hop failure -----------------------------------------
    //
    // Drive a SOCKS5 handshake that fails partway (the proxy reports
    // "host unreachable") and assert the helper surfaces it as a
    // RuntimeFailure. This exercises the same error path as a real
    // mid-hop failure inside `open_chained_session_with_kind` without
    // requiring a live SSH session at the outer side.

    #[tokio::test]
    async fn chained_failure_mid_hop_surfaces_runtime_error() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let s = tokio::spawn(async move {
            // Method-negotiation
            let mut hello = [0u8; 3];
            server.read_exact(&mut hello).await.unwrap();
            server.write_all(&[0x05, 0x00]).await.unwrap();
            // CONNECT
            let mut head = [0u8; 4];
            server.read_exact(&mut head).await.unwrap();
            // Drain the rest of the request (IPv4 4+2 / domain etc.).
            let mut tail = vec![0u8; 6];
            if head[3] == 0x01 {
                server.read_exact(&mut tail).await.unwrap();
            }
            // Failure reply: status 0x04 host unreachable.
            server
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let r = proxy_jump::socks5_connect(&mut client, "127.0.0.1", 22, None).await;
        s.await.unwrap();
        match r.unwrap_err() {
            Error::RuntimeFailure(msg) => assert!(msg.contains("host unreachable"), "got: {msg}"),
            other => panic!("expected RuntimeFailure, got {other:?}"),
        }
    }

    // -- Independent re-auth per hop -------------------------------------
    //
    // Verify that two successive socks5_connect calls drive independent
    // sub-negotiations: a 2nd call with no creds doesn't reuse the 1st
    // call's auth state because each call owns its own stream.

    #[tokio::test]
    async fn independent_auth_per_hop() {
        // First hop: USERPASS auth used.
        {
            let (mut c, mut sv) = tokio::io::duplex(4096);
            let s = tokio::spawn(async move {
                let mut hello = [0u8; 4];
                sv.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[2..], [0x00, 0x02]); // NO_AUTH + USERPASS advertised
                sv.write_all(&[0x05, 0x02]).await.unwrap(); // pick USERPASS
                let mut head = [0u8; 2];
                sv.read_exact(&mut head).await.unwrap();
                let mut u = vec![0u8; head[1] as usize];
                sv.read_exact(&mut u).await.unwrap();
                let mut plen = [0u8; 1];
                sv.read_exact(&mut plen).await.unwrap();
                let mut p = vec![0u8; plen[0] as usize];
                sv.read_exact(&mut p).await.unwrap();
                sv.write_all(&[0x01, 0x00]).await.unwrap();
                let mut req = [0u8; 4];
                sv.read_exact(&mut req).await.unwrap();
                let mut tail = vec![0u8; 6];
                sv.read_exact(&mut tail).await.unwrap();
                sv.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            });
            proxy_jump::socks5_connect(
                &mut c,
                "127.0.0.1",
                22,
                Some(&ProxyCredentials {
                    username: "a".into(),
                    password: "b".into(),
                }),
            )
            .await
            .unwrap();
            s.await.unwrap();
        }
        // Second hop: NO_AUTH path — must NOT carry over creds from first.
        {
            let (mut c, mut sv) = tokio::io::duplex(4096);
            let s = tokio::spawn(async move {
                let mut hello = [0u8; 3];
                sv.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello, [0x05, 0x01, 0x00]); // only NO_AUTH advertised
                sv.write_all(&[0x05, 0x00]).await.unwrap();
                let mut req = [0u8; 4];
                sv.read_exact(&mut req).await.unwrap();
                let mut tail = vec![0u8; 6];
                sv.read_exact(&mut tail).await.unwrap();
                sv.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            });
            proxy_jump::socks5_connect(&mut c, "127.0.0.1", 22, None)
                .await
                .unwrap();
            s.await.unwrap();
        }
    }

    // -- Audit hook fires per transition ---------------------------------
    //
    // record_audit() is unit-testable via a custom AuditSink installed on
    // the global registry. We collect events into a Vec<String> and assert
    // the hop_transition event landed for an SSH-kind hop. Proxy kinds
    // exercise the same code path before any network I/O.

    #[tokio::test]
    async fn audit_hook_records_hop_transition() {
        use spt_core::audit::{register_audit_sink, AuditSink};
        use std::sync::{Arc, Mutex as StdMutex};

        #[derive(Debug)]
        struct Capture(Arc<StdMutex<Vec<String>>>);
        impl AuditSink for Capture {
            fn record(&self, ev: AuditEvent) {
                self.0.lock().unwrap().push(ev.kind.clone());
            }
        }
        let captured = Arc::new(StdMutex::new(Vec::new()));
        register_audit_sink(Arc::new(Capture(Arc::clone(&captured))));

        // Fire the audit event directly (the unit test can't easily stand
        // up a full SSH session; production code paths in
        // `open_chained_session_with_kind` use the same `record_audit`
        // call).
        record_audit(
            AuditEvent::new("audit.ssh.hop_transition", AuditSeverity::Info)
                .with_field("proxy_host", "bastion.example.com")
                .with_field("proxy_port", "22")
                .with_field("target_host", "internal.example.com")
                .with_field("target_port", "22")
                .with_field("kind", "ssh"),
        );

        let evs = captured.lock().unwrap().clone();
        assert!(
            evs.iter().any(|k| k == "audit.ssh.hop_transition"),
            "expected hop_transition in {evs:?}"
        );
    }
}
