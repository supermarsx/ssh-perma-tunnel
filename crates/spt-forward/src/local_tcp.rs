//! Accept-loop helper used by protocol backends inside their local-TCP
//! `open_local_forward` implementations.
//!
//! Note: the protocol backends are the actual owners of TCP listeners — see
//! the layering note in `lib.rs`. This module provides a generic accept-loop
//! that:
//!
//! * Polls a [`tokio::net::TcpListener`].
//! * Filters peers through a [`crate::ForwardAcl`].
//! * Acquires a permit from a [`crate::ConnectionGate`] (rejecting once the
//!   per-forward cap is hit).
//! * Dispatches each accepted connection to a user-supplied closure that
//!   typically opens a tunnel-side stream and runs
//!   [`crate::copy_bidirectional_throttled`].

use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::acl::ForwardAcl;
use crate::limits::ConnectionGate;

/// Accept-loop driver.
pub struct AcceptLoop {
    listener: TcpListener,
    acl: ForwardAcl,
    gate: ConnectionGate,
    shutdown: Option<oneshot::Receiver<()>>,
}

impl AcceptLoop {
    /// New driver wrapping `listener`. Apply `acl` and `gate` to every
    /// accepted connection.
    pub fn new(listener: TcpListener, acl: ForwardAcl, gate: ConnectionGate) -> Self {
        Self {
            listener,
            acl,
            gate,
            shutdown: None,
        }
    }

    /// Attach a shutdown signal — when the receiver fires, [`Self::run`] exits at
    /// the next accept boundary.
    #[must_use]
    pub fn with_shutdown(mut self, rx: oneshot::Receiver<()>) -> Self {
        self.shutdown = Some(rx);
        self
    }

    /// Run the accept loop. `handle` is invoked once per admitted connection;
    /// the supplied permit must outlive the connection (drop it when done).
    pub async fn run<F, Fut>(self, handle: F) -> std::io::Result<()>
    where
        F: Fn(tokio::net::TcpStream, std::net::SocketAddr, crate::limits::ConnectionPermit) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let Self {
            listener,
            acl,
            gate,
            shutdown,
        } = self;
        let handle = Arc::new(handle);
        let mut shutdown = shutdown;

        loop {
            let accept = listener.accept();
            tokio::pin!(accept);

            let (sock, peer) = if let Some(rx) = shutdown.as_mut() {
                tokio::select! {
                    res = &mut accept => res?,
                    _ = rx => return Ok(()),
                }
            } else {
                accept.await?
            };

            if !acl.decide(peer.ip()).is_allow() {
                tracing::debug!(?peer, "acl: deny");
                drop(sock);
                continue;
            }
            let permit = match gate.try_acquire() {
                Some(p) => p,
                None => {
                    tracing::warn!(?peer, "connection cap reached, rejecting");
                    drop(sock);
                    continue;
                }
            };

            let h = Arc::clone(&handle);
            tokio::spawn(async move {
                h(sock, peer, permit).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn accept_dispatches_and_caps() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let counter = Arc::new(AtomicU32::new(0));
        let counter2 = Arc::clone(&counter);
        let (tx, rx) = oneshot::channel();

        let driver = AcceptLoop::new(listener, ForwardAcl::allow_all(), ConnectionGate::new(0))
            .with_shutdown(rx);

        let server = tokio::spawn(async move {
            driver
                .run(move |mut sock, _peer, permit| {
                    let c = Arc::clone(&counter2);
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        let _ = sock.write_all(b"hi").await;
                        let _ = sock.shutdown().await;
                        drop(permit);
                    }
                })
                .await
                .unwrap();
        });

        for _ in 0..3 {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let mut buf = [0u8; 2];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hi");
        }

        let _ = tx.send(());
        let _ = server.await;
        assert!(counter.load(Ordering::SeqCst) >= 3);
    }
}
