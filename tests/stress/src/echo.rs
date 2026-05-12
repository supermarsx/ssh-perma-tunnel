//! Tiny in-process TCP echo server. Used by the stress tests as a
//! deterministic local target. Bound to `127.0.0.1:0` so each test gets a
//! fresh ephemeral port without coordination.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Handle to a running echo server. Drop or call [`EchoServer::shutdown`] to
/// stop the accept loop and join the task.
pub struct EchoServer {
    /// Address the listener is bound to.
    pub addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl EchoServer {
    /// Bind on `127.0.0.1:0` and start accepting echo connections in the
    /// current Tokio runtime.
    pub async fn start() -> io::Result<Self> {
        Self::start_with(ConnectionMode::Persistent).await
    }

    /// Bind on `127.0.0.1:0` and start an echo server that closes each
    /// connection after one echoed read.
    ///
    /// This is useful for long-running connection-churn soaks because the
    /// server performs the active close. Clients can observe EOF before
    /// dropping their sockets, which reduces client-side ephemeral port
    /// reuse pressure on Windows.
    pub async fn start_one_shot() -> io::Result<Self> {
        Self::start_with(ConnectionMode::CloseAfterFirstWrite).await
    }

    async fn start_with(mode: ConnectionMode) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (tx, mut rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    incoming = listener.accept() => {
                        let Ok((mut sock, _)) = incoming else { break; };
                        tokio::spawn(async move {
                            serve_connection(&mut sock, mode).await;
                        });
                    }
                }
            }
        });
        Ok(Self {
            addr,
            shutdown: Some(tx),
            task: Some(task),
        })
    }

    /// Cooperative shutdown.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

#[derive(Clone, Copy)]
enum ConnectionMode {
    Persistent,
    CloseAfterFirstWrite,
}

async fn serve_connection(sock: &mut TcpStream, mode: ConnectionMode) {
    let mut buf = [0u8; 4096];
    loop {
        match sock.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if sock.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                if matches!(mode, ConnectionMode::CloseAfterFirstWrite) {
                    break;
                }
            }
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}
