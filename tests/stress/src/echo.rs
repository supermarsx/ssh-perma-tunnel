//! Tiny in-process TCP echo server. Used by the stress tests as a
//! deterministic local target. Bound to `127.0.0.1:0` so each test gets a
//! fresh ephemeral port without coordination.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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
                            let mut buf = [0u8; 4096];
                            loop {
                                match sock.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if sock.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
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
