//! [`Ssh2Session`] — the [`spt_protocol::TunnelSession`] implementation.

use std::sync::Arc;

use async_ssh2_lite::session_stream::AsyncSessionStream;
use async_ssh2_lite::AsyncSession;
use async_trait::async_trait;
use parking_lot::Mutex;
use spt_core::{Error, Result};
use spt_protocol::forward::{LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec};
use spt_protocol::handle::ForwardHandle;
use spt_protocol::session::{SessionInfo, TunnelSession};

use crate::errors::from_async_ssh;
use crate::forward;

/// Type-erased handle to one libssh2 SSH session.
///
/// `S` is the underlying transport — `tokio::net::TcpStream` for the common
/// single-hop case, but other AsyncSessionStream-implementing types (e.g.
/// the loopback half of a multi-hop bridge) work too.
pub struct Ssh2Session<S>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    /// Shared async session — wrapped behind a `Mutex` because libssh2 is
    /// not internally Sync; channels can be opened from multiple tasks
    /// provided we serialize the calls that touch the session FFI handle.
    pub(crate) session: Arc<Mutex<AsyncSession<S>>>,
    /// Cached info populated at handshake time.
    pub(crate) info: SessionInfo,
}

impl<S> Ssh2Session<S>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    /// Construct a new session wrapper.
    #[must_use]
    pub fn new(session: AsyncSession<S>, info: SessionInfo) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
            info,
        }
    }

    /// Borrow the inner session under its mutex.
    #[must_use]
    pub fn inner(&self) -> Arc<Mutex<AsyncSession<S>>> {
        self.session.clone()
    }
}

#[async_trait]
impl<S> TunnelSession for Ssh2Session<S>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
        forward::open_local(self.session.clone(), spec).await
    }

    async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
        forward::open_remote(self.session.clone(), spec).await
    }

    async fn open_udp_forward(&mut self, _spec: &UdpForwardSpec) -> Result<ForwardHandle> {
        Err(Error::UnsupportedPlatform(
            "ssh2 does not support UDP forwards".into(),
        ))
    }

    async fn keepalive(&mut self) -> Result<()> {
        let s = self.session.lock().clone();
        s.keepalive_send()
            .await
            .map(|_| ())
            .map_err(|e| from_async_ssh("keepalive_send", e))
    }

    async fn close(self: Box<Self>) -> Result<()> {
        let s = self.session.lock().clone();
        s.disconnect(None, "spt: session close", None)
            .await
            .map_err(|e| Error::SessionCloseFailed(format!("disconnect: {e}")))
    }

    fn session_info(&self) -> SessionInfo {
        self.info.clone()
    }
}
