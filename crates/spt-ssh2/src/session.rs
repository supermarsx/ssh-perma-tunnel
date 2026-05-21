//! [`Ssh2Session`] — the [`spt_protocol::TunnelSession`] implementation.

use std::sync::Arc;

use async_ssh2_lite::session_stream::AsyncSessionStream;
use async_ssh2_lite::AsyncSession;
use async_trait::async_trait;
use parking_lot::Mutex;
use spt_core::{Error, Result};
use spt_protocol::forward::{
    DynamicForwardSpec, LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec,
};
use spt_protocol::handle::ForwardHandle;
use spt_protocol::session::{SessionInfo, TunnelSession};

use crate::errors::from_async_ssh;
use crate::forward;

// t6-e7:start scripting hook integration (do not touch the contents of these
// markers in t6-e13 or later — the script engine handle and its dispatch
// helpers live exclusively inside the t6-e7 marker pair so subsequent
// executors can extend `Ssh2Session` around the markers without merge pain).
use spt_scripting::config::HookName;
use spt_scripting::event::Event;
use spt_scripting::ScriptEngine;
// t6-e7:end

// t6-e13:start obfuscation transport integration. Hook surface only — the
// connect dispatcher itself lives in `crate::connect`. This block holds the
// audit-hook plumbing so the supervisor can attach a real audit subscriber
// before the first connect.
use spt_obfs::AuditHook;
// t6-e13:end

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
    // t6-e7:start
    /// Optional scripting engine for lifecycle hooks. `None` means the
    /// profile has no `[profiles.script]` configured; hook dispatch is a
    /// branch-predicted no-op with zero allocation.
    pub(crate) script_engine: Option<Arc<ScriptEngine>>,
    // t6-e7:end
    // t6-e13:start
    /// Static name of the obfuscation transport that produced the
    /// underlying byte stream (`obfs4`, `meek-http`, `ssh-over-websocket`,
    /// `ssh-over-shadowsocks`). `None` when the plain TCP path was used.
    /// Used for audit hooks and metrics labels.
    pub(crate) obfs_transport_name: Option<&'static str>,
    /// Optional audit hook for obfuscation-transport selection events.
    /// `None` keeps the connect path free of overhead.
    pub(crate) obfs_audit: Option<Arc<dyn AuditHook>>,
    // t6-e13:end
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
            // t6-e7:start
            script_engine: None,
            // t6-e7:end
            // t6-e13:start
            obfs_transport_name: None,
            obfs_audit: None,
            // t6-e13:end
        }
    }

    /// Borrow the inner session under its mutex.
    #[must_use]
    pub fn inner(&self) -> Arc<Mutex<AsyncSession<S>>> {
        self.session.clone()
    }

    // t6-e7:start
    /// Attach a scripting engine to this session. The engine is built by
    /// `spt-bin` from the profile's `[profiles.script]` config; passing
    /// `None` (the default) keeps every hook a no-op.
    pub fn with_script_engine(mut self, engine: Option<Arc<ScriptEngine>>) -> Self {
        self.script_engine = engine;
        self
    }

    /// Dispatch a structured event to the configured script hook. Returns
    /// silently when no engine is attached, when the hook slot is empty,
    /// or when the script side raises a non-fatal error (logged at WARN).
    /// Sandbox-limit violations are forwarded to the caller so the
    /// supervisor can record the offence and continue the session.
    pub fn dispatch_script_event(&self, hook: HookName, event: &Event) -> Result<()> {
        let Some(engine) = self.script_engine.as_ref() else {
            return Ok(());
        };
        match engine.invoke(hook, event) {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!(hook = %hook, error = %e, "spt-ssh2: script hook failed");
                Err(e.into())
            }
        }
    }
    // t6-e7:end

    // t6-e13:start
    /// Attach an obfuscation audit hook to this session. The supervisor
    /// uses this to install a real audit subscriber once
    /// `crate::connect::connect_to_endpoint` has resolved the transport;
    /// `None` keeps the hook free of overhead.
    pub fn with_obfs_audit(mut self, audit: Option<Arc<dyn AuditHook>>) -> Self {
        self.obfs_audit = audit;
        self
    }

    /// Record the static name of the obfuscation transport that produced
    /// the underlying byte stream. Invoked by the connect path immediately
    /// after the obfuscation handshake completes.
    pub fn with_obfs_transport_name(mut self, name: Option<&'static str>) -> Self {
        self.obfs_transport_name = name;
        self
    }

    /// Borrow the obfuscation transport identifier (if any) — exposed for
    /// observability and the Bwire audit subscriber.
    #[must_use]
    pub fn obfs_transport_name(&self) -> Option<&'static str> {
        self.obfs_transport_name
    }
    // t6-e13:end
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

    async fn open_dynamic_forward(&mut self, spec: &DynamicForwardSpec) -> Result<ForwardHandle> {
        forward::open_dynamic(self.session.clone(), spec).await
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
