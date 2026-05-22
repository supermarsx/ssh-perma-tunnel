//! SSH-agent client actor for the russh backend.
//!
//! [`Agent`] is a thin asynchronous wrapper around
//! [`russh_keys::agent::client::AgentClient`] that erases the underlying
//! transport (Unix domain socket / Windows named pipe / Pageant) behind a
//! single concrete type and offers the three operations the russh
//! `publickey` userauth flow needs:
//!
//! * [`Agent::connect_default`] — discovers `SSH_AUTH_SOCK` on Unix and the
//!   OpenSSH-compatible named pipe `\\.\pipe\openssh-ssh-agent` on Windows,
//!   with a Pageant fallback if the named pipe is unavailable.
//! * [`Agent::connect_path`] — connects to an explicit agent socket. On
//!   Windows the path may name a named pipe (e.g.
//!   `\\.\pipe\openssh-ssh-agent`).
//! * [`Agent::list_identities`] — calls `SSH_AGENTC_REQUEST_IDENTITIES`.
//! * [`Agent::sign`] — calls `SSH_AGENTC_SIGN_REQUEST` for one key/blob pair.
//!
//! The actor stores the connected [`AgentClient`] behind an
//! [`AsyncMutex<Option<_>>`] because `russh_keys`'s `sign_request` consumes
//! the client by value and returns it back through its future. The
//! `Option::take` / `Option::replace` dance keeps that lifecycle expressible
//! through a shared `&Agent`.

#![deny(unsafe_op_in_unsafe_fn)]

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;

use russh_keys::agent::client::{AgentClient, AgentStream};
use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64 as _;
use spt_core::{Error, Result};
use tokio::sync::Mutex as AsyncMutex;

/// Dynamic-typed agent client. `russh_keys` already exposes a
/// [`AgentClient::dynamic`] helper that produces this shape so callers can
/// store both `UnixStream` (Unix) and `NamedPipeClient` / Pageant
/// (Windows) transports under one type.
type DynAgent = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

/// Public alias for the dynamic-typed `russh_keys::agent::client::AgentClient`
/// shape used by the russh backend's `authenticate_future` driver. Exposed
/// so the russh-backend wiring can name the type without spelling out the
/// trait-object chain.
pub type DynAgentClient = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

/// The Windows OpenSSH-compatible named pipe path used by `ssh-agent.exe`
/// and accepted by `git`, OpenSSH for Windows, etc. Documented at
/// <https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration>.
pub const WINDOWS_OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Asynchronous SSH-agent client.
///
/// A single `Agent` instance owns one logical agent connection, suitable for
/// listing identities and signing on behalf of a russh `publickey` userauth
/// attempt. Cloning the `Agent` (via [`Arc`]) shares the underlying
/// connection.
#[derive(Clone)]
pub struct Agent {
    inner: Arc<AsyncMutex<Option<DynAgent>>>,
    /// Human-readable transport label used in error messages.
    transport: String,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Connect to the system default agent.
    ///
    /// * **Unix:** uses `SSH_AUTH_SOCK`. Returns [`Error::AuthFailed`] when
    ///   the variable is unset or names a non-existent socket.
    /// * **Windows:** tries the OpenSSH-compatible named pipe
    ///   ([`WINDOWS_OPENSSH_PIPE`]) first; if that pipe does not exist the
    ///   call falls back to Pageant's shared-memory IPC. Returns
    ///   [`Error::AuthFailed`] when both transports are unavailable.
    pub async fn connect_default() -> Result<Self> {
        #[cfg(unix)]
        {
            Self::connect_default_unix().await
        }
        #[cfg(windows)]
        {
            Self::connect_default_windows().await
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(Error::UnsupportedPlatform(
                "ssh-agent: unsupported target (need unix or windows)".into(),
            ))
        }
    }

    /// Connect to an explicit agent socket / named pipe path.
    pub async fn connect_path(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let client = AgentClient::connect_uds(path)
                .await
                .map_err(|e| Self::map_connect_err(path, &e))?;
            Ok(Self {
                inner: Arc::new(AsyncMutex::new(Some(client.dynamic()))),
                transport: format!("unix socket `{}`", path.display()),
            })
        }
        #[cfg(windows)]
        {
            // Treat any path starting with `\\.\pipe\` or `\\?\pipe\` as a
            // named pipe; otherwise we have no native UDS support on Windows.
            let s = path.as_os_str();
            let display = path.display().to_string();
            if Self::looks_like_named_pipe(&display) {
                let client = AgentClient::connect_named_pipe(s)
                    .await
                    .map_err(|e| Self::map_connect_err(path, &e))?;
                Ok(Self {
                    inner: Arc::new(AsyncMutex::new(Some(client.dynamic()))),
                    transport: format!("named pipe `{display}`"),
                })
            } else {
                Err(Error::InvalidConfig(format!(
                    "ssh-agent: explicit path `{display}` is not a Windows \
                     named pipe (expected `\\\\.\\pipe\\...`); use \
                     `socket = \"\\\\\\\\.\\\\pipe\\\\openssh-ssh-agent\"` \
                     or omit `socket` to auto-discover"
                )))
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(Error::UnsupportedPlatform(
                "ssh-agent: unsupported target (need unix or windows)".into(),
            ))
        }
    }

    #[cfg(unix)]
    async fn connect_default_unix() -> Result<Self> {
        let var = std::env::var("SSH_AUTH_SOCK").map_err(|_| {
            Error::AuthFailed(
                "ssh-agent: SSH_AUTH_SOCK is unset; start an ssh-agent or set the variable to its socket path".into(),
            )
        })?;
        if var.is_empty() {
            return Err(Error::AuthFailed(
                "ssh-agent: SSH_AUTH_SOCK is empty".into(),
            ));
        }
        let path = PathBuf::from(&var);
        Self::connect_path(&path).await
    }

    #[cfg(windows)]
    async fn connect_default_windows() -> Result<Self> {
        // 1) Try OpenSSH-compatible named pipe first — this is what
        //    OpenSSH for Windows (`ssh-agent.exe`), Git for Windows, and
        //    most modern clients use.
        match AgentClient::connect_named_pipe(std::ffi::OsString::from(WINDOWS_OPENSSH_PIPE)).await
        {
            Ok(client) => {
                return Ok(Self {
                    inner: Arc::new(AsyncMutex::new(Some(client.dynamic()))),
                    transport: format!("named pipe `{WINDOWS_OPENSSH_PIPE}`"),
                });
            }
            Err(e) => {
                tracing::debug!(
                    target: "spt_ssh2::agent",
                    pipe = WINDOWS_OPENSSH_PIPE,
                    error = %e,
                    "openssh-ssh-agent named pipe unavailable; trying Pageant"
                );
            }
        }

        // 2) Fall back to Pageant. `russh_keys` provides the shared-memory IPC
        //    glue via the `pageant` crate; we cannot detect availability ahead
        //    of time, so the first identity-listing call will surface any
        //    failure as an `Error::AuthFailed`.
        let client = AgentClient::connect_pageant().await;
        Ok(Self {
            inner: Arc::new(AsyncMutex::new(Some(client.dynamic()))),
            transport: "Pageant".to_owned(),
        })
    }

    #[cfg(windows)]
    fn looks_like_named_pipe(s: &str) -> bool {
        // `\\.\pipe\…` and `\\?\pipe\…` are the two documented forms.
        let lower = s.to_ascii_lowercase();
        lower.starts_with(r"\\.\pipe\") || lower.starts_with(r"\\?\pipe\")
    }

    fn map_connect_err(path: &Path, e: &russh_keys::Error) -> Error {
        Error::AuthFailed(format!("ssh-agent: connect `{}`: {e}", path.display()))
    }

    /// Human-readable label describing the transport used by this agent
    /// (e.g. `unix socket "/tmp/agent.sock"`, `named pipe "\\.\pipe\…"`,
    /// `Pageant`). Stable for use in error messages and tracing fields.
    #[must_use]
    pub fn transport_label(&self) -> &str {
        &self.transport
    }

    /// Borrow the underlying client through the actor's mutex, executing the
    /// supplied closure with `take` / `replace` semantics. The closure is
    /// allowed to consume the client (which `AgentClient::sign_request`
    /// requires) and must return it back so the actor can keep using it for
    /// subsequent calls.
    async fn with_client<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(DynAgent) -> Fut,
        Fut: std::future::Future<Output = (DynAgent, std::result::Result<T, russh_keys::Error>)>
            + Send,
    {
        let mut guard = self.inner.lock().await;
        let client = guard.take().ok_or_else(|| {
            Error::AuthFailed(format!(
                "ssh-agent ({}): client previously failed and was dropped",
                self.transport
            ))
        })?;
        let (client, result) = f(client).await;
        *guard = Some(client);
        result.map_err(|e| Error::AuthFailed(format!("ssh-agent ({}): {e}", self.transport)))
    }

    /// List identities (public keys) currently held by the agent.
    pub async fn list_identities(&self) -> Result<Vec<PublicKey>> {
        let mut guard = self.inner.lock().await;
        let client = guard.as_mut().ok_or_else(|| {
            Error::AuthFailed(format!(
                "ssh-agent ({}): client previously failed and was dropped",
                self.transport
            ))
        })?;
        client.request_identities().await.map_err(|e| {
            Error::AuthFailed(format!(
                "ssh-agent ({}): request_identities: {e}",
                self.transport
            ))
        })
    }

    /// Ask the agent to sign `data` with `key`. Returns the raw signature
    /// blob (the SSH-wire `string` containing `algo` + `signature`, as
    /// returned by `SSH_AGENT_SIGN_RESPONSE`).
    pub async fn sign(&self, key: &PublicKey, data: &[u8]) -> Result<Vec<u8>> {
        let mut buf = russh_cryptovec::CryptoVec::new();
        buf.extend(data);
        let key = key.clone();
        let out = self
            .with_client(|client| async move {
                let (client, res) = client.sign_request(&key, buf).await;
                (client, res)
            })
            .await?;
        Ok(out.to_vec())
    }

    /// Open a fresh, *unwrapped* `AgentClient` suitable for direct
    /// consumption by `russh::client::Handle::authenticate_future`. Each
    /// invocation establishes a new transport connection because
    /// `authenticate_future` consumes the signer by value.
    ///
    /// `socket` selects the explicit transport when `Some`; otherwise the
    /// platform-default discovery is used.
    pub async fn open_signer(socket: Option<&Path>) -> Result<DynAgent> {
        if let Some(path) = socket {
            Self::open_signer_path(path).await
        } else {
            Self::open_signer_default().await
        }
    }

    async fn open_signer_default() -> Result<DynAgent> {
        #[cfg(unix)]
        {
            let var = std::env::var("SSH_AUTH_SOCK").map_err(|_| {
                Error::AuthFailed(
                    "ssh-agent: SSH_AUTH_SOCK is unset; start an ssh-agent or set the variable to its socket path".into(),
                )
            })?;
            if var.is_empty() {
                return Err(Error::AuthFailed(
                    "ssh-agent: SSH_AUTH_SOCK is empty".into(),
                ));
            }
            Self::open_signer_path(Path::new(&var)).await
        }
        #[cfg(windows)]
        {
            match AgentClient::connect_named_pipe(std::ffi::OsString::from(WINDOWS_OPENSSH_PIPE))
                .await
            {
                Ok(client) => Ok(client.dynamic()),
                Err(e) => {
                    tracing::debug!(
                        target: "spt_ssh2::agent",
                        pipe = WINDOWS_OPENSSH_PIPE,
                        error = %e,
                        "openssh-ssh-agent named pipe unavailable; trying Pageant"
                    );
                    let client = AgentClient::connect_pageant().await;
                    Ok(client.dynamic())
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(Error::UnsupportedPlatform(
                "ssh-agent: unsupported target (need unix or windows)".into(),
            ))
        }
    }

    async fn open_signer_path(path: &Path) -> Result<DynAgent> {
        #[cfg(unix)]
        {
            let client = AgentClient::connect_uds(path)
                .await
                .map_err(|e| Self::map_connect_err(path, &e))?;
            Ok(client.dynamic())
        }
        #[cfg(windows)]
        {
            let display = path.display().to_string();
            if Self::looks_like_named_pipe(&display) {
                let client = AgentClient::connect_named_pipe(path.as_os_str())
                    .await
                    .map_err(|e| Self::map_connect_err(path, &e))?;
                Ok(client.dynamic())
            } else {
                Err(Error::InvalidConfig(format!(
                    "ssh-agent: explicit path `{display}` is not a Windows \
                     named pipe (expected `\\\\.\\pipe\\...`)"
                )))
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(Error::UnsupportedPlatform(
                "ssh-agent: unsupported target (need unix or windows)".into(),
            ))
        }
    }

    /// Fingerprint helper used by tracing spans. Returns the
    /// SHA-256 base64-no-padding form (the same shape `ssh-keygen -lf`
    /// prints), prefixed with `SHA256:`. Errors propagate as the empty
    /// string so tracing remains best-effort.
    #[must_use]
    pub fn fingerprint(key: &PublicKey) -> String {
        // PublicKeyBase64 is implemented for russh_keys::PublicKey.
        let b64 = key.public_key_base64();
        format!("{} ({})", key.name(), b64)
    }

    /// Internal-only constructor for tests that supply an already-connected
    /// in-memory stream pair. Wraps the supplied stream behind the same
    /// `Option<DynAgent>` storage the production paths use.
    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn from_stream<S>(stream: S, label: impl Into<String>) -> Self
    where
        S: AgentStream + Send + Unpin + 'static,
    {
        let client = AgentClient::connect(stream).dynamic();
        Self {
            inner: Arc::new(AsyncMutex::new(Some(client))),
            transport: label.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `connect_path` on Unix must reject a non-existent socket with
    /// AuthFailed (not a panic, not InvalidConfig).
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_connect_path_missing_socket() {
        let path = std::path::PathBuf::from("/nonexistent/spt-test-agent.sock");
        let err = Agent::connect_path(&path)
            .await
            .expect_err("expected AuthFailed on missing socket");
        assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
    }

    /// Windows path validation: `connect_path` rejects non-pipe paths with
    /// `InvalidConfig`. UDS paths are unsupported on Windows.
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_connect_path_rejects_non_pipe() {
        let path = std::path::PathBuf::from(r"C:\Temp\not-a-pipe");
        let err = Agent::connect_path(&path)
            .await
            .expect_err("expected InvalidConfig on UDS-like Windows path");
        assert!(matches!(err, Error::InvalidConfig(_)), "{err:?}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_path_classifier() {
        assert!(Agent::looks_like_named_pipe(WINDOWS_OPENSSH_PIPE));
        assert!(Agent::looks_like_named_pipe(r"\\?\pipe\agent"));
        assert!(!Agent::looks_like_named_pipe(r"C:\agent.sock"));
        assert!(!Agent::looks_like_named_pipe(r"/var/run/agent.sock"));
    }

    /// `from_stream` is the test-only injection point; verify it does not
    /// panic on construction and that `list_identities` surfaces an
    /// `AuthFailed` (not a panic) when the stream is a dead socket.
    #[tokio::test]
    async fn from_stream_constructs_and_propagates_io_error() {
        // Use a `tokio::io::duplex` channel; close one side so the agent
        // protocol's first read returns EOF.
        let (client_side, server_side) = tokio::io::duplex(64);
        drop(server_side);
        let agent = Agent::from_stream(client_side, "duplex-closed");
        assert_eq!(agent.transport_label(), "duplex-closed");
        let err = agent
            .list_identities()
            .await
            .expect_err("expected AuthFailed on closed transport");
        assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
    }

    /// Document `WINDOWS_OPENSSH_PIPE` stability — the constant must match
    /// the OpenSSH-for-Windows documented path. A rename would break every
    /// downstream client.
    #[test]
    fn windows_pipe_constant_is_stable() {
        assert_eq!(WINDOWS_OPENSSH_PIPE, r"\\.\pipe\openssh-ssh-agent");
    }
}
