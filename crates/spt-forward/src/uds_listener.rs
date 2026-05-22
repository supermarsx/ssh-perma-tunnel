//! Local UNIX-socket listener for the `local_uds` link kind (t6-e2).
//!
//! When a profile declares
//!
//! ```toml
//! [[profiles.forwards]]
//! name = "db"
//! type = "local"
//! kind = "local_uds"
//! local_socket_path = "/tmp/db.sock"
//! remote_socket_path = "/run/postgresql/.s.PGSQL.5432"
//! ```
//!
//! the supervisor binds an `AF_UNIX` listener on `local_socket_path`,
//! accepts client streams, and for each accepted stream asks the SSH2
//! backend to open a `direct-streamlocal@openssh.com` channel to
//! `remote_socket_path` and bidirectionally bridges the two.
//!
//! This module owns the *listener half* only. The channel-open is owned
//! by `spt_ssh2::uds_forward::open_local_uds`. Wiring the two together
//! into a [`ForwardRunner`](crate::ForwardRunner) is deferred to t6-Bwire
//! — this executor's lock scope intentionally stops at the building
//! blocks.
//!
//! ## Portability
//!
//! `AF_UNIX` listening is gated behind `cfg(unix)`. On Windows the
//! constructor returns [`spt_core::Error::UnsupportedPlatform`] (exit
//! code 10) — see [`open_listener`]. Outbound `direct-streamlocal`
//! channel opens (the "send onto a remote UDS" direction) remain
//! available on Windows; only the local-bind half is Unix-only.

use spt_core::{Error, Result};

/// Maximum permitted length for `local_socket_path`. Conservative cap
/// shared with [`spt_ssh2::uds_forward::validate_socket_path`].
const MAX_PATH_LEN: usize = 4096;

/// Validate the *local* UDS path against the same rules used for the
/// remote side. The platform layer is permitted to enforce stricter
/// limits (Linux `sun_path` is typically 108 bytes); we accept up to
/// 4096 and let the kernel reject longer values at bind time.
pub fn validate_local_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidConfig(
            "UDS local_socket_path is empty".into(),
        ));
    }
    if !path.starts_with('/') {
        return Err(Error::InvalidConfig(format!(
            "UDS local_socket_path must be absolute (start with `/`): `{path}`"
        )));
    }
    if path.contains('\0') {
        return Err(Error::InvalidConfig(format!(
            "UDS local_socket_path contains NUL byte: `{}`",
            path.escape_default()
        )));
    }
    if path.len() > MAX_PATH_LEN {
        return Err(Error::InvalidConfig(format!(
            "UDS local_socket_path exceeds {MAX_PATH_LEN} bytes ({} bytes)",
            path.len()
        )));
    }
    Ok(())
}

/// Construct and bind a [`UdsListener`] on the given local path.
///
/// On non-Unix targets the function returns
/// [`Error::UnsupportedPlatform`] without touching the filesystem.
#[cfg(unix)]
pub async fn open_listener(local_path: &str) -> Result<UdsListener> {
    validate_local_path(local_path)?;
    UdsListener::bind(local_path).await
}

/// Windows / non-Unix stub: returns `UnsupportedPlatform` cleanly.
///
/// The error message is parallel to
/// `spt_ssh2::uds_forward::windows_local_uds_unsupported` so operators
/// see one diagnostic regardless of which crate they touched first.
///
/// The signature mirrors the `cfg(unix)` variant — `async` and same
/// return type — so callers (e.g. a future `ForwardRunner`) can use the
/// same `.await` expression without per-target `cfg`.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
pub async fn open_listener(_local_path: &str) -> Result<UdsListener> {
    Err(Error::UnsupportedPlatform(
        "local_uds (client-side UNIX-socket listener) requires a Unix target; \
         outbound direct-streamlocal channels remain available, but binding the local \
         UDS listener is not supported on Windows"
            .into(),
    ))
}

// ---------------------------------------------------------------------------
// Unix-only listener
// ---------------------------------------------------------------------------

/// A bound `AF_UNIX` listener for the `local_uds` link kind. On non-Unix
/// targets this is a zero-sized stub that never instantiates (the only
/// constructor — [`open_listener`] — returns `UnsupportedPlatform`).
#[cfg(unix)]
pub struct UdsListener {
    inner: tokio::net::UnixListener,
    path: std::path::PathBuf,
    /// When `true`, [`Drop`] unlinks `path`. Default `true` for the
    /// supervisor-owned case; `false` when the caller wants to manage
    /// the lifecycle externally (set via
    /// [`UdsListener::keep_socket_on_drop`]).
    unlink_on_drop: bool,
}

/// Non-Unix stub. The only constructor — [`open_listener`] — returns
/// `Error::UnsupportedPlatform` on this target, so this type is
/// uninhabited at runtime.
#[cfg(not(unix))]
pub struct UdsListener {
    _never: std::convert::Infallible,
}

#[cfg(unix)]
impl UdsListener {
    /// Bind a fresh listener on `path`.
    ///
    /// If the path already exists as an `AF_UNIX` socket file the bind
    /// will fail with `AddrInUse`; callers must arrange for a clean
    /// path (typically by unlinking it via
    /// [`Self::unlink_existing_if_socket`] beforehand).
    pub async fn bind(path: &str) -> Result<Self> {
        let bind_path = std::path::PathBuf::from(path);
        let inner =
            tokio::net::UnixListener::bind(&bind_path).map_err(|e| Error::LocalBindFailed {
                address: path.to_owned(),
                reason: format!("bind UNIX socket: {e}"),
            })?;
        Ok(Self {
            inner,
            path: bind_path,
            unlink_on_drop: true,
        })
    }

    /// If `path` exists and is an `AF_UNIX` socket file, remove it. Other
    /// file types (regular files, directories, devices) are left
    /// untouched and the function succeeds — the subsequent
    /// [`Self::bind`] will fail loudly via the kernel.
    pub fn unlink_existing_if_socket(path: &str) -> Result<()> {
        use std::os::unix::fs::FileTypeExt as _;
        let p = std::path::Path::new(path);
        match std::fs::symlink_metadata(p) {
            Ok(meta) if meta.file_type().is_socket() => {
                std::fs::remove_file(p).map_err(|e| Error::LocalBindFailed {
                    address: path.to_owned(),
                    reason: format!("remove stale UNIX socket: {e}"),
                })?;
                Ok(())
            }
            Ok(_) | Err(_) => Ok(()),
        }
    }

    /// Disable the drop-time unlink (e.g. when an outer harness owns the
    /// path's lifecycle, like an integration test using `tempfile::TempDir`).
    pub fn keep_socket_on_drop(mut self) -> Self {
        self.unlink_on_drop = false;
        self
    }

    /// Path the listener is bound on.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Accept one inbound connection. Wraps
    /// `tokio::net::UnixListener::accept` and remaps the error into a
    /// workspace [`Error`].
    pub async fn accept(&self) -> Result<tokio::net::UnixStream> {
        let (sock, _peer) = self.inner.accept().await.map_err(|e| {
            Error::RuntimeFailure(format!(
                "accept on UNIX socket `{}`: {e}",
                self.path.display()
            ))
        })?;
        Ok(sock)
    }
}

#[cfg(unix)]
impl Drop for UdsListener {
    fn drop(&mut self) {
        if self.unlink_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_local_path_accepts_typical_absolute_paths() {
        validate_local_path("/tmp/foo.sock").unwrap();
        validate_local_path("/run/srv.sock").unwrap();
    }

    #[test]
    fn validate_local_path_rejects_empty() {
        let e = validate_local_path("").unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("empty")));
    }

    #[test]
    fn validate_local_path_rejects_relative() {
        let e = validate_local_path("foo.sock").unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("absolute")));
    }

    #[test]
    fn validate_local_path_rejects_nul_bytes() {
        let e = validate_local_path("/tmp/foo\0bar.sock").unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("NUL")));
    }

    #[test]
    fn validate_local_path_rejects_oversized() {
        let huge = format!("/{}", "a".repeat(MAX_PATH_LEN));
        let e = validate_local_path(&huge).unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(ref s) if s.contains("4096")));
    }

    /// On Windows, `open_listener` returns `UnsupportedPlatform`
    /// without ever touching the filesystem.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn open_listener_returns_unsupported_platform_on_windows() {
        match open_listener("/run/foo.sock").await {
            Ok(_) => panic!("expected UnsupportedPlatform on non-Unix"),
            Err(Error::UnsupportedPlatform(msg)) => {
                assert!(msg.contains("local_uds"), "msg: {msg}");
                assert!(
                    msg.contains("Unix") || msg.contains("Windows"),
                    "msg: {msg}"
                );
            }
            Err(other) => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    /// On Unix, `open_listener` binds a real UNIX socket and accepts
    /// one inbound `tokio::net::UnixStream::connect`.
    #[cfg(unix)]
    #[tokio::test]
    async fn open_listener_binds_and_accepts_unix_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("listener.sock");
        let path_str = path.to_string_lossy().into_owned();

        let listener = open_listener(&path_str).await.expect("bind listener");
        assert_eq!(listener.path(), path);

        // Spawn an acceptor that yields once.
        let listener = std::sync::Arc::new(listener);
        let lc = std::sync::Arc::clone(&listener);
        let server_task = tokio::spawn(async move {
            let _stream = lc.accept().await.expect("accept");
        });

        let _client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("client connect");
        server_task.await.expect("server task joins");
    }

    /// Drop removes the socket file by default.
    #[cfg(unix)]
    #[tokio::test]
    async fn drop_unlinks_socket_file_by_default() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("drop.sock");
        {
            let _listener = open_listener(&path.to_string_lossy())
                .await
                .expect("bind listener");
            assert!(path.exists());
        }
        // After drop, the socket file is gone.
        assert!(!path.exists(), "socket file should be unlinked on drop");
    }

    /// `keep_socket_on_drop` suppresses the unlink.
    #[cfg(unix)]
    #[tokio::test]
    async fn keep_socket_on_drop_preserves_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("keep.sock");
        {
            let listener = open_listener(&path.to_string_lossy())
                .await
                .expect("bind listener")
                .keep_socket_on_drop();
            let _ = listener;
        }
        assert!(path.exists(), "socket file should be preserved");
        // Tidy up so the tempdir teardown succeeds on every platform.
        let _ = std::fs::remove_file(&path);
    }

    /// `unlink_existing_if_socket` removes a stale socket and is a
    /// no-op when the path doesn't exist or isn't a socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn unlink_existing_if_socket_removes_stale_socket() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("stale.sock");

        // Bind once, then drop without unlinking.
        {
            let l = open_listener(&path.to_string_lossy())
                .await
                .expect("bind listener")
                .keep_socket_on_drop();
            drop(l);
        }
        assert!(path.exists(), "stale socket present");

        UdsListener::unlink_existing_if_socket(&path.to_string_lossy()).unwrap();
        assert!(
            !path.exists(),
            "unlink_existing_if_socket should remove the stale socket"
        );

        // No-op when the path doesn't exist.
        UdsListener::unlink_existing_if_socket(&path.to_string_lossy()).unwrap();

        // No-op (and Ok) when the path is a regular file, not a socket.
        let regular = tmp.path().join("not_a_socket.txt");
        std::fs::write(&regular, b"hi").unwrap();
        UdsListener::unlink_existing_if_socket(&regular.to_string_lossy()).unwrap();
        assert!(regular.exists(), "regular file must be left alone");
    }
}
