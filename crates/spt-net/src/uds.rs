//! Unix domain socket listener.
//!
//! On Unix, [`bind_unix`] removes any pre-existing socket file at `path`,
//! binds, and chmods to `0600`. On Windows it returns
//! [`Error::UnsupportedPlatform`].

use std::path::Path;

use spt_core::error::{Error, Result};

#[cfg(unix)]
use tokio::net::UnixListener;

/// Bind a `tokio::net::UnixListener` at `path`.
#[cfg(unix)]
pub fn bind_unix(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    if path.exists() {
        std::fs::remove_file(path).map_err(|e| Error::LocalBindFailed {
            address: path.display().to_string(),
            reason: format!("could not remove existing socket: {e}"),
        })?;
    }
    let listener = UnixListener::bind(path).map_err(|e| Error::LocalBindFailed {
        address: path.display().to_string(),
        reason: e.to_string(),
    })?;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| Error::LocalBindFailed {
        address: path.display().to_string(),
        reason: format!("could not chmod 0600: {e}"),
    })?;
    Ok(listener)
}

/// Windows stub: UDS listeners are not supported by this module.
///
/// (Windows 10+ does support `AF_UNIX` `SOCK_STREAM`, but Tokio's
/// `UnixListener` is unix-only; cross-platform UDS is out of scope here.)
#[cfg(windows)]
pub fn bind_unix(path: &Path) -> Result<()> {
    Err(Error::UnsupportedPlatform(format!(
        "Unix domain sockets are not supported on Windows (path was `{}`)",
        path.display()
    )))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test(flavor = "current_thread")]
    async fn bind_unix_creates_socket_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("spt.sock");
        let _listener = bind_unix(&path).unwrap();
        assert!(path.exists());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bind_unix_replaces_stale_socket() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("spt.sock");
        let l1 = bind_unix(&path).unwrap();
        drop(l1);
        let _l2 = bind_unix(&path).unwrap();
        assert!(path.exists());
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn bind_unix_unsupported_on_windows() {
        let err = bind_unix(Path::new(r"C:\temp\spt.sock")).unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }
}
