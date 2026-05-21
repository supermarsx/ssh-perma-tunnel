//! SHA-256 helpers for end-to-end transfer verification.
//!
//! [`sha256_local_file`] streams a local file through a [`Sha256`] hasher
//! without buffering the whole file in memory. [`sha256_remote_file`] does
//! the same against a remote SFTP file by repeatedly reading 64 KiB chunks
//! through the supplied [`SftpClient`].

use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::client::SftpClient;
use crate::error::SftpError;

const CHUNK: usize = 64 * 1024;

/// SHA-256 the local file at `path`, returning the lowercase hex digest.
pub async fn sha256_local_file(path: &Path) -> Result<String, SftpError> {
    let mut file = File::open(path).await.map_err(|e| SftpError::Local {
        op: "checksum-local-open",
        detail: format!("{}: {e}", path.display()),
    })?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf).await.map_err(|e| SftpError::Local {
            op: "checksum-local-read",
            detail: format!("{}: {e}", path.display()),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// SHA-256 a remote file by streaming 64 KiB chunks through the supplied
/// [`SftpClient`].
pub async fn sha256_remote_file(client: &SftpClient, path: &str) -> Result<String, SftpError> {
    let mut file = client.open_for_read(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    // Always start at the beginning regardless of any cached position.
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|e| SftpError::Local {
            op: "checksum-remote-seek",
            detail: format!("{path}: {e}"),
        })?;
    loop {
        let n = file.read(&mut buf).await.map_err(|e| SftpError::Local {
            op: "checksum-remote-read",
            detail: format!("{path}: {e}"),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
