//! SFTP client operations over an established SSH2/russh session.

use russh_sftp::client::SftpSession as RusshSftpSession;
use russh_sftp::protocol::FileAttributes;
use spt_core::{Error, Result};
use tokio::io::AsyncWriteExt as _;

/// High-level SFTP client used by CLI and runtime management surfaces.
pub struct SftpClient {
    inner: RusshSftpSession,
}

impl SftpClient {
    pub(crate) fn from_russh(inner: RusshSftpSession) -> Self {
        Self { inner }
    }

    /// Canonicalize a remote path through the server.
    pub async fn canonicalize(&self, path: impl Into<String>) -> Result<String> {
        self.inner
            .canonicalize(path)
            .await
            .map_err(map_sftp_error("canonicalize"))
    }

    /// List a remote directory.
    pub async fn read_dir(&self, path: impl Into<String>) -> Result<Vec<SftpDirEntry>> {
        let entries = self
            .inner
            .read_dir(path)
            .await
            .map_err(map_sftp_error("read_dir"))?;
        Ok(entries
            .map(|entry| SftpDirEntry {
                file_name: entry.file_name(),
                metadata: SftpMetadata::from_attrs(&entry.metadata()),
            })
            .collect())
    }

    /// Read a whole remote file.
    pub async fn read_file(&self, path: impl Into<String>) -> Result<Vec<u8>> {
        self.inner
            .read(path)
            .await
            .map_err(map_sftp_error("read_file"))
    }

    /// Create or truncate a remote file and write all bytes.
    pub async fn write_file(&self, path: impl Into<String>, data: &[u8]) -> Result<()> {
        let mut file = self
            .inner
            .create(path)
            .await
            .map_err(map_sftp_error("create_file"))?;
        file.write_all(data)
            .await
            .map_err(|e| Error::RuntimeFailure(format!("sftp write_file: {e}")))?;
        file.shutdown()
            .await
            .map_err(|e| Error::RuntimeFailure(format!("sftp close written file: {e}")))
    }

    /// Fetch metadata for a remote path.
    pub async fn metadata(&self, path: impl Into<String>) -> Result<SftpMetadata> {
        let metadata = self
            .inner
            .metadata(path)
            .await
            .map_err(map_sftp_error("metadata"))?;
        Ok(SftpMetadata::from_attrs(&metadata))
    }

    /// Create a remote directory.
    pub async fn create_dir(&self, path: impl Into<String>) -> Result<()> {
        self.inner
            .create_dir(path)
            .await
            .map_err(map_sftp_error("create_dir"))
    }

    /// Remove a remote file.
    pub async fn remove_file(&self, path: impl Into<String>) -> Result<()> {
        self.inner
            .remove_file(path)
            .await
            .map_err(map_sftp_error("remove_file"))
    }

    /// Remove a remote directory.
    pub async fn remove_dir(&self, path: impl Into<String>) -> Result<()> {
        self.inner
            .remove_dir(path)
            .await
            .map_err(map_sftp_error("remove_dir"))
    }

    /// Rename a remote file or directory.
    pub async fn rename(
        &self,
        old_path: impl Into<String>,
        new_path: impl Into<String>,
    ) -> Result<()> {
        self.inner
            .rename(old_path, new_path)
            .await
            .map_err(map_sftp_error("rename"))
    }

    /// Close the SFTP channel.
    pub async fn close(&self) -> Result<()> {
        self.inner.close().await.map_err(map_sftp_error("close"))
    }
}

/// One remote directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SftpDirEntry {
    /// Remote file name, relative to the listed directory.
    pub file_name: String,
    /// Metadata returned with the entry.
    pub metadata: SftpMetadata,
}

/// Normalized SFTP metadata independent of the underlying crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SftpMetadata {
    /// File size when provided by the server.
    pub size: Option<u64>,
    /// Numeric POSIX permissions when provided by the server.
    pub permissions: Option<u32>,
    /// Last modification time as seconds since UNIX epoch.
    pub modified_unix: Option<u32>,
    /// Whether the server marks this path as a directory.
    pub is_dir: bool,
    /// Whether the server marks this path as a regular file.
    pub is_file: bool,
    /// Whether the server marks this path as a symbolic link.
    pub is_symlink: bool,
}

impl SftpMetadata {
    fn from_attrs(attrs: &FileAttributes) -> Self {
        Self {
            size: attrs.size,
            permissions: attrs.permissions,
            modified_unix: attrs.mtime,
            is_dir: attrs.is_dir(),
            is_file: attrs.is_regular(),
            is_symlink: attrs.is_symlink(),
        }
    }
}

fn map_sftp_error(
    op: &'static str,
) -> impl FnOnce(russh_sftp::client::error::Error) -> Error + Send + 'static {
    move |e| Error::RuntimeFailure(format!("sftp {op}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_normalizes_regular_file_attrs() {
        let mut attrs = FileAttributes {
            size: Some(42),
            permissions: Some(0o100_644),
            mtime: Some(1_700_000_000),
            ..FileAttributes::default()
        };
        attrs.set_regular(true);

        let metadata = SftpMetadata::from_attrs(&attrs);
        assert_eq!(metadata.size, Some(42));
        assert_eq!(metadata.permissions, attrs.permissions);
        assert_eq!(metadata.modified_unix, Some(1_700_000_000));
        assert!(metadata.is_file);
        assert!(!metadata.is_dir);
        assert!(!metadata.is_symlink);
    }
}
