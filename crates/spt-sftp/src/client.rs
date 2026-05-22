//! Transport-agnostic SFTP client.
//!
//! `SftpClient` wraps an established [`russh_sftp::client::SftpSession`]
//! handle. Construct via [`SftpClient::from_russh`] from the spt-ssh2 backend
//! (or from the `mock` test harness).

use std::path::PathBuf;

use russh_sftp::client::fs::File as RusshFile;
use russh_sftp::client::SftpSession as RusshSftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::error::SftpError;

/// Default cap on `cat`-style whole-file reads (4 MiB).
pub const DEFAULT_CAT_SIZE_CAP: u64 = 4 * 1024 * 1024;

/// High-level SFTP client used by the CLI and runtime management surfaces.
pub struct SftpClient {
    inner: RusshSftpSession,
}

impl SftpClient {
    /// Wrap an already-negotiated [`RusshSftpSession`]. The spt-ssh2 backend
    /// produces these once a russh channel has had its `sftp` subsystem
    /// requested.
    #[must_use]
    pub fn from_russh(inner: RusshSftpSession) -> Self {
        Self { inner }
    }

    /// Borrow the underlying russh-sftp session. Useful for tests that want
    /// to drive low-level extensions; production code should prefer the
    /// methods on [`SftpClient`].
    #[must_use]
    pub fn inner(&self) -> &RusshSftpSession {
        &self.inner
    }

    /// Canonicalize a remote path through the server.
    pub async fn canonicalize(&self, path: impl Into<String>) -> Result<String, SftpError> {
        self.inner
            .canonicalize(path)
            .await
            .map_err(|e| SftpError::from_russh("canonicalize", e))
    }

    /// Canonicalize a remote path and return it as a [`PathBuf`] (alias for
    /// the SFTP `realpath` op).
    pub async fn realpath(&self, path: impl Into<String>) -> Result<PathBuf, SftpError> {
        let s = self.canonicalize(path).await?;
        Ok(PathBuf::from(s))
    }

    /// List a remote directory.
    pub async fn read_dir(&self, path: impl Into<String>) -> Result<Vec<SftpDirEntry>, SftpError> {
        let entries = self
            .inner
            .read_dir(path)
            .await
            .map_err(|e| SftpError::from_russh("read_dir", e))?;
        Ok(entries
            .map(|entry| SftpDirEntry {
                file_name: entry.file_name(),
                metadata: SftpMetadata::from_attrs(&entry.metadata()),
            })
            .collect())
    }

    /// Read a whole remote file.
    pub async fn read_file(&self, path: impl Into<String>) -> Result<Vec<u8>, SftpError> {
        self.inner
            .read(path)
            .await
            .map_err(|e| SftpError::from_russh("read_file", e))
    }

    /// `cat` a remote file, refusing to read more than `size_cap` bytes.
    /// Use [`DEFAULT_CAT_SIZE_CAP`] for a sensible default.
    pub async fn cat(
        &self,
        path: impl Into<String> + Clone,
        size_cap: u64,
    ) -> Result<Vec<u8>, SftpError> {
        let meta = self.metadata(path.clone()).await?;
        if let Some(size) = meta.size {
            if size > size_cap {
                return Err(SftpError::Local {
                    op: "cat",
                    detail: format!(
                        "remote file size {size} exceeds cap {size_cap} bytes; pass --size-cap to override"
                    ),
                });
            }
        }
        self.read_file(path).await
    }

    /// Read at most the last `last_n_bytes` of a remote file. If the file is
    /// shorter than `last_n_bytes`, the whole file is returned.
    pub async fn tail(
        &self,
        path: impl Into<String> + Clone,
        last_n_bytes: u64,
    ) -> Result<Vec<u8>, SftpError> {
        let meta = self.metadata(path.clone()).await?;
        let size = meta.size.unwrap_or(0);
        if size == 0 {
            return Ok(Vec::new());
        }
        let offset = size.saturating_sub(last_n_bytes);
        let path_str: String = path.into();
        let mut file = self
            .inner
            .open(path_str.clone())
            .await
            .map_err(|e| SftpError::from_russh("tail-open", e))?;
        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| SftpError::Local {
                    op: "tail-seek",
                    detail: format!("{path_str}: {e}"),
                })?;
        }
        let want = (size - offset) as usize;
        let mut out = vec![0u8; want];
        // SFTP `read` may return short; loop until EOF or buffer full.
        let mut filled = 0;
        while filled < want {
            let n = tokio::io::AsyncReadExt::read(&mut file, &mut out[filled..])
                .await
                .map_err(|e| SftpError::Local {
                    op: "tail-read",
                    detail: format!("{path_str}: {e}"),
                })?;
            if n == 0 {
                out.truncate(filled);
                break;
            }
            filled += n;
        }
        Ok(out)
    }

    /// Create or truncate a remote file and write all bytes.
    pub async fn write_file(&self, path: impl Into<String>, data: &[u8]) -> Result<(), SftpError> {
        let mut file = self
            .inner
            .create(path)
            .await
            .map_err(|e| SftpError::from_russh("create_file", e))?;
        file.write_all(data).await.map_err(|e| SftpError::Local {
            op: "write_file",
            detail: format!("{e}"),
        })?;
        file.shutdown().await.map_err(|e| SftpError::Local {
            op: "close_written_file",
            detail: format!("{e}"),
        })
    }

    /// Open a remote file for reading.
    pub async fn open_for_read(&self, path: impl Into<String>) -> Result<RusshFile, SftpError> {
        self.inner
            .open(path)
            .await
            .map_err(|e| SftpError::from_russh("open", e))
    }

    /// Open a remote file for writing, creating it if absent and seeking to
    /// `start_offset`. Used by the recursive uploader's `--resume` path.
    pub async fn open_for_resume_write(
        &self,
        path: impl Into<String>,
        start_offset: u64,
    ) -> Result<RusshFile, SftpError> {
        let mut flags = OpenFlags::WRITE | OpenFlags::CREATE;
        if start_offset == 0 {
            flags |= OpenFlags::TRUNCATE;
        }
        let path_str: String = path.into();
        let mut file = self
            .inner
            .open_with_flags(path_str.clone(), flags)
            .await
            .map_err(|e| SftpError::from_russh("open_for_resume", e))?;
        if start_offset > 0 {
            file.seek(std::io::SeekFrom::Start(start_offset))
                .await
                .map_err(|e| SftpError::Local {
                    op: "open_for_resume_seek",
                    detail: format!("{path_str}: {e}"),
                })?;
        }
        Ok(file)
    }

    /// Fetch metadata for a remote path.
    pub async fn metadata(&self, path: impl Into<String>) -> Result<SftpMetadata, SftpError> {
        let metadata = self
            .inner
            .metadata(path)
            .await
            .map_err(|e| SftpError::from_russh("metadata", e))?;
        Ok(SftpMetadata::from_attrs(&metadata))
    }

    /// Fetch metadata for a remote path without following symlinks.
    pub async fn lstat(&self, path: impl Into<String>) -> Result<SftpMetadata, SftpError> {
        let metadata = self
            .inner
            .symlink_metadata(path)
            .await
            .map_err(|e| SftpError::from_russh("lstat", e))?;
        Ok(SftpMetadata::from_attrs(&metadata))
    }

    /// Change POSIX permission bits on a remote path.
    pub async fn chmod(&self, path: impl Into<String>, mode: u32) -> Result<(), SftpError> {
        let attrs = FileAttributes {
            permissions: Some(mode),
            ..FileAttributes::default()
        };
        self.inner
            .set_metadata(path, attrs)
            .await
            .map_err(|e| SftpError::from_russh("chmod", e))
    }

    /// Read the target of a remote symbolic link.
    pub async fn readlink(&self, path: impl Into<String>) -> Result<PathBuf, SftpError> {
        let target = self
            .inner
            .read_link(path)
            .await
            .map_err(|e| SftpError::from_russh("readlink", e))?;
        Ok(PathBuf::from(target))
    }

    /// Create a remote symbolic link at `linkpath` pointing at `target`.
    pub async fn symlink(
        &self,
        target: impl Into<String>,
        linkpath: impl Into<String>,
    ) -> Result<(), SftpError> {
        // `russh-sftp` follows the SFTP wire order `(linkpath, target)`.
        self.inner
            .symlink(linkpath, target)
            .await
            .map_err(|e| SftpError::from_russh("symlink", e))
    }

    /// Create a remote directory.
    pub async fn create_dir(&self, path: impl Into<String>) -> Result<(), SftpError> {
        self.inner
            .create_dir(path)
            .await
            .map_err(|e| SftpError::from_russh("create_dir", e))
    }

    /// Create a remote directory, ignoring any “already exists” failure so
    /// callers can re-mkdir parents idempotently.
    pub async fn create_dir_idem(&self, path: impl Into<String> + Clone) -> Result<(), SftpError> {
        match self.create_dir(path.clone()).await {
            Ok(()) => Ok(()),
            Err(SftpError::Other { detail, .. })
                if detail.contains("Failure") || detail.to_ascii_lowercase().contains("exists") =>
            {
                // Treat as already-present; verify it's actually a directory.
                let meta = self.metadata(path).await?;
                if meta.is_dir {
                    Ok(())
                } else {
                    Err(SftpError::NotADirectory {
                        op: "create_dir_idem",
                        detail: "target exists and is not a directory".into(),
                    })
                }
            }
            Err(other) => Err(other),
        }
    }

    /// Remove a remote file.
    pub async fn remove_file(&self, path: impl Into<String>) -> Result<(), SftpError> {
        self.inner
            .remove_file(path)
            .await
            .map_err(|e| SftpError::from_russh("remove_file", e))
    }

    /// Remove a remote directory.
    pub async fn remove_dir(&self, path: impl Into<String>) -> Result<(), SftpError> {
        self.inner
            .remove_dir(path)
            .await
            .map_err(|e| SftpError::from_russh("remove_dir", e))
    }

    /// Rename a remote file or directory.
    pub async fn rename(
        &self,
        old_path: impl Into<String>,
        new_path: impl Into<String>,
    ) -> Result<(), SftpError> {
        self.inner
            .rename(old_path, new_path)
            .await
            .map_err(|e| SftpError::from_russh("rename", e))
    }

    /// Probe whether a remote path exists.
    pub async fn try_exists(&self, path: impl Into<String>) -> Result<bool, SftpError> {
        self.inner
            .try_exists(path)
            .await
            .map_err(|e| SftpError::from_russh("try_exists", e))
    }

    /// Close the SFTP channel.
    pub async fn close(&self) -> Result<(), SftpError> {
        self.inner
            .close()
            .await
            .map_err(|e| SftpError::from_russh("close", e))
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
    /// Project a [`russh_sftp::protocol::FileAttributes`] into the
    /// transport-agnostic shape consumed by the rest of the workspace.
    #[must_use]
    pub fn from_attrs(attrs: &FileAttributes) -> Self {
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
