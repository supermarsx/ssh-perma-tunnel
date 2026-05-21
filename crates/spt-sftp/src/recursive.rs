//! Recursive directory transfer over SFTP.
//!
//! Both directions ([`put_recursive`], [`get_recursive`]) walk the source
//! tree, mirror it on the destination, and shuttle file bodies in 64 KiB
//! chunks through the supplied [`SftpClient`]. The walker is intentionally
//! eager (uses [`Vec`]-collected DFS) since the workspace tests cap each
//! transfer at a handful of files; switching to a streaming async iterator
//! is unnecessary for the production CLI surface.
//!
//! ## Options
//!
//! [`RecursiveOptions`] carries the cross-cutting features the CLI exposes:
//! * `resume`: pre-existing target files are seeked-to (upload) or
//!   appended-to (download) instead of truncated.
//! * `bps`: a [`TokenBucket`] rate-limits chunk delivery against the actual
//!   data direction.
//! * `checksum`: post-transfer SHA-256 comparison of source and destination.
//!
//! `RecursiveOptions::follow_symlinks` defaults to `false`. Symlinks
//! encountered during a walk are checked against a `visited` set of
//! canonicalised paths so a loop (`a -> b -> a`) does not blow the stack.

use std::collections::HashSet;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::bw::TokenBucket;
use crate::checksum::{sha256_local_file, sha256_remote_file};
use crate::client::SftpClient;
use crate::error::SftpError;

const CHUNK: usize = 64 * 1024;

/// Optional features for [`put_recursive`] / [`get_recursive`].
#[derive(Debug, Clone, Default)]
pub struct RecursiveOptions {
    /// Resume mode: seek/append into pre-existing target files instead of
    /// truncating them.
    pub resume: bool,
    /// Bandwidth limit in bytes per second. `0` disables limiting.
    pub bps: u64,
    /// Optional post-transfer integrity verification.
    pub checksum: ChecksumMode,
    /// Follow symbolic links during the walk. Off by default; loops are
    /// detected via a `visited` set regardless.
    pub follow_symlinks: bool,
}

/// Checksum verification mode for recursive transfers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChecksumMode {
    /// No post-transfer verification.
    #[default]
    None,
    /// SHA-256 each file on both ends after transfer.
    Sha256,
}

/// Summary of files moved by a recursive transfer.
#[derive(Debug, Clone, Default)]
pub struct RecursiveReport {
    /// Number of regular files transferred (or resumed).
    pub files: u64,
    /// Number of directories created at the destination.
    pub directories: u64,
    /// Number of symlinks recreated at the destination.
    pub symlinks: u64,
    /// Total bytes transferred (post-resume, so this counts only the bytes
    /// the wire actually carried).
    pub bytes: u64,
}

/// Upload a local directory to a remote SFTP path, mirroring its tree.
pub async fn put_recursive(
    client: &SftpClient,
    local_dir: &Path,
    remote_dir: &str,
    opts: &RecursiveOptions,
) -> Result<RecursiveReport, SftpError> {
    let bucket = Arc::new(TokenBucket::new(opts.bps));
    let mut report = RecursiveReport::default();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    client.create_dir_idem(remote_dir.to_owned()).await?;
    report.directories += 1;
    put_dir_inner(
        client,
        local_dir,
        remote_dir,
        opts,
        &bucket,
        &mut report,
        &mut visited,
    )
    .await?;
    Ok(report)
}

async fn put_dir_inner(
    client: &SftpClient,
    local_dir: &Path,
    remote_dir: &str,
    opts: &RecursiveOptions,
    bucket: &Arc<TokenBucket>,
    report: &mut RecursiveReport,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), SftpError> {
    let canonical = fs::canonicalize(local_dir)
        .await
        .map_err(|e| SftpError::Local {
            op: "put-canonicalize",
            detail: format!("{}: {e}", local_dir.display()),
        })?;
    if !visited.insert(canonical) {
        return Err(SftpError::Local {
            op: "put-walk",
            detail: format!("symlink loop detected at `{}`", local_dir.display()),
        });
    }
    let mut entries = fs::read_dir(local_dir)
        .await
        .map_err(|e| SftpError::Local {
            op: "put-read_dir",
            detail: format!("{}: {e}", local_dir.display()),
        })?;
    while let Some(entry) = entries.next_entry().await.map_err(|e| SftpError::Local {
        op: "put-next_entry",
        detail: format!("{}: {e}", local_dir.display()),
    })? {
        let file_type = entry.file_type().await.map_err(|e| SftpError::Local {
            op: "put-file_type",
            detail: format!("{}: {e}", entry.path().display()),
        })?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy().into_owned();
        let remote_child = join_remote(remote_dir, &name_str);
        let local_child = entry.path();

        if file_type.is_symlink() {
            if opts.follow_symlinks {
                // Treat as the link target, which we resolve via canonicalize
                // — but the symlink-loop set captures it.
                let target_meta =
                    fs::metadata(&local_child)
                        .await
                        .map_err(|e| SftpError::Local {
                            op: "put-symlink-stat",
                            detail: format!("{}: {e}", local_child.display()),
                        })?;
                if target_meta.is_dir() {
                    client.create_dir_idem(remote_child.clone()).await?;
                    report.directories += 1;
                    Box::pin(put_dir_inner(
                        client,
                        &local_child,
                        &remote_child,
                        opts,
                        bucket,
                        report,
                        visited,
                    ))
                    .await?;
                } else {
                    upload_file(client, &local_child, &remote_child, opts, bucket, report).await?;
                }
            } else {
                let target = fs::read_link(&local_child)
                    .await
                    .map_err(|e| SftpError::Local {
                        op: "put-readlink",
                        detail: format!("{}: {e}", local_child.display()),
                    })?;
                client
                    .symlink(target.to_string_lossy().into_owned(), remote_child.clone())
                    .await?;
                report.symlinks += 1;
            }
        } else if file_type.is_dir() {
            client.create_dir_idem(remote_child.clone()).await?;
            report.directories += 1;
            Box::pin(put_dir_inner(
                client,
                &local_child,
                &remote_child,
                opts,
                bucket,
                report,
                visited,
            ))
            .await?;
        } else if file_type.is_file() {
            upload_file(client, &local_child, &remote_child, opts, bucket, report).await?;
        }
    }
    Ok(())
}

async fn upload_file(
    client: &SftpClient,
    local: &Path,
    remote: &str,
    opts: &RecursiveOptions,
    bucket: &Arc<TokenBucket>,
    report: &mut RecursiveReport,
) -> Result<(), SftpError> {
    let mut start_offset = 0u64;
    if opts.resume {
        if let Ok(meta) = client.metadata(remote.to_owned()).await {
            if let Some(size) = meta.size {
                start_offset = size;
            }
        }
    }
    let mut local_file = fs::File::open(local).await.map_err(|e| SftpError::Local {
        op: "put-open-local",
        detail: format!("{}: {e}", local.display()),
    })?;
    if start_offset > 0 {
        local_file
            .seek(SeekFrom::Start(start_offset))
            .await
            .map_err(|e| SftpError::Local {
                op: "put-seek-local",
                detail: format!("{}: {e}", local.display()),
            })?;
    }
    let mut remote_file = client
        .open_for_resume_write(remote.to_owned(), start_offset)
        .await?;

    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = local_file
            .read(&mut buf)
            .await
            .map_err(|e| SftpError::Local {
                op: "put-read-local",
                detail: format!("{}: {e}", local.display()),
            })?;
        if n == 0 {
            break;
        }
        bucket.consume(n as u64).await;
        remote_file
            .write_all(&buf[..n])
            .await
            .map_err(|e| SftpError::Local {
                op: "put-write-remote",
                detail: format!("{remote}: {e}"),
            })?;
        report.bytes += n as u64;
    }
    remote_file.shutdown().await.map_err(|e| SftpError::Local {
        op: "put-shutdown-remote",
        detail: format!("{remote}: {e}"),
    })?;
    drop(remote_file);
    report.files += 1;

    if matches!(opts.checksum, ChecksumMode::Sha256) {
        let local_hash = sha256_local_file(local).await?;
        let remote_hash = sha256_remote_file(client, remote).await?;
        if local_hash != remote_hash {
            return Err(SftpError::Local {
                op: "put-checksum",
                detail: format!(
                    "sha256 mismatch for `{}` → `{}`: local={} remote={}",
                    local.display(),
                    remote,
                    local_hash,
                    remote_hash,
                ),
            });
        }
    }
    Ok(())
}

/// Download a remote SFTP directory tree to a local path, mirroring its
/// structure.
pub async fn get_recursive(
    client: &SftpClient,
    remote_dir: &str,
    local_dir: &Path,
    opts: &RecursiveOptions,
) -> Result<RecursiveReport, SftpError> {
    let bucket = Arc::new(TokenBucket::new(opts.bps));
    let mut report = RecursiveReport::default();
    fs::create_dir_all(local_dir)
        .await
        .map_err(|e| SftpError::Local {
            op: "get-mkdir-local",
            detail: format!("{}: {e}", local_dir.display()),
        })?;
    report.directories += 1;
    let mut visited: HashSet<String> = HashSet::new();
    get_dir_inner(
        client,
        remote_dir,
        local_dir,
        opts,
        &bucket,
        &mut report,
        &mut visited,
    )
    .await?;
    Ok(report)
}

async fn get_dir_inner(
    client: &SftpClient,
    remote_dir: &str,
    local_dir: &Path,
    opts: &RecursiveOptions,
    bucket: &Arc<TokenBucket>,
    report: &mut RecursiveReport,
    visited: &mut HashSet<String>,
) -> Result<(), SftpError> {
    let canonical = client.canonicalize(remote_dir.to_owned()).await?;
    if !visited.insert(canonical) {
        return Err(SftpError::Local {
            op: "get-walk",
            detail: format!("symlink loop detected at `{remote_dir}`"),
        });
    }
    let entries = client.read_dir(remote_dir.to_owned()).await?;
    for entry in entries {
        // Skip the conventional `.` / `..` entries (some servers include
        // them in READDIR responses).
        if entry.file_name == "." || entry.file_name == ".." {
            continue;
        }
        let remote_child = join_remote(remote_dir, &entry.file_name);
        let local_child = local_dir.join(&entry.file_name);

        if entry.metadata.is_symlink {
            if opts.follow_symlinks {
                // Recurse into the link target. `metadata()` follows the link.
                let target_meta = client.metadata(remote_child.clone()).await?;
                if target_meta.is_dir {
                    fs::create_dir_all(&local_child)
                        .await
                        .map_err(|e| SftpError::Local {
                            op: "get-mkdir-local",
                            detail: format!("{}: {e}", local_child.display()),
                        })?;
                    report.directories += 1;
                    Box::pin(get_dir_inner(
                        client,
                        &remote_child,
                        &local_child,
                        opts,
                        bucket,
                        report,
                        visited,
                    ))
                    .await?;
                } else {
                    download_file(client, &remote_child, &local_child, opts, bucket, report)
                        .await?;
                }
            } else {
                let target = client.readlink(remote_child.clone()).await?;
                #[cfg(unix)]
                {
                    tokio::fs::symlink(&target, &local_child)
                        .await
                        .map_err(|e| SftpError::Local {
                            op: "get-symlink-local",
                            detail: format!("{}: {e}", local_child.display()),
                        })?;
                }
                #[cfg(windows)]
                {
                    // On Windows we don't have privilege to create symlinks
                    // by default; record the target by writing a `.symlink`
                    // sidecar so the mirror is auditable but the test
                    // doesn't require Administrator.
                    let sidecar = local_child.with_extension("symlink");
                    fs::write(&sidecar, target.to_string_lossy().into_owned())
                        .await
                        .map_err(|e| SftpError::Local {
                            op: "get-symlink-sidecar",
                            detail: format!("{}: {e}", sidecar.display()),
                        })?;
                }
                report.symlinks += 1;
            }
        } else if entry.metadata.is_dir {
            fs::create_dir_all(&local_child)
                .await
                .map_err(|e| SftpError::Local {
                    op: "get-mkdir-local",
                    detail: format!("{}: {e}", local_child.display()),
                })?;
            report.directories += 1;
            Box::pin(get_dir_inner(
                client,
                &remote_child,
                &local_child,
                opts,
                bucket,
                report,
                visited,
            ))
            .await?;
        } else {
            download_file(client, &remote_child, &local_child, opts, bucket, report).await?;
        }
    }
    Ok(())
}

async fn download_file(
    client: &SftpClient,
    remote: &str,
    local: &Path,
    opts: &RecursiveOptions,
    bucket: &Arc<TokenBucket>,
    report: &mut RecursiveReport,
) -> Result<(), SftpError> {
    let mut start_offset = 0u64;
    if opts.resume {
        if let Ok(meta) = fs::metadata(local).await {
            start_offset = meta.len();
        }
    }
    let mut remote_file = client.open_for_read(remote.to_owned()).await?;
    if start_offset > 0 {
        remote_file
            .seek(SeekFrom::Start(start_offset))
            .await
            .map_err(|e| SftpError::Local {
                op: "get-seek-remote",
                detail: format!("{remote}: {e}"),
            })?;
    }
    if let Some(parent) = local.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| SftpError::Local {
                    op: "get-mkdir-parent",
                    detail: format!("{}: {e}", parent.display()),
                })?;
        }
    }
    let mut local_file = if start_offset > 0 {
        fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(local)
            .await
            .map_err(|e| SftpError::Local {
                op: "get-open-local-append",
                detail: format!("{}: {e}", local.display()),
            })?
    } else {
        fs::File::create(local)
            .await
            .map_err(|e| SftpError::Local {
                op: "get-create-local",
                detail: format!("{}: {e}", local.display()),
            })?
    };

    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = remote_file
            .read(&mut buf)
            .await
            .map_err(|e| SftpError::Local {
                op: "get-read-remote",
                detail: format!("{remote}: {e}"),
            })?;
        if n == 0 {
            break;
        }
        bucket.consume(n as u64).await;
        local_file
            .write_all(&buf[..n])
            .await
            .map_err(|e| SftpError::Local {
                op: "get-write-local",
                detail: format!("{}: {e}", local.display()),
            })?;
        report.bytes += n as u64;
    }
    local_file.flush().await.map_err(|e| SftpError::Local {
        op: "get-flush-local",
        detail: format!("{}: {e}", local.display()),
    })?;
    report.files += 1;

    if matches!(opts.checksum, ChecksumMode::Sha256) {
        let local_hash = sha256_local_file(local).await?;
        let remote_hash = sha256_remote_file(client, remote).await?;
        if local_hash != remote_hash {
            return Err(SftpError::Local {
                op: "get-checksum",
                detail: format!(
                    "sha256 mismatch for `{remote}` → `{}`: local={} remote={}",
                    local.display(),
                    local_hash,
                    remote_hash,
                ),
            });
        }
    }
    Ok(())
}

fn join_remote(base: &str, child: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{child}")
    } else if base.is_empty() {
        child.to_owned()
    } else {
        format!("{base}/{child}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_remote_handles_trailing_slash() {
        assert_eq!(join_remote("/a", "b"), "/a/b");
        assert_eq!(join_remote("/a/", "b"), "/a/b");
        assert_eq!(join_remote("", "b"), "b");
    }
}
