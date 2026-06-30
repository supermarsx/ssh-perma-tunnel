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
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use spt_core::escape_control;

use crate::bw::TokenBucket;
use crate::checksum::{sha256_local_file, sha256_remote_file};
use crate::client::SftpClient;
use crate::error::SftpError;

const CHUNK: usize = 64 * 1024;

/// Render a server-controlled `readlink` target for safe inclusion in an
/// operator-facing log line.
///
/// SECURITY (M2): the SFTP server is the untrusted side of this product and a
/// malicious server can return a symlink target containing control / ANSI /
/// newline bytes. Logging it verbatim (`target.display()`) would let the
/// server forge log lines or emit terminal escape sequences (clear-screen,
/// cursor moves, hyperlink/clipboard injection). [`escape_control`]
/// neutralizes those bytes, matching how the entry name is escaped at the
/// READDIR sites.
fn display_link_target(target: &Path) -> String {
    escape_control(&target.to_string_lossy()).into_owned()
}

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
    // The download root every server-returned name must stay within. We
    // normalise it once lexically so the per-entry containment check is a
    // pure prefix test (the root itself is created above and exists, but we
    // avoid `canonicalize` to keep the check identical on all platforms).
    let local_root = local_dir.to_path_buf();
    let mut visited: HashSet<String> = HashSet::new();
    get_dir_inner(
        client,
        remote_dir,
        local_dir,
        &local_root,
        opts,
        &bucket,
        &mut report,
        &mut visited,
    )
    .await?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)] // walker threads root + bucket + report + visited.
async fn get_dir_inner(
    client: &SftpClient,
    remote_dir: &str,
    local_dir: &Path,
    local_root: &Path,
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

        // SECURITY: the entry name is server-controlled and the server is the
        // untrusted side of this product. Reject (skip-with-warning, matching
        // the walker's continue-on-skip policy) any name that is not a single
        // benign local component — `..`, absolute, drive/UNC-prefixed, or
        // separator-bearing names would otherwise escape the download root.
        if let Err(reason) = sanitize_entry_name(&entry.file_name) {
            tracing::warn!(
                target: "spt_sftp::recursive",
                remote_dir = %remote_dir,
                entry = %entry.file_name.escape_default(),
                reason = %reason,
                "skipping SFTP entry with unsafe server-supplied name (path-traversal guard)",
            );
            continue;
        }

        let remote_child = join_remote(remote_dir, &entry.file_name);
        let local_child = local_dir.join(&entry.file_name);

        // Defence in depth: even after component sanitisation, assert the
        // joined target stays within the original download root before any
        // create/write touches the local filesystem.
        if !is_within_root(local_root, &local_child) {
            tracing::warn!(
                target: "spt_sftp::recursive",
                local_child = %local_child.display(),
                local_root = %local_root.display(),
                "skipping SFTP entry whose local target escapes the download root",
            );
            continue;
        }

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
                        local_root,
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
                // SECURITY: never recreate a symlink whose (resolved,
                // relative-to-jail) target leaves the download root. A server
                // returning `../../etc/passwd` or an absolute target would
                // otherwise plant an escaping symlink that a later read/write
                // through it lands outside the jail. Skip-with-warning.
                let link_parent = local_child.parent().unwrap_or(local_root);
                if !symlink_target_within_root(local_root, link_parent, &target) {
                    tracing::warn!(
                        target: "spt_sftp::recursive",
                        local_child = %local_child.display(),
                        link_target = %display_link_target(&target),
                        "skipping SFTP symlink whose target escapes the download root",
                    );
                    continue;
                }
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
                local_root,
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

/// Validate that a server-returned READDIR entry name is a single, benign
/// local path component before it is joined onto the local download root.
///
/// The remote SFTP server is the *untrusted* side of this product: a
/// malicious or compromised server can return an entry named
/// `../../../../etc/passwd`, an absolute path, a Windows drive/UNC path, or
/// a name embedding path separators, all of which would escape the intended
/// local destination directory when naively `Path::join`-ed.
///
/// Returns `Ok(())` only for names that are exactly one safe path component.
/// Rejected (with the reason as the error string):
/// * empty / `.` / `..`
/// * any name containing a `/` or `\` separator (would introduce extra
///   components, including traversal like `a/../..`)
/// * any name containing an embedded NUL or ASCII control character
/// * absolute paths, or names with a root / drive (`C:`) / UNC (`\\srv`)
///   prefix — including the bare drive-relative `C:foo` form
///
/// This is the same class of defense `spt-ftp-translator` applies to FTP
/// verb arguments ([`validate_path_argument`]), specialised here to a single
/// component because READDIR returns leaf names, not paths.
///
/// [`validate_path_argument`]: ../../spt_ftp_translator/server/fn.validate_path_argument.html
fn sanitize_entry_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty entry name".to_owned());
    }
    if name == "." || name == ".." {
        return Err(format!("traversal component `{name}`"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err("embedded path separator".to_owned());
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("embedded control/NUL byte".to_owned());
    }
    // M1: reject Windows reserved device names (CON, PRN, AUX, NUL, COM1-9,
    // LPT1-9, including `name.ext` and trailing dot/space variants). A hostile
    // server could otherwise make a recursive download write to a device
    // (`local_dir.join("CON")` resolves to the console/NUL device on Windows),
    // hanging or destroying data. Refused on every platform for parity and
    // defence-in-depth, matching the cross-platform drive-letter rejection.
    if is_windows_reserved_name(name) {
        return Err("windows reserved device name".to_owned());
    }
    // Reject a Windows drive-letter prefix (`C:`, `C:foo`) explicitly and on
    // every platform: `Path` only parses it as a `Prefix` component on
    // Windows, so a Linux client of a hostile server would otherwise accept
    // `C:foo` as a plain leaf. It is never a legitimate single component, so
    // refuse it uniformly for defence-in-depth and cross-platform parity.
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err("windows drive-letter prefix".to_owned());
    }
    // Reject anything that `Path` would not treat as a single `Normal`
    // component: absolute paths, root dirs, Windows drive prefixes
    // (`C:`, `C:foo`), UNC / verbatim prefixes, and the `.`/`..` forms
    // (already handled above, but kept defensively for cross-platform
    // parsing differences).
    let mut comps = Path::new(name).components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(c)), None) if c == std::ffi::OsStr::new(name) => Ok(()),
        _ => Err("not a single normal path component".to_owned()),
    }
}

/// `true` when `name` is (a variant of) a Windows reserved device name.
///
/// Windows treats `CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, and `LPT1`..`LPT9`
/// as device names *regardless of extension* and *ignoring trailing dots and
/// spaces*, so `CON`, `con.txt`, `NUL.`, and `aux ` all resolve to a device.
/// The comparison is case-insensitive and made against the base name (the part
/// before the first `.`), with trailing spaces/dots stripped first.
fn is_windows_reserved_name(name: &str) -> bool {
    // Strip trailing dots/spaces (Windows ignores them when resolving), then
    // take the portion before the first '.' as the base device candidate.
    let trimmed = name.trim_end_matches(['.', ' ']);
    let base = trimmed.split('.').next().unwrap_or(trimmed);
    let base = base.trim_end_matches([' ']);
    if base.is_empty() {
        return false;
    }
    let upper = base.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    // COMn / LPTn where n is a single 1-9 digit.
    let rest = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"));
    matches!(
        rest,
        Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
    )
}

/// Lexically test whether `candidate` stays within `root` without touching
/// the filesystem (the target may not exist yet, so `canonicalize` is not an
/// option). Both paths are normalised by resolving `.`/`..` against the
/// component stack; a `candidate` that pops above `root` fails containment.
fn is_within_root(root: &Path, candidate: &Path) -> bool {
    fn normalise(p: &Path) -> Option<PathBuf> {
        let mut out = PathBuf::new();
        for comp in p.components() {
            match comp {
                Component::CurDir => {}
                Component::ParentDir => {
                    // Refuse to pop above a prefix/root anchor.
                    if !out.pop() {
                        return None;
                    }
                }
                other => out.push(other.as_os_str()),
            }
        }
        Some(out)
    }
    match (normalise(root), normalise(candidate)) {
        (Some(r), Some(c)) => c.starts_with(&r),
        _ => false,
    }
}

/// Resolve a server-supplied symlink `target` (which may be relative to the
/// link's parent directory, or absolute) against `link_parent`, then confirm
/// the result stays within `local_root`. A server returning a symlink to
/// `../../etc/passwd` or `/etc/passwd` must NOT be recreated locally.
///
/// Returns `true` only when the link is safe to materialise.
fn symlink_target_within_root(local_root: &Path, link_parent: &Path, target: &Path) -> bool {
    // An absolute target escapes any relative jail by definition. A target
    // with a Windows drive/UNC prefix likewise.
    let has_anchor = target
        .components()
        .next()
        .is_some_and(|c| matches!(c, Component::RootDir | Component::Prefix(_)));
    if has_anchor {
        return false;
    }
    let joined = link_parent.join(target);
    is_within_root(local_root, &joined)
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

    #[test]
    fn sanitize_entry_name_accepts_benign_leaf_names() {
        assert!(sanitize_entry_name("file.txt").is_ok());
        assert!(sanitize_entry_name("sub").is_ok());
        // A literal double-dot is fine when it is not the WHOLE component.
        assert!(sanitize_entry_name("..hidden").is_ok());
        assert!(sanitize_entry_name("file..bak").is_ok());
        assert!(sanitize_entry_name("a b c").is_ok());
    }

    #[test]
    fn sanitize_entry_name_rejects_traversal_and_empty() {
        assert!(sanitize_entry_name("").is_err());
        assert!(sanitize_entry_name(".").is_err());
        assert!(sanitize_entry_name("..").is_err());
    }

    #[test]
    fn sanitize_entry_name_rejects_embedded_separators() {
        assert!(sanitize_entry_name("../escape").is_err());
        assert!(sanitize_entry_name("a/b").is_err());
        assert!(sanitize_entry_name("a\\b").is_err());
        assert!(sanitize_entry_name("..\\escape").is_err());
        assert!(sanitize_entry_name("sub/../..").is_err());
    }

    #[test]
    fn sanitize_entry_name_rejects_absolute_and_prefixed() {
        assert!(sanitize_entry_name("/etc/passwd").is_err());
        // Windows drive + UNC + drive-relative forms.
        assert!(sanitize_entry_name("C:\\evil").is_err());
        assert!(sanitize_entry_name("C:evil").is_err());
        assert!(sanitize_entry_name("\\\\srv\\share").is_err());
    }

    #[test]
    fn sanitize_entry_name_rejects_windows_reserved_devices() {
        // Bare device names (any case).
        for n in ["CON", "con", "PRN", "aux", "NUL", "COM1", "lpt9"] {
            assert!(sanitize_entry_name(n).is_err(), "should reject {n}");
        }
        // With extensions and trailing dots/spaces.
        for n in ["nul.txt", "CON.", "aux ", "COM1.log", "Lpt3.dat"] {
            assert!(sanitize_entry_name(n).is_err(), "should reject {n}");
        }
        // Not reserved: a digit out of range, or a longer/different name.
        for n in [
            "COM0",
            "COM10",
            "LPT0",
            "console",
            "communicate",
            "nullable",
        ] {
            assert!(sanitize_entry_name(n).is_ok(), "should allow {n}");
        }
    }

    #[test]
    fn is_windows_reserved_name_matrix() {
        assert!(is_windows_reserved_name("CON"));
        assert!(is_windows_reserved_name("NuL.TXT"));
        assert!(is_windows_reserved_name("com5"));
        assert!(is_windows_reserved_name("LPT7.dat"));
        assert!(!is_windows_reserved_name("com"));
        assert!(!is_windows_reserved_name("com12"));
        assert!(!is_windows_reserved_name("contents"));
        assert!(!is_windows_reserved_name(""));
    }

    #[test]
    fn sanitize_entry_name_rejects_control_bytes() {
        assert!(sanitize_entry_name("foo\0bar").is_err());
        assert!(sanitize_entry_name("foo\nbar").is_err());
        assert!(sanitize_entry_name("foo\u{7f}bar").is_err());
    }

    #[test]
    fn display_link_target_escapes_esc_and_newline() {
        // A malicious server returns a symlink target laced with an ANSI
        // escape sequence and a newline (log-forging / terminal injection).
        let hostile = Path::new("/safe\u{1b}[2Jevil\ntarget");
        let rendered = display_link_target(hostile);
        // No raw control bytes survive into the log string.
        assert!(
            !rendered.contains('\u{1b}'),
            "ESC byte must be escaped: {rendered:?}"
        );
        assert!(
            !rendered.contains('\n'),
            "newline must be escaped: {rendered:?}"
        );
        // The escaped, human-readable forms are present instead.
        assert!(
            rendered.contains("\\x1b") || rendered.contains("\\u{1b}"),
            "ESC must appear in escaped form: {rendered:?}"
        );
        assert!(
            rendered.contains("\\n"),
            "newline escaped form: {rendered:?}"
        );
        // Benign content is preserved verbatim.
        assert!(rendered.contains("evil"));
        assert!(rendered.contains("target"));
    }

    #[test]
    fn display_link_target_passes_benign_path_through() {
        let benign = Path::new("../sibling/file.txt");
        assert_eq!(display_link_target(benign), "../sibling/file.txt");
    }

    #[test]
    fn is_within_root_basic_containment() {
        let root = Path::new("/dl/root");
        assert!(is_within_root(root, Path::new("/dl/root/sub/file")));
        assert!(is_within_root(root, Path::new("/dl/root")));
        assert!(is_within_root(root, Path::new("/dl/root/a/./b")));
        assert!(!is_within_root(root, Path::new("/dl/root/../escape")));
        assert!(!is_within_root(root, Path::new("/dl/other")));
        assert!(!is_within_root(root, Path::new("/etc/passwd")));
    }

    #[test]
    fn symlink_target_within_root_rejects_escapes() {
        let root = Path::new("/dl/root");
        let parent = Path::new("/dl/root/sub");
        // Benign relative target inside the jail.
        assert!(symlink_target_within_root(
            root,
            parent,
            Path::new("sibling.txt")
        ));
        assert!(symlink_target_within_root(
            root,
            parent,
            Path::new("../other-sub/x")
        ));
        // Escapes.
        assert!(!symlink_target_within_root(
            root,
            parent,
            Path::new("../../etc/passwd")
        ));
        assert!(!symlink_target_within_root(
            root,
            parent,
            Path::new("/etc/passwd")
        ));
    }
}
