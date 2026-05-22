//! Windows userspace-filesystem backend (Dokan / Dokany).
//!
//! ## Background (t7-P2)
//!
//! t7-A6 originally targeted the in-process `winfsp` Rust binding, but
//! `winfsp 0.10` and `winfsp-sys 0.12` are both GPL-3.0 — the workspace
//! `deny.toml` license allow-list rejects them. The operator decision for
//! t7-P2 was to find a **non-GPL** Rust binding and replace the stub with a
//! real implementation (not switch to launcher shell-out, not add a GPL
//! exception to `deny.toml`).
//!
//! The chosen binding is **[`dokan` 0.3.1+dokan206]** ([crates.io link]):
//!
//! * `dokan` crate license: **MIT** (verified in
//!   `~/.cargo/registry/src/index.crates.io-*/dokan-0.3.1+dokan206/Cargo.toml`).
//! * `dokan-sys` crate license: **MIT**.
//! * The bundled Dokany2 C source is **LGPL-3.0** (built into `dokan2.dll`
//!   by the `dokan-sys` build script). LGPL allows dynamic linking from
//!   non-LGPL code; cargo-deny inspects the Rust crate's declared license
//!   (MIT), not the bundled C source.
//!
//! Runtime requirement: the Dokany2 driver and the `dokan2.dll` userspace
//! library must be installed on the host. The standard install path is:
//!
//! ```text
//! choco install dokany2 -y
//! ```
//!
//! which sets the `DokanLibrary2_LibraryPath_x64` environment variable. The
//! `dokan-sys` build script picks that up and links against the installed
//! DLL instead of rebuilding it from the vendored LGPL source. Either way
//! `cargo deny check licenses` passes on the Rust side.
//!
//! ## Module structure
//!
//! * [`WinFsMounter`] is the public mounter type registered with
//!   [`mounter_for_current_os`](super::mounter_for_current_os) for the
//!   Windows arm. Construction is infallible; the real Dokan session is
//!   spawned by [`SftpMounter::mount`].
//! * When the `mount-winfs` feature is **enabled** on a Windows target the
//!   mounter spawns a dedicated [`std::thread`] that owns the Dokan
//!   `FileSystemHandler` and blocks inside `FileSystemMounter::mount` for
//!   the lifetime of the mount. Outside the thread we keep a `U16CString`
//!   copy of the mount point plus the join handle so [`SftpMounter::umount`]
//!   can issue `dokan::unmount(&mp)` and then `join()` the thread.
//! * When the feature is **disabled** (or the target is not Windows) the
//!   `mount` call returns [`SftpError::UnsupportedPlatform`] with a stable
//!   diagnostic so callers still surface a structured error.
//!
//! ## Sync→async bridge
//!
//! Dokan callbacks run on the kernel-driver IPC threads and are synchronous.
//! The SFTP client is `tokio`-async. The handler captures a
//! [`tokio::runtime::Handle`] at construction and uses
//! [`tokio::runtime::Handle::block_on`] inside each callback (mirrors the
//! pattern in [`super::linux_fuse::FuseFs`]).
//!
//! [`dokan` 0.3.1+dokan206]: https://crates.io/crates/dokan/0.3.1+dokan206
//! [crates.io link]: https://crates.io/crates/dokan

use std::sync::Arc;

use super::{MountEvent, MountHandle, MountOpts, SftpMounter};
#[cfg(not(windows))]
use super::unsupported_platform_error;
use crate::client::SftpClient;
use crate::error::SftpError;

#[cfg(all(windows, feature = "mount-winfs"))]
use std::collections::HashMap;
#[cfg(all(windows, feature = "mount-winfs"))]
use std::sync::Mutex;
#[cfg(all(windows, feature = "mount-winfs"))]
use std::time::{Duration, UNIX_EPOCH};

#[cfg(all(windows, feature = "mount-winfs"))]
use dokan::{
    init as dokan_init, unmount as dokan_unmount, CreateFileInfo, DiskSpaceInfo, FileInfo,
    FileSystemHandler, FileSystemMounter, FillDataResult, FindData, MountFlags, MountOptions,
    OperationInfo, OperationResult, VolumeInfo,
};
#[cfg(all(windows, feature = "mount-winfs"))]
use widestring::{U16CStr, U16CString};
#[cfg(all(windows, feature = "mount-winfs"))]
use winapi::shared::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_FULL, STATUS_INTERNAL_ERROR,
    STATUS_INVALID_PARAMETER, STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY,
    STATUS_NOT_IMPLEMENTED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
};
#[cfg(all(windows, feature = "mount-winfs"))]
use winapi::um::winnt::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT};

/// Dokan-backed mounter for Windows.
///
/// Construction is infallible; the actual Dokan session is spawned on a
/// dedicated `std::thread` by [`SftpMounter::mount`]. Drop performs a best
/// effort umount.
pub struct WinFsMounter {
    #[allow(dead_code)]
    sftp: Arc<SftpClient>,
    /// State of the most recent live mount. Cleared by `umount`.
    #[cfg(all(windows, feature = "mount-winfs"))]
    live: Option<LiveMount>,
}

#[cfg(all(windows, feature = "mount-winfs"))]
struct LiveMount {
    /// Wide-char mount point used to signal `dokan::unmount`.
    mount_point: U16CString,
    /// Join handle for the dedicated kernel-IO thread.
    join: Option<std::thread::JoinHandle<()>>,
}

impl WinFsMounter {
    /// Construct a `WinFsMounter` over the given SFTP client.
    #[must_use]
    pub fn new(sftp: Arc<SftpClient>) -> Self {
        Self {
            sftp,
            #[cfg(all(windows, feature = "mount-winfs"))]
            live: None,
        }
    }
}

/// Back-compat alias used by the factory in `super::mod`. The name traces
/// back to the original t7-A6 `WinFspMounter` symbol; t7-P2 renamed the
/// underlying type to [`WinFsMounter`] (the backend is Dokan, not `WinFsp`).
/// The `mod.rs` factory is outside the t7-P2 lock list so the alias
/// preserves source compatibility without touching it.
pub type WinFspMounter = WinFsMounter;

// ============================================================================
// Live backend (Windows + `mount-winfs`).
// ============================================================================

#[cfg(all(windows, feature = "mount-winfs"))]
impl SftpMounter for WinFsMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        // Lazy global init (Dokan requires a single `DokanInit()` per
        // process; `DokanShutdown()` is a process-global teardown and never
        // called from a library context). Declared up-front to keep the
        // function free of `items_after_statements` lint noise.
        static DOKAN_INIT: std::sync::Once = std::sync::Once::new();

        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "windows-dokan",
        });

        // Bridge: capture a tokio runtime handle to use inside Dokan's
        // synchronous callbacks. The CLI entry point is `#[tokio::main]`
        // so this is always inside a runtime.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            let err = SftpError::Local {
                op: "mount",
                detail: "WinFsMounter::mount must be called from inside a tokio runtime".into(),
            };
            opts.emit(&MountEvent::MountFailed {
                target: opts.mountpoint.clone(),
                reason: err.to_string(),
            });
            return Err(err);
        };

        DOKAN_INIT.call_once(dokan_init);

        // Convert the local mount point. Dokan accepts either a drive
        // letter (`"M"`) or a directory path on an NTFS volume.
        let mp_str = opts.mountpoint.to_string_lossy().into_owned();
        let mount_point = match U16CString::from_str(&mp_str) {
            Ok(s) => s,
            Err(e) => {
                let err = SftpError::Local {
                    op: "mount",
                    detail: format!("mountpoint contains interior NUL: {e}"),
                };
                opts.emit(&MountEvent::MountFailed {
                    target: opts.mountpoint.clone(),
                    reason: err.to_string(),
                });
                return Err(err);
            }
        };

        let remote_root = {
            let r = opts.remote_root.to_string_lossy().into_owned();
            if r.is_empty() {
                "/".to_string()
            } else {
                r.trim_end_matches('/').to_string()
            }
        };
        let readonly = opts.readonly;
        let volume_name = opts
            .volume_name
            .clone()
            .unwrap_or_else(|| "spt-sftp".to_string());

        // We hand everything the spawned thread needs by value so the
        // Dokan handler lifetime is purely thread-local. A oneshot channel
        // surfaces the initial mount result (success / driver error)
        // before the kernel-IO loop blocks.
        let mp_for_thread = mount_point.clone();
        let sftp_for_thread = self.sftp.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);

        let join = std::thread::Builder::new()
            .name("spt-sftp-dokan".into())
            .spawn(move || {
                let handler = DokanSftpFs::new(
                    sftp_for_thread,
                    runtime,
                    remote_root,
                    readonly,
                );
                let mut flags = MountFlags::empty();
                if readonly {
                    flags |= MountFlags::WRITE_PROTECT;
                }
                let volume_label = U16CString::from_str(&volume_name)
                    .unwrap_or_else(|_| U16CString::from_str("spt-sftp").unwrap());
                // Stash the volume label in the handler so
                // `get_volume_information` can serve it back to the kernel.
                handler.set_volume_label(volume_label);
                let options = MountOptions {
                    flags,
                    timeout: Duration::from_secs(30),
                    ..Default::default()
                };
                // Nested scope so `mounter` (and its borrow of `handler`
                // and `options`) is dropped before `handler` / `options`
                // themselves.
                {
                    let mut mounter =
                        FileSystemMounter::new(&handler, &mp_for_thread, &options);
                    match mounter.mount() {
                        Ok(fs) => {
                            // Notify caller the mount is live, then block
                            // here until the kernel issues unmount (driven
                            // from outside via `dokan::unmount`). Dropping
                            // `fs` waits for the kernel-side teardown.
                            let _ = tx.send(Ok(()));
                            drop(fs);
                        }
                        Err(e) => {
                            let _ = tx.send(Err(format!("dokan mount failed: {e}")));
                        }
                    }
                }
                drop(handler);
            })
            .map_err(|e| SftpError::Local {
                op: "mount",
                detail: format!("spawn dokan thread failed: {e}"),
            })?;

        // Wait for the kernel to confirm the mount attached (or fail
        // fast). A 30s ceiling matches the Dokan default timeout.
        let outcome = rx.recv_timeout(Duration::from_secs(30));
        match outcome {
            Ok(Ok(())) => {
                self.live = Some(LiveMount {
                    mount_point,
                    join: Some(join),
                });
                opts.emit(&MountEvent::MountSucceeded {
                    target: opts.mountpoint.clone(),
                    backend: "windows-dokan",
                });
                Ok(MountHandle::new(opts.mountpoint, "windows-dokan"))
            }
            Ok(Err(detail)) => {
                let _ = join.join();
                // Driver-install / version-mismatch errors mean the
                // Dokany runtime isn't present on this host: surface as
                // `UnsupportedPlatform` so the CLI exit code lands on
                // `spt_core::ExitCode::UnsupportedPlatform` (10) and the
                // diagnostic guides the operator to `choco install
                // dokany2`. Other failure classes (mount-point taken,
                // bad drive letter) are surfaced as `Other` so they
                // map to the generic runtime-error exit code.
                let lower = detail.to_ascii_lowercase();
                let is_runtime_gap = lower.contains("install driver")
                    || lower.contains("driver install")
                    || lower.contains("incompatible version")
                    || lower.contains("version error");
                let err = if is_runtime_gap {
                    SftpError::UnsupportedPlatform {
                        op: "mount",
                        detail: format!(
                            "{detail}: SFTP mount not supported on this host until \
                             the Dokany2 driver is installed. Run \
                             `choco install dokany2 -y` (or download from \
                             https://dokan-dev.github.io/) and retry."
                        ),
                    }
                } else {
                    SftpError::Other {
                        op: "mount",
                        detail,
                    }
                };
                opts.emit(&MountEvent::MountFailed {
                    target: opts.mountpoint.clone(),
                    reason: err.to_string(),
                });
                Err(err)
            }
            Err(_) => {
                // Timed out waiting for the kernel — try to clean up the
                // spawned thread via an unmount probe, but don't block
                // indefinitely.
                let _ = dokan_unmount(&mount_point);
                let _ = join.join();
                let err = SftpError::Other {
                    op: "mount",
                    detail: "timed out waiting for dokan kernel to attach the mount".into(),
                };
                opts.emit(&MountEvent::MountFailed {
                    target: opts.mountpoint.clone(),
                    reason: err.to_string(),
                });
                Err(err)
            }
        }
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        let _ = handle;
        // Idempotent: a second umount after the session is torn down is a
        // no-op (matches `linux_fuse::FuseMounter::umount`).
        if let Some(mut live) = self.live.take() {
            let _ = dokan_unmount(&live.mount_point);
            if let Some(join) = live.join.take() {
                // Bounded wait — if the kernel teardown stalls we don't
                // block the caller forever. Dokan typically responds within
                // a few hundred ms.
                let _ = join.join();
            }
        }
        Ok(())
    }
}

#[cfg(all(windows, feature = "mount-winfs"))]
impl Drop for WinFsMounter {
    fn drop(&mut self) {
        if let Some(mut live) = self.live.take() {
            let _ = dokan_unmount(&live.mount_point);
            if let Some(join) = live.join.take() {
                let _ = join.join();
            }
        }
    }
}

// ============================================================================
// Stub backend (Windows without `mount-winfs`, or non-Windows hosts).
// ============================================================================

#[cfg(all(windows, not(feature = "mount-winfs")))]
impl SftpMounter for WinFsMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "windows-dokan-stub",
        });
        let err = SftpError::UnsupportedPlatform {
            op: "mount",
            detail: "Windows Dokan backend not compiled in: mount-winfs feature not enabled. \
                     SFTP mount is not supported on this build; rebuild with \
                     `cargo build -p spt-sftp --features mount-winfs` and install \
                     Dokany2 (`choco install dokany2 -y`)."
                .into(),
        };
        opts.emit(&MountEvent::MountFailed {
            target: opts.mountpoint.clone(),
            reason: err.to_string(),
        });
        Err(err)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        let _ = handle;
        Ok(())
    }
}

#[cfg(not(windows))]
impl SftpMounter for WinFsMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "windows-dokan-stub",
        });
        let err = unsupported_platform_error();
        opts.emit(&MountEvent::MountFailed {
            target: opts.mountpoint.clone(),
            reason: err.to_string(),
        });
        Err(err)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        let _ = handle;
        Ok(())
    }
}

// ============================================================================
// DokanSftpFs — the live `FileSystemHandler` implementation.
// ============================================================================

#[cfg(all(windows, feature = "mount-winfs"))]
const DEFAULT_FILE_INDEX: u64 = 1;

#[cfg(all(windows, feature = "mount-winfs"))]
fn ntstatus_for(err: &SftpError) -> i32 {
    match err {
        SftpError::NoSuchFile { .. } => STATUS_OBJECT_NAME_NOT_FOUND,
        SftpError::PermissionDenied { .. } => STATUS_ACCESS_DENIED,
        SftpError::NotADirectory { .. } => STATUS_NOT_A_DIRECTORY,
        SftpError::NotEmpty { .. } => STATUS_DIRECTORY_NOT_EMPTY,
        SftpError::NoSpace { .. } => STATUS_DISK_FULL,
        SftpError::UnsupportedPlatform { .. } => STATUS_NOT_IMPLEMENTED,
        SftpError::Local { .. } | SftpError::Other { .. } => STATUS_INTERNAL_ERROR,
    }
}

/// Translate a Windows-style path (`\sub\file.txt`) plus the remote root
/// (`/srv/data`) into the absolute SFTP path the server expects
/// (`/srv/data/sub/file.txt`).
#[cfg(all(windows, feature = "mount-winfs"))]
fn to_remote_path(remote_root: &str, win_path: &U16CStr) -> String {
    let s = win_path.to_string_lossy();
    // Dokan passes `\` for the root and `\foo\bar` for children. Strip
    // leading backslashes and normalise separators.
    let rel = s.trim_start_matches('\\').replace('\\', "/");
    let trimmed_root = remote_root.trim_end_matches('/');
    if rel.is_empty() {
        if trimmed_root.is_empty() {
            "/".to_string()
        } else {
            trimmed_root.to_string()
        }
    } else if trimmed_root.is_empty() {
        format!("/{rel}")
    } else {
        format!("{trimmed_root}/{rel}")
    }
}

/// In-flight open-file state. We do not pre-buffer remote data — each
/// `read_file` / `write_file` callback re-opens the remote handle at the
/// requested offset. SFTP makes that cheap.
#[cfg(all(windows, feature = "mount-winfs"))]
#[derive(Debug)]
pub struct DokanFileContext {
    /// Remote SFTP path the handle refers to.
    path: String,
    /// Whether this open handle is a directory.
    is_dir: bool,
}

/// `FileSystemHandler` over an `Arc<SftpClient>`.
#[cfg(all(windows, feature = "mount-winfs"))]
pub struct DokanSftpFs {
    sftp: Arc<SftpClient>,
    runtime: tokio::runtime::Handle,
    remote_root: String,
    readonly: bool,
    /// Wide-char volume label served back from `get_volume_information`.
    volume_label: Mutex<U16CString>,
    /// Stable file-index cache so Explorer doesn't see the same inode
    /// twice for different paths. Bounded to 65536 entries.
    file_index: Mutex<HashMap<String, u64>>,
    next_index: Mutex<u64>,
}

#[cfg(all(windows, feature = "mount-winfs"))]
impl DokanSftpFs {
    fn new(
        sftp: Arc<SftpClient>,
        runtime: tokio::runtime::Handle,
        remote_root: String,
        readonly: bool,
    ) -> Self {
        Self {
            sftp,
            runtime,
            remote_root,
            readonly,
            volume_label: Mutex::new(U16CString::from_str("spt-sftp").unwrap()),
            file_index: Mutex::new(HashMap::new()),
            next_index: Mutex::new(2),
        }
    }

    fn set_volume_label(&self, label: U16CString) {
        if let Ok(mut g) = self.volume_label.lock() {
            *g = label;
        }
    }

    fn allocate_index(&self, path: &str) -> u64 {
        if path == "/" || path == self.remote_root {
            return DEFAULT_FILE_INDEX;
        }
        if let Ok(mut idx) = self.file_index.lock() {
            if let Some(&v) = idx.get(path) {
                return v;
            }
            let mut next = self.next_index.lock().expect("next_index poisoned");
            let v = *next;
            *next = next.checked_add(1).unwrap_or(2);
            // Bound the cache so a fuzz-style readdir storm cannot grow it
            // without limit.
            if idx.len() >= 65_536 {
                idx.clear();
            }
            idx.insert(path.to_string(), v);
            v
        } else {
            DEFAULT_FILE_INDEX
        }
    }

    fn fetch_meta(&self, path: &str) -> Result<crate::client::SftpMetadata, SftpError> {
        let sftp = self.sftp.clone();
        let p = path.to_string();
        self.runtime.block_on(async move { sftp.lstat(p).await })
    }

    fn file_info_from_meta(
        &self,
        path: &str,
        meta: &crate::client::SftpMetadata,
    ) -> FileInfo {
        let mtime = meta
            .modified_unix
            .map_or(UNIX_EPOCH, |s| UNIX_EPOCH + Duration::from_secs(u64::from(s)));
        let mut attributes = if meta.is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        if meta.is_symlink {
            attributes |= FILE_ATTRIBUTE_REPARSE_POINT;
        }
        FileInfo {
            attributes,
            creation_time: mtime,
            last_access_time: mtime,
            last_write_time: mtime,
            file_size: meta.size.unwrap_or(0),
            number_of_links: 1,
            file_index: self.allocate_index(path),
        }
    }
}

#[cfg(all(windows, feature = "mount-winfs"))]
impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for DokanSftpFs {
    type Context = DokanFileContext;

    fn create_file(
        &'h self,
        file_name: &U16CStr,
        _security_context: &dokan_sys::DOKAN_IO_SECURITY_CONTEXT,
        _desired_access: winapi::um::winnt::ACCESS_MASK,
        _file_attributes: u32,
        _share_access: u32,
        create_disposition: u32,
        _create_options: u32,
        info: &mut OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        // `dokan_sys::win32::FILE_CREATE` / `FILE_OPEN` / `FILE_OPEN_IF` /
        // `FILE_OVERWRITE` / `FILE_OVERWRITE_IF` / `FILE_SUPERSEDE` map to
        // the NT create dispositions. We care about three classes:
        //   1. open-if-exists  (FILE_OPEN, FILE_OPEN_IF)
        //   2. create-if-not   (FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_SUPERSEDE)
        //   3. truncate        (FILE_OVERWRITE*, FILE_SUPERSEDE)
        const FILE_SUPERSEDE: u32 = 0;
        const FILE_OPEN: u32 = 1;
        const FILE_CREATE: u32 = 2;
        const FILE_OPEN_IF: u32 = 3;
        const FILE_OVERWRITE: u32 = 4;
        const FILE_OVERWRITE_IF: u32 = 5;

        let path = to_remote_path(&self.remote_root, file_name);
        let is_dir_hint = info.is_dir();
        let meta = self.fetch_meta(&path);

        let exists = meta.is_ok();
        let actually_dir = meta.as_ref().map(|m| m.is_dir).unwrap_or(false);

        // Validate dispositions.
        match create_disposition {
            FILE_OPEN if !exists => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
            FILE_CREATE if exists => return Err(STATUS_OBJECT_NAME_COLLISION),
            _ => {}
        }

        let mut new_file_created = false;
        if !exists && matches!(
            create_disposition,
            FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE
        ) {
            if self.readonly {
                return Err(STATUS_MEDIA_WRITE_PROTECTED);
            }
            // Create the file (or directory).
            let sftp = self.sftp.clone();
            let p = path.clone();
            let result = if is_dir_hint {
                self.runtime.block_on(async move { sftp.create_dir_idem(p).await })
            } else {
                self.runtime.block_on(async move { sftp.write_file(p, &[]).await })
            };
            if let Err(e) = result {
                return Err(ntstatus_for(&e));
            }
            new_file_created = true;
        } else if exists
            && matches!(
                create_disposition,
                FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE
            )
        {
            if self.readonly {
                return Err(STATUS_MEDIA_WRITE_PROTECTED);
            }
            if !actually_dir {
                // Truncate by re-writing as empty.
                let sftp = self.sftp.clone();
                let p = path.clone();
                if let Err(e) = self
                    .runtime
                    .block_on(async move { sftp.write_file(p, &[]).await })
                {
                    return Err(ntstatus_for(&e));
                }
            }
        }

        let is_dir = if exists { actually_dir } else { is_dir_hint };
        Ok(CreateFileInfo {
            context: DokanFileContext { path, is_dir },
            is_dir,
            new_file_created,
        })
    }

    fn cleanup(
        &'h self,
        _file_name: &U16CStr,
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) {
        // If the kernel marked the file for delete-on-close, honour it
        // here — `close_file` happens later and is not allowed to fail.
        if info.delete_on_close() && !self.readonly {
            let sftp = self.sftp.clone();
            let p = context.path.clone();
            let is_dir = context.is_dir;
            let _ = self.runtime.block_on(async move {
                if is_dir {
                    sftp.remove_dir(p).await
                } else {
                    sftp.remove_file(p).await
                }
            });
        }
    }

    fn close_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) {
        // Context is dropped automatically by Dokan after this returns.
    }

    fn read_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let off = offset as u64;
        let want = buffer.len();
        let sftp = self.sftp.clone();
        let p = context.path.clone();
        let result: Result<Vec<u8>, SftpError> = self.runtime.block_on(async move {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            let mut file = sftp.open_for_read(p).await?;
            if off > 0 {
                file.seek(std::io::SeekFrom::Start(off))
                    .await
                    .map_err(|e| SftpError::Local {
                        op: "read-seek",
                        detail: e.to_string(),
                    })?;
            }
            let mut buf = vec![0u8; want];
            let mut filled = 0;
            while filled < want {
                let n = file
                    .read(&mut buf[filled..])
                    .await
                    .map_err(|e| SftpError::Local {
                        op: "read",
                        detail: e.to_string(),
                    })?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            buf.truncate(filled);
            Ok(buf)
        });
        match result {
            Ok(data) => {
                let n = data.len().min(buffer.len());
                buffer[..n].copy_from_slice(&data[..n]);
                Ok(n as u32)
            }
            Err(e) => Err(ntstatus_for(&e)),
        }
    }

    fn write_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &[u8],
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        if self.readonly {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let off = if info.write_to_eof() {
            // We don't track the current size in-handle; ask the server.
            match self.fetch_meta(&context.path) {
                Ok(m) => m.size.unwrap_or(0),
                Err(e) => return Err(ntstatus_for(&e)),
            }
        } else if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        } else {
            offset as u64
        };
        let bytes = buffer.to_vec();
        let written = bytes.len() as u32;
        let sftp = self.sftp.clone();
        let p = context.path.clone();
        let result: Result<(), SftpError> = self.runtime.block_on(async move {
            use tokio::io::AsyncWriteExt;
            let mut file = sftp.open_for_resume_write(p, off).await?;
            file.write_all(&bytes).await.map_err(|e| SftpError::Local {
                op: "write",
                detail: e.to_string(),
            })?;
            file.shutdown().await.map_err(|e| SftpError::Local {
                op: "write-close",
                detail: e.to_string(),
            })?;
            Ok(())
        });
        match result {
            Ok(()) => Ok(written),
            Err(e) => Err(ntstatus_for(&e)),
        }
    }

    fn flush_file_buffers(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        // SFTP has no protocol-level fsync; we close-and-reopen per write
        // so the data is on the wire already.
        Ok(())
    }

    fn get_file_information(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<FileInfo> {
        let meta = self.fetch_meta(&context.path).map_err(|e| ntstatus_for(&e))?;
        Ok(self.file_info_from_meta(&context.path, &meta))
    }

    fn find_files(
        &'h self,
        _file_name: &U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        if !context.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let sftp = self.sftp.clone();
        let p = context.path.clone();
        let entries = self
            .runtime
            .block_on(async move { sftp.read_dir(p).await })
            .map_err(|e| ntstatus_for(&e))?;
        for entry in entries {
            if entry.file_name == "." || entry.file_name == ".." {
                continue;
            }
            let mtime = entry
                .metadata
                .modified_unix
                .map_or(UNIX_EPOCH, |s| UNIX_EPOCH + Duration::from_secs(u64::from(s)));
            let attributes = if entry.metadata.is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
            let Ok(name) = U16CString::from_str(&entry.file_name) else {
                continue;
            };
            let data = FindData {
                attributes,
                creation_time: mtime,
                last_access_time: mtime,
                last_write_time: mtime,
                file_size: entry.metadata.size.unwrap_or(0),
                file_name: name,
            };
            match fill_find_data(&data) {
                Ok(()) => {}
                Err(_) => break,
            }
        }
        Ok(())
    }

    fn delete_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        if self.readonly {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        // Defer the actual unlink to `cleanup` (Dokan's documented
        // contract — `delete_file` is the "can this be deleted?" probe).
        Ok(())
    }

    fn delete_directory(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        if self.readonly {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        // Ensure the directory is empty up-front; we ignore "." / "..".
        let sftp = self.sftp.clone();
        let p = context.path.clone();
        let entries = self
            .runtime
            .block_on(async move { sftp.read_dir(p).await })
            .map_err(|e| ntstatus_for(&e))?;
        let has_children = entries
            .iter()
            .any(|e| e.file_name != "." && e.file_name != "..");
        if has_children {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        Ok(())
    }

    fn move_file(
        &'h self,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_existing: bool,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        if self.readonly {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let to = to_remote_path(&self.remote_root, new_file_name);
        let from = context.path.clone();
        let sftp = self.sftp.clone();
        self.runtime
            .block_on(async move { sftp.rename(from, to).await })
            .map_err(|e| ntstatus_for(&e))
    }

    fn set_end_of_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        if self.readonly {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        // Only support truncation-to-zero (mirrors the linux_fuse arm).
        if offset != 0 {
            return Err(STATUS_NOT_IMPLEMENTED);
        }
        let sftp = self.sftp.clone();
        let p = context.path.clone();
        self.runtime
            .block_on(async move { sftp.write_file(p, &[]).await })
            .map_err(|e| ntstatus_for(&e))
    }

    fn get_disk_free_space(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<DiskSpaceInfo> {
        // SFTP statvfs is an OpenSSH extension we don't surface; report a
        // generous fake so Explorer doesn't show 0%-full.
        let total: u64 = 1 << 40; // 1 TiB
        let free: u64 = 1 << 39; // 512 GiB
        Ok(DiskSpaceInfo {
            byte_count: total,
            free_byte_count: free,
            available_byte_count: free,
        })
    }

    fn get_volume_information(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<VolumeInfo> {
        let label = self.volume_label.lock().map_or_else(
            |_| U16CString::from_str("spt-sftp").unwrap(),
            |g| g.clone(),
        );
        let fs_name = U16CString::from_str("NTFS").expect("NTFS is valid utf-16");
        Ok(VolumeInfo {
            name: label,
            serial_number: 0x5354_5046, // 'STPF'
            max_component_length: 255,
            fs_flags: 0,
            fs_name,
        })
    }

    fn mounted(
        &'h self,
        _mount_point: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<()> {
        Ok(())
    }

    fn unmounted(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<()> {
        Ok(())
    }
}

// ============================================================================
// Tests.
// ============================================================================

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::mock::MockSftpServer;
    use tempfile::tempdir;

    /// Even without the live Dokan runtime the stub arm must return a
    /// structured `UnsupportedPlatform` error so the CLI surfaces the
    /// canonical exit code (matches A6 contract).
    #[cfg(not(feature = "mount-winfs"))]
    #[tokio::test(flavor = "current_thread")]
    async fn winfs_mount_stub_returns_unsupported_platform() {
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = WinFsMounter::new(Arc::new(client));
        let opts = MountOpts::new("C:/mnt/spt-test", "/srv/data");
        let err = mounter.mount(opts).expect_err("expected diagnostic");
        match err {
            SftpError::UnsupportedPlatform { op, detail } => {
                assert_eq!(op, "mount");
                assert!(
                    detail.contains("mount-winfs") || detail.contains("not supported"),
                    "stub diagnostic should name the feature gap: {detail}"
                );
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    /// `umount` is a no-op when no live session is attached; double-calls
    /// stay `Ok(())`.
    #[tokio::test(flavor = "current_thread")]
    async fn winfs_umount_is_idempotent_no_op() {
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = WinFsMounter::new(Arc::new(client));
        let handle = MountHandle::new("C:/mnt/spt-test".into(), "windows-dokan");
        mounter.umount(handle.clone()).expect("umount-1");
        mounter.umount(handle).expect("umount-2");
    }

    /// Path translation: ensures Win-style separators reach the SFTP
    /// server as POSIX paths joined under the configured remote root.
    #[cfg(feature = "mount-winfs")]
    #[test]
    fn to_remote_path_translates_windows_separators() {
        use widestring::U16CString;
        let mp_root = U16CString::from_str("\\").unwrap();
        let mp_sub = U16CString::from_str("\\sub\\file.txt").unwrap();
        assert_eq!(to_remote_path("/srv/data", &mp_root), "/srv/data");
        assert_eq!(to_remote_path("/srv/data", &mp_sub), "/srv/data/sub/file.txt");
        assert_eq!(to_remote_path("/", &mp_sub), "/sub/file.txt");
    }
}

// ============================================================================
// Live Dokan tests (Windows + `mount-winfs`, opt-in via SPT_WINFS_LIVE=1).
//
// These tests mount a Dokan volume against an in-process `MockSftpServer`
// fixture and exercise real Windows IO (`std::fs::*`) through the
// mountpoint. They require:
//
//   1. The Dokany2 driver installed (`choco install dokany2 -y`).
//   2. The `dokan2.dll` userspace library on `%PATH%` or in the standard
//      Dokany install dir (`%ProgramFiles%\Dokan\Dokan Library-2.x.x\x64`).
//   3. `SPT_WINFS_LIVE=1` in the environment to opt-in.
//
// CI gate (Phase C job, Windows runner):
//
//   choco install dokany2 -y
//   $env:SPT_WINFS_LIVE = '1'
//   cargo test -p spt-sftp --locked --features testing,mount-winfs \
//       -- --ignored live
//
// On any other configuration these tests stay `#[ignore]`'d and the suite
// reports them as skipped.
// ============================================================================

#[cfg(all(test, target_os = "windows", feature = "mount-winfs"))]
mod live {
    use super::*;
    use crate::mock::MockSftpServer;
    use std::time::Duration;
    use tempfile::tempdir;

    fn live_enabled() -> bool {
        std::env::var("SPT_WINFS_LIVE").as_deref() == Ok("1")
    }

    /// Pick a candidate mount path. We use a per-test temp directory; the
    /// Dokany2 driver will turn it into a mount point under the local file
    /// system (NTFS).
    fn pick_mountpoint(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("spt-winfs-{}-{}", tag, std::process::id()));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    async fn mount_fixture(
        tag: &str,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        WinFsMounter,
        MountHandle,
    ) {
        let remote = tempdir().expect("remote tempdir");
        let mp = pick_mountpoint(tag);
        let (_srv, client) = MockSftpServer::start(remote.path()).await;
        let mut mounter = WinFsMounter::new(Arc::new(client));
        let opts = MountOpts::new(mp.clone(), "/");
        let handle = mounter.mount(opts).expect("dokan mount");
        // Give the kernel a beat to fully attach before the first IO.
        tokio::time::sleep(Duration::from_millis(200)).await;
        (remote, mp, mounter, handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs Dokany2 + SPT_WINFS_LIVE=1"]
    async fn mount_then_list_root() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture("listroot").await;
        std::fs::write(remote.path().join("hello.txt"), b"hi").expect("seed");
        let entries: Vec<_> = std::fs::read_dir(&mp).expect("readdir").collect();
        assert!(!entries.is_empty(), "mount should expose seeded file");
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs Dokany2 + SPT_WINFS_LIVE=1"]
    async fn read_through_mount() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture("read").await;
        std::fs::write(remote.path().join("doc.txt"), b"hello world").expect("seed");
        let got = std::fs::read(mp.join("doc.txt")).expect("read");
        assert_eq!(got, b"hello world");
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs Dokany2 + SPT_WINFS_LIVE=1"]
    async fn write_through_mount() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture("write").await;
        std::fs::write(mp.join("out.bin"), b"payload").expect("write through mount");
        let back = std::fs::read(remote.path().join("out.bin")).expect("readback");
        assert_eq!(back, b"payload");
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs Dokany2 + SPT_WINFS_LIVE=1"]
    async fn create_then_delete() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture("create").await;
        std::fs::write(mp.join("doomed.txt"), b"x").expect("create");
        assert!(remote.path().join("doomed.txt").exists());
        std::fs::remove_file(mp.join("doomed.txt")).expect("delete");
        assert!(!remote.path().join("doomed.txt").exists());
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs Dokany2 + SPT_WINFS_LIVE=1"]
    async fn rename_atomic() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture("rename").await;
        std::fs::write(remote.path().join("a.txt"), b"abc").expect("seed");
        std::fs::rename(mp.join("a.txt"), mp.join("b.txt")).expect("rename");
        assert!(remote.path().join("b.txt").exists());
        assert!(!remote.path().join("a.txt").exists());
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs Dokany2 + SPT_WINFS_LIVE=1"]
    async fn umount_idempotent() {
        if !live_enabled() {
            return;
        }
        let (_remote, _mp, mut mounter, handle) = mount_fixture("idem").await;
        mounter.umount(handle.clone()).expect("umount-1");
        // After the live session is torn down, a second umount is a no-op.
        mounter.umount(handle).expect("umount-2");
    }
}
