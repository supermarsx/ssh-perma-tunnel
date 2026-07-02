//! Linux FUSE backend.
//!
//! When the `mount-fuse` cargo feature is **enabled** *and* the build target
//! is `linux`, this module wires [`SftpClient`] callbacks to the kernel via
//! the `fuser` crate (0.16). The session is hosted by
//! `fuser::BackgroundSession`, which owns a dedicated [`std::thread`]
//! driving the kernel IO loop. Each `fuser::Filesystem` callback is
//! synchronous; the backend captures a [`tokio::runtime::Handle`] at mount
//! time and uses [`tokio::runtime::Handle::block_on`] to call back into the
//! async [`SftpClient`].
//!
//! When the feature is **disabled** (or the target is not linux) the
//! backend compiles to a stub whose `mount` returns
//! [`SftpError::UnsupportedPlatform`] cleanly — this keeps
//! `cargo build --workspace --locked` working on hosts that don't have
//! `libfuse-dev` installed and on non-Linux operators.
//!
//! ## SFTP↔FUSE error translation
//!
//! | [`SftpError`] variant     | `errno` returned to the kernel |
//! |---------------------------|--------------------------------|
//! | `NoSuchFile`              | `ENOENT`                       |
//! | `PermissionDenied`        | `EACCES`                       |
//! | `NotADirectory`           | `ENOTDIR`                      |
//! | `NotEmpty`                | `ENOTEMPTY`                    |
//! | `NoSpace`                 | `ENOSPC`                       |
//! | `Local`                   | `EIO`                          |
//! | `Other`                   | `EIO` (default)                |
//! | `UnsupportedPlatform`     | `ENOSYS`                       |
//!
//! Stale handles surface `ESTALE`. The translation lives in
//! `errno_for` for future audit.

use std::sync::Arc;

use super::{MountEvent, MountHandle, MountOpts, SftpMounter};
use crate::client::SftpClient;
use crate::error::SftpError;

/// t8-A2: render a `catch_unwind` payload as a human-readable string.
///
/// Shared utility for the panic-recovery boundary helpers below. The
/// `Box<dyn Any + Send>` returned by [`std::panic::catch_unwind`] is the
/// raw panic payload — almost always `String` or `&'static str`; anything
/// else falls through to a stable marker.
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
fn panic_string(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = p.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    "(non-string panic payload)".to_string()
}

/// t8-A2: catch a panic crossing the fuser callback boundary and return a
/// fallback errno so the kernel sees `EIO` (the documented "I/O error"
/// reply) rather than the supervisor process aborting.
///
/// fuser callbacks run on a dedicated kernel-IO thread. The SFTP futures
/// they call into are user-supplied (`russh-sftp` + `Arc<SftpClient>`);
/// a panic inside `block_on(async { … })` would otherwise unwind through
/// the fuser dispatch loop and tear down the mount. We catch here, log
/// via `tracing::error!`, and surface as `EIO` — operators see a clean
/// I/O failure on the mounted path and the supervisor stays up.
///
/// The closure takes no arguments; capture whatever it needs by move.
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
fn catch_fuse_callback<T>(
    label: &'static str,
    f: impl FnOnce() -> Result<T, SftpError>,
) -> Result<T, SftpError> {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(panic) => {
            let msg = panic_string(&panic);
            tracing::error!(
                target = "spt_sftp::mount::fuse",
                callback = label,
                panic = %msg,
                "fuser callback panicked across the FFI boundary; replying EIO",
            );
            Err(SftpError::Local {
                op: "fuse-callback",
                detail: format!("fuser `{label}` callback panicked: {msg}"),
            })
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
use std::collections::HashMap;
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
use std::ffi::OsStr;
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
use std::sync::Mutex;
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
use fuser::{
    BackgroundSession, FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow,
};

/// FUSE-backed mounter for Linux.
pub struct FuseMounter {
    #[allow(dead_code)]
    sftp: Arc<SftpClient>,
    /// Active background session. Dropping it unmounts; held in `Option` so
    /// `umount` can `take()` to force the kernel umount before the
    /// `FuseMounter` itself is dropped.
    #[cfg(all(target_os = "linux", feature = "mount-fuse"))]
    session: Option<BackgroundSession>,
}

impl FuseMounter {
    /// Construct a `FuseMounter` over `sftp`. Returns immediately; the
    /// FUSE session is started by [`SftpMounter::mount`].
    #[must_use]
    pub fn new(sftp: Arc<SftpClient>) -> Self {
        Self {
            sftp,
            #[cfg(all(target_os = "linux", feature = "mount-fuse"))]
            session: None,
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
impl SftpMounter for FuseMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "linux-fuse",
        });

        // We need a tokio runtime handle to bridge sync FUSE callbacks into
        // the async `SftpClient`. The caller is expected to invoke `mount`
        // from inside a tokio context (the CLI's `#[tokio::main]` runtime
        // or a `Runtime::block_on` shell).
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            let err = SftpError::Local {
                op: "mount",
                detail: "FuseMounter::mount must be called from inside a tokio runtime".into(),
            };
            opts.emit(&MountEvent::MountFailed {
                target: opts.mountpoint.clone(),
                reason: err.to_string(),
            });
            return Err(err);
        };

        let fs = FuseFs::new(self.sftp.clone(), handle, &opts);

        let mut fuse_opts: Vec<MountOption> = vec![
            MountOption::FSName("spt-sftp".into()),
            MountOption::Subtype("spt".into()),
            MountOption::DefaultPermissions,
        ];
        if opts.readonly {
            fuse_opts.push(MountOption::RO);
        } else {
            fuse_opts.push(MountOption::RW);
        }
        if opts.allow_other {
            fuse_opts.push(MountOption::AllowOther);
        }

        match fuser::spawn_mount2(fs, &opts.mountpoint, &fuse_opts) {
            Ok(session) => {
                self.session = Some(session);
                opts.emit(&MountEvent::MountSucceeded {
                    target: opts.mountpoint.clone(),
                    backend: "linux-fuse",
                });
                Ok(MountHandle::new(opts.mountpoint, "linux-fuse"))
            }
            Err(e) => {
                let err = SftpError::Other {
                    op: "mount",
                    detail: format!("fuser::spawn_mount2 failed: {e}"),
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
        // Dropping `BackgroundSession` issues `fusermount -u` (libfuse) or
        // `umount` (libc) as appropriate. Calling `umount` twice against
        // the same handle is benign — the second call finds `session ==
        // None`.
        let _ = handle;
        drop(self.session.take());
        Ok(())
    }
}

#[cfg(not(all(target_os = "linux", feature = "mount-fuse")))]
impl SftpMounter for FuseMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "linux-fuse-stub",
        });
        let err = SftpError::UnsupportedPlatform {
            op: "mount",
            detail: "linux FUSE backend not compiled in (enable the `mount-fuse` feature on a Linux target with libfuse-dev installed)".into(),
        };
        opts.emit(&MountEvent::MountFailed {
            target: opts.mountpoint.clone(),
            reason: err.to_string(),
        });
        Err(err)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        // Nothing to tear down when the backend is stubbed.
        let _ = handle;
        Ok(())
    }
}

// ============================================================================
// Real FUSE Filesystem implementation (Linux + `mount-fuse` feature).
// ============================================================================

/// Map an [`SftpError`] into a Linux `errno` for kernel-facing FUSE replies.
///
/// Documented in the module-level error table so future audits can confirm
/// the mapping without re-reading the trait impl.
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
fn errno_for(err: &SftpError) -> i32 {
    match err {
        SftpError::NoSuchFile { .. } => libc::ENOENT,
        SftpError::PermissionDenied { .. } => libc::EACCES,
        SftpError::NotADirectory { .. } => libc::ENOTDIR,
        SftpError::NotEmpty { .. } => libc::ENOTEMPTY,
        SftpError::NoSpace { .. } => libc::ENOSPC,
        SftpError::UnsupportedPlatform { .. } => libc::ENOSYS,
        SftpError::Local { .. } | SftpError::Other { .. } => libc::EIO,
    }
}

/// Stable mapping between FUSE inode numbers and remote SFTP paths.
///
/// Inode 1 is reserved for the mount root. New inodes are allocated on the
/// first `lookup` for a path and pinned for the lifetime of the
/// [`FuseFs`]. A reverse map keeps repeated `lookup` calls for the same
/// path cheap.
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
struct InodeTable {
    next: u64,
    path_for_ino: HashMap<u64, String>,
    ino_for_path: HashMap<String, u64>,
}

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
impl InodeTable {
    fn new(root: &str) -> Self {
        let mut t = Self {
            next: 2,
            path_for_ino: HashMap::new(),
            ino_for_path: HashMap::new(),
        };
        t.path_for_ino.insert(1, root.to_string());
        t.ino_for_path.insert(root.to_string(), 1);
        t
    }

    fn allocate(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.ino_for_path.get(path) {
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.path_for_ino.insert(ino, path.to_string());
        self.ino_for_path.insert(path.to_string(), ino);
        ino
    }

    fn path(&self, ino: u64) -> Option<String> {
        self.path_for_ino.get(&ino).cloned()
    }

    fn forget(&mut self, ino: u64) {
        if let Some(p) = self.path_for_ino.remove(&ino) {
            self.ino_for_path.remove(&p);
        }
    }
}

/// Tiny TTL-bounded attribute cache. Keyed by inode; values evicted when
/// they exceed [`ATTR_TTL`]. Capped to 4096 entries (bounded blast radius
/// for a misbehaving server).
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
const ATTR_TTL: Duration = Duration::from_secs(1);

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
const ATTR_CACHE_CAP: usize = 4096;

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
struct AttrCache {
    by_ino: HashMap<u64, (FileAttr, Instant)>,
}

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
impl AttrCache {
    fn new() -> Self {
        Self {
            by_ino: HashMap::new(),
        }
    }

    fn get(&self, ino: u64) -> Option<FileAttr> {
        self.by_ino.get(&ino).and_then(|(attr, ts)| {
            if ts.elapsed() < ATTR_TTL {
                Some(*attr)
            } else {
                None
            }
        })
    }

    fn put(&mut self, ino: u64, attr: FileAttr) {
        if self.by_ino.len() >= ATTR_CACHE_CAP {
            // Drop the entry with the oldest timestamp. O(n) but capped.
            if let Some((oldest_ino, _)) = self
                .by_ino
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, v)| (*k, *v))
            {
                self.by_ino.remove(&oldest_ino);
            }
        }
        self.by_ino.insert(ino, (attr, Instant::now()));
    }

    fn invalidate(&mut self, ino: u64) {
        self.by_ino.remove(&ino);
    }
}

/// In-flight open-file handle state. We materialise read data lazily on
/// each `read` callback (no streaming buffer) — SFTP supports random
/// reads cheaply.
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
struct OpenHandle {
    /// Remote path the handle refers to.
    path: String,
    /// Whether the handle was opened for write.
    write: bool,
}

/// Real `fuser::Filesystem` over an `Arc<SftpClient>`.
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
pub struct FuseFs {
    sftp: Arc<SftpClient>,
    handle: tokio::runtime::Handle,
    remote_root: String,
    /// Whether the mount was created read-only (rejects writes early with
    /// `EROFS` rather than round-tripping a permission failure).
    readonly: bool,
    /// Override uid/gid in `FileAttr` (the mount-owner masking knob).
    uid: u32,
    gid: u32,
    inode_table: Mutex<InodeTable>,
    attr_cache: Mutex<AttrCache>,
    fh_table: Mutex<HashMap<u64, OpenHandle>>,
    next_fh: std::sync::atomic::AtomicU64,
}

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
impl FuseFs {
    fn new(sftp: Arc<SftpClient>, handle: tokio::runtime::Handle, opts: &MountOpts) -> Self {
        let root = opts.remote_root.to_string_lossy().into_owned();
        // Normalise: SFTP servers expect `/foo`, not `/foo/`.
        let root_norm = if root.is_empty() {
            "/".to_string()
        } else {
            root.trim_end_matches('/').to_string()
        };
        let root_for_table = if root_norm.is_empty() {
            "/".to_string()
        } else {
            root_norm.clone()
        };
        // t8-D2: standalone libc FFI — not inside the fuser callback
        // chokepoint, so `catch_fuse_callback` does not wrap it. The two
        // calls below are POSIX-mandated pure reads with no input pointers
        // and no Rust-level invariants to violate. They are placed in
        // separate `unsafe { … }` blocks so each carries its own adjacent
        // SAFETY comment (clippy::undocumented_unsafe_blocks).
        //
        // SAFETY: `libc::getuid()` is a POSIX-defined syscall that returns
        // the caller's real UID. It takes no arguments, performs no
        // pointer dereference, and cannot fail per POSIX.1-2024.
        let uid = opts.uid.unwrap_or_else(|| unsafe { libc::getuid() });
        // SAFETY: `libc::getgid()` is a POSIX-defined syscall that returns
        // the caller's real GID. Same contract as `getuid` above — no
        // arguments, no failure mode.
        let gid = opts.gid.unwrap_or_else(|| unsafe { libc::getgid() });
        Self {
            sftp,
            handle,
            remote_root: root_norm,
            readonly: opts.readonly,
            uid,
            gid,
            inode_table: Mutex::new(InodeTable::new(&root_for_table)),
            attr_cache: Mutex::new(AttrCache::new()),
            fh_table: Mutex::new(HashMap::new()),
            next_fh: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn ino_to_path(&self, ino: u64) -> Option<String> {
        self.inode_table.lock().ok()?.path(ino)
    }

    /// Read-only enforcement chokepoint shared by every mutating FUSE callback
    /// (`setattr` / `mkdir` / `unlink` / `rmdir` / `symlink` / `rename` /
    /// `create` / `write`, and the write path of `open`).
    ///
    /// Returns `Some(EROFS)` when the mount was created read-only, so writes
    /// are rejected at the VFS boundary rather than after a round-trip to the
    /// server. Centralised so the read-only policy is exercised by a single
    /// unit test (see `readonly_mount_rejects_writes`).
    #[must_use]
    fn readonly_reject(&self) -> Option<i32> {
        self.readonly.then_some(libc::EROFS)
    }

    fn alloc_ino(&self, path: &str) -> u64 {
        self.inode_table
            .lock()
            .map(|mut t| t.allocate(path))
            .unwrap_or(0)
    }

    fn join(parent: &str, name: &str) -> String {
        if parent == "/" {
            format!("/{name}")
        } else {
            format!("{parent}/{name}")
        }
    }

    fn alloc_fh(&self, path: String, write: bool) -> u64 {
        let fh = self
            .next_fh
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut t) = self.fh_table.lock() {
            t.insert(fh, OpenHandle { path, write });
        }
        fh
    }

    fn fh_path(&self, fh: u64) -> Option<(String, bool)> {
        self.fh_table
            .lock()
            .ok()?
            .get(&fh)
            .map(|h| (h.path.clone(), h.write))
    }

    fn release_fh(&self, fh: u64) {
        if let Ok(mut t) = self.fh_table.lock() {
            t.remove(&fh);
        }
    }

    /// Build a [`FileAttr`] from a [`crate::client::SftpMetadata`].
    fn attr_from_meta(&self, ino: u64, meta: &crate::client::SftpMetadata) -> FileAttr {
        let kind = if meta.is_dir {
            FileType::Directory
        } else if meta.is_symlink {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };
        let size = meta.size.unwrap_or(0);
        let mtime = meta.modified_unix.map_or(UNIX_EPOCH, |s| {
            UNIX_EPOCH + Duration::from_secs(u64::from(s))
        });
        let perm = meta
            .permissions
            .unwrap_or(if meta.is_dir { 0o755 } else { 0o644 }) as u16
            & 0o7777;
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm,
            nlink: if meta.is_dir { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn cached_or_fetch_attr(&self, ino: u64, path: &str) -> Result<FileAttr, SftpError> {
        if let Ok(c) = self.attr_cache.lock() {
            if let Some(a) = c.get(ino) {
                return Ok(a);
            }
        }
        let sftp = self.sftp.clone();
        let p = path.to_string();
        let meta = self.handle.block_on(async move { sftp.lstat(p).await })?;
        let attr = self.attr_from_meta(ino, &meta);
        if let Ok(mut c) = self.attr_cache.lock() {
            c.put(ino, attr);
        }
        Ok(attr)
    }
}

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
impl Filesystem for FuseFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // t8-A2: chokepoint panic-recovery wrapper. Anything that panics
        // inside the closure (`block_on(async {…})`, an attribute-cache
        // double-lock, …) surfaces as `EIO` to the kernel instead of
        // aborting the FUSE thread.
        let result = catch_fuse_callback("lookup", || {
            let parent_path = self.ino_to_path(parent).ok_or(SftpError::NoSuchFile {
                op: "lookup",
                detail: format!("ino={parent}"),
            })?;
            let name_str = name.to_str().ok_or(SftpError::Local {
                op: "lookup",
                detail: "non-utf8 name".into(),
            })?;
            let full = Self::join(&parent_path, name_str);
            let sftp = self.sftp.clone();
            let p = full.clone();
            let meta = self.handle.block_on(async move { sftp.lstat(p).await })?;
            let ino = self.alloc_ino(&full);
            let attr = self.attr_from_meta(ino, &meta);
            if let Ok(mut c) = self.attr_cache.lock() {
                c.put(ino, attr);
            }
            Ok(attr)
        });
        match result {
            Ok(attr) => reply.entry(&ATTR_TTL, &attr, 0),
            Err(e) => {
                // Map ESTALE back for the inode-table-miss case so the
                // kernel retries the lookup via the parent — preserves the
                // pre-t8 semantics.
                let errno = match &e {
                    SftpError::NoSuchFile { op, .. } if *op == "lookup" => libc::ESTALE,
                    SftpError::Local { op, .. } if *op == "lookup" => libc::EINVAL,
                    other => errno_for(other),
                };
                reply.error(errno);
            }
        }
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, _nlookup: u64) {
        if ino == 1 {
            return; // root never forgotten
        }
        if let Ok(mut t) = self.inode_table.lock() {
            t.forget(ino);
        }
        if let Ok(mut c) = self.attr_cache.lock() {
            c.invalidate(ino);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(path) = self.ino_to_path(ino) else {
            reply.error(libc::ESTALE);
            return;
        };
        // t8-A2: panic-recovery boundary. A panic inside the cached_or_fetch
        // path (locked-mutex poison, block_on future panic) surfaces as
        // `EIO` rather than aborting the fuser thread.
        let result = catch_fuse_callback("getattr", || self.cached_or_fetch_attr(ino, &path));
        match result {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if let Some(errno) = self.readonly_reject() {
            reply.error(errno);
            return;
        }
        let Some(path) = self.ino_to_path(ino) else {
            reply.error(libc::ESTALE);
            return;
        };
        let sftp = self.sftp.clone();
        if let Some(m) = mode {
            let p = path.clone();
            let res = self.handle.block_on(async move { sftp.chmod(p, m).await });
            if let Err(e) = res {
                reply.error(errno_for(&e));
                return;
            }
        }
        // Truncate (size = 0 is the common case via `open(O_TRUNC)`); the
        // SFTP wire doesn't expose a generic "set size" — we approximate
        // by re-creating the file when size == 0. Non-zero truncations
        // are not supported and surface EOPNOTSUPP.
        if let Some(s) = size {
            if s != 0 {
                reply.error(libc::EOPNOTSUPP);
                return;
            }
            let sftp = self.sftp.clone();
            let p = path.clone();
            let res = self
                .handle
                .block_on(async move { sftp.write_file(p, &[]).await });
            if let Err(e) = res {
                reply.error(errno_for(&e));
                return;
            }
        }
        if let Ok(mut c) = self.attr_cache.lock() {
            c.invalidate(ino);
        }
        match self.cached_or_fetch_attr(ino, &path) {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let Some(path) = self.ino_to_path(ino) else {
            reply.error(libc::ESTALE);
            return;
        };
        let sftp = self.sftp.clone();
        let p = path.clone();
        match self.handle.block_on(async move { sftp.readlink(p).await }) {
            Ok(target) => reply.data(target.to_string_lossy().as_bytes()),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if let Some(errno) = self.readonly_reject() {
            reply.error(errno);
            return;
        }
        let Some(parent_path) = self.ino_to_path(parent) else {
            reply.error(libc::ESTALE);
            return;
        };
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let full = Self::join(&parent_path, name_str);
        let sftp = self.sftp.clone();
        let p = full.clone();
        if let Err(e) = self
            .handle
            .block_on(async move { sftp.create_dir(p).await })
        {
            reply.error(errno_for(&e));
            return;
        }
        let ino = self.alloc_ino(&full);
        match self.cached_or_fetch_attr(ino, &full) {
            Ok(attr) => reply.entry(&ATTR_TTL, &attr, 0),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if let Some(errno) = self.readonly_reject() {
            reply.error(errno);
            return;
        }
        let Some(parent_path) = self.ino_to_path(parent) else {
            reply.error(libc::ESTALE);
            return;
        };
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let full = Self::join(&parent_path, name_str);
        let sftp = self.sftp.clone();
        match self
            .handle
            .block_on(async move { sftp.remove_file(full).await })
        {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if let Some(errno) = self.readonly_reject() {
            reply.error(errno);
            return;
        }
        let Some(parent_path) = self.ino_to_path(parent) else {
            reply.error(libc::ESTALE);
            return;
        };
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let full = Self::join(&parent_path, name_str);
        let sftp = self.sftp.clone();
        match self
            .handle
            .block_on(async move { sftp.remove_dir(full).await })
        {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        if let Some(errno) = self.readonly_reject() {
            reply.error(errno);
            return;
        }
        let Some(parent_path) = self.ino_to_path(parent) else {
            reply.error(libc::ESTALE);
            return;
        };
        let Some(link_str) = link_name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let target_str = target.to_string_lossy().into_owned();
        let full = Self::join(&parent_path, link_str);
        let sftp = self.sftp.clone();
        let p = full.clone();
        if let Err(e) = self
            .handle
            .block_on(async move { sftp.symlink(target_str, p).await })
        {
            reply.error(errno_for(&e));
            return;
        }
        let ino = self.alloc_ino(&full);
        match self.cached_or_fetch_attr(ino, &full) {
            Ok(attr) => reply.entry(&ATTR_TTL, &attr, 0),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        if let Some(errno) = self.readonly_reject() {
            reply.error(errno);
            return;
        }
        let Some(p1) = self.ino_to_path(parent) else {
            reply.error(libc::ESTALE);
            return;
        };
        let Some(p2) = self.ino_to_path(newparent) else {
            reply.error(libc::ESTALE);
            return;
        };
        let Some(n1) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let Some(n2) = newname.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let from = Self::join(&p1, n1);
        let to = Self::join(&p2, n2);
        let sftp = self.sftp.clone();
        match self
            .handle
            .block_on(async move { sftp.rename(from, to).await })
        {
            Ok(()) => {
                if let Ok(mut c) = self.attr_cache.lock() {
                    c.invalidate(parent);
                    c.invalidate(newparent);
                }
                reply.ok();
            }
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(path) = self.ino_to_path(ino) else {
            reply.error(libc::ESTALE);
            return;
        };
        let write = (flags & libc::O_ACCMODE) != libc::O_RDONLY;
        if write {
            if let Some(errno) = self.readonly_reject() {
                reply.error(errno);
                return;
            }
        }
        let fh = self.alloc_fh(path, write);
        reply.opened(fh, 0);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if let Some(errno) = self.readonly_reject() {
            reply.error(errno);
            return;
        }
        let Some(parent_path) = self.ino_to_path(parent) else {
            reply.error(libc::ESTALE);
            return;
        };
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let full = Self::join(&parent_path, name_str);
        // Touch the file to create it (zero-byte).
        let sftp = self.sftp.clone();
        let p = full.clone();
        if let Err(e) = self
            .handle
            .block_on(async move { sftp.write_file(p, &[]).await })
        {
            reply.error(errno_for(&e));
            return;
        }
        let ino = self.alloc_ino(&full);
        if let Ok(mut c) = self.attr_cache.lock() {
            c.invalidate(ino);
        }
        match self.cached_or_fetch_attr(ino, &full) {
            Ok(attr) => {
                let fh = self.alloc_fh(full, true);
                reply.created(&ATTR_TTL, &attr, 0, fh, 0);
            }
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some((path, _w)) = self.fh_path(fh) else {
            reply.error(libc::ESTALE);
            return;
        };
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let off = offset as u64;
        let want = size as usize;
        let sftp = self.sftp.clone();
        // t8-A2: chokepoint panic-recovery. Any panic inside the SFTP
        // future (russh transport, codec parser, …) surfaces as `EIO`
        // instead of aborting the fuser thread.
        let result = catch_fuse_callback("read", || {
            self.handle.block_on(async move {
                // Read a window via seek + read. The russh-sftp client
                // gives us an `AsyncRead + AsyncSeek` file handle.
                use tokio::io::{AsyncReadExt, AsyncSeekExt};
                let mut file = sftp.open_for_read(path).await?;
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
                Ok::<_, SftpError>(buf)
            })
        });
        match result {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if let Some(errno) = self.readonly_reject() {
            reply.error(errno);
            return;
        }
        let Some((path, _w)) = self.fh_path(fh) else {
            reply.error(libc::ESTALE);
            return;
        };
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let off = offset as u64;
        let bytes = data.to_vec();
        let written = bytes.len() as u32;
        let sftp = self.sftp.clone();
        // t8-A2: chokepoint panic-recovery — see the `read` callback for
        // the full rationale. A panic in the write-path future never
        // aborts the fuser thread.
        let result = catch_fuse_callback("write", || {
            self.handle.block_on(async move {
                use tokio::io::AsyncWriteExt;
                let mut file = sftp.open_for_resume_write(path, off).await?;
                file.write_all(&bytes).await.map_err(|e| SftpError::Local {
                    op: "write",
                    detail: e.to_string(),
                })?;
                file.shutdown().await.map_err(|e| SftpError::Local {
                    op: "write-close",
                    detail: e.to_string(),
                })?;
                Ok::<_, SftpError>(())
            })
        });
        if let Ok(mut c) = self.attr_cache.lock() {
            c.invalidate(ino);
        }
        match result {
            Ok(()) => reply.written(written),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.release_fh(fh);
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        // SFTP has no explicit fsync; the server flushed when we closed
        // the handle on `write`. Returning Ok matches the autossh sshfs
        // behaviour.
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let Some(path) = self.ino_to_path(ino) else {
            reply.error(libc::ESTALE);
            return;
        };
        let fh = self.alloc_fh(path, false);
        reply.opened(fh, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.ino_to_path(ino) else {
            reply.error(libc::ESTALE);
            return;
        };
        let sftp = self.sftp.clone();
        let p = path.clone();
        // t8-A2: chokepoint panic-recovery around `read_dir`. A codec
        // panic on a malformed `SSH_FXP_NAME` packet must not abort the
        // fuser thread.
        let entries = match catch_fuse_callback("readdir", || {
            self.handle.block_on(async move { sftp.read_dir(p).await })
        }) {
            Ok(e) => e,
            Err(e) => {
                reply.error(errno_for(&e));
                return;
            }
        };
        // Always emit `.` and `..` first.
        let mut all: Vec<(u64, FileType, String)> = Vec::with_capacity(entries.len() + 2);
        all.push((ino, FileType::Directory, ".".to_string()));
        all.push((ino, FileType::Directory, "..".to_string()));
        for entry in entries {
            // Skip `.` and `..` if the server already returned them.
            if entry.file_name == "." || entry.file_name == ".." {
                continue;
            }
            let full = Self::join(&path, &entry.file_name);
            let kind = if entry.metadata.is_dir {
                FileType::Directory
            } else if entry.metadata.is_symlink {
                FileType::Symlink
            } else {
                FileType::RegularFile
            };
            let child_ino = self.alloc_ino(&full);
            all.push((child_ino, kind, entry.file_name));
        }
        let start = offset as usize;
        for (i, (child_ino, kind, name)) in all.into_iter().enumerate().skip(start) {
            // `i + 1` is the offset cookie for the *next* entry.
            if reply.add(child_ino, (i + 1) as i64, kind, name) {
                // Buffer full; the kernel will call back with `offset = i + 1`.
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        self.release_fh(fh);
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        // SFTP has an optional `statvfs@openssh.com` extension; russh-sftp
        // doesn't expose it through the high-level client. Report a
        // generous fake so callers can `df` without surprises.
        reply.statfs(
            1_000_000, // total blocks
            500_000,   // free blocks
            500_000,   // avail
            1,         // files
            0,         // ffree
            4096,      // bsize
            255,       // namelen
            4096,      // frsize
        );
    }
}

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
impl Drop for FuseMounter {
    fn drop(&mut self) {
        // Ensure the kernel sees the umount when the mounter is dropped
        // without an explicit `umount` call.
        drop(self.session.take());
    }
}

// Avoid `remote_root` unused-warning when only the constructor uses it.
#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
#[allow(dead_code)]
impl FuseFs {
    /// Borrow the configured remote root. Exposed for tests and audit hooks.
    pub fn remote_root(&self) -> &str {
        &self.remote_root
    }
}

// ============================================================================
// t8-A2: panic-recovery boundary tests for the fuser callback helper.
//
// We exercise the helper directly because spinning up a live fuser
// session to provoke a panic in a callback requires the kernel
// `/dev/fuse` device, root or `user_allow_other`, and a real mountpoint.
// The helper test verifies the contract — panics surface as
// `SftpError::Local` (which `errno_for` maps to `EIO`), never abort.
// ============================================================================

#[cfg(all(test, target_os = "linux", feature = "mount-fuse"))]
mod boundary_tests {
    use super::*;

    /// `panic_string` extracts both `String` and `&'static str` payloads.
    #[test]
    fn panic_string_handles_common_payloads() {
        let s_payload: Box<dyn std::any::Any + Send> = Box::new(String::from("fuse panic"));
        assert_eq!(panic_string(&s_payload), "fuse panic");
        let static_payload: Box<dyn std::any::Any + Send> = Box::new("static fuse");
        assert_eq!(panic_string(&static_payload), "static fuse");
        let other: Box<dyn std::any::Any + Send> = Box::new(99_u8);
        assert_eq!(panic_string(&other), "(non-string panic payload)");
    }

    /// `catch_fuse_callback` passes through `Ok` returns unchanged.
    #[test]
    fn catch_fuse_callback_passes_through_ok() {
        let v = catch_fuse_callback("getattr", || Ok::<i32, SftpError>(42)).expect("ok");
        assert_eq!(v, 42);
    }

    /// `catch_fuse_callback` passes through structured errors unchanged
    /// — no false-positive `Local` wrapping for legitimate SFTP errors.
    #[test]
    fn catch_fuse_callback_passes_through_structured_err() {
        let err = catch_fuse_callback("lookup", || {
            Err::<(), _>(SftpError::NoSuchFile {
                op: "lookup",
                detail: "/missing".into(),
            })
        })
        .expect_err("err");
        assert_eq!(errno_for(&err), libc::ENOENT);
    }

    /// A panic inside the wrapped closure surfaces as `SftpError::Local`
    /// — `errno_for` maps it to `EIO` which is what the kernel sees on
    /// the FUSE reply.
    #[test]
    fn fuse_lookup_panic_returns_eio_not_abort() {
        let err = catch_fuse_callback("lookup", || -> Result<(), SftpError> {
            panic!("simulated codec panic")
        })
        .expect_err("panic must surface as Err");
        // The kernel-facing errno must be EIO so the I/O bubbles up to
        // userspace, not a process abort.
        assert_eq!(errno_for(&err), libc::EIO);
        match err {
            SftpError::Local { op, detail } => {
                assert_eq!(op, "fuse-callback");
                assert!(detail.contains("lookup"), "label missing: {detail}");
                assert!(
                    detail.contains("simulated codec panic"),
                    "panic payload missing: {detail}",
                );
            }
            other => panic!("expected SftpError::Local, got {other:?}"),
        }
    }

    /// `read` callback panic-recovery: same contract, different label.
    #[test]
    fn fuse_read_panic_returns_eio_not_abort() {
        let err = catch_fuse_callback("read", || -> Result<Vec<u8>, SftpError> {
            panic!("offset out of range")
        })
        .expect_err("panic");
        assert_eq!(errno_for(&err), libc::EIO);
        match err {
            SftpError::Local { op, detail } => {
                assert_eq!(op, "fuse-callback");
                assert!(detail.contains("read"));
            }
            other => panic!("expected Local, got {other:?}"),
        }
    }

    /// Static-string-literal panics carry through to the diagnostic
    /// untouched.
    #[test]
    fn fuse_callback_preserves_static_str_payload() {
        let err = catch_fuse_callback("readdir", || -> Result<(), SftpError> {
            panic!("static-string panic")
        })
        .expect_err("panic");
        let SftpError::Local { detail, .. } = err else {
            panic!("expected Local");
        };
        assert!(detail.contains("static-string panic"), "{detail}");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::mock::MockSftpServer;
    use tempfile::tempdir;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fuse_mounter_returns_diagnostic_when_session_not_wired() {
        // Linux harness check: with or without `mount-fuse`, the backend
        // must surface a structured error (not panic) when the live
        // kernel session isn't reachable.
        //
        // * Feature off → UnsupportedPlatform.
        // * Feature on but no `/dev/fuse` or an unwritable mountpoint →
        //   Other (the `fuser::spawn_mount2` ioctl/open failure).
        //
        // We point at a path the kernel definitely cannot mount on
        // (a regular file inside a tempdir) so the wired path errors out
        // cleanly without leaving a live FUSE session behind.
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = FuseMounter::new(Arc::new(client));
        let bogus = root.path().join("not-a-dir");
        let mut opts = MountOpts::new(bogus, "/srv/data");
        opts.readonly = true;
        let err = mounter.mount(opts).expect_err("expected diagnostic");
        assert!(matches!(
            err,
            SftpError::UnsupportedPlatform { .. } | SftpError::Other { .. }
        ));
    }
}

#[cfg(all(test, target_os = "linux", feature = "mount-fuse"))]
mod readonly_enforcement_tests {
    use super::*;
    use crate::mock::MockSftpServer;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// A read-only mount must reject writes: every mutating FUSE callback
    /// funnels through `FuseFs::readonly_reject`, which returns `EROFS` when
    /// the mount was created read-only and `None` otherwise. This pins the
    /// enforcement decision on a real `FuseFs` built from a live (mock)
    /// client, so a read_only mount can never silently accept writes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readonly_mount_rejects_writes() {
        let root = tempdir().expect("tempdir");
        let handle = tokio::runtime::Handle::current();

        // Read-only mount → writes denied with EROFS.
        let (_srv_ro, client_ro) = MockSftpServer::start(root.path()).await;
        let mut ro_opts = MountOpts::new(root.path(), "/srv/data");
        ro_opts.readonly = true;
        let ro_fs = FuseFs::new(Arc::new(client_ro), handle.clone(), &ro_opts);
        assert_eq!(
            ro_fs.readonly_reject(),
            Some(libc::EROFS),
            "read-only mount must reject writes with EROFS"
        );

        // Read-write mount → no restriction.
        let (_srv_rw, client_rw) = MockSftpServer::start(root.path()).await;
        let mut rw_opts = MountOpts::new(root.path(), "/srv/data");
        rw_opts.readonly = false;
        let rw_fs = FuseFs::new(Arc::new(client_rw), handle, &rw_opts);
        assert_eq!(rw_fs.readonly_reject(), None);
    }
}
