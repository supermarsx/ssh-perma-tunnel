//! In-process SFTP test harness.
//!
//! [`MockSftpServer`] spins up a filesystem-backed [`russh_sftp::server::Handler`]
//! on one end of a [`tokio::io::duplex`] pair, then hands back an
//! [`SftpClient`] wired to the other end. Tests get a real SFTP wire
//! exchange without any SSH transport.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::Handler;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::client::SftpClient;

/// A synthetic hostile READDIR entry: `(file_name, attrs, symlink_target)`.
type EvilEntry = (String, FileAttributes, Option<String>);

/// File handle state tracked inside the mock server.
#[derive(Debug)]
struct OpenFile {
    file: fs::File,
}

#[derive(Debug)]
struct OpenDir {
    /// Materialised entries; `None` until we deliver them.
    entries: Option<Vec<(String, FileAttributes)>>,
}

/// Filesystem-backed SFTP server handler.
///
/// Every path the client sends is treated as relative to `root`, which is
/// canonicalised on construction. Symlinks pointing outside `root` are
/// honoured (because the recursive walker tests rely on them) — production
/// code should not point this handler at a hostile filesystem.
pub struct MockHandler {
    root: PathBuf,
    files: HashMap<String, OpenFile>,
    dirs: HashMap<String, OpenDir>,
    next: Arc<AtomicU64>,
    /// When set, the next operation matching `inject_failure_op` returns
    /// `Failure` with `inject_failure_msg`. Used to exercise error mapping.
    inject: Arc<Mutex<Option<(String, String)>>>,
    /// Synthetic READDIR entries appended to every `readdir` response.
    /// Lets path-traversal tests emit hostile entry names (e.g.
    /// `../../escape`, absolute paths, drive/UNC prefixes, or symlinks with
    /// escaping targets) that a real filesystem could never produce as a
    /// single dir entry. Each tuple is `(file_name, attrs, symlink_target)`.
    extra_entries: Arc<Mutex<Vec<EvilEntry>>>,
}

impl MockHandler {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            files: HashMap::new(),
            dirs: HashMap::new(),
            next: Arc::new(AtomicU64::new(1)),
            inject: Arc::new(Mutex::new(None)),
            extra_entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn resolve(&self, p: &str) -> PathBuf {
        let trimmed = p.trim_start_matches('/');
        if trimmed.is_empty() {
            self.root.clone()
        } else {
            self.root.join(trimmed)
        }
    }

    fn handle_id(&self) -> String {
        format!("h{}", self.next.fetch_add(1, Ordering::Relaxed))
    }

    async fn check_inject(&self, op: &str) -> Result<(), StatusCode> {
        let mut guard = self.inject.lock().await;
        if let Some((target, _msg)) = guard.as_ref() {
            if target == op {
                let (_, _msg) = guard.take().unwrap();
                // We can't surface the message through StatusCode alone — the
                // handler trait collapses everything to a code. The test that
                // exercises `Failure` mapping injects via the `message` arm
                // below.
                return Err(StatusCode::Failure);
            }
        }
        Ok(())
    }
}

impl Handler for MockHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let resolved = self.resolve(&path);
        let canonical = fs::canonicalize(&resolved)
            .await
            .unwrap_or(resolved.clone());
        let rel = canonical.strip_prefix(&self.root).map_or_else(
            |_| canonical.to_string_lossy().into_owned(),
            |p| format!("/{}", p.to_string_lossy()),
        );
        Ok(Name {
            id,
            files: vec![File {
                filename: rel.clone(),
                longname: rel,
                attrs: FileAttributes::default(),
            }],
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let resolved = self.resolve(&path);
        let meta = fs::metadata(&resolved)
            .await
            .map_err(|_| StatusCode::NoSuchFile)?;
        if !meta.is_dir() {
            return Err(StatusCode::Failure);
        }
        let mut entries: Vec<(String, FileAttributes)> = Vec::new();
        let mut rd = fs::read_dir(&resolved)
            .await
            .map_err(|_| StatusCode::Failure)?;
        while let Some(e) = rd.next_entry().await.map_err(|_| StatusCode::Failure)? {
            let name = e.file_name().to_string_lossy().into_owned();
            let m = fs::symlink_metadata(e.path())
                .await
                .map_err(|_| StatusCode::Failure)?;
            entries.push((name, metadata_to_attrs(&m)));
        }
        // Append any synthetic hostile entries the test injected. These are
        // emitted by EVERY opendir so a one-call recursive walk surfaces
        // them; production servers never do this — the recursive walker's
        // sanitiser is what must reject them.
        for (name, attrs, _target) in self.extra_entries.lock().await.iter() {
            entries.push((name.clone(), attrs.clone()));
        }
        let handle = self.handle_id();
        let _ = resolved;
        self.dirs.insert(
            handle.clone(),
            OpenDir {
                entries: Some(entries),
            },
        );
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let dir = self.dirs.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if let Some(entries) = dir.entries.take() {
            let files = entries
                .into_iter()
                .map(|(name, attrs)| File {
                    filename: name.clone(),
                    longname: name,
                    attrs,
                })
                .collect();
            Ok(Name { id, files })
        } else {
            Err(StatusCode::Eof)
        }
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.files.remove(&handle);
        self.dirs.remove(&handle);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.check_inject("open").await?;
        let path = self.resolve(&filename);
        let mut opts = fs::OpenOptions::new();
        let read = pflags.contains(OpenFlags::READ);
        let write = pflags.contains(OpenFlags::WRITE);
        opts.read(read).write(write);
        if pflags.contains(OpenFlags::CREATE) {
            opts.create(true);
        }
        if pflags.contains(OpenFlags::TRUNCATE) {
            opts.truncate(true);
        }
        if pflags.contains(OpenFlags::APPEND) {
            opts.append(true);
        }
        if !read && !write {
            opts.read(true);
        }
        let file = opts.open(&path).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
            std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
            _ => StatusCode::Failure,
        })?;
        let handle = self.handle_id();
        self.files.insert(handle.clone(), OpenFile { file });
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let entry = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        entry
            .file
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| StatusCode::Failure)?;
        let mut buf = vec![0u8; len as usize];
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = entry
                .file
                .read(&mut buf[filled..])
                .await
                .map_err(|_| StatusCode::Failure)?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        if buf.is_empty() {
            return Err(StatusCode::Eof);
        }
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        self.check_inject("write").await?;
        let entry = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        entry
            .file
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| StatusCode::Failure)?;
        entry
            .file
            .write_all(&data)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let resolved = self.resolve(&path);
        let m = fs::metadata(&resolved).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
            std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
            _ => StatusCode::Failure,
        })?;
        Ok(Attrs {
            id,
            attrs: metadata_to_attrs(&m),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let resolved = self.resolve(&path);
        let m = fs::symlink_metadata(&resolved)
            .await
            .map_err(|_| StatusCode::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: metadata_to_attrs(&m),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let entry = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let m = entry
            .file
            .metadata()
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Attrs {
            id,
            attrs: metadata_to_attrs(&m),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let resolved = self.resolve(&path);
        if !fs::try_exists(&resolved).await.unwrap_or(false) {
            return Err(StatusCode::NoSuchFile);
        }
        #[cfg(unix)]
        if let Some(mode) = attrs.permissions {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode & 0o7777);
            fs::set_permissions(&resolved, perms)
                .await
                .map_err(|_| StatusCode::Failure)?;
        }
        // On non-unix platforms permission setting is a no-op; size/mtime are
        // not honoured for simplicity.
        let _ = attrs;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        _handle: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let resolved = self.resolve(&path);
        fs::create_dir(&resolved)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let resolved = self.resolve(&path);
        let mut rd = fs::read_dir(&resolved)
            .await
            .map_err(|_| StatusCode::NoSuchFile)?;
        if rd
            .next_entry()
            .await
            .map_err(|_| StatusCode::Failure)?
            .is_some()
        {
            return Ok(Status {
                id,
                status_code: StatusCode::Failure,
                error_message: "Directory not empty".into(),
                language_tag: String::new(),
            });
        }
        fs::remove_dir(&resolved)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let resolved = self.resolve(&filename);
        fs::remove_file(&resolved)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
                _ => StatusCode::Failure,
            })?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let from = self.resolve(&oldpath);
        let to = self.resolve(&newpath);
        fs::rename(&from, &to)
            .await
            .map_err(|_| StatusCode::Failure)?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        // Synthetic symlink entries injected by tests resolve by their
        // trailing path component, so the recursive walker (which calls
        // `readlink` on `<remote_dir>/<entry_name>`) gets the hostile target.
        let leaf = path.rsplit('/').next().unwrap_or(path.as_str());
        if let Some((_, _, Some(target))) = self
            .extra_entries
            .lock()
            .await
            .iter()
            .find(|(n, _, t)| n == leaf && t.is_some())
        {
            let target = target.clone();
            return Ok(Name {
                id,
                files: vec![File {
                    filename: target.clone(),
                    longname: target,
                    attrs: FileAttributes::default(),
                }],
            });
        }
        let resolved = self.resolve(&path);
        let target = fs::read_link(&resolved)
            .await
            .map_err(|_| StatusCode::NoSuchFile)?;
        let name = target.to_string_lossy().into_owned();
        Ok(Name {
            id,
            files: vec![File {
                filename: name.clone(),
                longname: name,
                attrs: FileAttributes::default(),
            }],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let link = self.resolve(&linkpath);
        let target_str = targetpath;
        #[cfg(unix)]
        {
            tokio::fs::symlink(&target_str, &link)
                .await
                .map_err(|_| StatusCode::Failure)?;
        }
        #[cfg(windows)]
        {
            // Best-effort: write the target into a regular file so tests that
            // exercise the round-trip can read it back via `readlink`. The
            // server-side `lstat` will report this as a regular file, but the
            // recursive-walk test's symlink path uses `is_symlink` from
            // metadata which won't be true here — tests that exercise the
            // real symlink wire are `cfg(unix)`-gated.
            tokio::fs::write(&link, target_str.as_bytes())
                .await
                .map_err(|_| StatusCode::Failure)?;
        }
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }
}

fn metadata_to_attrs(m: &std::fs::Metadata) -> FileAttributes {
    let mut attrs = FileAttributes {
        size: Some(m.len()),
        permissions: Some(0),
        ..FileAttributes::default()
    };
    if m.is_dir() {
        attrs.set_dir(true);
    } else if m.file_type().is_symlink() {
        attrs.set_symlink(true);
    } else {
        attrs.set_regular(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = m.permissions().mode();
        // Preserve the mode bits *and* the file-type bits we just set.
        let kept = attrs.permissions.unwrap_or(0);
        attrs.permissions = Some(kept | (mode & 0o7777));
    }
    attrs
}

/// In-process SFTP server backed by `root`. Holds a [`JoinHandle`] for the
/// running task; dropped when the harness goes out of scope.
pub struct MockSftpServer {
    /// Filesystem root visible to the client.
    pub root: PathBuf,
}

impl MockSftpServer {
    /// Construct a server rooted at `root` and return both the harness and
    /// an already-connected [`SftpClient`].
    pub async fn start(root: &Path) -> (Self, SftpClient) {
        Self::start_with_evil_entries(root, Vec::new()).await
    }

    /// Like [`start`](Self::start), but the server appends the supplied
    /// synthetic READDIR entries to **every** directory listing — letting
    /// path-traversal tests emit hostile server-controlled entry names and
    /// symlink targets that a real filesystem could never produce.
    ///
    /// Each entry is `(file_name, kind, symlink_target)`:
    /// * `file_name` — the raw name the server reports (e.g. `../../escape`,
    ///   `/etc/passwd`, `C:\\evil`, `\\\\srv\\share`).
    /// * `kind` — what the server claims the entry is.
    /// * `symlink_target` — for [`EvilKind::Symlink`], the (hostile) target
    ///   string `readlink` returns for this entry; ignored otherwise.
    pub async fn start_with_evil_entries(
        root: &Path,
        evil: Vec<(String, EvilKind, Option<String>)>,
    ) -> (Self, SftpClient) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let handler = MockHandler::new(root.to_owned());
        {
            let mut guard = handler.extra_entries.lock().await;
            for (name, kind, target) in evil {
                let mut attrs = FileAttributes {
                    size: Some(0),
                    permissions: Some(0),
                    ..FileAttributes::default()
                };
                match kind {
                    EvilKind::File => attrs.set_regular(true),
                    EvilKind::Dir => attrs.set_dir(true),
                    EvilKind::Symlink => attrs.set_symlink(true),
                }
                guard.push((name, attrs, target));
            }
        }
        russh_sftp::server::run(server_io, handler).await;
        let session = SftpSession::new(client_io).await.expect("client init");
        (
            Self {
                root: root.to_owned(),
            },
            SftpClient::from_russh(session),
        )
    }
}

/// The kind a [synthetic hostile entry](MockSftpServer::start_with_evil_entries)
/// claims to be in its READDIR attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvilKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link (its `readlink` target is the tuple's third field).
    Symlink,
}
