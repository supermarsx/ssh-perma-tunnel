//! In-process test fixtures.
//!
//! [`MockSftpFactory`] hands out `Arc<SftpClient>` instances that point
//! at a [`spt_sftp::mock::MockSftpServer`] rooted at a tempdir.
//!
//! Gated on `feature = "testing"` (or `cfg(test)`); production binaries
//! should not pull this in.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use spt_sftp::mock::MockSftpServer;
use spt_sftp::SftpClient;

use crate::error::TranslatorError;
use crate::factory::SftpFactory;

/// Filesystem-backed SFTP factory.
///
/// Each `open_for` call spins up a *fresh* mock server rooted at `root`
/// — the existing mock harness can't multiplex one server across
/// multiple clients, so we re-create. The on-disk tree is shared across
/// invocations.
pub struct MockSftpFactory {
    /// Root filesystem path. All operations are jailed under this dir.
    pub root: PathBuf,
}

impl MockSftpFactory {
    /// New factory rooted at `root` (must already exist).
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

#[async_trait]
impl SftpFactory for MockSftpFactory {
    async fn open_for(&self, _user: &str) -> Result<Arc<SftpClient>, TranslatorError> {
        let (_server, client) = MockSftpServer::start(&self.root).await;
        // The MockSftpServer object is dropped here; the in-process
        // handler task it spawned keeps running for the duration of the
        // SftpClient because the duplex pair owns the read/write halves.
        // This matches how `spt-sftp/tests/ops.rs` uses the harness.
        let _ = _server;
        Ok(Arc::new(client))
    }
}
