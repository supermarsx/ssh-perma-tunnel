//! SFTP-session factory trait.
//!
//! Each authenticated FTP control session asks the factory to open an
//! SFTP client on its behalf. Production code wires this to the
//! `spt-ssh2` runtime; tests use [`crate::mock::MockSftpFactory`].

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::TranslatorError;

/// Source of [`spt_sftp::SftpClient`] instances per FTP user.
#[async_trait]
pub trait SftpFactory: Send + Sync {
    /// Open an SFTP session for the given (already-authenticated) user.
    /// Errors propagate as `TranslatorError::Sftp` to the FTP reply layer.
    async fn open_for(&self, user: &str) -> Result<Arc<spt_sftp::SftpClient>, TranslatorError>;
}
