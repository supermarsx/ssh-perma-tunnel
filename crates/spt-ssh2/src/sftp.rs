//! SFTP client operations over an established SSH2/russh session.
//!
//! As of t6-e4 the implementation lives in the dedicated [`spt_sftp`] crate;
//! this module is retained as a thin re-export so existing callers of
//! `spt_ssh2::sftp::SftpClient` (and the public `spt_ssh2::SftpClient` re-
//! export from `lib.rs`) keep compiling unchanged.

pub use spt_sftp::{SftpClient, SftpDirEntry, SftpMetadata};
