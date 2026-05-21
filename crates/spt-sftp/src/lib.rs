//! SFTP client for spt, lifted from `spt-ssh2` and extended with one-shot
//! convenience operations (`cat`, `tail`, `chmod`, `symlink`, `readlink`,
//! `realpath`), recursive directory transfer (`put_recursive`,
//! `get_recursive`), resume, bandwidth limiting, and SHA-256 checksum
//! verification.
//!
//! The transport-level handshake (russh channel ↔ SFTP subsystem) still lives
//! in `spt-ssh2`; this crate consumes an already-established
//! [`russh_sftp::client::SftpSession`] via [`SftpClient::from_russh`] and
//! exposes a stable, transport-agnostic API to the rest of the workspace.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod bw;
pub mod checksum;
pub mod client;
pub mod error;
pub mod mount;
pub mod recursive;

#[cfg(any(test, feature = "testing"))]
pub mod mock;

pub use bw::TokenBucket;
pub use checksum::{sha256_local_file, sha256_remote_file};
pub use client::{SftpClient, SftpDirEntry, SftpMetadata};
pub use error::SftpError;
pub use mount::{
    mounter_for_current_os, unsupported_platform_error, AuditHook, MountEvent, MountHandle,
    MountOpts, NullMounter, SftpMounter,
};
pub use recursive::{
    get_recursive, put_recursive, ChecksumMode, RecursiveOptions, RecursiveReport,
};
