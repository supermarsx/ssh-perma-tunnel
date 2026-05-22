//! SFTP-specific error mapping.
//!
//! `russh-sftp` surfaces nine `StatusCode` values defined by SFTP draft-02
//! (`NoSuchFile`, `PermissionDenied`, `Failure`, ...). The five canonical
//! filesystem error categories we need to differentiate at the CLI layer —
//! [`SftpError::NoSuchFile`], [`SftpError::PermissionDenied`],
//! [`SftpError::NotADirectory`], [`SftpError::NotEmpty`],
//! [`SftpError::NoSpace`] — are split out by inspecting the server-provided
//! [`Status::error_message`] string when the raw [`StatusCode`] is
//! `Failure`, because the SFTP wire protocol does not encode them
//! distinctly.
//!
//! `From<SftpError> for spt_core::Error` collapses the discrimination back
//! to the small set of [`spt_core::Error`] variants exposed by the spec.

use russh_sftp::client::error::Error as RusshSftpError;
use russh_sftp::protocol::{Status, StatusCode};
use spt_core::Error as CoreError;
use thiserror::Error;

/// Categorised SFTP errors.
///
/// Construct directly in tests, or via `SftpError::from_op` when wrapping
/// a [`russh-sftp` client error](russh_sftp::client::error::Error).
#[derive(Debug, Error, Clone)]
pub enum SftpError {
    /// Remote path does not exist.
    #[error("sftp {op}: no such file: {detail}")]
    NoSuchFile {
        /// SFTP operation tag (`open`, `stat`, ...).
        op: &'static str,
        /// Server-supplied detail.
        detail: String,
    },

    /// Authenticated user lacks permission for the operation.
    #[error("sftp {op}: permission denied: {detail}")]
    PermissionDenied {
        /// SFTP operation tag.
        op: &'static str,
        /// Server-supplied detail.
        detail: String,
    },

    /// Target exists but is not a directory.
    #[error("sftp {op}: not a directory: {detail}")]
    NotADirectory {
        /// SFTP operation tag.
        op: &'static str,
        /// Server-supplied detail.
        detail: String,
    },

    /// Directory is not empty.
    #[error("sftp {op}: directory not empty: {detail}")]
    NotEmpty {
        /// SFTP operation tag.
        op: &'static str,
        /// Server-supplied detail.
        detail: String,
    },

    /// Out of disk space on the server.
    #[error("sftp {op}: no space left on device: {detail}")]
    NoSpace {
        /// SFTP operation tag.
        op: &'static str,
        /// Server-supplied detail.
        detail: String,
    },

    /// I/O or protocol failure not covered by the categories above.
    #[error("sftp {op}: {detail}")]
    Other {
        /// SFTP operation tag.
        op: &'static str,
        /// Server-supplied detail.
        detail: String,
    },

    /// Local invariant violation while staging or verifying a transfer
    /// (size cap exceeded, checksum mismatch, symlink loop, ...).
    #[error("sftp {op}: {detail}")]
    Local {
        /// Operation tag.
        op: &'static str,
        /// Description of the failure.
        detail: String,
    },

    /// The requested operation is not supported on this OS or this
    /// build (e.g. FUSE backend on Linux without `mount-fuse`, or any
    /// SFTP mount on an unrecognised platform). Maps to
    /// [`spt_core::ExitCode::UnsupportedPlatform`] (exit 10) so operators
    /// can branch on the structured exit code instead of grep-ing logs.
    #[error("sftp {op}: unsupported platform: {detail}")]
    UnsupportedPlatform {
        /// Operation tag (`mount`, `umount`).
        op: &'static str,
        /// Diagnostic explaining what's missing and how to enable it.
        detail: String,
    },
}

impl SftpError {
    /// Map a [`russh-sftp` client error](RusshSftpError) into an
    /// [`SftpError`], tagging it with `op` for diagnostics.
    #[must_use]
    #[allow(clippy::match_same_arms)] // Each arm is documented separately.
    pub fn from_russh(op: &'static str, err: RusshSftpError) -> Self {
        match err {
            RusshSftpError::Status(status) => Self::from_status(op, status),
            RusshSftpError::IO(detail) => Self::Other { op, detail },
            RusshSftpError::Timeout => Self::Other {
                op,
                detail: "timeout waiting for sftp response".into(),
            },
            RusshSftpError::Limited(detail) => Self::Other { op, detail },
            RusshSftpError::UnexpectedPacket => Self::Other {
                op,
                detail: "unexpected sftp packet".into(),
            },
            RusshSftpError::UnexpectedBehavior(detail) => Self::Other { op, detail },
        }
    }

    /// Categorise a raw SFTP [`Status`] response.
    #[must_use]
    pub fn from_status(op: &'static str, status: Status) -> Self {
        let detail = status.error_message;
        match status.status_code {
            StatusCode::NoSuchFile => Self::NoSuchFile { op, detail },
            StatusCode::PermissionDenied => Self::PermissionDenied { op, detail },
            StatusCode::Failure => Self::classify_failure(op, detail),
            other => Self::Other {
                op,
                detail: format!("{other}: {detail}"),
            },
        }
    }

    fn classify_failure(op: &'static str, detail: String) -> Self {
        let needle = detail.to_ascii_lowercase();
        if needle.contains("not a directory") || needle.contains("notdir") {
            Self::NotADirectory { op, detail }
        } else if needle.contains("not empty") || needle.contains("notempty") {
            Self::NotEmpty { op, detail }
        } else if needle.contains("no space")
            || needle.contains("nospc")
            || needle.contains("disk full")
        {
            Self::NoSpace { op, detail }
        } else {
            Self::Other { op, detail }
        }
    }

    /// Operation tag attached at construction.
    #[must_use]
    pub fn op(&self) -> &'static str {
        match self {
            Self::NoSuchFile { op, .. }
            | Self::PermissionDenied { op, .. }
            | Self::NotADirectory { op, .. }
            | Self::NotEmpty { op, .. }
            | Self::NoSpace { op, .. }
            | Self::Other { op, .. }
            | Self::Local { op, .. }
            | Self::UnsupportedPlatform { op, .. } => op,
        }
    }
}

impl From<SftpError> for CoreError {
    fn from(err: SftpError) -> Self {
        match err {
            SftpError::PermissionDenied { .. } => CoreError::PermissionDenied(err.to_string()),
            SftpError::UnsupportedPlatform { .. } => {
                CoreError::UnsupportedPlatform(err.to_string())
            }
            other => CoreError::RuntimeFailure(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(code: StatusCode, msg: &str) -> Status {
        Status {
            id: 1,
            status_code: code,
            error_message: msg.into(),
            language_tag: String::new(),
        }
    }

    #[test]
    fn maps_no_such_file_status() {
        let err = SftpError::from_status("open", status(StatusCode::NoSuchFile, "missing"));
        assert!(matches!(err, SftpError::NoSuchFile { .. }));
    }

    #[test]
    fn maps_permission_denied_status() {
        let err = SftpError::from_status("open", status(StatusCode::PermissionDenied, "no"));
        assert!(matches!(err, SftpError::PermissionDenied { .. }));
    }

    #[test]
    fn maps_not_a_directory_via_failure_message() {
        let err = SftpError::from_status("opendir", status(StatusCode::Failure, "Not a directory"));
        assert!(matches!(err, SftpError::NotADirectory { .. }));
    }

    #[test]
    fn maps_directory_not_empty_via_failure_message() {
        let err =
            SftpError::from_status("rmdir", status(StatusCode::Failure, "Directory not empty"));
        assert!(matches!(err, SftpError::NotEmpty { .. }));
    }

    #[test]
    fn maps_no_space_via_failure_message() {
        let err = SftpError::from_status(
            "write",
            status(StatusCode::Failure, "No space left on device"),
        );
        assert!(matches!(err, SftpError::NoSpace { .. }));
    }

    #[test]
    fn maps_other_failure() {
        let err = SftpError::from_status("write", status(StatusCode::Failure, "weird"));
        assert!(matches!(err, SftpError::Other { .. }));
    }

    #[test]
    fn into_core_error_preserves_permission_denied() {
        let err = SftpError::PermissionDenied {
            op: "open",
            detail: "x".into(),
        };
        let core: CoreError = err.into();
        assert!(matches!(core, CoreError::PermissionDenied(_)));
    }

    #[test]
    fn into_core_error_uses_runtime_for_other_categories() {
        let err = SftpError::NoSuchFile {
            op: "open",
            detail: "x".into(),
        };
        let core: CoreError = err.into();
        assert!(matches!(core, CoreError::RuntimeFailure(_)));
    }

    #[test]
    fn into_core_error_maps_unsupported_platform_to_exit_code_10() {
        // SftpError::UnsupportedPlatform must land on
        // CoreError::UnsupportedPlatform so the CLI dispatcher emits
        // ExitCode::UnsupportedPlatform (10) — operators rely on the
        // structured exit code to differentiate "no driver installed"
        // from a generic runtime failure.
        let err = SftpError::UnsupportedPlatform {
            op: "mount",
            detail: "sshfs missing".into(),
        };
        let core: CoreError = err.into();
        assert!(matches!(core, CoreError::UnsupportedPlatform(_)));
    }
}
