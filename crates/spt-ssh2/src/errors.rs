//! Internal error helpers translating libssh2 / async-ssh2-lite failures into
//! the workspace [`spt_core::Error`] variants.

use std::io;

use async_ssh2_lite::Error as AsyncSshError;
use spt_core::Error;

/// Translate an `async-ssh2-lite` error to the matching `spt-core` variant.
///
/// Heuristics:
/// * `ssh2::ErrorCode::Session(LIBSSH2_ERROR_AUTHENTICATION_FAILED)` → `AuthFailed`
/// * IO timeouts and refused/unreachable addresses → `NetworkUnreachable`
/// * everything else → `RuntimeFailure`
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn from_async_ssh(context: &str, e: AsyncSshError) -> Error {
    match &e {
        AsyncSshError::Ssh2(ssh2_err) => from_ssh2(context, ssh2_err),
        AsyncSshError::Io(io_err) => from_io(context, io_err),
        AsyncSshError::Other(_) => Error::RuntimeFailure(format!("{context}: {e}")),
    }
}

/// Translate a raw `ssh2::Error` to the matching `spt-core` variant.
#[must_use]
pub fn from_ssh2(context: &str, e: &ssh2::Error) -> Error {
    let code = e.code();
    // -18 = LIBSSH2_ERROR_AUTHENTICATION_FAILED,
    // -16 = LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED,
    // -19 = LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED.
    if matches!(code, ssh2::ErrorCode::Session(-18 | -16 | -19)) {
        return Error::AuthFailed(format!("{context}: {e}"));
    }
    if matches!(code, ssh2::ErrorCode::Session(-44) /* HOSTKEY_INIT */) {
        return Error::TrustFailed(format!("{context}: {e}"));
    }
    Error::RuntimeFailure(format!("{context}: {e}"))
}

/// Translate a `std::io::Error` to a workspace error.
#[must_use]
pub fn from_io(context: &str, e: &io::Error) -> Error {
    use io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::NotConnected
        | ErrorKind::AddrNotAvailable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::HostUnreachable => Error::NetworkUnreachable(format!("{context}: {e}")),
        ErrorKind::TimedOut => Error::KeepaliveTimeout { after_ms: 0 },
        ErrorKind::PermissionDenied => Error::PermissionDenied(format!("{context}: {e}")),
        _ => Error::RuntimeFailure(format!("{context}: {e}")),
    }
}
