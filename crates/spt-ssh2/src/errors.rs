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

#[cfg(test)]
mod tests {
    use super::*;
    use async_ssh2_lite::Error as AsyncSshError;
    use io::ErrorKind;
    use ssh2::ErrorCode;

    fn mk_ssh2(code: i32, msg: &'static str) -> ssh2::Error {
        ssh2::Error::new(ErrorCode::Session(code), msg)
    }

    #[test]
    fn from_ssh2_auth_failed_negative_18() {
        let e = mk_ssh2(-18, "auth fail");
        let mapped = from_ssh2("ctx", &e);
        assert!(matches!(mapped, Error::AuthFailed(ref s) if s.contains("ctx") && s.contains("auth fail")));
    }

    #[test]
    fn from_ssh2_auth_failed_negative_16_pubkey_unrecognized() {
        let e = mk_ssh2(-16, "pubkey unrecognized");
        assert!(matches!(from_ssh2("ctx", &e), Error::AuthFailed(_)));
    }

    #[test]
    fn from_ssh2_auth_failed_negative_19_pubkey_unverified() {
        let e = mk_ssh2(-19, "pubkey unverified");
        assert!(matches!(from_ssh2("ctx", &e), Error::AuthFailed(_)));
    }

    #[test]
    fn from_ssh2_hostkey_init_negative_44_yields_trust_failed() {
        let e = mk_ssh2(-44, "hostkey init failed");
        assert!(matches!(from_ssh2("ctx", &e), Error::TrustFailed(_)));
    }

    #[test]
    fn from_ssh2_default_negative_8_is_runtime_failure() {
        // The famous -8 KEY_EXCHANGE_FAILURE.
        let e = mk_ssh2(-8, "kex failure");
        let mapped = from_ssh2("kex", &e);
        match mapped {
            Error::RuntimeFailure(s) => {
                assert!(s.contains("kex"));
                assert!(s.contains("kex failure"));
            }
            other => panic!("expected RuntimeFailure, got {other:?}"),
        }
    }

    #[test]
    fn from_io_connection_refused_is_network_unreachable() {
        let e = io::Error::from(ErrorKind::ConnectionRefused);
        assert!(matches!(from_io("ctx", &e), Error::NetworkUnreachable(_)));
    }

    #[test]
    fn from_io_connection_reset_is_network_unreachable() {
        let e = io::Error::from(ErrorKind::ConnectionReset);
        assert!(matches!(from_io("ctx", &e), Error::NetworkUnreachable(_)));
    }

    #[test]
    fn from_io_connection_aborted_is_network_unreachable() {
        let e = io::Error::from(ErrorKind::ConnectionAborted);
        assert!(matches!(from_io("ctx", &e), Error::NetworkUnreachable(_)));
    }

    #[test]
    fn from_io_not_connected_is_network_unreachable() {
        let e = io::Error::from(ErrorKind::NotConnected);
        assert!(matches!(from_io("ctx", &e), Error::NetworkUnreachable(_)));
    }

    #[test]
    fn from_io_addr_not_available_is_network_unreachable() {
        let e = io::Error::from(ErrorKind::AddrNotAvailable);
        assert!(matches!(from_io("ctx", &e), Error::NetworkUnreachable(_)));
    }

    #[test]
    fn from_io_timed_out_is_keepalive_timeout() {
        let e = io::Error::from(ErrorKind::TimedOut);
        match from_io("ctx", &e) {
            Error::KeepaliveTimeout { after_ms } => assert_eq!(after_ms, 0),
            other => panic!("expected KeepaliveTimeout, got {other:?}"),
        }
    }

    #[test]
    fn from_io_permission_denied() {
        let e = io::Error::from(ErrorKind::PermissionDenied);
        assert!(matches!(from_io("ctx", &e), Error::PermissionDenied(_)));
    }

    #[test]
    fn from_io_other_kinds_fall_through_to_runtime_failure() {
        let e = io::Error::other("weird");
        assert!(matches!(from_io("ctx", &e), Error::RuntimeFailure(_)));
        let e = io::Error::from(ErrorKind::InvalidData);
        assert!(matches!(from_io("ctx", &e), Error::RuntimeFailure(_)));
        let e = io::Error::from(ErrorKind::BrokenPipe);
        assert!(matches!(from_io("ctx", &e), Error::RuntimeFailure(_)));
    }

    #[test]
    fn from_async_ssh_routes_ssh2_variant() {
        let e = AsyncSshError::Ssh2(mk_ssh2(-18, "auth fail"));
        assert!(matches!(from_async_ssh("ctx", e), Error::AuthFailed(_)));
    }

    #[test]
    fn from_async_ssh_routes_io_variant() {
        let e = AsyncSshError::Io(io::Error::from(ErrorKind::ConnectionRefused));
        assert!(matches!(from_async_ssh("ctx", e), Error::NetworkUnreachable(_)));
    }

    #[test]
    fn from_async_ssh_routes_io_timeout_to_keepalive() {
        let e = AsyncSshError::Io(io::Error::from(ErrorKind::TimedOut));
        assert!(matches!(
            from_async_ssh("ctx", e),
            Error::KeepaliveTimeout { .. }
        ));
    }

    #[test]
    fn from_async_ssh_routes_other_variant_to_runtime_failure() {
        let inner: Box<dyn std::error::Error + Send + Sync + 'static> = "boom".into();
        let e = AsyncSshError::Other(inner);
        match from_async_ssh("ctx", e) {
            Error::RuntimeFailure(s) => assert!(s.contains("ctx")),
            other => panic!("expected RuntimeFailure, got {other:?}"),
        }
    }

    #[test]
    fn context_is_propagated_into_message() {
        let e = io::Error::from(ErrorKind::ConnectionRefused);
        match from_io("dial-bastion", &e) {
            Error::NetworkUnreachable(s) => assert!(s.contains("dial-bastion")),
            other => panic!("unexpected {other:?}"),
        }
    }
}
