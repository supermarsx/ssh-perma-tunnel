//! Error helpers.
//!
//! Pre-t7 this module translated `async-ssh2-lite` and raw `ssh2` errors
//! into [`spt_core::Error`] variants. After t7-Phase0 the libssh2 path is
//! gone; the russh backend in `crate::russh_backend` formats errors
//! inline against the `russh::Error` shape. A small `std::io::Error`
//! translator survives because [`crate::proxy_jump`] still needs to map
//! `ErrorKind` values that `tokio::io` surfaces during the CONNECT
//! handshake.

use std::io;

use spt_core::Error;

/// Translate a `std::io::Error` to the matching workspace `Error` variant.
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
    use io::ErrorKind;

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
        let e = io::Error::from(ErrorKind::InvalidData);
        assert!(matches!(from_io("ctx", &e), Error::RuntimeFailure(_)));
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
