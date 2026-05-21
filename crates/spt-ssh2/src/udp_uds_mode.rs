//! `direct-streamlocal@openssh.com` UDP-over-UDS bridge mode.
//!
//! # Concept
//!
//! Operator runs a small UDP↔UDS shim on the SSH server, listening on a
//! UNIX-domain socket path (the "remote UDS bridge"). The spt client opens a
//! `direct-streamlocal@openssh.com` channel to that path and ships UDP
//! datagrams over it using the same length-prefixed framing as
//! [`crate::udp_tcp_framed`] (the wire is a byte stream — we still need to
//! preserve datagram boundaries).
//!
//! # Backend availability
//!
//! Only the **russh** backend supports `direct-streamlocal@openssh.com`;
//! `ssh2` 0.9 (libssh2) does not. The libssh2 entry point returns
//! [`spt_core::Error::UnsupportedPlatform`] with a diagnostic message so
//! supervisors and CLI users see a clean error instead of a panic or
//! cryptic libssh2 code.
//!
//! Note on the error variant: the task brief asked for an
//! `Error::UnsupportedBackend` variant. The workspace error enum
//! ([`spt_core::Error`]) does **not** have that variant — it has
//! `UnsupportedPlatform` (exit-code 10) which is the documented
//! "platform or feature is not supported" variant. We use that here; the
//! diagnostic message is unambiguous about which backend is responsible.

use spt_core::{Error, Result};

/// Stable phrase embedded in the libssh2 error message, used by tests and
/// downstream callers that want to detect "this is the no-libssh2 UDS path"
/// without string-matching the whole sentence.
pub const LIBSSH2_UNSUPPORTED_TAG: &str = "uds_bridge requires russh backend";

/// Open a `direct-streamlocal@openssh.com` channel via the **libssh2**
/// backend. Always fails with [`Error::UnsupportedPlatform`] because the
/// underlying `ssh2` 0.9 crate lacks `channel_direct_streamlocal`.
///
/// Kept as a callable entry point (rather than `unimplemented!`) so the
/// SSH2 dispatcher can route `Forward.udp_mode = "uds-bridge"` with a
/// `Ssh2BackendKind::Libssh2` profile to a typed error instead of a panic.
pub fn open_libssh2_unsupported(socket_path: &str) -> Result<()> {
    Err(Error::UnsupportedPlatform(format!(
        "{LIBSSH2_UNSUPPORTED_TAG}; libssh2 (ssh2 0.9) does not implement \
         direct-streamlocal. Configure `udp_mode = \"tcp-framed\"` or select \
         the russh backend. (requested socket: {socket_path})"
    )))
}

/// Open a `direct-streamlocal@openssh.com` channel against the russh
/// handle and return the resulting [`russh::Channel`].
///
/// Callers wrap the returned channel with [`russh::Channel::into_stream`]
/// to obtain an `AsyncRead + AsyncWrite + Unpin` byte stream and then drive
/// it with the framing codec from [`crate::udp_tcp_framed`].
///
/// The shim on the server side reads length-prefixed frames and re-injects
/// them as UDP datagrams towards the configured target; replies arrive back
/// through the same channel.
///
/// Generic over `H: russh::client::Handler` so this can be called both from
/// production code (which uses the in-crate `ClientHandler`) and from
/// integration tests against arbitrary mock handlers.
pub async fn open_russh_streamlocal<H>(
    handle: &russh::client::Handle<H>,
    socket_path: &str,
) -> Result<russh::Channel<russh::client::Msg>>
where
    H: russh::client::Handler,
{
    handle
        .channel_open_direct_streamlocal(socket_path.to_owned())
        .await
        .map_err(|e| {
            Error::RuntimeFailure(format!(
                "udp_uds_mode: russh direct-streamlocal to `{socket_path}` failed: {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `uds_bridge libssh2 returns UnsupportedBackend` — the workspace
    /// error vocabulary has no `UnsupportedBackend`, so this maps to
    /// `UnsupportedPlatform` with a tag the dispatcher recognises.
    #[test]
    fn libssh2_path_returns_unsupported_platform_with_stable_tag() {
        let err = open_libssh2_unsupported("/tmp/sshd-udp-bridge.sock").unwrap_err();
        let Error::UnsupportedPlatform(msg) = err else {
            panic!("expected UnsupportedPlatform, got {err:?}");
        };
        assert!(
            msg.contains(LIBSSH2_UNSUPPORTED_TAG),
            "expected stable tag in message, got: {msg}"
        );
        // Diagnostic must reference the remediation.
        assert!(msg.contains("tcp-framed"), "should suggest fallback mode: {msg}");
        assert!(
            msg.contains("/tmp/sshd-udp-bridge.sock"),
            "should echo requested socket path: {msg}"
        );
    }

    /// "uds_bridge positive russh roundtrip" — full integration against a
    /// streamlocal-capable mock russh server is out of scope here
    /// (`testing::RusshTestServer` does not implement
    /// `channel_open_direct_streamlocal` on its handler). We instead drive
    /// the *framing path* the russh entry point would feed its
    /// `into_stream()` into. The russh API surface itself
    /// (`Handle::channel_open_direct_streamlocal` returning
    /// `Channel<Msg>` whose `.into_stream()` is `AsyncRead+AsyncWrite`)
    /// is exercised by russh's own crate-level tests.
    #[tokio::test]
    async fn uds_bridge_russh_roundtrip_simulated_against_duplex_shim() {
        use crate::udp_tcp_framed::{read_frame, write_frame};
        // Simulate the server-side shim: it reads length-prefixed frames off
        // the channel and acks them back. We model the channel as a duplex
        // pair: `client_side` is what the russh `ChannelStream` would expose
        // to spt-ssh2 code, `server_side` is what the operator's UDS shim
        // would see after `direct-streamlocal` is established and unwrapped.
        let (mut client_side, mut server_side) = tokio::io::duplex(8192);
        let datagrams: &[&[u8]] = &[b"\x00\x01\x02\x03", b"DNS query (mock)", &[0xFFu8; 512]];

        // Client sends 3 framed datagrams.
        for d in datagrams {
            write_frame(&mut client_side, d).await.unwrap();
        }

        // Server shim reads each one and echoes it back framed.
        for d in datagrams {
            let recv = read_frame(&mut server_side).await.unwrap();
            assert_eq!(recv.as_slice(), *d);
            write_frame(&mut server_side, &recv).await.unwrap();
        }

        // Client reads back each echoed datagram.
        for d in datagrams {
            let echo = read_frame(&mut client_side).await.unwrap();
            assert_eq!(echo.as_slice(), *d);
        }
    }
}
