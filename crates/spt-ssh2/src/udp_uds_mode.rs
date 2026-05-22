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
//! Since t7-Phase0 the russh path is the only path; the libssh2 stub
//! (`open_libssh2_unsupported`) and the `LIBSSH2_UNSUPPORTED_TAG` constant
//! were removed.

use spt_core::{Error, Result};

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
    use crate::udp_tcp_framed::{read_frame, write_frame};

    /// "uds_bridge positive russh roundtrip" — full integration against a
    /// streamlocal-capable mock russh server is out of scope here
    /// (`testing::RusshTestServer` does not implement
    /// `channel_open_direct_streamlocal` on its handler). We instead drive
    /// the *framing path* the russh entry point would feed its
    /// `into_stream()` into.
    #[tokio::test]
    async fn uds_bridge_russh_roundtrip_simulated_against_duplex_shim() {
        let (mut client_side, mut server_side) = tokio::io::duplex(8192);
        let datagrams: &[&[u8]] = &[b"\x00\x01\x02\x03", b"DNS query (mock)", &[0xFFu8; 512]];

        for d in datagrams {
            write_frame(&mut client_side, d).await.unwrap();
        }

        for d in datagrams {
            let recv = read_frame(&mut server_side).await.unwrap();
            assert_eq!(recv.as_slice(), *d);
            write_frame(&mut server_side, &recv).await.unwrap();
        }

        for d in datagrams {
            let echo = read_frame(&mut client_side).await.unwrap();
            assert_eq!(echo.as_slice(), *d);
        }
    }
}
