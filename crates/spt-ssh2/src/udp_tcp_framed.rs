//! UDP-over-SSH framing codec — length-prefixed datagrams sent over an
//! SSH `direct-tcpip` byte stream.
//!
//! ## Frame format
//!
//! ```text
//! +-------------------+--------------------+
//! | u32_be len        | payload (len bytes)|
//! +-------------------+--------------------+
//! ```
//!
//! `len` is the byte length of `payload`. The maximum is **64 KiB**
//! ([`MAX_FRAME_BYTES`]); a frame whose advertised `len` exceeds the cap is
//! rejected with [`spt_core::Error::RuntimeFailure`] (the channel is considered
//! poisoned at that point and the caller must drop it). `len == 0` represents
//! a legitimate empty UDP datagram and is admitted.
//!
//! ## Why this codec exists
//!
//! Both the libssh2 and russh backends speak `direct-tcpip` (a reliable
//! byte stream); to ship UDP datagrams over that stream we need to preserve
//! datagram boundaries. RFC 4254 §7.2 has no native UDP channel type, and
//! `direct-streamlocal@openssh.com` is unavailable on the libssh2 backend
//! (see [`crate::udp_uds_mode`]). Length-prefixing is the simplest portable
//! framing.
//!
//! ## Transport-agnostic
//!
//! Both `read_frame` and `write_frame` are generic over
//! [`tokio::io::AsyncRead`] / [`tokio::io::AsyncWrite`] so the same codec
//! drives a real `direct-tcpip` channel in production and a
//! `tokio::io::duplex()` mock in unit tests.

use spt_core::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single framed datagram payload: 64 KiB.
///
/// 64 KiB is the SSH datagram-style sweet spot — comfortably above the
/// 65 507-byte theoretical max UDP datagram (65 535 minus the IPv4 + UDP
/// headers) so that any datagram that could have arrived on the wire fits.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Write `payload` as a single length-prefixed frame onto `w`.
///
/// Returns [`Error::RuntimeFailure`] if `payload.len()` exceeds
/// [`MAX_FRAME_BYTES`], or if the underlying stream errors.
pub async fn write_frame<W>(w: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_FRAME_BYTES {
        return Err(Error::RuntimeFailure(format!(
            "udp_tcp_framed: refusing to write oversize frame ({} > {} bytes)",
            payload.len(),
            MAX_FRAME_BYTES
        )));
    }
    let len = u32::try_from(payload.len()).map_err(|_| {
        Error::RuntimeFailure("udp_tcp_framed: payload length does not fit in u32".into())
    })?;
    w.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| Error::RuntimeFailure(format!("udp_tcp_framed: write length: {e}")))?;
    w.write_all(payload)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("udp_tcp_framed: write payload: {e}")))?;
    Ok(())
}

/// Read a single length-prefixed frame from `r`.
///
/// * Returns `Ok(payload)` on success.
/// * Returns [`Error::RuntimeFailure`] when the advertised length exceeds
///   [`MAX_FRAME_BYTES`] (oversize reject), or when the stream errors.
/// * On a clean EOF before the length prefix has been read, returns
///   `Err(Error::RuntimeFailure)` carrying the EOF as a transport failure;
///   callers distinguish "peer closed" from "framing error" by inspecting
///   the message but normally treat both as terminal for the channel.
pub async fn read_frame<R>(r: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("udp_tcp_framed: read length: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::RuntimeFailure(format!(
            "udp_tcp_framed: oversize frame rejected ({len} > {MAX_FRAME_BYTES} bytes)"
        )));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload)
            .await
            .map_err(|e| Error::RuntimeFailure(format!("udp_tcp_framed: read payload: {e}")))?;
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// "tcp_framed positive roundtrip both backends" — the codec is transport-
    /// agnostic, so exercising it over `tokio::io::duplex()` demonstrates the
    /// behaviour both backends see. The libssh2 backend hands us an
    /// `AsyncChannel` (implementing `AsyncRead+AsyncWrite`) and the russh
    /// backend hands us a `ChannelStream`; both are covered by this single
    /// generic codec.
    #[tokio::test]
    async fn frame_roundtrip_transport_agnostic() {
        let (mut a, mut b) = duplex(8192);
        let payloads: &[&[u8]] = &[b"", b"hello", &[0xAB; 1500], &[0xCD; 4096]];
        for p in payloads {
            write_frame(&mut a, p).await.unwrap();
        }
        for p in payloads {
            let got = read_frame(&mut b).await.unwrap();
            assert_eq!(got.as_slice(), *p);
        }
    }

    #[tokio::test]
    async fn frame_oversize_write_rejected_64kib_plus_one() {
        let (mut a, _b) = duplex(8192);
        let too_big = vec![0u8; MAX_FRAME_BYTES + 1];
        let err = write_frame(&mut a, &too_big).await.unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(s) if s.contains("oversize")));
    }

    #[tokio::test]
    async fn frame_oversize_read_rejected_64kib_plus_one() {
        // Craft a length prefix exceeding MAX_FRAME_BYTES on the wire. The
        // parser must reject without attempting to allocate / fill the buffer.
        let (mut a, mut b) = duplex(64);
        let bogus_len: u32 = (MAX_FRAME_BYTES as u32) + 1;
        a.write_all(&bogus_len.to_be_bytes()).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(s) if s.contains("oversize")));
    }

    #[tokio::test]
    async fn frame_malformed_length_eof_mid_prefix_rejected() {
        // Only 3 bytes of the 4-byte length arrive, then EOF. read_exact
        // must surface as a RuntimeFailure.
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0x00, 0x00, 0x05]).await.unwrap();
        drop(a); // EOF
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }

    #[tokio::test]
    async fn frame_zero_length_payload_admitted() {
        let (mut a, mut b) = duplex(64);
        write_frame(&mut a, b"").await.unwrap();
        let got = read_frame(&mut b).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn frame_max_size_admitted_at_boundary() {
        let (mut a, mut b) = duplex(MAX_FRAME_BYTES + 8);
        let max = vec![0x77u8; MAX_FRAME_BYTES];
        write_frame(&mut a, &max).await.unwrap();
        let got = read_frame(&mut b).await.unwrap();
        assert_eq!(got.len(), MAX_FRAME_BYTES);
        assert!(got.iter().all(|&v| v == 0x77));
    }
}
