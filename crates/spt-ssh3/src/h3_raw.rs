//! Hand-rolled minimal HTTP/3 + QPACK for the SSH3 Extended-CONNECT
//! bootstrap.
//!
//! # Why this exists
//!
//! `h3 0.0.8` (the version we are MSRV-pinned to) ships a closed
//! [`Protocol`](https://docs.rs/h3/0.0.8/h3/ext/struct.Protocol.html) enum
//! with only `WEB_TRANSPORT` and `CONNECT_UDP` variants and no public
//! constructor for an arbitrary `:protocol` value. The SSH3 reference server
//! (`francoismichel/ssh3`) requires the literal `:protocol = ssh3` pseudo
//! header on the Extended-CONNECT request (RFC 9220).
//!
//! Rather than vendor h3 wholesale (option B in the design doc — heavy and
//! cascades into a quinn-version pin change) we bypass `h3` for the
//! bootstrap request only:
//!
//! 1. The h3 client driver still runs on the same QUIC connection. That
//!    driver opens a unidirectional client control stream and emits the
//!    mandatory HTTP/3 SETTINGS frame so the peer's HTTP/3 stack is happy.
//! 2. We open our **own** bidirectional stream on a clone of the same
//!    [`quinn::Connection`] and write a HEADERS frame by hand containing
//!    `:method = CONNECT`, `:protocol = ssh3`, `:scheme = https`,
//!    `:authority`, `:path`, plus `authorization`, `user-agent`, and
//!    `x-ssh3-protocol` (the latter kept for backward compatibility with
//!    any responder still keyed on the prior X-header wire contract).
//! 3. We read the response HEADERS frame back, decode it, and surface the
//!    `:status`.
//!
//! After CONNECT-200 the bidi stream is the SSH3 control channel — handed
//! straight back to `transport.rs`.
//!
//! # QPACK subset implemented
//!
//! Encoder:
//!
//! * Field-section prefix = `0x00 0x00` (Required Insert Count = 0,
//!   sign = 0, Delta Base = 0; no dynamic-table references).
//! * Each field encoded as:
//!     - "Literal Field Line With Name Reference" (RFC 9204 §4.5.4) if the
//!       name is in the static table.
//!     - "Literal Field Line With Literal Name" (§4.5.6) otherwise — used
//!       for `:protocol` and `x-ssh3-protocol`.
//! * No Huffman coding (always `H = 0`).
//!
//! Decoder (sufficient to parse a `:status` HEADERS frame):
//!
//! * "Indexed Field Line" against the static table (§4.5.2).
//! * "Literal Field Line With Name Reference" against the static table
//!   (§4.5.4).
//! * "Literal Field Line With Literal Name" (§4.5.6).
//!
//! Anything else (dynamic-table refs, Huffman-coded strings, post-base
//! references) is rejected as an unsupported encoding — the
//! reference SSH3 server never produces those on the response HEADERS for a
//! single `:status` answer.

use std::time::Duration;

use bytes::{BufMut, BytesMut};
use spt_core::{Error, Result};

/// Maximum bytes we will read for the response HEADERS frame. Generous
/// upper bound; a CONNECT-200 from any sane server is < 4 KiB.
const RESPONSE_HEADERS_MAX_LEN: u64 = 64 * 1024;

/// HTTP/3 HEADERS frame type (RFC 9114 §7.2.2).
const FRAME_HEADERS: u64 = 0x01;

/// Encode a QUIC variable-length integer (RFC 9000 §16).
pub(crate) fn write_varint(buf: &mut BytesMut, v: u64) {
    if v < 1 << 6 {
        buf.put_u8(v as u8);
    } else if v < 1 << 14 {
        buf.put_u16(0x4000 | v as u16);
    } else if v < 1 << 30 {
        buf.put_u32(0x8000_0000 | v as u32);
    } else if v < 1 << 62 {
        buf.put_u64(0xC000_0000_0000_0000 | v);
    } else {
        // Caller-side bug; truncate to highest legal value to avoid panic
        // in release.
        buf.put_u64(0xC000_0000_0000_0000 | ((1u64 << 62) - 1));
    }
}

/// Decode a QUIC varint from a slice. Returns `(value, bytes_consumed)`.
pub(crate) fn read_varint(buf: &[u8]) -> Result<(u64, usize)> {
    if buf.is_empty() {
        return Err(Error::RuntimeFailure(
            "ssh3 h3_raw: varint underflow".into(),
        ));
    }
    let first = buf[0];
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if buf.len() < len {
        return Err(Error::RuntimeFailure(format!(
            "ssh3 h3_raw: varint wants {len} bytes, have {}",
            buf.len()
        )));
    }
    // Top 2 bits encode the length; the remaining 6 bits are the high bits of
    // the value.
    let mask: u8 = 0x3F;
    let mut v = u64::from(first & mask);
    for &b in &buf[1..len] {
        v = (v << 8) | u64::from(b);
    }
    Ok((v, len))
}

/// RFC 7541 §5.1 prefix-int writer with prefix `n` bits and high `top` bits
/// already populated in `first`. `n` is in `1..=8`.
fn write_prefix_int(buf: &mut BytesMut, top: u8, n: u8, value: u64) {
    debug_assert!((1..=8).contains(&n));
    let max = (1u64 << n) - 1;
    if value < max {
        buf.put_u8(top | (value as u8));
    } else {
        buf.put_u8(top | (max as u8));
        let mut remaining = value - max;
        while remaining >= 128 {
            buf.put_u8(((remaining & 0x7F) as u8) | 0x80);
            remaining >>= 7;
        }
        buf.put_u8(remaining as u8);
    }
}

/// RFC 7541 §5.1 prefix-int reader.
fn read_prefix_int(buf: &[u8], n: u8) -> Result<(u64, usize)> {
    debug_assert!((1..=8).contains(&n));
    if buf.is_empty() {
        return Err(Error::RuntimeFailure(
            "ssh3 qpack: prefix-int underflow".into(),
        ));
    }
    let max: u64 = (1u64 << n) - 1;
    let mut value = u64::from(buf[0]) & max;
    let mut consumed = 1usize;
    if value < max {
        return Ok((value, consumed));
    }
    let mut shift = 0u32;
    loop {
        if consumed >= buf.len() {
            return Err(Error::RuntimeFailure(
                "ssh3 qpack: prefix-int continuation underflow".into(),
            ));
        }
        let b = buf[consumed];
        consumed += 1;
        value = value
            .checked_add(u64::from(b & 0x7F) << shift)
            .ok_or_else(|| Error::RuntimeFailure("ssh3 qpack: prefix-int overflow".into()))?;
        if (b & 0x80) == 0 {
            return Ok((value, consumed));
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::RuntimeFailure(
                "ssh3 qpack: prefix-int continuation too long".into(),
            ));
        }
    }
}

/// QPACK static-table name index for the small subset we touch on either
/// side of the bootstrap. Returning `None` means "encode the name
/// literally".
///
/// Indices are from RFC 9204 Appendix A and verified against the
/// `h3 0.0.8` static-table mirror in
/// `crates/.cargo-cache/.../h3-0.0.8/src/qpack/static_.rs` (lines 22-128).
fn static_name_index(name: &[u8]) -> Option<u64> {
    match name {
        b":authority" => Some(0),
        b":path" => Some(1),
        b":method" => Some(15),
        b":scheme" => Some(22),
        b":status" => Some(24),
        b"authorization" => Some(84),
        b"user-agent" => Some(95),
        _ => None,
    }
}

/// Decode a QPACK static-table entry into its `(name, value)` byte pair.
/// Covers only the entries we expect on a response from a CONNECT-200.
///
/// Per RFC 9204 Appendix A.
fn static_entry(index: u64) -> Result<(&'static [u8], &'static [u8])> {
    let pair: (&[u8], &[u8]) = match index {
        0 => (b":authority", b""),
        1 => (b":path", b"/"),
        15 => (b":method", b"CONNECT"),
        17 => (b":method", b"GET"),
        22 => (b":scheme", b"http"),
        23 => (b":scheme", b"https"),
        24 => (b":status", b"103"),
        25 => (b":status", b"200"),
        26 => (b":status", b"304"),
        27 => (b":status", b"404"),
        28 => (b":status", b"503"),
        63 => (b":status", b"100"),
        64 => (b":status", b"204"),
        65 => (b":status", b"206"),
        66 => (b":status", b"302"),
        67 => (b":status", b"400"),
        68 => (b":status", b"403"),
        69 => (b":status", b"421"),
        70 => (b":status", b"425"),
        71 => (b":status", b"500"),
        84 => (b"authorization", b""),
        92 => (b"server", b""),
        95 => (b"user-agent", b""),
        _ => {
            return Err(Error::RuntimeFailure(format!(
                "ssh3 qpack: static index {index} not supported by minimal decoder",
            )));
        }
    };
    Ok(pair)
}

/// Encode the QPACK field-section prefix (§4.5.1) + the field lines for
/// `fields`. Always emits zero dynamic-table references.
pub(crate) fn qpack_encode(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(64 + fields.len() * 32);
    // Required Insert Count = 0 (prefix=8 bits, top=0).
    write_prefix_int(&mut out, 0x00, 8, 0);
    // Sign=0, Delta Base=0 (prefix=7 bits, top=0).
    write_prefix_int(&mut out, 0x00, 7, 0);

    for (name, value) in fields {
        if let Some(idx) = static_name_index(name) {
            // Literal Field Line With Name Reference (§4.5.4):
            // 0 1 N T NNNN — N=0 (not-never-indexed), T=1 (static).
            // Prefix bits = 4, top = 0b01010000 = 0x50.
            write_prefix_int(&mut out, 0x50, 4, idx);
        } else {
            // Literal Field Line With Literal Name (§4.5.6):
            // 0 0 1 N H LLL — N=0, H=0, prefix bits = 3, top = 0x20.
            write_prefix_int(&mut out, 0x20, 3, name.len() as u64);
            out.put_slice(name);
        }
        // Value: H=0, prefix=7. Top = 0x00.
        write_prefix_int(&mut out, 0x00, 7, value.len() as u64);
        out.put_slice(value);
    }
    out.to_vec()
}

/// Decode a QPACK-encoded field section into a sequence of
/// `(name, value)` byte pairs. Limited to the representations used by
/// CONNECT-200 responses (see module docs).
pub(crate) fn qpack_decode(mut buf: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    // Field-section prefix: Required Insert Count (prefix=8) + Sign+Delta Base
    // (prefix=7). We tolerate any value for RIC/DeltaBase — there's no dynamic
    // table on either side so they only inform absolute base, which we don't
    // use.
    let (_ric, n) = read_prefix_int(buf, 8)?;
    buf = &buf[n..];
    let (_db, n) = read_prefix_int(buf, 7)?;
    buf = &buf[n..];

    let mut out = Vec::new();
    while !buf.is_empty() {
        let first = buf[0];
        if first & 0b1000_0000 != 0 {
            // Indexed Field Line (§4.5.2): 1 T NNNN NN — prefix=6.
            let t_static = first & 0b0100_0000 != 0;
            let (idx, n) = read_prefix_int(buf, 6)?;
            buf = &buf[n..];
            if !t_static {
                return Err(Error::RuntimeFailure(
                    "ssh3 qpack: dynamic-table indexed field not supported".into(),
                ));
            }
            let (name, value) = static_entry(idx)?;
            out.push((name.to_vec(), value.to_vec()));
        } else if first & 0b0100_0000 != 0 {
            // Literal Field Line With Name Reference (§4.5.4): 0 1 N T NNNN —
            // prefix=4 for name index.
            let t_static = first & 0b0001_0000 != 0;
            let (idx, n) = read_prefix_int(buf, 4)?;
            buf = &buf[n..];
            if !t_static {
                return Err(Error::RuntimeFailure(
                    "ssh3 qpack: dynamic-table literal-name-ref not supported".into(),
                ));
            }
            let (name, _) = static_entry(idx)?;
            let (value, consumed) = read_literal_string(buf)?;
            buf = &buf[consumed..];
            out.push((name.to_vec(), value));
        } else if first & 0b0010_0000 != 0 {
            // Literal Field Line With Literal Name (§4.5.6): 0 0 1 N H LLL —
            // prefix=3 for name length; H bit at position 4 from MSB.
            if first & 0b0000_1000 != 0 {
                return Err(Error::RuntimeFailure(
                    "ssh3 qpack: huffman-coded literal name not supported".into(),
                ));
            }
            let (name_len, n) = read_prefix_int(buf, 3)?;
            buf = &buf[n..];
            let name_len = name_len as usize;
            if buf.len() < name_len {
                return Err(Error::RuntimeFailure("ssh3 qpack: name underflow".into()));
            }
            let name = buf[..name_len].to_vec();
            buf = &buf[name_len..];
            let (value, consumed) = read_literal_string(buf)?;
            buf = &buf[consumed..];
            out.push((name, value));
        } else {
            return Err(Error::RuntimeFailure(format!(
                "ssh3 qpack: unsupported field-line opcode byte 0x{first:02x}",
            )));
        }
    }
    Ok(out)
}

/// Read a `H | Length(7+) | bytes` literal string. Rejects Huffman.
fn read_literal_string(buf: &[u8]) -> Result<(Vec<u8>, usize)> {
    if buf.is_empty() {
        return Err(Error::RuntimeFailure("ssh3 qpack: value underflow".into()));
    }
    if buf[0] & 0b1000_0000 != 0 {
        return Err(Error::RuntimeFailure(
            "ssh3 qpack: huffman-coded string not supported".into(),
        ));
    }
    let (len, n) = read_prefix_int(buf, 7)?;
    let len = len as usize;
    if buf.len() < n + len {
        return Err(Error::RuntimeFailure(format!(
            "ssh3 qpack: value wants {len} bytes after header, have {}",
            buf.len() - n
        )));
    }
    let value = buf[n..n + len].to_vec();
    Ok((value, n + len))
}

/// Wrap a QPACK-encoded payload in an HTTP/3 HEADERS frame.
pub(crate) fn build_headers_frame(qpack_payload: &[u8]) -> Vec<u8> {
    let mut frame = BytesMut::with_capacity(qpack_payload.len() + 8);
    write_varint(&mut frame, FRAME_HEADERS);
    write_varint(&mut frame, qpack_payload.len() as u64);
    frame.put_slice(qpack_payload);
    frame.to_vec()
}

/// Read one HTTP/3 frame from `recv`, returning `(type, payload)`. Bounded
/// by `RESPONSE_HEADERS_MAX_LEN`. Skips frames whose type is not
/// `expected_type`; per RFC 9114 §7.2 unknown frames MUST be ignored.
pub(crate) async fn read_frame_typed(
    recv: &mut quinn::RecvStream,
    expected_type: u64,
) -> Result<Vec<u8>> {
    loop {
        let ty = read_varint_from_stream(recv).await?;
        let len = read_varint_from_stream(recv).await?;
        if len > RESPONSE_HEADERS_MAX_LEN {
            return Err(Error::RuntimeFailure(format!(
                "ssh3 h3_raw: frame length {len} > cap {RESPONSE_HEADERS_MAX_LEN}",
            )));
        }
        let mut payload = vec![0u8; len as usize];
        read_exact_from_stream(recv, &mut payload).await?;
        if ty == expected_type {
            return Ok(payload);
        }
        // Otherwise drop and read the next.
        tracing::debug!(?ty, "ssh3 h3_raw: skipping unexpected frame type");
    }
}

async fn read_varint_from_stream(recv: &mut quinn::RecvStream) -> Result<u64> {
    let mut first = [0u8; 1];
    read_exact_from_stream(recv, &mut first).await?;
    let prefix = first[0] >> 6;
    let total = 1usize << prefix;
    let mut buf = vec![0u8; total];
    buf[0] = first[0];
    if total > 1 {
        read_exact_from_stream(recv, &mut buf[1..]).await?;
    }
    let (v, _) = read_varint(&buf)?;
    Ok(v)
}

async fn read_exact_from_stream(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = recv
            .read(&mut buf[filled..])
            .await
            .map_err(|e| Error::RuntimeFailure(format!("ssh3 h3_raw: stream read: {e}")))?
            .ok_or_else(|| Error::RuntimeFailure("ssh3 h3_raw: stream closed mid-frame".into()))?;
        if n == 0 {
            return Err(Error::RuntimeFailure(
                "ssh3 h3_raw: stream returned zero bytes".into(),
            ));
        }
        filled += n;
    }
    Ok(())
}

/// Issue an Extended-CONNECT request on `connection` using the raw HTTP/3
/// frame path and return the open bidi stream halves alongside the
/// response metadata.
///
/// `auth_header` is the prebuilt `Authorization` header value (e.g.
/// `Bearer <jwt>`). `user_agent` is the User-Agent value. `protocol_token`
/// is the `:protocol` pseudo-header value (default `ssh3`; see
/// [`crate::config::Ssh3Config::protocol_token`]).
///
/// On a non-2xx response the bidi stream is dropped and an error is
/// returned mapped to [`Error::AuthFailed`] (401/403) or
/// [`Error::RuntimeFailure`].
pub(crate) async fn extended_connect_raw(
    connection: &quinn::Connection,
    host: &str,
    port: u16,
    url_path: &str,
    auth_header: &str,
    user_agent: &str,
    protocol_token: &str,
) -> Result<RawConnectOutcome> {
    let authority = format!("{host}:{port}");
    let protocol_bytes = protocol_token.as_bytes();
    let fields: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"CONNECT"),
        (b":scheme", b"https"),
        (b":authority", authority.as_bytes()),
        (b":path", url_path.as_bytes()),
        (b":protocol", protocol_bytes),
        (b"authorization", auth_header.as_bytes()),
        (b"user-agent", user_agent.as_bytes()),
        // Kept as a redundant marker so any responder still keyed on the
        // pre-raw-path X-header continues to interop. The pseudo-header
        // is the wire contract per RFC 9220; the X-header is a belt.
        (b"x-ssh3-protocol", protocol_bytes),
    ];
    let qpack = qpack_encode(&fields);
    let frame = build_headers_frame(&qpack);

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 h3_raw: open_bi: {e}")))?;
    send.write_all(&frame)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 h3_raw: write HEADERS: {e}")))?;

    // Read response HEADERS, capped by an outer timeout.
    let resp_payload = tokio::time::timeout(
        Duration::from_secs(30),
        read_frame_typed(&mut recv, FRAME_HEADERS),
    )
    .await
    .map_err(|_| Error::RuntimeFailure("ssh3 h3_raw: response HEADERS timeout".into()))??;
    let decoded = qpack_decode(&resp_payload)?;

    let mut status: Option<u16> = None;
    let mut server: Option<String> = None;
    for (n, v) in &decoded {
        if n == b":status" {
            let s = std::str::from_utf8(v).map_err(|_| {
                Error::RuntimeFailure(format!(
                    "ssh3 h3_raw: :status not utf-8 ({} bytes)",
                    v.len()
                ))
            })?;
            status =
                Some(s.parse().map_err(|_| {
                    Error::RuntimeFailure(format!("ssh3 h3_raw: bad :status `{s}`"))
                })?);
        } else if n == b"server" {
            server = std::str::from_utf8(v).ok().map(str::to_owned);
        }
    }
    let status = status.ok_or_else(|| {
        Error::RuntimeFailure("ssh3 h3_raw: response missing :status pseudo-header".into())
    })?;

    Ok(RawConnectOutcome {
        status,
        peer_version: server,
        send,
        recv,
    })
}

/// Open a server-side HTTP/3 control stream (a unidirectional stream whose
/// first byte is the CONTROL stream type `0x00`) and write an empty `SETTINGS`
/// frame on it.
///
/// This is the minimal peer-side h3 handshake the *client's* h3 driver
/// (`h3::client`'s `poll_close` → `poll_control`) needs to observe so it stays
/// alive instead of treating the connection as closeable and tearing it down
/// when its driver task drops. The real francoismichel/ssh3 server (a full h3
/// server) provides this implicitly; our in-repo [`crate::server::Ssh3Server`]
/// provides it explicitly with this helper. Returns the kept-open
/// [`quinn::SendStream`] (the caller must hold it for the connection's
/// lifetime — dropping it finishes the control stream, which the client
/// tolerates but which is cleaner to keep open).
#[cfg(any(test, feature = "server"))]
pub(crate) async fn write_server_control_stream(
    connection: &quinn::Connection,
) -> Result<quinn::SendStream> {
    /// HTTP/3 CONTROL stream type (RFC 9114 §6.2.1).
    const STREAM_TYPE_CONTROL: u64 = 0x00;
    /// HTTP/3 SETTINGS frame type (RFC 9114 §7.2.4).
    const FRAME_SETTINGS: u64 = 0x04;

    let mut uni = connection
        .open_uni()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 h3_raw: open_uni control: {e}")))?;
    let mut buf = BytesMut::new();
    write_varint(&mut buf, STREAM_TYPE_CONTROL);
    // Empty SETTINGS frame: type + length(0).
    write_varint(&mut buf, FRAME_SETTINGS);
    write_varint(&mut buf, 0);
    uni.write_all(&buf)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 h3_raw: write control SETTINGS: {e}")))?;
    Ok(uni)
}

/// The outcome of a [`extended_connect_raw`] call.
pub(crate) struct RawConnectOutcome {
    pub status: u16,
    pub peer_version: Option<String>,
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_small() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x01);
        let (v, n) = read_varint(&buf).unwrap();
        assert_eq!(v, 0x01);
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_roundtrip_2byte() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x3FFF);
        let (v, n) = read_varint(&buf).unwrap();
        assert_eq!(v, 0x3FFF);
        assert_eq!(n, 2);
    }

    #[test]
    fn varint_roundtrip_4byte() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x3FFF_FFFF);
        let (v, n) = read_varint(&buf).unwrap();
        assert_eq!(v, 0x3FFF_FFFF);
        assert_eq!(n, 4);
    }

    #[test]
    fn prefix_int_short_roundtrip() {
        let mut buf = BytesMut::new();
        write_prefix_int(&mut buf, 0x40, 4, 5);
        // Top bits 0100, value 5 in 4-bit prefix.
        assert_eq!(buf[0], 0x45);
        let (v, n) = read_prefix_int(&buf, 4).unwrap();
        assert_eq!(v, 5);
        assert_eq!(n, 1);
    }

    #[test]
    fn prefix_int_long_roundtrip() {
        let mut buf = BytesMut::new();
        write_prefix_int(&mut buf, 0x00, 7, 256);
        // First byte saturates to 127 (= 2^7 - 1), then 129 = (256 - 127) =
        // 129 → continuation byte 0x81 then 0x01.
        let (v, _) = read_prefix_int(&buf, 7).unwrap();
        assert_eq!(v, 256);
    }

    #[test]
    fn qpack_roundtrip_pseudo_headers() {
        let fields: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", b"example.com:443"),
            (b":path", b"/ssh3"),
            (b":protocol", b"ssh3"),
            (b"authorization", b"Bearer abc"),
            (b"user-agent", b"spt/0.1"),
            (b"x-ssh3-protocol", b"ssh3"),
        ];
        let encoded = qpack_encode(&fields);
        let decoded = qpack_decode(&encoded).unwrap();
        assert_eq!(decoded.len(), fields.len());
        for ((dn, dv), (en, ev)) in decoded.iter().zip(fields.iter()) {
            assert_eq!(dn.as_slice(), *en, "name mismatch");
            assert_eq!(dv.as_slice(), *ev, "value mismatch");
        }
    }

    #[test]
    fn qpack_roundtrip_long_value() {
        // 300-byte authorization value forces multi-byte prefix-int length.
        let big: Vec<u8> = (0..300u32).map(|i| (i % 26) as u8 + b'a').collect();
        let fields: Vec<(&[u8], &[u8])> =
            vec![(b":method", b"CONNECT"), (b"authorization", &big[..])];
        let enc = qpack_encode(&fields);
        let dec = qpack_decode(&enc).unwrap();
        assert_eq!(dec.len(), 2);
        assert_eq!(dec[1].0, b"authorization".to_vec());
        assert_eq!(dec[1].1, big);
    }

    #[test]
    fn qpack_decode_indexed_static_status_200() {
        // Hand-craft the smallest possible response: just `:status=200` as
        // an indexed field line against static index 25.
        // Prefix 0x00 0x00, then 0b1100_0000 | 25 = 0xD9.
        let payload = vec![0x00, 0x00, 0xC0 | 25];
        let dec = qpack_decode(&payload).unwrap();
        assert_eq!(dec, vec![(b":status".to_vec(), b"200".to_vec())]);
    }

    #[test]
    fn qpack_decode_literal_name_ref_status_200() {
        // Same but using literal-with-name-reference: static name idx 24
        // (= `:status`) and value literal `200`.
        // First byte: 0b0101_0000 | 8(24-16? — idx is prefix-int 4-bit) →
        // need continuation since 24 >= 15.
        let mut payload = vec![0x00, 0x00];
        // 0x50 | 15 = 0x5F, then (24 - 15) = 9 as continuation.
        payload.push(0x5F);
        payload.push(9);
        // Value: H=0, length=3 → 0x03 then "200".
        payload.push(0x03);
        payload.extend_from_slice(b"200");
        let dec = qpack_decode(&payload).unwrap();
        assert_eq!(dec, vec![(b":status".to_vec(), b"200".to_vec())]);
    }

    #[test]
    fn build_headers_frame_writes_type_then_length() {
        let qp = vec![0x00, 0x00, 0xC0 | 25];
        let f = build_headers_frame(&qp);
        // First byte: varint type=1 → 0x01.
        assert_eq!(f[0], 0x01);
        // Next: varint length=3 → 0x03.
        assert_eq!(f[1], 0x03);
        assert_eq!(&f[2..], &qp[..]);
    }

    #[test]
    fn qpack_reject_huffman_value() {
        // 0x00 0x00 prefix, then indexed (static, idx 0 = :authority),
        // then a value byte with H=1.
        let payload = vec![0x00, 0x00, 0x50, 0x80, 0x00];
        let err = qpack_decode(&payload).unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }

    #[test]
    fn qpack_reject_dynamic_indexed() {
        // 1 T NNNN NN with T=0 → dynamic table.
        let payload = vec![0x00, 0x00, 0b1000_0001];
        let err = qpack_decode(&payload).unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }
}
