//! Proxy-jump helpers: SOCKS5 and HTTP CONNECT handshakes spoken across
//! an already-established byte stream.
//!
//! These helpers are intentionally **transport-agnostic** — they operate on
//! anything that implements [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`]
//! so unit tests can drive them against `tokio::io::duplex()` mock peers
//! and the production code can drive them against either a real
//! `TcpStream` or the loopback half of a multi-hop pump
//! (`crate::multi_hop`).
//!
//! ### What's implemented
//!
//! * **SOCKS5** — RFC 1928 (method negotiation + `CONNECT`) + RFC 1929
//!   (username/password sub-negotiation). IPv4, IPv6 and domain-name target
//!   addressing are supported. `BIND` and `UDP ASSOCIATE` are out of scope:
//!   spt only proxy-jumps via `CONNECT`.
//! * **HTTP CONNECT** — RFC 7231 §4.3.6. Optional
//!   `Proxy-Authorization: Basic …` header. Any 2xx response is treated as
//!   success; `407 Proxy Authentication Required` returns a typed
//!   [`spt_core::Error::AuthFailed`]; everything else is a
//!   [`spt_core::Error::RuntimeFailure`]. The implementation reads the
//!   response headers up to the first `\r\n\r\n` and ignores any body — a
//!   CONNECT response should not carry one once the tunnel is established.
//!
//! Both helpers consume the stream's handshake-leading bytes only; once the
//! helper returns `Ok(())` the stream is positioned to pass application
//! traffic (SSH, in spt's case) through to the proxied destination.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use spt_core::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ---------------------------------------------------------------------------
// SOCKS5 (RFC 1928 + RFC 1929)
// ---------------------------------------------------------------------------

/// Optional SOCKS5 / HTTP CONNECT credentials.
#[derive(Debug, Clone)]
pub struct ProxyCredentials {
    /// Username sent in the auth sub-negotiation (SOCKS5) or the
    /// `Proxy-Authorization: Basic …` header (HTTP CONNECT).
    pub username: String,
    /// Password sent in the auth sub-negotiation (SOCKS5) or the
    /// `Proxy-Authorization: Basic …` header (HTTP CONNECT).
    pub password: String,
}

/// Speak the SOCKS5 client handshake over `stream`, requesting
/// `CONNECT (host, port)`.
///
/// * On success the stream is positioned to pass through bytes to/from
///   `(host, port)`.
/// * Returns [`Error::AuthFailed`] for SOCKS5 auth failures (sub-negotiation
///   status != 0), [`Error::RuntimeFailure`] for any other protocol error or
///   transport I/O error.
///
/// Note: this is *blocking on the stream's I/O futures*. Callers that need
/// to time-bound the handshake should wrap the future in
/// `tokio::time::timeout`.
pub async fn socks5_connect<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    creds: Option<&ProxyCredentials>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ---- Method negotiation ---------------------------------------------
    // VER=0x05, NMETHODS=1 or 2, METHODS=...
    // Always advertise NO_AUTH; advertise USERNAME/PASSWORD only when
    // credentials are present (so unauthenticated proxies don't see us asking
    // for an auth method they don't support).
    let mut hello: Vec<u8> = Vec::with_capacity(4);
    hello.push(0x05); // VER
    if creds.is_some() {
        hello.push(0x02); // NMETHODS
        hello.push(0x00); // NO_AUTH
        hello.push(0x02); // USERNAME/PASSWORD
    } else {
        hello.push(0x01);
        hello.push(0x00);
    }
    write_all(stream, &hello).await?;

    let mut reply = [0u8; 2];
    read_exact(stream, &mut reply).await?;
    if reply[0] != 0x05 {
        return Err(Error::RuntimeFailure(format!(
            "socks5: unexpected version byte 0x{:02x} in method-negotiation reply",
            reply[0]
        )));
    }
    match reply[1] {
        0x00 => { /* NO_AUTH selected — proceed */ }
        0x02 => {
            // Server picked USERNAME/PASSWORD; we'd better have creds.
            let c = creds.ok_or_else(|| {
                Error::auth_failed(
                    spt_core::Diagnostic::what(
                        "SOCKS5 proxy requires username/password but none configured",
                    )
                    .why("server replied with method 0x02 (USERNAME/PASSWORD); we advertised no creds")
                    .how_to_fix(
                        "Set `proxy.credentials.username` and `proxy.credentials.password` \
                         in your config, or change the proxy to allow NO_AUTH (0x00).",
                    )
                    .retry_advice(spt_core::RetryAdvice::NotRetryable)
                    .build(),
                )
            })?;
            socks5_userpass_auth(stream, c).await?;
        }
        0xff => {
            return Err(Error::auth_failed(
                spt_core::Diagnostic::what(
                    "SOCKS5 proxy rejected all advertised auth methods",
                )
                .why("server replied with NO_ACCEPTABLE_METHODS (0xff)")
                .how_to_fix(
                    "Check what auth methods the proxy requires (consult its docs or \
                     server logs) and configure matching credentials. We currently \
                     advertise NO_AUTH and USERNAME/PASSWORD only.",
                )
                .retry_advice(spt_core::RetryAdvice::NotRetryable)
                .build(),
            ));
        }
        other => {
            return Err(Error::RuntimeFailure(format!(
                "socks5: unsupported auth method 0x{other:02x}"
            )));
        }
    }

    // ---- CONNECT request ------------------------------------------------
    // VER=0x05, CMD=CONNECT(0x01), RSV=0x00, ATYP, DST.ADDR, DST.PORT
    let mut req: Vec<u8> = Vec::with_capacity(7 + host.len());
    req.push(0x05);
    req.push(0x01); // CONNECT
    req.push(0x00); // RSV
    if let Ok(ip4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip4.octets());
    } else if let Ok(ip6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip6.octets());
    } else {
        if host.len() > 255 {
            return Err(Error::RuntimeFailure(format!(
                "socks5: domain name {} bytes exceeds 255-byte limit",
                host.len()
            )));
        }
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    write_all(stream, &req).await?;

    // ---- CONNECT reply --------------------------------------------------
    let mut head = [0u8; 4];
    read_exact(stream, &mut head).await?;
    if head[0] != 0x05 {
        return Err(Error::RuntimeFailure(format!(
            "socks5: unexpected version byte 0x{:02x} in CONNECT reply",
            head[0]
        )));
    }
    let status = head[1];
    if status != 0x00 {
        return Err(socks5_status_to_error(status));
    }
    // Drain BND.ADDR + BND.PORT so subsequent reads see only payload bytes.
    match head[3] {
        0x01 => {
            let mut buf = [0u8; 4 + 2];
            read_exact(stream, &mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 16 + 2];
            read_exact(stream, &mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            read_exact(stream, &mut buf).await?;
        }
        other => {
            return Err(Error::RuntimeFailure(format!(
                "socks5: unknown ATYP 0x{other:02x} in CONNECT reply"
            )));
        }
    }
    Ok(())
}

async fn socks5_userpass_auth<S>(stream: &mut S, creds: &ProxyCredentials) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if creds.username.len() > 255 || creds.password.len() > 255 {
        return Err(Error::InvalidArgs(
            "socks5 username/password must each be ≤255 bytes (RFC 1929)".into(),
        ));
    }
    let mut req: Vec<u8> = Vec::with_capacity(3 + creds.username.len() + creds.password.len());
    req.push(0x01); // RFC 1929 version
    req.push(creds.username.len() as u8);
    req.extend_from_slice(creds.username.as_bytes());
    req.push(creds.password.len() as u8);
    req.extend_from_slice(creds.password.as_bytes());
    write_all(stream, &req).await?;

    let mut reply = [0u8; 2];
    read_exact(stream, &mut reply).await?;
    if reply[0] != 0x01 {
        return Err(Error::RuntimeFailure(format!(
            "socks5: unexpected sub-negotiation version 0x{:02x}",
            reply[0]
        )));
    }
    if reply[1] != 0x00 {
        return Err(Error::auth_failed(
            spt_core::Diagnostic::what(
                "SOCKS5 proxy rejected the supplied username/password",
            )
            .why(format!(
                "RFC 1929 sub-negotiation returned status 0x{:02x} (0x00 = success)",
                reply[1]
            ))
            .how_to_fix(
                "Verify `proxy.credentials.username` and `proxy.credentials.password` \
                 match what the proxy expects. Consult the proxy's auth log if \
                 available.",
            )
            .retry_advice(spt_core::RetryAdvice::NotRetryable)
            .build(),
        ));
    }
    Ok(())
}

fn socks5_status_to_error(status: u8) -> Error {
    // RFC 1928 §6.
    let msg = match status {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unspecified SOCKS5 failure",
    };
    Error::RuntimeFailure(format!("socks5: {msg} (status 0x{status:02x})"))
}

// ---------------------------------------------------------------------------
// HTTP CONNECT (RFC 7231 §4.3.6 + RFC 7235)
// ---------------------------------------------------------------------------

/// Speak the HTTP `CONNECT host:port HTTP/1.1` handshake over `stream`.
///
/// * On 2xx, returns `Ok(())` and the stream is positioned at the start of
///   the proxied connection.
/// * 407 → [`Error::AuthFailed`].
/// * Any other status, malformed reply, or transport error →
///   [`Error::RuntimeFailure`].
pub async fn http_connect<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    creds: Option<&ProxyCredentials>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = String::new();
    req.push_str(&format!("CONNECT {host}:{port} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {host}:{port}\r\n"));
    req.push_str("Proxy-Connection: keep-alive\r\n");
    if let Some(c) = creds {
        let token = B64.encode(format!("{}:{}", c.username, c.password));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    write_all(stream, req.as_bytes()).await?;

    let (status, _headers) = read_http_response_head(stream).await?;
    if (200..300).contains(&status) {
        Ok(())
    } else if status == 407 {
        Err(Error::AuthFailed(format!(
            "http-connect: proxy returned 407 Proxy Authentication Required for {host}:{port}"
        )))
    } else {
        Err(Error::RuntimeFailure(format!(
            "http-connect: proxy returned status {status} for {host}:{port}"
        )))
    }
}

/// Read until `\r\n\r\n`, returning `(status, raw_head)`.
///
/// A 64 KiB cap keeps a malicious proxy from exhausting memory. We process
/// byte-at-a-time because HTTP CONNECT replies are tiny and we MUST stop
/// at the end of the headers — anything after `\r\n\r\n` is proxied payload.
async fn read_http_response_head<S>(stream: &mut S) -> Result<(u16, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const MAX: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut one = [0u8; 1];
    loop {
        let n = stream.read(&mut one).await.map_err(|e| {
            Error::RuntimeFailure(format!("http-connect: read proxy response: {e}"))
        })?;
        if n == 0 {
            return Err(Error::RuntimeFailure(
                "http-connect: proxy closed the connection mid-response".into(),
            ));
        }
        buf.push(one[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > MAX {
            return Err(Error::RuntimeFailure(
                "http-connect: response head exceeded 64 KiB".into(),
            ));
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let first = head
        .split("\r\n")
        .next()
        .ok_or_else(|| Error::RuntimeFailure("http-connect: empty response".into()))?;
    // Status-line: `HTTP/1.x <code> <reason>`.
    let mut parts = first.splitn(3, ' ');
    let _ver = parts
        .next()
        .ok_or_else(|| Error::RuntimeFailure(format!("http-connect: bad status line `{first}`")))?;
    let code = parts
        .next()
        .ok_or_else(|| Error::RuntimeFailure(format!("http-connect: bad status line `{first}`")))?;
    let code: u16 = code.parse().map_err(|e| {
        Error::RuntimeFailure(format!("http-connect: bad status code `{code}`: {e}"))
    })?;
    Ok((code, head))
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

async fn write_all<S: AsyncWrite + Unpin>(stream: &mut S, buf: &[u8]) -> Result<()> {
    stream
        .write_all(buf)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("proxy-jump: write: {e}")))
}

async fn read_exact<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> Result<()> {
    stream
        .read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|e| Error::RuntimeFailure(format!("proxy-jump: read: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Drive a SOCKS5 server-side script over `duplex` while the client
    /// performs `socks5_connect`. Returns the bytes the client wrote and the
    /// client-side result.
    async fn run_socks5(
        host: &str,
        port: u16,
        creds: Option<ProxyCredentials>,
        server_script: impl FnOnce(
                tokio::io::DuplexStream,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + 'static,
    ) -> Result<()> {
        let (mut client, server) = tokio::io::duplex(8192);
        let s = tokio::spawn(server_script(server));
        let c = socks5_connect(&mut client, host, port, creds.as_ref()).await;
        s.await.unwrap();
        c
    }

    // --- SOCKS5 -----------------------------------------------------------

    #[tokio::test]
    async fn socks5_positive_no_auth_ipv4() {
        let res = run_socks5("127.0.0.1", 2222, None, |mut sv| {
            Box::pin(async move {
                let mut hello = [0u8; 3];
                sv.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello, [0x05, 0x01, 0x00]);
                sv.write_all(&[0x05, 0x00]).await.unwrap(); // NO_AUTH selected
                let mut hdr = [0u8; 4];
                sv.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], 0x05);
                assert_eq!(hdr[1], 0x01);
                assert_eq!(hdr[3], 0x01); // IPv4
                let mut tail = [0u8; 6];
                sv.read_exact(&mut tail).await.unwrap();
                assert_eq!(&tail[0..4], &[127, 0, 0, 1]);
                assert_eq!(u16::from_be_bytes([tail[4], tail[5]]), 2222);
                // Success reply with IPv4 BND.
                sv.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            })
        })
        .await;
        assert!(res.is_ok(), "expected ok, got {res:?}");
    }

    #[tokio::test]
    async fn socks5_positive_userpass_auth_domain() {
        let creds = ProxyCredentials {
            username: "alice".into(),
            password: "s3cret".into(),
        };
        let res = run_socks5("example.com", 22, Some(creds), |mut sv| {
            Box::pin(async move {
                // Method negotiation: client advertised NO_AUTH + USERPASS.
                let mut hello = [0u8; 4];
                sv.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello, [0x05, 0x02, 0x00, 0x02]);
                sv.write_all(&[0x05, 0x02]).await.unwrap(); // pick USERPASS

                // RFC 1929 sub-negotiation
                let mut head = [0u8; 2];
                sv.read_exact(&mut head).await.unwrap();
                assert_eq!(head[0], 0x01);
                let ulen = head[1] as usize;
                let mut u = vec![0u8; ulen];
                sv.read_exact(&mut u).await.unwrap();
                assert_eq!(&u, b"alice");
                let mut plen = [0u8; 1];
                sv.read_exact(&mut plen).await.unwrap();
                let mut p = vec![0u8; plen[0] as usize];
                sv.read_exact(&mut p).await.unwrap();
                assert_eq!(&p, b"s3cret");
                sv.write_all(&[0x01, 0x00]).await.unwrap();

                // CONNECT to example.com:22
                let mut head = [0u8; 5];
                sv.read_exact(&mut head).await.unwrap();
                assert_eq!(head[0..3], [0x05, 0x01, 0x00]);
                assert_eq!(head[3], 0x03); // domain
                let dlen = head[4] as usize;
                let mut d = vec![0u8; dlen];
                sv.read_exact(&mut d).await.unwrap();
                assert_eq!(&d, b"example.com");
                let mut pbuf = [0u8; 2];
                sv.read_exact(&mut pbuf).await.unwrap();
                assert_eq!(u16::from_be_bytes(pbuf), 22);

                sv.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            })
        })
        .await;
        assert!(res.is_ok(), "expected ok, got {res:?}");
    }

    #[tokio::test]
    async fn socks5_auth_rejected_returns_auth_failed() {
        let creds = ProxyCredentials {
            username: "alice".into(),
            password: "bad".into(),
        };
        let res = run_socks5("h", 1, Some(creds), |mut sv| {
            Box::pin(async move {
                let mut hello = [0u8; 4];
                sv.read_exact(&mut hello).await.unwrap();
                sv.write_all(&[0x05, 0x02]).await.unwrap();
                // Read auth attempt then reject.
                let mut head = [0u8; 2];
                sv.read_exact(&mut head).await.unwrap();
                let mut u = vec![0u8; head[1] as usize];
                sv.read_exact(&mut u).await.unwrap();
                let mut plen = [0u8; 1];
                sv.read_exact(&mut plen).await.unwrap();
                let mut p = vec![0u8; plen[0] as usize];
                sv.read_exact(&mut p).await.unwrap();
                sv.write_all(&[0x01, 0x01]).await.unwrap(); // failure
            })
        })
        .await;
        // t8-A1: site was converted to AuthFailedDiagnostic; the spec
        // still requires ExitCode::AuthFailed so we assert at that layer.
        let err = res.unwrap_err();
        assert_eq!(err.exit_code(), spt_core::ExitCode::AuthFailed);
    }

    #[tokio::test]
    async fn socks5_all_methods_rejected_returns_auth_failed() {
        let res = run_socks5("h", 1, None, |mut sv| {
            Box::pin(async move {
                let mut hello = [0u8; 3];
                sv.read_exact(&mut hello).await.unwrap();
                sv.write_all(&[0x05, 0xff]).await.unwrap();
            })
        })
        .await;
        // t8-A1: see above; assert at the stable ExitCode layer.
        let err = res.unwrap_err();
        assert_eq!(err.exit_code(), spt_core::ExitCode::AuthFailed);
    }

    // --- HTTP CONNECT ----------------------------------------------------

    async fn run_http(
        host: &str,
        port: u16,
        creds: Option<ProxyCredentials>,
        server_script: impl FnOnce(
                tokio::io::DuplexStream,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + 'static,
    ) -> Result<()> {
        let (mut client, server) = tokio::io::duplex(8192);
        let s = tokio::spawn(server_script(server));
        let r = http_connect(&mut client, host, port, creds.as_ref()).await;
        s.await.unwrap();
        r
    }

    #[tokio::test]
    async fn http_connect_positive_no_auth() {
        let res = run_http("example.com", 443, None, |mut sv| {
            Box::pin(async move {
                let mut buf = Vec::new();
                let mut one = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    sv.read_exact(&mut one).await.unwrap();
                    buf.push(one[0]);
                }
                let s = String::from_utf8_lossy(&buf);
                assert!(s.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
                assert!(!s.contains("Proxy-Authorization"));
                sv.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
            })
        })
        .await;
        assert!(res.is_ok(), "got {res:?}");
    }

    #[tokio::test]
    async fn http_connect_basic_auth_header_present() {
        let creds = ProxyCredentials {
            username: "u".into(),
            password: "p".into(),
        };
        let res = run_http("h", 1, Some(creds), |mut sv| {
            Box::pin(async move {
                let mut buf = Vec::new();
                let mut one = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    sv.read_exact(&mut one).await.unwrap();
                    buf.push(one[0]);
                }
                let s = String::from_utf8_lossy(&buf);
                // base64("u:p") == "dTpw"
                assert!(
                    s.contains("Proxy-Authorization: Basic dTpw\r\n"),
                    "missing/incorrect Basic header in: {s}"
                );
                sv.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            })
        })
        .await;
        assert!(res.is_ok(), "got {res:?}");
    }

    #[tokio::test]
    async fn http_connect_407_returns_auth_failed() {
        let res = run_http("h", 1, None, |mut sv| {
            Box::pin(async move {
                let mut one = [0u8; 1];
                let mut buf = Vec::new();
                while !buf.ends_with(b"\r\n\r\n") {
                    sv.read_exact(&mut one).await.unwrap();
                    buf.push(one[0]);
                }
                sv.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"x\"\r\n\r\n",
                )
                .await
                .unwrap();
            })
        })
        .await;
        match res.unwrap_err() {
            Error::AuthFailed(msg) => assert!(msg.contains("407"), "got: {msg}"),
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_connect_5xx_returns_runtime_failure() {
        let res = run_http("h", 1, None, |mut sv| {
            Box::pin(async move {
                let mut one = [0u8; 1];
                let mut buf = Vec::new();
                while !buf.ends_with(b"\r\n\r\n") {
                    sv.read_exact(&mut one).await.unwrap();
                    buf.push(one[0]);
                }
                sv.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await
                    .unwrap();
            })
        })
        .await;
        match res.unwrap_err() {
            Error::RuntimeFailure(msg) => assert!(msg.contains("502"), "got: {msg}"),
            other => panic!("expected RuntimeFailure, got {other:?}"),
        }
    }

    // ──────── t8-A1: diagnostic regression tests ──────────────────────

    #[tokio::test]
    async fn socks5_userpass_rejection_renders_structured_diagnostic() {
        let creds = ProxyCredentials {
            username: "alice".into(),
            password: "wrong".into(),
        };
        let res = run_socks5("h", 1, Some(creds), |mut sv| {
            Box::pin(async move {
                let mut hello = [0u8; 4];
                sv.read_exact(&mut hello).await.unwrap();
                sv.write_all(&[0x05, 0x02]).await.unwrap();
                let mut p = [0u8; 13];
                sv.read_exact(&mut p).await.unwrap();
                sv.write_all(&[0x01, 0x01]).await.unwrap();
            })
        })
        .await;
        let err = res.unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "SOCKS5 proxy rejected the supplied username/password",
            why: "0x01",
            how_to_fix: "proxy.credentials",
        );
    }

    #[tokio::test]
    async fn socks5_no_acceptable_methods_renders_structured_diagnostic() {
        let res = run_socks5("h", 1, None, |mut sv| {
            Box::pin(async move {
                let mut hello = [0u8; 3];
                sv.read_exact(&mut hello).await.unwrap();
                sv.write_all(&[0x05, 0xff]).await.unwrap();
            })
        })
        .await;
        let err = res.unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "rejected all advertised auth methods",
            why: "NO_ACCEPTABLE_METHODS",
            how_to_fix: "NO_AUTH and USERNAME/PASSWORD",
        );
    }

    #[tokio::test]
    async fn socks5_demands_userpass_without_creds_renders_diagnostic() {
        // With creds=None the client hello is 3 bytes (VER, NMETHODS=1, NO_AUTH).
        let res = run_socks5("h", 1, None, |mut sv| {
            Box::pin(async move {
                let mut hello = [0u8; 3];
                sv.read_exact(&mut hello).await.unwrap();
                // Server picks USERNAME/PASSWORD despite the client only
                // advertising NO_AUTH — exercises the diagnostic path.
                sv.write_all(&[0x05, 0x02]).await.unwrap();
            })
        })
        .await;
        let err = res.unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "SOCKS5 proxy requires username/password",
            why: "method 0x02",
            how_to_fix: "proxy.credentials.username",
        );
    }
}
