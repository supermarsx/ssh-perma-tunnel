//! SOCKS4, SOCKS4A, SOCKS5, and HTTP CONNECT parsing for SSH2 dynamic forwards.

use spt_core::{Error, Result};
use spt_protocol::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_HTTP_CONNECT_HEADER: usize = 16 * 1024;
const SOCKS4_VERSION: u8 = 0x04;
const SOCKS4_CONNECT: u8 = 0x01;
const SOCKS4_REPLY_VERSION: u8 = 0x00;
const SOCKS4_GRANTED: u8 = 0x5a;
const SOCKS4_REJECTED: u8 = 0x5b;
const MAX_SOCKS4_USER_ID: usize = 1024;
const MAX_SOCKS4_DOMAIN: usize = 255;
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// Client proxy protocol detected on a dynamic forward listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DynamicProxyProtocol {
    /// SOCKS4 CONNECT with an IPv4 target.
    Socks4,
    /// SOCKS4A CONNECT with remote DNS.
    Socks4a,
    /// SOCKS5 CONNECT.
    Socks5,
    /// HTTP/1.x CONNECT.
    HttpConnect,
}

/// Enabled proxy protocols for one dynamic listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DynamicProxyProtocolSet {
    /// Accept SOCKS4 CONNECT requests with IPv4 targets.
    pub(crate) socks4: bool,
    /// Accept SOCKS4A CONNECT requests with remote DNS targets.
    pub(crate) socks4a: bool,
    /// Accept SOCKS5 CONNECT requests.
    pub(crate) socks5: bool,
    /// Accept HTTP CONNECT requests.
    pub(crate) http_connect: bool,
}

/// Parsed client request for one dynamic proxy connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynamicProxyRequest {
    /// Requested remote target.
    pub(crate) target: TargetAddr,
    /// Protocol that carried the request.
    pub(crate) protocol: DynamicProxyProtocol,
}

/// Read and parse one SOCKS4, SOCKS4A, SOCKS5, or HTTP CONNECT request from
/// `sock`.
pub(crate) async fn read_request(
    sock: &mut TcpStream,
    protocols: DynamicProxyProtocolSet,
) -> Result<DynamicProxyRequest> {
    let mut first = [0_u8; 1];
    let n = sock
        .peek(&mut first)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("dynamic proxy peek: {e}")))?;
    if n == 0 {
        return Err(Error::RuntimeFailure(
            "dynamic proxy client closed before handshake".into(),
        ));
    }

    match first[0] {
        SOCKS4_VERSION if protocols.socks4 || protocols.socks4a => read_socks4(sock, protocols).await,
        SOCKS4_VERSION => {
            let _ = write_socks4_reply(sock, false).await;
            Err(Error::UnsupportedPlatform(
                "SOCKS4/SOCKS4A are disabled for this dynamic forward".into(),
            ))
        }
        SOCKS5_VERSION if protocols.socks5 => read_socks5(sock).await,
        SOCKS5_VERSION => Err(Error::UnsupportedPlatform(
            "SOCKS5 is disabled for this dynamic forward".into(),
        )),
        b'C' | b'c' if protocols.http_connect => read_http_connect(sock).await,
        b'C' | b'c' => Err(Error::UnsupportedPlatform(
            "HTTP CONNECT is disabled for this dynamic forward".into(),
        )),
        other => Err(Error::InvalidConfig(format!(
            "dynamic proxy expected SOCKS4/SOCKS4A/SOCKS5 or HTTP CONNECT, got first byte 0x{other:02x}"
        ))),
    }
}

/// Send the success response for the already parsed proxy protocol.
pub(crate) async fn reply_success(
    sock: &mut TcpStream,
    protocol: DynamicProxyProtocol,
) -> Result<()> {
    match protocol {
        DynamicProxyProtocol::Socks4 | DynamicProxyProtocol::Socks4a => {
            write_socks4_reply(sock, true).await?;
        }
        DynamicProxyProtocol::Socks5 => {
            sock.write_all(&[
                SOCKS5_VERSION,
                0x00,
                0x00,
                SOCKS5_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 success reply: {e}")))?;
        }
        DynamicProxyProtocol::HttpConnect => {
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(|e| Error::RuntimeFailure(format!("HTTP CONNECT success reply: {e}")))?;
        }
    }
    Ok(())
}

/// Best-effort failure response before closing a dynamic proxy connection.
pub(crate) async fn reply_failure(
    sock: &mut TcpStream,
    protocol: DynamicProxyProtocol,
) -> Result<()> {
    match protocol {
        DynamicProxyProtocol::Socks4 | DynamicProxyProtocol::Socks4a => {
            write_socks4_reply(sock, false).await?;
        }
        DynamicProxyProtocol::Socks5 => {
            sock.write_all(&[
                SOCKS5_VERSION,
                0x01,
                0x00,
                SOCKS5_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 failure reply: {e}")))?;
        }
        DynamicProxyProtocol::HttpConnect => {
            sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await
                .map_err(|e| Error::RuntimeFailure(format!("HTTP CONNECT failure reply: {e}")))?;
        }
    }
    Ok(())
}

/// Reject a parsed request whose target is forbidden by the destination ACL,
/// using each protocol's "not allowed by ruleset" code where one exists:
///
/// * SOCKS5 → reply code `0x02` ("connection not allowed by ruleset", RFC 1928).
/// * SOCKS4/4A → request rejected (`0x5b`; SOCKS4 has no distinct ACL code).
/// * HTTP CONNECT → `403 Forbidden`.
///
/// Best-effort: write errors are ignored by the caller (the connection is
/// closed regardless).
pub(crate) async fn reply_denied(
    sock: &mut TcpStream,
    protocol: DynamicProxyProtocol,
) -> Result<()> {
    match protocol {
        DynamicProxyProtocol::Socks4 | DynamicProxyProtocol::Socks4a => {
            write_socks4_reply(sock, false).await?;
        }
        DynamicProxyProtocol::Socks5 => {
            sock.write_all(&[
                SOCKS5_VERSION,
                0x02, // connection not allowed by ruleset
                0x00,
                SOCKS5_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 deny reply: {e}")))?;
        }
        DynamicProxyProtocol::HttpConnect => {
            sock.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                .await
                .map_err(|e| Error::RuntimeFailure(format!("HTTP CONNECT deny reply: {e}")))?;
        }
    }
    Ok(())
}

async fn write_socks4_reply(sock: &mut TcpStream, granted: bool) -> Result<()> {
    let status = if granted {
        SOCKS4_GRANTED
    } else {
        SOCKS4_REJECTED
    };
    sock.write_all(&[SOCKS4_REPLY_VERSION, status, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|e| Error::RuntimeFailure(format!("SOCKS4 reply: {e}")))
}

async fn read_socks4(
    sock: &mut TcpStream,
    protocols: DynamicProxyProtocolSet,
) -> Result<DynamicProxyRequest> {
    let mut head = [0_u8; 8];
    sock.read_exact(&mut head)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("SOCKS4 request header: {e}")))?;
    if head[0] != SOCKS4_VERSION {
        return Err(Error::InvalidConfig(
            "SOCKS4 request version mismatch".into(),
        ));
    }
    if head[1] != SOCKS4_CONNECT {
        let _ = write_socks4_reply(sock, false).await;
        return Err(Error::UnsupportedPlatform(
            "SOCKS4 dynamic forward supports CONNECT only".into(),
        ));
    }

    let port = u16::from_be_bytes([head[2], head[3]]);
    if port == 0 {
        let _ = write_socks4_reply(sock, false).await;
        return Err(Error::InvalidConfig(
            "SOCKS4 target port cannot be zero".into(),
        ));
    }
    let octets = [head[4], head[5], head[6], head[7]];
    let _user_id = read_cstring(sock, "SOCKS4 user id", MAX_SOCKS4_USER_ID).await?;

    let socks4a = octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] != 0;
    if socks4a {
        let domain = read_cstring(sock, "SOCKS4A domain", MAX_SOCKS4_DOMAIN).await?;
        if domain.is_empty() {
            let _ = write_socks4_reply(sock, false).await;
            return Err(Error::InvalidConfig(
                "SOCKS4A domain cannot be empty".into(),
            ));
        }
        if !protocols.socks4a {
            let _ = write_socks4_reply(sock, false).await;
            return Err(Error::UnsupportedPlatform(
                "SOCKS4A is disabled for this dynamic forward".into(),
            ));
        }
        let Ok(host) = String::from_utf8(domain) else {
            let _ = write_socks4_reply(sock, false).await;
            return Err(Error::InvalidConfig("SOCKS4A domain is not UTF-8".into()));
        };
        return Ok(DynamicProxyRequest {
            target: TargetAddr::new(host, port),
            protocol: DynamicProxyProtocol::Socks4a,
        });
    }

    if octets == [0, 0, 0, 0] {
        let _ = write_socks4_reply(sock, false).await;
        return Err(Error::InvalidConfig(
            "SOCKS4 IPv4 target cannot be 0.0.0.0".into(),
        ));
    }
    if !protocols.socks4 {
        let _ = write_socks4_reply(sock, false).await;
        return Err(Error::UnsupportedPlatform(
            "SOCKS4 is disabled for this dynamic forward".into(),
        ));
    }

    Ok(DynamicProxyRequest {
        target: TargetAddr::new(std::net::Ipv4Addr::from(octets).to_string(), port),
        protocol: DynamicProxyProtocol::Socks4,
    })
}

async fn read_cstring(sock: &mut TcpStream, label: &str, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let byte = sock
            .read_u8()
            .await
            .map_err(|e| Error::RuntimeFailure(format!("{label}: {e}")))?;
        if byte == 0 {
            return Ok(bytes);
        }
        if bytes.len() >= max {
            return Err(Error::InvalidConfig(format!(
                "{label} exceeded {max} bytes before NUL terminator"
            )));
        }
        bytes.push(byte);
    }
}

async fn read_socks5(sock: &mut TcpStream) -> Result<DynamicProxyRequest> {
    let mut greeting = [0_u8; 2];
    sock.read_exact(&mut greeting)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 greeting: {e}")))?;
    if greeting[0] != SOCKS5_VERSION {
        return Err(Error::InvalidConfig(
            "SOCKS5 greeting version mismatch".into(),
        ));
    }

    let mut methods = vec![0_u8; usize::from(greeting[1])];
    sock.read_exact(&mut methods)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 auth methods: {e}")))?;
    if !methods.contains(&SOCKS5_NO_AUTH) {
        let _ = sock.write_all(&[SOCKS5_VERSION, 0xff]).await;
        return Err(Error::UnsupportedPlatform(
            "SOCKS5 client offered no supported authentication method".into(),
        ));
    }
    sock.write_all(&[SOCKS5_VERSION, SOCKS5_NO_AUTH])
        .await
        .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 method select: {e}")))?;

    let mut head = [0_u8; 4];
    sock.read_exact(&mut head)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 request header: {e}")))?;
    if head[0] != SOCKS5_VERSION {
        return Err(Error::InvalidConfig(
            "SOCKS5 request version mismatch".into(),
        ));
    }
    if head[1] != SOCKS5_CONNECT {
        let _ = sock
            .write_all(&[
                SOCKS5_VERSION,
                0x07,
                0x00,
                SOCKS5_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await;
        return Err(Error::UnsupportedPlatform(
            "SOCKS5 dynamic forward supports CONNECT only".into(),
        ));
    }

    let host = match head[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            sock.read_exact(&mut octets)
                .await
                .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 IPv4 address: {e}")))?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        SOCKS5_ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            sock.read_exact(&mut octets)
                .await
                .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 IPv6 address: {e}")))?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        SOCKS5_ATYP_DOMAIN => {
            let len = sock
                .read_u8()
                .await
                .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 domain length: {e}")))?;
            let mut name = vec![0_u8; usize::from(len)];
            sock.read_exact(&mut name)
                .await
                .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 domain: {e}")))?;
            String::from_utf8(name)
                .map_err(|_| Error::InvalidConfig("SOCKS5 domain is not UTF-8".into()))?
        }
        other => {
            return Err(Error::UnsupportedPlatform(format!(
                "SOCKS5 address type 0x{other:02x} is not supported"
            )));
        }
    };

    let mut port_bytes = [0_u8; 2];
    sock.read_exact(&mut port_bytes)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("SOCKS5 port: {e}")))?;
    let port = u16::from_be_bytes(port_bytes);
    if port == 0 {
        return Err(Error::InvalidConfig(
            "SOCKS5 target port cannot be zero".into(),
        ));
    }

    Ok(DynamicProxyRequest {
        target: TargetAddr::new(host, port),
        protocol: DynamicProxyProtocol::Socks5,
    })
}

async fn read_http_connect(sock: &mut TcpStream) -> Result<DynamicProxyRequest> {
    let mut header = Vec::with_capacity(512);
    loop {
        if header.len() >= MAX_HTTP_CONNECT_HEADER {
            return Err(Error::InvalidConfig(format!(
                "HTTP CONNECT header exceeded {MAX_HTTP_CONNECT_HEADER} bytes"
            )));
        }
        let byte = sock
            .read_u8()
            .await
            .map_err(|e| Error::RuntimeFailure(format!("HTTP CONNECT header: {e}")))?;
        header.push(byte);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let text = std::str::from_utf8(&header)
        .map_err(|_| Error::InvalidConfig("HTTP CONNECT header is not UTF-8".into()))?;
    let line = text
        .lines()
        .next()
        .ok_or_else(|| Error::InvalidConfig("HTTP CONNECT request line missing".into()))?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let authority = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(Error::InvalidConfig(format!(
            "dynamic HTTP proxy expected CONNECT, got `{method}`"
        )));
    }
    if authority.is_empty() || !version.starts_with("HTTP/") {
        return Err(Error::InvalidConfig(
            "malformed HTTP CONNECT request line".into(),
        ));
    }
    let target = parse_authority(authority)?;
    Ok(DynamicProxyRequest {
        target,
        protocol: DynamicProxyProtocol::HttpConnect,
    })
}

fn parse_authority(authority: &str) -> Result<TargetAddr> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| Error::InvalidConfig("IPv6 CONNECT authority missing `]`".into()))?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| Error::InvalidConfig("IPv6 CONNECT authority missing port".into()))?;
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .ok_or_else(|| Error::InvalidConfig("CONNECT authority must be `host:port`".into()))?
    };
    if host.is_empty() {
        return Err(Error::InvalidConfig("CONNECT host cannot be empty".into()));
    }
    let port = port
        .parse::<u16>()
        .map_err(|e| Error::InvalidConfig(format!("CONNECT port `{port}`: {e}")))?;
    if port == 0 {
        return Err(Error::InvalidConfig("CONNECT port cannot be zero".into()));
    }
    Ok(TargetAddr::new(host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    fn all_protocols() -> DynamicProxyProtocolSet {
        DynamicProxyProtocolSet {
            socks4: true,
            socks4a: true,
            socks5: true,
            http_connect: true,
        }
    }

    #[tokio::test]
    async fn parses_http_connect_target_and_replies() {
        let (mut client, mut server) = loopback_pair().await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();

        let request = read_request(&mut server, all_protocols()).await.unwrap();
        assert_eq!(request.protocol, DynamicProxyProtocol::HttpConnect);
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 443);
        reply_success(&mut server, request.protocol).await.unwrap();

        let mut response = vec![0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    }

    #[tokio::test]
    async fn parses_socks5_domain_target_and_replies() {
        let (mut client, mut server) = loopback_pair().await;
        client
            .write_all(&[
                0x05, 0x01, 0x00, // greeting: no auth
                0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .await
            .unwrap();

        let request = read_request(&mut server, all_protocols()).await.unwrap();
        assert_eq!(request.protocol, DynamicProxyProtocol::Socks5);
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 443);
        reply_success(&mut server, request.protocol).await.unwrap();

        let mut response = [0_u8; 12];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..2], &[0x05, 0x00]);
        assert_eq!(&response[2..], &[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn parses_socks4_ipv4_target_and_replies() {
        let (mut client, mut server) = loopback_pair().await;
        client
            .write_all(&[
                0x04, 0x01, 0x01, 0xbb, 192, 0, 2, 10, b'u', b's', b'e', b'r', 0x00,
            ])
            .await
            .unwrap();

        let request = read_request(&mut server, all_protocols()).await.unwrap();
        assert_eq!(request.protocol, DynamicProxyProtocol::Socks4);
        assert_eq!(request.target.host, "192.0.2.10");
        assert_eq!(request.target.port, 443);
        reply_success(&mut server, request.protocol).await.unwrap();

        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x00, 0x5a, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn parses_socks4a_domain_target_and_replies() {
        let (mut client, mut server) = loopback_pair().await;
        client
            .write_all(&[
                0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0x00, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
                b'.', b'c', b'o', b'm', 0x00,
            ])
            .await
            .unwrap();

        let request = read_request(&mut server, all_protocols()).await.unwrap();
        assert_eq!(request.protocol, DynamicProxyProtocol::Socks4a);
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 80);
        reply_success(&mut server, request.protocol).await.unwrap();

        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x00, 0x5a, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn rejects_disabled_socks4a_after_parsing_domain() {
        let (mut client, mut server) = loopback_pair().await;
        client
            .write_all(&[0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0x00, b'e', b'x', 0x00])
            .await
            .unwrap();

        let err = read_request(
            &mut server,
            DynamicProxyProtocolSet {
                socks4: true,
                socks4a: false,
                socks5: true,
                http_connect: true,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));

        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x00, 0x5b, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn parses_ipv6_http_authority() {
        let target = parse_authority("[2001:db8::1]:8443").unwrap();
        assert_eq!(target.host, "2001:db8::1");
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn rejects_authority_without_port() {
        assert!(matches!(
            parse_authority("example.com"),
            Err(Error::InvalidConfig(_))
        ));
    }
}
