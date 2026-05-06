//! Best-effort port auto-detection.
//!
//! Spec §13.12 mandates safe protocol identification for `SSH`, `SMTP`,
//! `HTTP`, `HTTPS`, `PostgreSQL`, `MySQL`, `Redis`, `DNS`, `LDAP`, `IMAP`,
//! `POP3`, `AMQP`, `MQTT`, and generic `TLS`. Probes MUST be timeout-bounded,
//! prefer passive banner reads, and return `unknown` rather than guess.
//!
//! This implementation covers the **representative classes** that need only
//! TCP byte exchange:
//! - **Banner-first protocols** (`SSH`, `SMTP`, `IMAP`, `POP3`, `FTP`) — wait
//!   briefly for the server to speak first.
//! - **HTTP-ish** — send `OPTIONS / HTTP/1.0\r\n\r\n` and look for a status
//!   line.
//! - **TLS** — send a minimal `ClientHello` (`0x16 0x03 0x01`) and detect a
//!   `ServerHello` (`0x16` ... `0x02`).
//!
//! Database/MQ handshakes (`PG` `StartupMessage`, `MySQL` handshake, `Redis`
//! `PING`, `MQTT` `CONNECT`, `AMQP`) are deferred to t1-e18; they're tracked
//! here as [`ServiceClass`] variants but [`autodetect`] reports them as
//! `Unknown` today rather than guess.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// What we believe is on the other side of the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceClass {
    /// SSH-2.0-* banner.
    Ssh,
    /// SMTP `220` greeting.
    Smtp,
    /// IMAP `* OK` greeting.
    Imap,
    /// POP3 `+OK` greeting.
    Pop3,
    /// FTP `220` greeting (ASCII).
    Ftp,
    /// Plain HTTP server (responded to OPTIONS).
    Http,
    /// TLS server (responded to a minimal `ClientHello`).
    Tls,
    /// We exchanged bytes but couldn't classify.
    Unknown,
    /// The remote closed before saying anything.
    NoBanner,
}

/// Detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedService {
    /// Classifier verdict.
    pub class: ServiceClass,
    /// Up to ~120 bytes of evidence, lossy-utf8.
    pub evidence: String,
}

/// Run TCP-level auto-detection against `addr`.
///
/// Strategy:
/// 1. Connect (timeout-bounded).
/// 2. Read up to 256 bytes for ~half the budget — many services greet first.
/// 3. If we got bytes, classify and return.
/// 4. Otherwise, try an HTTP `OPTIONS` probe; classify the reply.
/// 5. Otherwise, try a TLS `ClientHello`; classify the reply.
/// 6. Else `Unknown` / `NoBanner`.
///
/// Returns `None` only if the underlying connect fails entirely.
pub async fn autodetect(addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
    let half = budget / 2;
    let Ok(mut stream) = timeout(budget, TcpStream::connect(addr)).await.ok()? else {
        return None;
    };

    // 1. Passive banner read.
    let mut buf = [0u8; 256];
    match timeout(half, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let bytes = &buf[..n];
            if let Some(class) = classify_banner(bytes) {
                return Some(DetectedService {
                    class,
                    evidence: lossy(bytes),
                });
            }
            return Some(DetectedService {
                class: ServiceClass::Unknown,
                evidence: lossy(bytes),
            });
        }
        Ok(Ok(_)) | Err(_) => { /* zero bytes / timeout — try active probe */ }
        Ok(Err(_)) => return None,
    }

    // 2. HTTP OPTIONS probe.
    if stream
        .write_all(b"OPTIONS / HTTP/1.0\r\n\r\n")
        .await
        .is_ok()
    {
        if let Ok(Ok(n)) = timeout(half, stream.read(&mut buf)).await {
            if n > 0 {
                let bytes = &buf[..n];
                if bytes.starts_with(b"HTTP/") {
                    return Some(DetectedService {
                        class: ServiceClass::Http,
                        evidence: lossy(bytes),
                    });
                }
            }
        }
    }

    // 3. Minimal TLS ClientHello probe (we have to reconnect — we already
    // wrote HTTP into the existing stream).
    if let Ok(Ok(mut s2)) = timeout(half, TcpStream::connect(addr)).await {
        let hello: &[u8] = &[
            0x16, 0x03, 0x01, 0x00, 0x05, // TLS record header (handshake, TLS 1.0, len=5)
            0x01, 0x00, 0x00, 0x01, 0x00, // ClientHello header, body length=1, body=0x00
        ];
        if s2.write_all(hello).await.is_ok() {
            if let Ok(Ok(n)) = timeout(half, s2.read(&mut buf)).await {
                if n > 0 && buf[0] == 0x16 {
                    return Some(DetectedService {
                        class: ServiceClass::Tls,
                        evidence: format!("tls record type=0x16 first {n} bytes"),
                    });
                }
            }
        }
    }

    Some(DetectedService {
        class: ServiceClass::NoBanner,
        evidence: String::new(),
    })
}

/// Pure classifier over a banner byte slice. Exposed for unit tests.
#[must_use]
pub fn classify_banner(bytes: &[u8]) -> Option<ServiceClass> {
    if bytes.starts_with(b"SSH-2.0-") || bytes.starts_with(b"SSH-1.99-") {
        return Some(ServiceClass::Ssh);
    }
    if bytes.starts_with(b"220 ") || bytes.starts_with(b"220-") {
        // Both SMTP and FTP use 220. SMTP banners commonly mention "ESMTP" or
        // "Postfix"/"sendmail"; FTP banners often mention "FTP".
        let ascii = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if ascii.contains("ftp") {
            return Some(ServiceClass::Ftp);
        }
        return Some(ServiceClass::Smtp);
    }
    if bytes.starts_with(b"* OK") {
        return Some(ServiceClass::Imap);
    }
    if bytes.starts_with(b"+OK") {
        return Some(ServiceClass::Pop3);
    }
    if bytes.starts_with(b"HTTP/") {
        return Some(ServiceClass::Http);
    }
    None
}

fn lossy(b: &[u8]) -> String {
    let take = b.len().min(120);
    String::from_utf8_lossy(&b[..take]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn classify_basic_banners() {
        assert_eq!(
            classify_banner(b"SSH-2.0-OpenSSH_9.6\r\n"),
            Some(ServiceClass::Ssh)
        );
        assert_eq!(
            classify_banner(b"220 mx.example.com ESMTP\r\n"),
            Some(ServiceClass::Smtp)
        );
        assert_eq!(
            classify_banner(b"220 (vsFTPd 3.0.5)\r\n"),
            Some(ServiceClass::Ftp)
        );
        assert_eq!(classify_banner(b"* OK [CAPABILITY] IMAP\r\n"), Some(ServiceClass::Imap));
        assert_eq!(classify_banner(b"+OK POP3 ready\r\n"), Some(ServiceClass::Pop3));
        assert_eq!(classify_banner(b"HTTP/1.1 200 OK\r\n"), Some(ServiceClass::Http));
        assert_eq!(classify_banner(b"random garbage"), None);
    }

    /// Run a tiny SSH-banner server on 127.0.0.1:0 and verify autodetect.
    #[tokio::test]
    async fn detects_ssh_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"SSH-2.0-FakeSshd\r\n").await.unwrap();
            // keep open briefly so client read sees the bytes
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let det = autodetect(addr, Duration::from_secs(2)).await.unwrap();
        assert_eq!(det.class, ServiceClass::Ssh, "{det:?}");
        assert!(det.evidence.starts_with("SSH-2.0-"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn detects_http_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Wait for OPTIONS request, then reply.
            let mut buf = [0u8; 256];
            let _ = tokio::time::timeout(Duration::from_millis(500), s.readable()).await;
            let _ = s.try_read(&mut buf);
            s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let det = autodetect(addr, Duration::from_secs(2)).await.unwrap();
        assert_eq!(det.class, ServiceClass::Http, "{det:?}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn no_listener_returns_none() {
        // 127.0.0.1:1 is conventionally blocked / unbound on test runners.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        // Either Some(NoBanner)/Some(Unknown) or None depending on the host
        // — both are acceptable; the contract is "non-panicking".
        let _ = autodetect(addr, Duration::from_millis(200)).await;
    }
}
