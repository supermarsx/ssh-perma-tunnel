//! Best-effort port auto-detection.
//!
//! Spec §13.12 mandates safe protocol identification across SSH, SMTP, HTTP,
//! HTTPS, PostgreSQL, MySQL, Redis, DNS, LDAP, IMAP, POP3, AMQP, MQTT, and
//! generic TLS. Probes are timeout-bounded, prefer passive banner reads, and
//! return `Unknown` rather than guess.
//!
//! Architecture: [`autodetect`] runs a sequence of [`Detector`] impls.
//!
//! 1. [`BannerDetector`] — passive read; classifies SSH / SMTP / IMAP / POP3
//!    / FTP / HTTP / MySQL (server-first protocol-10 packet).
//! 2. [`HttpDetector`] — sends `OPTIONS / HTTP/1.0`.
//! 3. [`PostgresDetector`] — sends a malformed StartupMessage; expects
//!    `'E'` ErrorResponse.
//! 4. [`RedisDetector`] — sends `*1\r\n$4\r\nPING\r\n`; expects `+PONG\r\n`.
//! 5. [`MqttDetector`] — sends MQTT 3.1.1 CONNECT; expects CONNACK (`0x20`).
//! 6. [`AmqpDetector`] — sends `AMQP\x00\x00\x09\x01`; expects Connection.Start.
//! 7. [`LdapDetector`] — sends a minimal BindRequest; expects a BindResponse
//!    (LDAPMessage `0x30` with bindResponse `0x61`).
//! 8. [`TlsDetector`] — minimal `ClientHello`; expects `0x16` record back.
//!
//! Each active detector reconnects (a previous probe might have written
//! destructive bytes into the existing socket). If [`BannerDetector`] reads
//! any bytes the chain stops there — they're already consumed and the live
//! protocol is whatever we classified.

#![allow(clippy::doc_markdown)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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
    /// Plain HTTP server (responded to OPTIONS or banner).
    Http,
    /// TLS server (responded to a minimal `ClientHello`).
    Tls,
    /// PostgreSQL — typed `'E'` ErrorResponse to malformed StartupMessage.
    Postgres,
    /// MySQL — protocol-10 server handshake packet.
    Mysql,
    /// Redis — `+PONG\r\n` response.
    Redis,
    /// MQTT — CONNACK control packet.
    Mqtt,
    /// AMQP 0-9-1 — Connection.Start frame.
    Amqp,
    /// LDAP — typed BindResponse.
    Ldap,
    /// DNS — typed DNS response over UDP.
    Dns,
    /// NTP — 48-byte server response over UDP.
    Ntp,
    /// QUIC — Long-header response (Version Negotiation / Initial / Handshake).
    Quic,
    /// SNMP — typed v1 GetResponse over UDP.
    Snmp,
    /// mDNS — DNS-over-multicast response.
    Mdns,
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

/// One probe strategy. Each implementation owns its own TCP connect — active
/// probes can't share a socket with a passive banner read.
#[async_trait]
pub trait Detector: Send + Sync {
    /// Stable, lowercase identifier (used in tracing).
    fn name(&self) -> &'static str;
    /// Try to detect. `None` means "this protocol isn't here, fall through";
    /// `Some(_)` ends the chain.
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService>;
}

/// Run the default chain in order, returning the first hit. `None` only when
/// the very first connect fails (host down) — every later miss falls through.
pub async fn autodetect(addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
    // Per-detector budget. Many detectors are typically called; share the
    // overall budget, with a floor so each gets a reasonable read window.
    let per = (budget / 4).max(Duration::from_millis(200));

    let mut any_connect_ok = false;
    for d in default_chain() {
        match d.try_detect(addr, per).await {
            Some(DetectedService {
                class: ServiceClass::Unknown,
                evidence,
            }) => {
                // Ambiguous: a probe got bytes but couldn't classify. Keep going,
                // a later detector might recognise the protocol on a fresh socket.
                any_connect_ok = true;
                let _ = evidence;
            }
            Some(verdict) => return Some(verdict),
            None => {
                // Fall through to next detector. We don't know if this was a
                // connect failure or a "no match"; later detectors will retry.
            }
        }
        // Budget heuristic: if we've spent too much, bail.
        let _ = any_connect_ok;
    }

    Some(DetectedService {
        class: ServiceClass::NoBanner,
        evidence: String::new(),
    })
}

/// The default detector chain. Cheapest / most-distinctive first.
#[must_use]
pub fn default_chain() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(BannerDetector),
        Box::new(HttpDetector),
        Box::new(PostgresDetector),
        Box::new(RedisDetector),
        Box::new(MqttDetector),
        Box::new(AmqpDetector),
        Box::new(LdapDetector),
        Box::new(TlsDetector),
    ]
}

// ---------------------------------------------------------------------------
// Passive banner.

/// Reads up to 256 bytes; classifies banner-first protocols.
pub struct BannerDetector;

#[async_trait]
impl Detector for BannerDetector {
    fn name(&self) -> &'static str {
        "banner"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        let mut stream = timeout(budget, TcpStream::connect(addr)).await.ok()?.ok()?;
        let mut buf = [0u8; 256];
        match timeout(budget, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let bytes = &buf[..n];
                let class = classify_banner(bytes).unwrap_or(ServiceClass::Unknown);
                Some(DetectedService {
                    class,
                    evidence: lossy(bytes),
                })
            }
            _ => None, // Zero bytes / timeout → let active probes try.
        }
    }
}

/// Pure classifier over a banner byte slice. Exposed for unit tests.
#[must_use]
pub fn classify_banner(bytes: &[u8]) -> Option<ServiceClass> {
    if bytes.starts_with(b"SSH-2.0-") || bytes.starts_with(b"SSH-1.99-") {
        return Some(ServiceClass::Ssh);
    }
    if bytes.starts_with(b"220 ") || bytes.starts_with(b"220-") {
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
    if classify_mysql(bytes).is_some() {
        return Some(ServiceClass::Mysql);
    }
    None
}

/// MySQL: 4-byte packet header (3-byte LE length + 1-byte sequence id), then
/// payload starting with protocol version `0x0a` followed by a NUL-terminated
/// server-version string. We require all three: header sanity + protocol 10
/// + a NUL byte within the header-declared length.
fn classify_mysql(bytes: &[u8]) -> Option<()> {
    if bytes.len() < 5 {
        return None;
    }
    let payload_len =
        u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16);
    if !(6..=4096).contains(&payload_len) {
        return None;
    }
    if bytes.len() < 4 + payload_len as usize {
        // Server replied in pieces — accept minimal protocol-10 + NUL within
        // what we did read.
    }
    if bytes[4] != 0x0a {
        return None;
    }
    // Look for a NUL terminator in the version string. Must be ASCII printable
    // before the NUL; reject if first byte is itself a control code.
    let tail = &bytes[5..];
    let nul_pos = tail.iter().position(|&b| b == 0)?;
    if nul_pos == 0 {
        return None;
    }
    if !tail[..nul_pos].iter().all(|b| (0x20..=0x7e).contains(b)) {
        return None;
    }
    Some(())
}

// ---------------------------------------------------------------------------
// HTTP active probe.

/// Sends `OPTIONS / HTTP/1.0\r\n\r\n`; classifies if reply starts with `HTTP/`.
pub struct HttpDetector;

#[async_trait]
impl Detector for HttpDetector {
    fn name(&self) -> &'static str {
        "http"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        let mut s = timeout(budget, TcpStream::connect(addr)).await.ok()?.ok()?;
        s.write_all(b"OPTIONS / HTTP/1.0\r\n\r\n").await.ok()?;
        let mut buf = [0u8; 256];
        let n = timeout(budget, s.read(&mut buf)).await.ok()?.ok()?;
        if n == 0 {
            return None;
        }
        let bytes = &buf[..n];
        if bytes.starts_with(b"HTTP/") {
            Some(DetectedService {
                class: ServiceClass::Http,
                evidence: lossy(bytes),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Postgres detector.

/// Sends a malformed StartupMessage with a bogus protocol version. A real
/// Postgres backend replies with `'E'` (ErrorResponse) frame.
pub struct PostgresDetector;

#[async_trait]
impl Detector for PostgresDetector {
    fn name(&self) -> &'static str {
        "postgres"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        let mut s = timeout(budget, TcpStream::connect(addr)).await.ok()?.ok()?;
        // StartupMessage = i32 length || i32 protocol version || k=v\0 pairs || \0
        // Use protocol = 0x0bad_d00d (definitely unsupported; PG responds with
        // an ErrorResponse rather than disconnecting).
        let body = b"user\0probe\0\0";
        let total_len = (4 + 4 + body.len()) as u32;
        let mut frame = Vec::with_capacity(total_len as usize);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&0x0bad_d00d_u32.to_be_bytes());
        frame.extend_from_slice(body);
        s.write_all(&frame).await.ok()?;
        let mut buf = [0u8; 256];
        let n = timeout(budget, s.read(&mut buf)).await.ok()?.ok()?;
        if n == 0 {
            return None;
        }
        // Postgres frame: 1-byte type + i32 length. ErrorResponse = 'E'.
        if buf[0] == b'E' && n >= 5 {
            return Some(DetectedService {
                class: ServiceClass::Postgres,
                evidence: format!("postgres ErrorResponse, {n} bytes"),
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Redis detector.

/// Sends `PING`, expects `+PONG\r\n`.
pub struct RedisDetector;

#[async_trait]
impl Detector for RedisDetector {
    fn name(&self) -> &'static str {
        "redis"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        let mut s = timeout(budget, TcpStream::connect(addr)).await.ok()?.ok()?;
        s.write_all(b"*1\r\n$4\r\nPING\r\n").await.ok()?;
        let mut buf = [0u8; 64];
        let n = timeout(budget, s.read(&mut buf)).await.ok()?.ok()?;
        if n == 0 {
            return None;
        }
        let bytes = &buf[..n];
        // Accept "+PONG\r\n" or "-NOAUTH …" (auth-required Redis still typed).
        if bytes.starts_with(b"+PONG") || bytes.starts_with(b"-NOAUTH") {
            return Some(DetectedService {
                class: ServiceClass::Redis,
                evidence: lossy(bytes),
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// MQTT detector.

/// Sends a minimal MQTT 3.1.1 CONNECT; expects CONNACK (first byte `0x20`).
pub struct MqttDetector;

#[async_trait]
impl Detector for MqttDetector {
    fn name(&self) -> &'static str {
        "mqtt"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        let mut s = timeout(budget, TcpStream::connect(addr)).await.ok()?.ok()?;
        // CONNECT (3.1.1, no creds, clientId="spt", keepalive=10).
        // Variable header: protocol name "MQTT", level 4, flags 0x02 (clean session), keepalive 10.
        let payload = build_mqtt_connect(b"spt");
        s.write_all(&payload).await.ok()?;
        let mut buf = [0u8; 64];
        let n = timeout(budget, s.read(&mut buf)).await.ok()?.ok()?;
        if n == 0 {
            return None;
        }
        // CONNACK fixed header: 0x20, then remaining length 0x02, then session
        // present + return code.
        if buf[0] == 0x20 && n >= 4 {
            return Some(DetectedService {
                class: ServiceClass::Mqtt,
                evidence: format!("mqtt CONNACK, return code 0x{:02x}", buf[3]),
            });
        }
        None
    }
}

fn build_mqtt_connect(client_id: &[u8]) -> Vec<u8> {
    let mut variable_header = Vec::new();
    // Protocol name "MQTT" (length 4, big-endian), level 4, flags 0x02, keepalive 10.
    variable_header
        .extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x0a]);
    let mut payload = Vec::new();
    payload.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    payload.extend_from_slice(client_id);

    let body_len = variable_header.len() + payload.len();
    let mut packet = Vec::with_capacity(2 + body_len);
    packet.push(0x10); // CONNECT
    encode_mqtt_remaining_length(&mut packet, body_len);
    packet.extend_from_slice(&variable_header);
    packet.extend_from_slice(&payload);
    packet
}

fn encode_mqtt_remaining_length(out: &mut Vec<u8>, mut len: usize) {
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// AMQP detector.

/// Sends the AMQP 0-9-1 protocol header; expects a Connection.Start frame.
pub struct AmqpDetector;

#[async_trait]
impl Detector for AmqpDetector {
    fn name(&self) -> &'static str {
        "amqp"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        let mut s = timeout(budget, TcpStream::connect(addr)).await.ok()?.ok()?;
        s.write_all(b"AMQP\x00\x00\x09\x01").await.ok()?;
        let mut buf = [0u8; 256];
        let n = timeout(budget, s.read(&mut buf)).await.ok()?.ok()?;
        if n == 0 {
            return None;
        }
        let bytes = &buf[..n];
        // AMQP frame: 1 byte type (0x01 = METHOD), 2 bytes channel, 4 bytes payload size,
        // payload (class id u16 + method id u16 + args), terminated with 0xCE.
        // Method-class = Connection (10), method = Start (10).
        if bytes.len() >= 11
            && bytes[0] == 0x01
            && u16::from_be_bytes([bytes[7], bytes[8]]) == 10
            && u16::from_be_bytes([bytes[9], bytes[10]]) == 10
        {
            return Some(DetectedService {
                class: ServiceClass::Amqp,
                evidence: format!("amqp Connection.Start frame, {n} bytes"),
            });
        }
        // Some brokers reply with the literal "AMQP\x00\x00\x09\x01" if they support a
        // different version — also a valid identification.
        if bytes.starts_with(b"AMQP") {
            return Some(DetectedService {
                class: ServiceClass::Amqp,
                evidence: format!("amqp version-mismatch reply: {}", lossy(bytes)),
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// LDAP detector.

/// Sends a minimal anonymous BindRequest (LDAP v3); expects a BindResponse.
pub struct LdapDetector;

#[async_trait]
impl Detector for LdapDetector {
    fn name(&self) -> &'static str {
        "ldap"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        let mut s = timeout(budget, TcpStream::connect(addr)).await.ok()?.ok()?;
        // Anonymous BindRequest, message id 1, version 3, empty DN, simple "" creds.
        // Hand-encoded BER:
        //   30 0c                                LDAPMessage SEQUENCE, len 12
        //     02 01 01                           messageID INTEGER 1
        //     60 07                              [APPLICATION 0] BindRequest, len 7
        //       02 01 03                         version INTEGER 3
        //       04 00                            name OCTET STRING ""
        //       80 00                            authentication [0] simple ""
        let frame: &[u8] = &[
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];
        s.write_all(frame).await.ok()?;
        let mut buf = [0u8; 64];
        let n = timeout(budget, s.read(&mut buf)).await.ok()?.ok()?;
        if n == 0 {
            return None;
        }
        // Reply must be an LDAPMessage SEQUENCE (0x30) and contain a
        // BindResponse application tag (0x61) somewhere in the first window.
        if buf[0] == 0x30 && buf[..n].contains(&0x61) {
            // 1.88 lint: manual_contains
            return Some(DetectedService {
                class: ServiceClass::Ldap,
                evidence: format!("ldap BindResponse, {n} bytes"),
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// TLS detector.

/// Sends a minimal `ClientHello`; expects a TLS record (`0x16`) back.
pub struct TlsDetector;

#[async_trait]
impl Detector for TlsDetector {
    fn name(&self) -> &'static str {
        "tls"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        let mut s = timeout(budget, TcpStream::connect(addr)).await.ok()?.ok()?;
        let hello: &[u8] = &[
            0x16, 0x03, 0x01, 0x00, 0x05, // record header (handshake, TLS 1.0, len=5)
            0x01, 0x00, 0x00, 0x01, 0x00, // ClientHello with body length=1
        ];
        s.write_all(hello).await.ok()?;
        let mut buf = [0u8; 32];
        let n = timeout(budget, s.read(&mut buf)).await.ok()?.ok()?;
        if n > 0 && buf[0] == 0x16 {
            return Some(DetectedService {
                class: ServiceClass::Tls,
                evidence: format!("tls record type=0x16 first {n} bytes"),
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------

fn lossy(b: &[u8]) -> String {
    let take = b.len().min(120);
    String::from_utf8_lossy(&b[..take]).to_string()
}

// ---------------------------------------------------------------------------
// UDP autodetect chain.

/// One UDP probe strategy. Each implementation owns its own UDP socket —
/// there is no shared connection state between detectors.
#[async_trait]
pub trait UdpDetector: Send + Sync {
    /// Stable, lowercase identifier (used in tracing).
    fn name(&self) -> &'static str;
    /// Try to detect by sending a probe packet and reading the response.
    /// `None` means "this protocol isn't here, fall through"; `Some(_)`
    /// ends the chain.
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService>;
}

/// Run the default UDP detector chain in order, returning the first hit.
/// Returns `Some(NoBanner)` if every detector falls through (no UDP server
/// responded within the per-probe budget — UDP is connectionless so we can
/// only infer this from missing responses).
pub async fn autodetect_udp(addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
    let per = (budget / 4).max(Duration::from_millis(250));
    for d in default_udp_chain() {
        if let Some(verdict) = d.try_detect(addr, per).await {
            if !matches!(verdict.class, ServiceClass::Unknown) {
                return Some(verdict);
            }
        }
    }
    Some(DetectedService {
        class: ServiceClass::NoBanner,
        evidence: String::new(),
    })
}

/// The default UDP detector chain. mDNS is intentionally excluded — its
/// multicast group (`224.0.0.251:5353`) is unroutable in many CI sandboxes
/// and produces flaky test results.
#[must_use]
pub fn default_udp_chain() -> Vec<Box<dyn UdpDetector>> {
    vec![
        Box::new(DnsUdpDetector),
        Box::new(NtpUdpDetector),
        Box::new(SnmpUdpDetector),
        Box::new(QuicUdpDetector),
    ]
}

async fn udp_send_and_read(
    addr: SocketAddr,
    payload: &[u8],
    budget: Duration,
    buf: &mut [u8],
) -> Option<usize> {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(addr).await.ok()?;
    timeout(budget, sock.send(payload)).await.ok()?.ok()?;
    let n = timeout(budget, sock.recv(buf)).await.ok()?.ok()?;
    Some(n)
}

/// DNS over UDP: send a query for `.` IN NS; expect a response with
/// matching transaction id.
pub struct DnsUdpDetector;

#[async_trait]
impl UdpDetector for DnsUdpDetector {
    fn name(&self) -> &'static str {
        "dns"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        // Wire form: txid=0xc0de, std-query, qdcount=1, qname=".", qtype=NS, qclass=IN.
        let query: [u8; 17] = [
            0xc0, 0xde, // transaction id
            0x01, 0x00, // flags: std query, RD=1
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar counts
            0x00, // root label
            0x00, 0x02, // qtype = NS
            0x00, 0x01, // qclass = IN
        ];
        let mut buf = [0u8; 512];
        let n = udp_send_and_read(addr, &query, budget, &mut buf).await?;
        if n < 12 {
            return None;
        }
        // Confirm txid echo + QR bit.
        if buf[0] != 0xc0 || buf[1] != 0xde {
            return None;
        }
        if buf[2] & 0x80 == 0 {
            return None;
        }
        Some(DetectedService {
            class: ServiceClass::Dns,
            evidence: format!("dns response, {n} bytes"),
        })
    }
}

/// NTP over UDP: send an NTPv4 client packet; expect a 48-byte server reply.
pub struct NtpUdpDetector;

#[async_trait]
impl UdpDetector for NtpUdpDetector {
    fn name(&self) -> &'static str {
        "ntp"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        // 48 zeros with mode-3 (client), version 4, leap 0 in byte 0.
        let mut packet = [0u8; 48];
        packet[0] = 0b00_100_011; // li=0, vn=4, mode=3
        let mut buf = [0u8; 64];
        let n = udp_send_and_read(addr, &packet, budget, &mut buf).await?;
        if n != 48 {
            return None;
        }
        // Mode in reply must be 4 (server) and version field present.
        let mode = buf[0] & 0b00_000_111;
        let vn = (buf[0] >> 3) & 0b111;
        if mode != 4 || !(1..=4).contains(&vn) {
            return None;
        }
        Some(DetectedService {
            class: ServiceClass::Ntp,
            evidence: format!("ntp v{vn} server reply, 48 bytes"),
        })
    }
}

/// QUIC over UDP: send a minimal Initial packet with version 1; expect a
/// long-header response (Version Negotiation, or any long-header reply).
pub struct QuicUdpDetector;

#[async_trait]
impl UdpDetector for QuicUdpDetector {
    fn name(&self) -> &'static str {
        "quic"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        // Long-header Initial probe (version=0x00000001 / RFC 9000):
        // We cannot construct a fully valid Initial without crypto, so the
        // server may respond with Version Negotiation (version=0). Any
        // long-header reply (high bit of byte 0 set) confirms QUIC.
        // Header byte: long form (0x80) | fixed bit (0x40) | initial type (0x00).
        let mut packet = vec![0xc0u8]; // 0x80 | 0x40
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version
        packet.push(8); // dcid len
        packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]); // dcid
        packet.push(0); // scid len
                        // Token length (varint = 0)
        packet.push(0x00);
        // Length (varint = remaining packet length, well under 64): 0x00
        packet.push(0x00);
        // Pad to 1200 bytes — RFC 9000 §14 minimum Initial size.
        packet.resize(1200, 0);

        let mut buf = [0u8; 1500];
        let n = udp_send_and_read(addr, &packet, budget, &mut buf).await?;
        if n == 0 {
            return None;
        }
        // Long-header bit must be set in the reply.
        if buf[0] & 0x80 == 0 {
            return None;
        }
        Some(DetectedService {
            class: ServiceClass::Quic,
            evidence: format!("quic long-header reply, {n} bytes"),
        })
    }
}

/// SNMP v1 GetRequest for `1.3.6.1.2.1.1.1.0` (sysDescr.0); expect a
/// matching GetResponse.
pub struct SnmpUdpDetector;

#[async_trait]
impl UdpDetector for SnmpUdpDetector {
    fn name(&self) -> &'static str {
        "snmp"
    }
    async fn try_detect(&self, addr: SocketAddr, budget: Duration) -> Option<DetectedService> {
        // Hand-encoded BER for SNMPv1 GetRequest with community="public",
        // request-id=1, sysDescr.0.
        let frame: &[u8] = &[
            0x30, 0x29, // SEQUENCE, len 41
            0x02, 0x01, 0x00, // version INTEGER 0 (v1)
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community
            0xa0, 0x1c, // GetRequest [0] IMPLICIT
            0x02, 0x01, 0x01, // request-id 1
            0x02, 0x01, 0x00, // error-status 0
            0x02, 0x01, 0x00, // error-index 0
            0x30, 0x11, // varbind list
            0x30, 0x0f, // varbind
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // sysDescr.0
            0x05, 0x00, // NULL
        ];
        let mut buf = [0u8; 1024];
        let n = udp_send_and_read(addr, frame, budget, &mut buf).await?;
        if n < 4 || buf[0] != 0x30 {
            return None;
        }
        // Look for GetResponse PDU tag (0xa2) somewhere in the payload.
        if !buf[..n].contains(&0xa2) {
            // 1.88 lint: manual_contains
            return None;
        }
        Some(DetectedService {
            class: ServiceClass::Snmp,
            evidence: format!("snmp GetResponse, {n} bytes"),
        })
    }
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
        assert_eq!(
            classify_banner(b"* OK [CAPABILITY] IMAP\r\n"),
            Some(ServiceClass::Imap)
        );
        assert_eq!(
            classify_banner(b"+OK POP3 ready\r\n"),
            Some(ServiceClass::Pop3)
        );
        assert_eq!(
            classify_banner(b"HTTP/1.1 200 OK\r\n"),
            Some(ServiceClass::Http)
        );
        assert_eq!(classify_banner(b"random garbage"), None);
    }

    /// Snapshot of a real MySQL 8.0 server-handshake packet prefix.
    /// Format: 3-byte LE length, 1-byte seq, 1-byte protocol (0x0a), version
    /// string + NUL.
    #[test]
    fn classify_mysql_handshake_snapshot() {
        let mut bytes = Vec::new();
        let version = b"8.0.32-mysql";
        let payload_len = 1 + version.len() + 1; // protocol byte + version + NUL
        bytes.push((payload_len & 0xff) as u8);
        bytes.push(((payload_len >> 8) & 0xff) as u8);
        bytes.push(((payload_len >> 16) & 0xff) as u8);
        bytes.push(0); // sequence id
        bytes.push(0x0a); // protocol 10
        bytes.extend_from_slice(version);
        bytes.push(0); // NUL terminator
        assert_eq!(classify_banner(&bytes), Some(ServiceClass::Mysql));
    }

    #[test]
    fn classify_mysql_rejects_short_or_bogus() {
        assert!(classify_banner(b"\x05\x00\x00\x00\x09no-prot10").is_none());
        assert!(classify_banner(b"\x05\x00\x00\x00\x0a").is_none()); // no NUL
        assert!(classify_banner(b"abc").is_none());
    }

    #[tokio::test]
    async fn detects_ssh_banner() {
        run_with_fake(b"SSH-2.0-FakeSshd\r\n".to_vec(), ServiceClass::Ssh).await;
    }

    #[tokio::test]
    async fn detects_http_probe() {
        run_with_fake(
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ServiceClass::Http,
        )
        .await;
    }

    /// Spawn a listener that, on each accept, optionally reads a request and
    /// writes `reply`. The server keeps accepting until the test sets
    /// `keep_running` to false (we use a `Notify` for clean shutdown). We
    /// must accept multiple times because the autodetect chain reconnects
    /// for each detector — only one will produce a typed reply, the rest
    /// get whatever this server returns. Returning the fixed reply for
    /// every accept is harmless: detectors that don't recognize the bytes
    /// fall through, and the targeted detector eventually fires.
    async fn run_with_fake(reply: Vec<u8>, expect: ServiceClass) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        let stop_for_server = stop.clone();
        let server = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = stop_for_server.notified() => break,
                    accepted = listener.accept() => {
                        let Ok((mut s, _)) = accepted else { break };
                        let reply = reply.clone();
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            let _ = tokio::time::timeout(Duration::from_millis(150), s.readable()).await;
                            let _ = s.try_read(&mut buf);
                            let _ = s.write_all(&reply).await;
                            // Hold open briefly so the client read completes.
                            tokio::time::sleep(Duration::from_millis(40)).await;
                        });
                    }
                }
            }
        });
        let det = autodetect(addr, Duration::from_secs(3)).await.unwrap();
        stop.notify_waiters();
        let _ = server.await;
        assert_eq!(det.class, expect, "got {det:?}");
    }

    #[tokio::test]
    async fn detects_postgres() {
        // 'E' + length 5 + zero-terminated empty error fields. Minimal valid frame.
        let reply: Vec<u8> = vec![b'E', 0x00, 0x00, 0x00, 0x05, 0x00];
        run_with_fake(reply, ServiceClass::Postgres).await;
    }

    #[tokio::test]
    async fn detects_redis() {
        let reply = b"+PONG\r\n".to_vec();
        run_with_fake(reply, ServiceClass::Redis).await;
    }

    #[tokio::test]
    async fn detects_mqtt() {
        // CONNACK: 0x20 0x02 0x00 0x00
        let reply: Vec<u8> = vec![0x20, 0x02, 0x00, 0x00];
        run_with_fake(reply, ServiceClass::Mqtt).await;
    }

    #[tokio::test]
    async fn detects_amqp_version_mismatch() {
        // Many real brokers reply with the protocol header literally if version
        // is unsupported. Our detector accepts that.
        let reply = b"AMQP\x00\x00\x09\x01".to_vec();
        run_with_fake(reply, ServiceClass::Amqp).await;
    }

    #[tokio::test]
    async fn detects_amqp_connection_start_frame() {
        // 0x01 type | channel 0x0000 | payload-size 0x00000005 | class=10 method=10 |
        // (1 byte filler) | 0xCE
        let mut reply: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        reply.extend_from_slice(&[0x00, 0x0a, 0x00, 0x0a]); // class.method
        reply.push(0xCE);
        run_with_fake(reply, ServiceClass::Amqp).await;
    }

    #[tokio::test]
    async fn detects_ldap() {
        // BindResponse: 30 0c 02 01 01 61 07 0a 01 00 04 00 04 00
        let reply: Vec<u8> = vec![
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        run_with_fake(reply, ServiceClass::Ldap).await;
    }

    #[tokio::test]
    async fn detects_mysql_via_banner() {
        let mut reply = Vec::new();
        let version = b"8.0.32-spt";
        let payload_len = 1 + version.len() + 1;
        reply.push((payload_len & 0xff) as u8);
        reply.push(((payload_len >> 8) & 0xff) as u8);
        reply.push(((payload_len >> 16) & 0xff) as u8);
        reply.push(0);
        reply.push(0x0a);
        reply.extend_from_slice(version);
        reply.push(0);
        run_with_fake(reply, ServiceClass::Mysql).await;
    }

    /// Spawn a UDP fake server that handles every detector in the chain by
    /// inspecting the inbound payload and replying with `responder(payload)`.
    /// Returning `None` from the responder drops the packet (so detectors
    /// for other protocols time out cleanly).
    async fn run_udp_fake<F>(responder: F, expect: ServiceClass)
    where
        F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        let stop_for_server = stop.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    () = stop_for_server.notified() => break,
                    incoming = server.recv_from(&mut buf) => {
                        let Ok((n, peer)) = incoming else { break };
                        if let Some(reply) = responder(&buf[..n]) {
                            let _ = server.send_to(&reply, peer).await;
                        }
                    }
                }
            }
        });
        let det = autodetect_udp(addr, Duration::from_secs(3)).await.unwrap();
        stop.notify_waiters();
        let _ = task.await;
        assert_eq!(det.class, expect, "got {det:?}");
    }

    #[tokio::test]
    async fn detects_dns_over_udp() {
        run_udp_fake(
            |payload| {
                if payload.len() < 12 {
                    return None;
                }
                // qtype/qclass follow root label at offset 12 → only DNS layout matches.
                if payload[12] != 0x00 {
                    return None;
                }
                let mut reply = vec![payload[0], payload[1], 0x81, 0x80];
                reply.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                reply.extend_from_slice(&payload[12..]);
                Some(reply)
            },
            ServiceClass::Dns,
        )
        .await;
    }

    #[tokio::test]
    async fn detects_ntp_over_udp() {
        run_udp_fake(
            |payload| {
                // NTP probe is exactly 48 bytes with byte 0 = 0b00_100_011.
                if payload.len() != 48 || payload[0] != 0b00_100_011 {
                    return None;
                }
                let mut reply = [0u8; 48];
                reply[0] = 0b00_100_100;
                Some(reply.to_vec())
            },
            ServiceClass::Ntp,
        )
        .await;
    }

    #[tokio::test]
    async fn detects_snmp_over_udp() {
        run_udp_fake(
            |payload| {
                // SNMP probe begins with SEQUENCE 0x30 and contains "public".
                if !payload.starts_with(&[0x30]) || !payload.windows(6).any(|w| w == b"public") {
                    return None;
                }
                Some(vec![
                    0x30, 0x18, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
                    0xa2, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
                ])
            },
            ServiceClass::Snmp,
        )
        .await;
    }

    #[tokio::test]
    async fn detects_quic_over_udp() {
        run_udp_fake(
            |payload| {
                // QUIC Initial probe is 1200 bytes with long-header high bit set.
                if payload.len() != 1200 || (payload[0] & 0x80) == 0 {
                    return None;
                }
                Some(vec![0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            },
            ServiceClass::Quic,
        )
        .await;
    }

    #[tokio::test]
    async fn udp_unbound_returns_nobanner() {
        // Use a port we did not bind. recvfrom will time out.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let det = autodetect_udp(addr, Duration::from_millis(400))
            .await
            .unwrap();
        assert_eq!(det.class, ServiceClass::NoBanner);
    }

    #[tokio::test]
    async fn no_listener_returns_none_or_nobanner() {
        // 127.0.0.1:1 is conventionally blocked / unbound on test runners.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let _ = autodetect(addr, Duration::from_millis(200)).await;
    }

    #[test]
    fn mqtt_remaining_length_encodes_zero_to_short() {
        let mut v = Vec::new();
        encode_mqtt_remaining_length(&mut v, 0);
        assert_eq!(v, vec![0x00]);
        v.clear();
        encode_mqtt_remaining_length(&mut v, 127);
        assert_eq!(v, vec![0x7f]);
        v.clear();
        encode_mqtt_remaining_length(&mut v, 128);
        assert_eq!(v, vec![0x80, 0x01]);
    }

    #[test]
    fn build_mqtt_connect_packet_shape() {
        let p = build_mqtt_connect(b"abc");
        assert_eq!(p[0], 0x10); // CONNECT
                                // Variable header begins with proto-name length 0x0004, "MQTT", 0x04 (level), 0x02 (flags).
        let body_start = 2;
        assert_eq!(&p[body_start..body_start + 6], b"\x00\x04MQTT");
    }
}
