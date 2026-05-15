//! RFC 5424 syslog over TLS-on-TCP (RFC 5425) tracing layer.
//!
//! ## Wire format
//!
//! Every log record is encoded as:
//!
//! ```text
//! <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
//! ```
//!
//! where:
//!
//! * `PRI = facility * 8 + severity` (default facility `local0` = 16, severity
//!   mapped from the tracing `Level`).
//! * `VERSION = 1`.
//! * `TIMESTAMP` is RFC 3339 with millisecond precision, UTC.
//! * `STRUCTURED-DATA` is `-` (none) or `[spt@32473 k="v" ...]` with our
//!   private enterprise number placeholder; values are escaped per RFC 5424.
//!
//! Frames are wrapped per RFC 5425 octet-counting: `<length> SP <message>`.
//!
//! ## Reliability
//!
//! Layers are synchronous; the `on_event` hook serialises the record and
//! pushes it via a bounded `mpsc` to a tokio task that owns the TLS
//! connection. The task keeps a `DiskSpool` for back-pressure and retry on
//! transient transport failure. On reconnect the task drains the spool
//! before serving live traffic.

use std::io;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::{DigitallySignedStruct, SignatureScheme};
use spt_core::RedactionMode;
use spt_state::{DiskSpool, SpoolConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;

use crate::syslog_common::{
    hostname_or, SyslogCounters, SyslogLayer, SyslogRenderConfig, DEFAULT_ENTERPRISE_ID,
};

/// Configuration for [`RemoteSyslogTlsLayer`].
#[derive(Debug, Clone)]
pub struct SyslogTlsConfig {
    /// Hostname (SNI) to connect to.
    pub host: String,
    /// Port (RFC 6587 standard: 6514).
    pub port: u16,
    /// `APP-NAME` field (≤48 ASCII printable). Default `"spt"`.
    pub app_name: String,
    /// `HOSTNAME` field (≤255). Default = local hostname.
    pub hostname: String,
    /// Facility (0..23). Default = 16 (local0).
    pub facility: u8,
    /// Structured-data enterprise ID.
    pub enterprise_id: u32,
    /// Optional pre-built rustls roots; if `None`, `webpki-roots` are used.
    pub roots: Option<RootCertStore>,
    /// SNI / verification name override. Defaults to `host`.
    pub server_name: Option<String>,
    /// Optional client certificate chain for mutual TLS.
    pub client_cert: Option<PathBuf>,
    /// Optional client private key for mutual TLS.
    pub client_key: Option<PathBuf>,
    /// Disable TLS certificate verification. Dangerous; never the default.
    pub allow_invalid_certs: bool,
    /// Disk spool directory for retry queue.
    pub spool_dir: PathBuf,
    /// Spool capacity.
    pub spool: SpoolConfig,
    /// Per-write timeout.
    pub timeout: Duration,
    /// Reconnect backoff between failed attempts.
    pub reconnect_backoff: Duration,
    /// Bounded in-memory queue length.
    pub queue_max_records: usize,
    /// Redaction mode applied before the message hits the wire.
    pub redact: RedactionMode,
}

impl SyslogTlsConfig {
    /// New config with reasonable defaults.
    pub fn new(host: impl Into<String>, port: u16, spool_dir: PathBuf) -> Self {
        let hostname = hostname_or("localhost");
        Self {
            host: host.into(),
            port,
            app_name: "spt".into(),
            hostname,
            facility: 16,
            enterprise_id: DEFAULT_ENTERPRISE_ID,
            roots: None,
            server_name: None,
            client_cert: None,
            client_key: None,
            allow_invalid_certs: false,
            spool_dir,
            spool: SpoolConfig::default(),
            timeout: Duration::from_secs(5),
            reconnect_backoff: Duration::from_millis(500),
            queue_max_records: 1024,
            redact: RedactionMode::Standard,
        }
    }
}

/// Tracing layer; spawn the writer task with [`spawn_writer`] then attach
/// this layer to a subscriber.
pub type RemoteSyslogTlsLayer = SyslogLayer;

/// Handle to a syslog-TLS background task.
pub struct SyslogTlsHandle {
    /// Join handle for the writer task.
    pub join: tokio::task::JoinHandle<()>,
    /// Sender; drop to signal shutdown.
    pub tx: mpsc::Sender<Vec<u8>>,
    counters: Arc<SyslogCounters>,
}

impl SyslogTlsHandle {
    pub fn counters(&self) -> Arc<SyslogCounters> {
        Arc::clone(&self.counters)
    }
}

/// Errors during [`spawn_writer`].
#[derive(Debug, thiserror::Error)]
pub enum SyslogTlsError {
    /// Disk spool open error.
    #[error("spool: {0}")]
    Spool(#[from] spt_core::Error),
    /// Rustls config build error.
    #[error("rustls: {0}")]
    Rustls(String),
    /// Invalid queue length.
    #[error("queue_max_records must be greater than zero")]
    EmptyQueue,
}

/// Build a default root store from platform roots plus `webpki-roots`.
fn default_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                let _ = roots.add(cert);
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "loading native root certificates failed; using webpki roots");
        }
    }
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Build a root store from system/webpki roots plus an optional PEM CA bundle.
pub fn root_store_with_ca_file(ca_file: Option<&std::path::Path>) -> io::Result<RootCertStore> {
    let mut roots = default_roots();
    if let Some(path) = ca_file {
        for cert in load_cert_chain(path)? {
            roots.add(cert).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid CA cert: {e}"))
            })?;
        }
    }
    Ok(roots)
}

fn build_client_config(cfg: &SyslogTlsConfig) -> Result<ClientConfig, SyslogTlsError> {
    let wants_client_cert = if cfg.allow_invalid_certs {
        tracing::warn!(
            sink_host = %cfg.host,
            "syslog_tls allow_invalid_certs=true; TLS certificate verification is disabled"
        );
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
    } else {
        let roots = cfg.roots.clone().unwrap_or_else(default_roots);
        ClientConfig::builder().with_root_certificates(roots)
    };

    match (&cfg.client_cert, &cfg.client_key) {
        (Some(cert), Some(key)) => {
            let certs = load_cert_chain(cert).map_err(|e| {
                SyslogTlsError::Rustls(format!("client_cert `{}`: {e}", cert.display()))
            })?;
            let key = load_private_key(key).map_err(|e| {
                SyslogTlsError::Rustls(format!("client_key `{}`: {e}", key.display()))
            })?;
            wants_client_cert
                .with_client_auth_cert(certs, key)
                .map_err(|e| SyslogTlsError::Rustls(e.to_string()))
        }
        (None, None) => Ok(wants_client_cert.with_no_client_auth()),
        _ => Err(SyslogTlsError::Rustls(
            "client_cert and client_key must be configured together".into(),
        )),
    }
}

fn load_cert_chain(path: &std::path::Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(path: &std::path::Path) -> io::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Spawn the background writer task. Returns the layer to register and a
/// handle for shutdown / join. The task owns the TCP+TLS connection and
/// `DiskSpool`.
pub fn spawn_writer(
    cfg: SyslogTlsConfig,
) -> Result<(RemoteSyslogTlsLayer, SyslogTlsHandle), SyslogTlsError> {
    if cfg.queue_max_records == 0 {
        return Err(SyslogTlsError::EmptyQueue);
    }
    let spool = DiskSpool::open(cfg.spool_dir.clone(), cfg.spool.clone())?;
    let counters = Arc::new(SyslogCounters::default());
    let (tx, rx) = mpsc::channel::<Vec<u8>>(cfg.queue_max_records);
    let render_cfg = SyslogRenderConfig {
        app_name: cfg.app_name.clone(),
        hostname: cfg.hostname.clone(),
        facility: cfg.facility,
        enterprise_id: cfg.enterprise_id,
        redact: cfg.redact,
    };
    let layer = SyslogLayer::new(tx.clone(), render_cfg, Arc::clone(&counters), None);

    let writer_tx = tx.clone();
    let writer_counters = Arc::clone(&counters);
    let join = tokio::spawn(async move {
        if let Err(e) = run_writer(cfg, rx, spool, writer_counters).await {
            tracing::warn!(error=%e, "syslog-tls writer exited");
        }
    });
    Ok((
        layer,
        SyslogTlsHandle {
            join,
            tx: writer_tx,
            counters,
        },
    ))
}

/// Send one already-rendered RFC 5424 record over TLS with RFC 5425 framing.
pub async fn send_one(cfg: &SyslogTlsConfig, payload: &[u8]) -> io::Result<()> {
    let client_cfg = build_client_config(cfg).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("build syslog_tls client config: {e}"),
        )
    })?;
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let mut stream = connect(&connector, cfg).await?;
    write_frame(&mut stream, payload, cfg.timeout).await
}

async fn run_writer(
    cfg: SyslogTlsConfig,
    mut rx: mpsc::Receiver<Vec<u8>>,
    spool: DiskSpool,
    counters: Arc<SyslogCounters>,
) -> Result<(), SyslogTlsError> {
    let client_cfg = build_client_config(&cfg)?;
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let spool = Arc::new(Mutex::new(spool));

    'outer: loop {
        // Connect.
        let stream = match connect(&connector, &cfg).await {
            Ok(s) => s,
            Err(e) => {
                #[cfg(test)]
                eprintln!("syslog-tls connect error: {e}");
                tracing::debug!(error=%e, "syslog-tls connect failed; backing off");
                // Even when disconnected, drain the channel into the spool so
                // we don't lose pending events while we wait.
                if let Ok(buf) = tokio::time::timeout(cfg.reconnect_backoff, rx.recv()).await {
                    match buf {
                        Some(buf) => {
                            if spool.lock().await.push(&buf).is_ok() {
                                counters.inc_spooled();
                            }
                        }
                        None => break 'outer,
                    }
                }
                continue;
            }
        };
        let mut stream = stream;

        // First, drain the spool.
        loop {
            let entry = {
                let mut s = spool.lock().await;
                s.pop().ok().flatten()
            };
            let Some(entry) = entry else { break };
            if let Err(e) = write_frame(&mut stream, &entry.payload, cfg.timeout).await {
                counters.inc_send_error();
                tracing::debug!(error=%e, "spool drain write failed; re-queueing");
                if spool.lock().await.push(&entry.payload).is_ok() {
                    counters.inc_spooled();
                }
                tokio::time::sleep(cfg.reconnect_backoff).await;
                continue 'outer;
            }
        }

        // Then live traffic.
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    let Some(buf) = msg else { break 'outer };
                    if let Err(e) = write_frame(&mut stream, &buf, cfg.timeout).await {
                        counters.inc_send_error();
                        tracing::debug!(error=%e, "live write failed; spooling");
                        if spool.lock().await.push(&buf).is_ok() {
                            counters.inc_spooled();
                        }
                        tokio::time::sleep(cfg.reconnect_backoff).await;
                        continue 'outer;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn connect(
    connector: &TlsConnector,
    cfg: &SyslogTlsConfig,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((cfg.host.as_str(), cfg.port))
        .await?
        .collect();
    let Some(addr) = addrs.into_iter().next() else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no addrs resolved"));
    };
    let tcp = tokio::time::timeout(cfg.timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timeout"))??;
    let name = cfg.server_name.as_ref().unwrap_or(&cfg.host).clone();
    let server_name = ServerName::try_from(name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let tls = connector.connect(server_name, tcp).await?;
    Ok(tls)
}

async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    payload: &[u8],
    to: Duration,
) -> io::Result<()> {
    // RFC 5425 octet-counting framing: ASCII length, SP, payload.
    let header = format!("{} ", payload.len());
    let fut = async {
        w.write_all(header.as_bytes()).await?;
        w.write_all(payload).await?;
        w.flush().await
    };
    tokio::time::timeout(to, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "syslog write timeout"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_defaults_are_bounded() {
        let cfg = SyslogTlsConfig::new("localhost", 6514, PathBuf::from("spool"));
        let msg = "hello world";
        let pri = u16::from(cfg.facility) * 8
            + u16::from(crate::syslog_common::severity_code(tracing::Level::INFO));
        assert_eq!(pri, 16 * 8 + 6);
        assert_eq!(cfg.queue_max_records, 1024);
        assert!(spt_core::redact(msg, cfg.redact).contains("hello"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_frame_emits_octet_counted_payload() {
        let payload = b"<134>1 2024-01-01T00:00:00.000Z host spt - - - hello";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload, Duration::from_secs(1))
            .await
            .unwrap();
        // Expected: "<len> <payload>"
        let header_len = format!("{} ", payload.len());
        assert!(buf.starts_with(header_len.as_bytes()));
        assert!(buf.ends_with(payload));
    }

    /// End-to-end TLS test: rcgen self-signed cert, rustls server on
    /// 127.0.0.1:0, the writer connects with the same cert in roots and
    /// sends one record. The server reads the octet-counted frame and
    /// asserts on the parsed RFC-5424 envelope.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn round_trip_against_self_signed_tls_listener() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc as StdArc;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        // Ambiguous default crypto provider with both ring and aws-lc-rs
        // present (rcgen pulls aws-lc-rs in). Pick ring explicitly.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // 1. Self-signed cert covering the loopback IP we'll dial.
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()])
            .unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

        // 2. Rustls server.
        let server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(StdArc::new(server_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Server task: accept one connection, read the frame, signal back.
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let server = tokio::spawn(async move {
            let (sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("listener.accept: {e}");
                    return;
                }
            };
            let mut tls = match acceptor.accept(sock).await {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("acceptor.accept: {e}");
                    return;
                }
            };
            // Read until we have at least one fully framed record. The
            // octet-counted framing is "<len> <payload>"; we keep reading
            // until the byte count matches.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = match tls.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("tls.read: {e}");
                        return;
                    }
                };
                buf.extend_from_slice(&chunk[..n]);
                // Have we read the expected number of payload bytes?
                if let Some(sp_idx) = buf.iter().position(|&b| b == b' ') {
                    if let Ok(s) = std::str::from_utf8(&buf[..sp_idx]) {
                        if let Ok(want) = s.parse::<usize>() {
                            if buf.len() >= sp_idx + 1 + want {
                                break;
                            }
                        }
                    }
                }
            }
            let _ = tx.send(buf);
        });

        // 3. Build a roots store with our self-signed cert.
        let mut roots = RootCertStore::empty();
        roots.add(der).unwrap();

        // 4. Spawn the writer pointing at the listener.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SyslogTlsConfig {
            host: "127.0.0.1".into(),
            port,
            app_name: "spt".into(),
            hostname: "host".into(),
            facility: 16,
            enterprise_id: crate::syslog_common::DEFAULT_ENTERPRISE_ID,
            roots: Some(roots),
            server_name: None,
            client_cert: None,
            client_key: None,
            allow_invalid_certs: false,
            spool_dir: tmp.path().to_path_buf(),
            spool: SpoolConfig::default(),
            timeout: Duration::from_secs(2),
            reconnect_backoff: Duration::from_millis(50),
            queue_max_records: 16,
            redact: RedactionMode::Standard,
        };
        let (layer, handle) = spawn_writer(cfg).unwrap();
        // Inject one rendered RFC-5424 record.
        let record = b"<134>1 2024-01-01T00:00:00.000Z host spt 1 - - hello world".to_vec();
        layer.try_send_raw(record.clone()).unwrap();

        // 5. Wait for the server to read.
        let received = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .expect("server read timed out")
            .unwrap();

        // Assertions: octet-counted framing → "<len> <payload>".
        let header = format!("{} ", record.len());
        assert!(
            received.starts_with(header.as_bytes()),
            "missing length header in {received:?}"
        );
        let payload_start = header.len();
        assert!(received.len() >= payload_start + record.len());
        let payload = &received[payload_start..payload_start + record.len()];
        let parsed = std::str::from_utf8(payload).unwrap();
        assert!(parsed.starts_with("<134>1 "), "PRI/version: {parsed:?}");
        assert!(parsed.contains(" host "), "HOSTNAME: {parsed:?}");
        assert!(parsed.contains(" spt "), "APP-NAME: {parsed:?}");
        assert!(parsed.ends_with("hello world"), "MSG: {parsed:?}");

        // Cleanup.
        drop(layer);
        drop(handle.tx);
        let _ = tokio::time::timeout(Duration::from_millis(500), handle.join).await;
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_spools_when_connect_fails() {
        // Point at an unreachable port; spool should accumulate.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SyslogTlsConfig {
            host: "127.0.0.1".into(),
            port: 1, // unbound
            app_name: "spt".into(),
            hostname: "host".into(),
            facility: 16,
            enterprise_id: crate::syslog_common::DEFAULT_ENTERPRISE_ID,
            roots: Some(RootCertStore::empty()),
            server_name: None,
            client_cert: None,
            client_key: None,
            allow_invalid_certs: false,
            spool_dir: tmp.path().to_path_buf(),
            spool: SpoolConfig::default(),
            timeout: Duration::from_millis(50),
            reconnect_backoff: Duration::from_millis(20),
            queue_max_records: 16,
            redact: RedactionMode::Standard,
        };
        let (layer, handle) = spawn_writer(cfg).unwrap();
        // Send a few records by directly pushing through the bounded layer.
        for _ in 0..3 {
            let _ = layer.try_send_raw(b"<134>1 - - spt - - - hi".to_vec());
        }
        // Give the writer a moment to fail-and-spool.
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Drop the sender to exit the loop.
        drop(layer);
        drop(handle.tx);
        // Wait for task termination.
        let _ = tokio::time::timeout(Duration::from_millis(500), handle.join).await;
        // At least one frame should have made it to the spool.
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bin"))
            .collect();
        assert!(
            !entries.is_empty(),
            "expected at least one spooled frame on failed connect"
        );
    }
}
