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
//! pushes it via an unbounded `mpsc` to a tokio task that owns the TLS
//! connection. The task keeps a `DiskSpool` for back-pressure and retry on
//! transient transport failure. On reconnect the task drains the spool
//! before serving live traffic.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls::RootCertStore;
use spt_core::{redact, RedactionMode};
use spt_state::{DiskSpool, SpoolConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

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
    /// Optional pre-built rustls roots; if `None`, `webpki-roots` are used.
    pub roots: Option<RootCertStore>,
    /// Disk spool directory for retry queue.
    pub spool_dir: PathBuf,
    /// Spool capacity.
    pub spool: SpoolConfig,
    /// Per-write timeout.
    pub timeout: Duration,
    /// Reconnect backoff between failed attempts.
    pub reconnect_backoff: Duration,
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
            roots: None,
            spool_dir,
            spool: SpoolConfig::default(),
            timeout: Duration::from_secs(5),
            reconnect_backoff: Duration::from_millis(500),
            redact: RedactionMode::Standard,
        }
    }
}

fn hostname_or(default: &str) -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| default.into())
}

/// Tracing layer; spawn the writer task with [`spawn_writer`] then attach
/// this layer to a subscriber.
pub struct RemoteSyslogTlsLayer {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    cfg: Arc<LayerCfg>,
}

struct LayerCfg {
    app_name: String,
    hostname: String,
    facility: u8,
    redact: RedactionMode,
}

/// Handle to a syslog-TLS background task.
pub struct SyslogTlsHandle {
    /// Join handle for the writer task.
    pub join: tokio::task::JoinHandle<()>,
    /// Sender; drop to signal shutdown.
    pub tx: mpsc::UnboundedSender<Vec<u8>>,
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
}

/// Build a default `webpki-roots` root store.
fn default_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Spawn the background writer task. Returns the layer to register and a
/// handle for shutdown / join. The task owns the TCP+TLS connection and
/// `DiskSpool`.
pub fn spawn_writer(
    cfg: SyslogTlsConfig,
) -> Result<(RemoteSyslogTlsLayer, SyslogTlsHandle), SyslogTlsError> {
    let spool = DiskSpool::open(cfg.spool_dir.clone(), cfg.spool.clone())?;
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let layer_cfg = Arc::new(LayerCfg {
        app_name: cfg.app_name.clone(),
        hostname: cfg.hostname.clone(),
        facility: cfg.facility,
        redact: cfg.redact,
    });
    let layer = RemoteSyslogTlsLayer {
        tx: tx.clone(),
        cfg: Arc::clone(&layer_cfg),
    };

    let writer_tx = tx.clone();
    let join = tokio::spawn(async move {
        if let Err(e) = run_writer(cfg, rx, spool).await {
            tracing::warn!(error=%e, "syslog-tls writer exited");
        }
    });
    Ok((
        layer,
        SyslogTlsHandle {
            join,
            tx: writer_tx,
        },
    ))
}

async fn run_writer(
    cfg: SyslogTlsConfig,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    spool: DiskSpool,
) -> Result<(), SyslogTlsError> {
    let roots = cfg.roots.clone().unwrap_or_else(default_roots);
    let client_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
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
                if let Ok(buf) =
                    tokio::time::timeout(cfg.reconnect_backoff, rx.recv()).await
                {
                    match buf {
                        Some(buf) => {
                            spool.lock().await.push(&buf).ok();
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
                tracing::debug!(error=%e, "spool drain write failed; re-queueing");
                spool.lock().await.push(&entry.payload).ok();
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
                        tracing::debug!(error=%e, "live write failed; spooling");
                        spool.lock().await.push(&buf).ok();
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
    let addrs: Vec<SocketAddr> =
        tokio::net::lookup_host((cfg.host.as_str(), cfg.port))
            .await?
            .collect();
    let Some(addr) = addrs.into_iter().next() else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no addrs resolved"));
    };
    let tcp = tokio::time::timeout(cfg.timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timeout"))??;
    let server_name = ServerName::try_from(cfg.host.clone())
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

impl<S> Layer<S> for RemoteSyslogTlsLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let payload = render_record(event, &self.cfg);
        let _ = self.tx.send(payload);
    }
}

fn severity_code(level: tracing::Level) -> u8 {
    match level {
        tracing::Level::ERROR => 3,
        tracing::Level::WARN => 4,
        tracing::Level::INFO => 6,
        tracing::Level::DEBUG | tracing::Level::TRACE => 7,
    }
}

fn render_record(event: &Event<'_>, cfg: &LayerCfg) -> Vec<u8> {
    let meta = event.metadata();
    let pri = u16::from(cfg.facility) * 8 + u16::from(severity_code(*meta.level()));
    let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

    let mut fields = FieldVisitor::default();
    event.record(&mut fields);
    let msg = fields.message.unwrap_or_else(|| meta.target().to_string());
    let msg_red = redact(&msg, cfg.redact);

    let sd = if fields.kvs.is_empty() {
        "-".to_string()
    } else {
        let mut s = String::from("[spt@32473");
        for (k, v) in &fields.kvs {
            s.push(' ');
            s.push_str(k);
            s.push_str("=\"");
            s.push_str(&escape_sd_value(&redact(v, cfg.redact)));
            s.push('"');
        }
        s.push(']');
        s
    };

    let line = format!(
        "<{}>1 {} {} {} {} - {} {}",
        pri,
        ts,
        sanitize_token(&cfg.hostname, 255),
        sanitize_token(&cfg.app_name, 48),
        std::process::id(),
        sd,
        msg_red,
    );
    line.into_bytes()
}

fn escape_sd_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '"' | '\\' | ']' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn sanitize_token(s: &str, max: usize) -> String {
    let s: String = s.chars().filter(|c| !c.is_whitespace() && *c != '<' && *c != '>').collect();
    if s.is_empty() {
        return "-".to_string();
    }
    if s.len() > max {
        s.chars().take(max).collect()
    } else {
        s
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    kvs: Vec<(String, String)>,
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.kvs.push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let v = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(v);
        } else {
            self.kvs.push((field.name().to_string(), v));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_record_has_pri_and_msg() {
        let cfg = LayerCfg {
            app_name: "spt".into(),
            hostname: "host".into(),
            facility: 16,
            redact: RedactionMode::Standard,
        };
        // Synthesise a minimal event by calling render_record's helpers
        // directly.  The `Event` fixture API is private; this test focuses on
        // formatting helpers.
        let msg = "hello world";
        let pri = u16::from(cfg.facility) * 8 + u16::from(severity_code(tracing::Level::INFO));
        assert_eq!(pri, 16 * 8 + 6);
        assert_eq!(escape_sd_value("a]b\"c"), "a\\]b\\\"c");
        assert_eq!(sanitize_token("a b", 10), "ab");
        assert_eq!(sanitize_token("", 10), "-");
        assert!(redact(msg, cfg.redact).contains("hello"));
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
        let cert =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()])
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
            roots: Some(roots),
            spool_dir: tmp.path().to_path_buf(),
            spool: SpoolConfig::default(),
            timeout: Duration::from_secs(2),
            reconnect_backoff: Duration::from_millis(50),
            redact: RedactionMode::Standard,
        };
        let (layer, handle) = spawn_writer(cfg).unwrap();
        // Inject one rendered RFC-5424 record.
        let record = b"<134>1 2024-01-01T00:00:00.000Z host spt 1 - - hello world".to_vec();
        layer.tx.send(record.clone()).unwrap();

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
            roots: Some(RootCertStore::empty()),
            spool_dir: tmp.path().to_path_buf(),
            spool: SpoolConfig::default(),
            timeout: Duration::from_millis(50),
            reconnect_backoff: Duration::from_millis(20),
            redact: RedactionMode::Standard,
        };
        let (layer, handle) = spawn_writer(cfg).unwrap();
        // Send a few records by directly pushing through the layer's tx.
        for _ in 0..3 {
            let _ = layer.tx.send(b"<134>1 - - spt - - - hi".to_vec());
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
