//! RFC 5424 syslog over TCP with RFC 6587 octet-counted framing.
//!
//! The writer owns reconnect/backoff and a bounded disk spool. The tracing
//! layer uses a bounded non-blocking queue so forwarding paths are never held
//! behind remote log delivery.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use spt_core::RedactionMode;
use spt_state::{DiskSpool, SpoolConfig};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::syslog_common::{
    hostname_or, SyslogCounters, SyslogLayer, SyslogRenderConfig, DEFAULT_ENTERPRISE_ID,
};

/// Configuration for [`RemoteSyslogTcpLayer`].
#[derive(Debug, Clone)]
pub struct SyslogTcpConfig {
    pub host: String,
    pub port: u16,
    pub app_name: String,
    pub hostname: String,
    pub facility: u8,
    pub enterprise_id: u32,
    pub spool_dir: PathBuf,
    pub spool: SpoolConfig,
    pub timeout: Duration,
    pub reconnect_backoff: Duration,
    pub queue_max_records: usize,
    pub redact: RedactionMode,
}

impl SyslogTcpConfig {
    /// New TCP syslog config with RFC defaults.
    pub fn new(host: impl Into<String>, port: u16, spool_dir: PathBuf) -> Self {
        Self {
            host: host.into(),
            port,
            app_name: "spt".into(),
            hostname: hostname_or("localhost"),
            facility: 16,
            enterprise_id: DEFAULT_ENTERPRISE_ID,
            spool_dir,
            spool: SpoolConfig::default(),
            timeout: Duration::from_secs(5),
            reconnect_backoff: Duration::from_millis(500),
            queue_max_records: 1024,
            redact: RedactionMode::Standard,
        }
    }
}

/// Tracing layer for TCP syslog.
pub type RemoteSyslogTcpLayer = SyslogLayer;

/// Handle to a TCP syslog writer.
pub struct SyslogTcpHandle {
    pub join: tokio::task::JoinHandle<()>,
    tx_keepalive: Option<mpsc::Sender<Vec<u8>>>,
    counters: Arc<SyslogCounters>,
}

impl SyslogTcpHandle {
    pub fn counters(&self) -> Arc<SyslogCounters> {
        Arc::clone(&self.counters)
    }

    pub async fn shutdown(mut self) {
        drop(self.tx_keepalive.take());
        let _ = self.join.await;
    }
}

/// Errors during TCP syslog writer startup.
#[derive(Debug, thiserror::Error)]
pub enum SyslogTcpError {
    #[error("spool: {0}")]
    Spool(#[from] spt_core::Error),
    #[error("queue_max_records must be greater than zero")]
    EmptyQueue,
}

pub fn spawn_writer(
    cfg: SyslogTcpConfig,
) -> Result<(RemoteSyslogTcpLayer, SyslogTcpHandle), SyslogTcpError> {
    if cfg.queue_max_records == 0 {
        return Err(SyslogTcpError::EmptyQueue);
    }
    let spool = DiskSpool::open(cfg.spool_dir.clone(), cfg.spool.clone())?;
    let counters = Arc::new(SyslogCounters::default());
    let (tx, rx) = mpsc::channel::<Vec<u8>>(cfg.queue_max_records);
    let render = SyslogRenderConfig {
        app_name: cfg.app_name.clone(),
        hostname: cfg.hostname.clone(),
        facility: cfg.facility,
        enterprise_id: cfg.enterprise_id,
        redact: cfg.redact,
    };
    let layer = SyslogLayer::new(tx.clone(), render, Arc::clone(&counters), None);
    let task_counters = Arc::clone(&counters);
    let join = tokio::spawn(async move {
        if let Err(e) = run_writer(cfg, rx, spool, task_counters).await {
            tracing::warn!(error = %e, "syslog-tcp writer exited");
        }
    });
    Ok((
        layer,
        SyslogTcpHandle {
            join,
            tx_keepalive: Some(tx),
            counters,
        },
    ))
}

/// Send one already-rendered RFC 5424 record over TCP with RFC 6587 framing.
pub async fn send_one(cfg: &SyslogTcpConfig, payload: &[u8]) -> io::Result<()> {
    let mut stream = connect(cfg).await?;
    write_frame(&mut stream, payload, cfg.timeout).await
}

pub(crate) async fn run_writer(
    cfg: SyslogTcpConfig,
    mut rx: mpsc::Receiver<Vec<u8>>,
    spool: DiskSpool,
    counters: Arc<SyslogCounters>,
) -> Result<(), SyslogTcpError> {
    let spool = Arc::new(Mutex::new(spool));

    'outer: loop {
        let mut stream = match connect(&cfg).await {
            Ok(s) => {
                counters.inc_reconnect();
                s
            }
            Err(e) => {
                tracing::debug!(error = %e, "syslog-tcp connect failed; backing off");
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

        loop {
            let entry = {
                let mut s = spool.lock().await;
                s.pop().ok().flatten()
            };
            let Some(entry) = entry else { break };
            if let Err(e) = write_frame(&mut stream, &entry.payload, cfg.timeout).await {
                counters.inc_send_error();
                tracing::debug!(error = %e, "syslog-tcp spool drain write failed; requeueing");
                if spool.lock().await.push(&entry.payload).is_ok() {
                    counters.inc_spooled();
                }
                tokio::time::sleep(cfg.reconnect_backoff).await;
                continue 'outer;
            }
        }

        loop {
            let Some(buf) = rx.recv().await else {
                break 'outer;
            };
            if let Err(e) = write_frame(&mut stream, &buf, cfg.timeout).await {
                counters.inc_send_error();
                tracing::debug!(error = %e, "syslog-tcp live write failed; spooling");
                if spool.lock().await.push(&buf).is_ok() {
                    counters.inc_spooled();
                }
                tokio::time::sleep(cfg.reconnect_backoff).await;
                continue 'outer;
            }
        }
    }
    Ok(())
}

async fn connect(cfg: &SyslogTcpConfig) -> io::Result<TcpStream> {
    let addr = resolve_one(&cfg.host, cfg.port).await?;
    tokio::time::timeout(cfg.timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timeout"))?
}

async fn resolve_one(host: &str, port: u16) -> io::Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addrs resolved"))
}

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
    to: Duration,
) -> io::Result<()> {
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
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test(flavor = "current_thread")]
    async fn write_frame_emits_octet_counted_payload() {
        let payload = b"<134>1 2024-01-01T00:00:00.000Z host spt - - - hello";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload, Duration::from_secs(1))
            .await
            .unwrap();
        let header_len = format!("{} ", payload.len());
        assert!(buf.starts_with(header_len.as_bytes()));
        assert!(buf.ends_with(payload));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_writer_sends_octet_counted_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0_u8; 256];
            loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(sp_idx) = buf.iter().position(|&b| b == b' ') {
                    let len = std::str::from_utf8(&buf[..sp_idx])
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    if buf.len() >= sp_idx + 1 + len {
                        break;
                    }
                }
            }
            let _ = tx.send(buf);
        });

        let tmp = tempfile::tempdir().unwrap();
        let cfg = SyslogTcpConfig {
            host: "127.0.0.1".into(),
            port,
            app_name: "spt".into(),
            hostname: "host".into(),
            facility: 16,
            enterprise_id: DEFAULT_ENTERPRISE_ID,
            spool_dir: tmp.path().to_path_buf(),
            spool: SpoolConfig::default(),
            timeout: Duration::from_secs(1),
            reconnect_backoff: Duration::from_millis(20),
            queue_max_records: 8,
            redact: RedactionMode::Standard,
        };
        let (layer, handle) = spawn_writer(cfg).unwrap();
        let record = b"<134>1 2024-01-01T00:00:00.000Z host spt 1 - - hello".to_vec();
        layer.try_send_raw(record.clone()).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .unwrap()
            .unwrap();
        let header = format!("{} ", record.len());
        assert!(received.starts_with(header.as_bytes()));
        drop(layer);
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_writer_spools_when_connect_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SyslogTcpConfig {
            host: "127.0.0.1".into(),
            port: 1,
            app_name: "spt".into(),
            hostname: "host".into(),
            facility: 16,
            enterprise_id: DEFAULT_ENTERPRISE_ID,
            spool_dir: tmp.path().to_path_buf(),
            spool: SpoolConfig::default(),
            timeout: Duration::from_millis(50),
            reconnect_backoff: Duration::from_millis(20),
            queue_max_records: 8,
            redact: RedactionMode::Standard,
        };
        let (layer, handle) = spawn_writer(cfg).unwrap();
        for _ in 0..3 {
            let _ = layer.try_send_raw(b"<134>1 - - spt - - - hi".to_vec());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(layer);
        handle.shutdown().await;
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bin"))
            .collect();
        assert!(!entries.is_empty(), "expected spooled frames");
    }
}
