//! RFC 5424 syslog over UDP.
//!
//! UDP delivery is best-effort by design: records are queued in a bounded
//! in-memory channel, sent as one datagram each, and never retried. Oversized
//! payloads are truncated before send so the writer never blocks forwarding.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use spt_core::RedactionMode;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::syslog_common::{
    hostname_or, SyslogCounters, SyslogLayer, SyslogRenderConfig, DEFAULT_ENTERPRISE_ID,
};

/// Configuration for [`RemoteSyslogUdpLayer`].
#[derive(Debug, Clone)]
pub struct SyslogUdpConfig {
    pub host: String,
    pub port: u16,
    pub app_name: String,
    pub hostname: String,
    pub facility: u8,
    pub enterprise_id: u32,
    pub timeout: Duration,
    pub queue_max_records: usize,
    pub max_datagram_bytes: usize,
    pub redact: RedactionMode,
}

impl SyslogUdpConfig {
    /// New UDP syslog config with RFC defaults.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            app_name: "spt".into(),
            hostname: hostname_or("localhost"),
            facility: 16,
            enterprise_id: DEFAULT_ENTERPRISE_ID,
            timeout: Duration::from_secs(5),
            queue_max_records: 1024,
            max_datagram_bytes: 8192,
            redact: RedactionMode::Standard,
        }
    }
}

/// Tracing layer for UDP syslog.
pub type RemoteSyslogUdpLayer = SyslogLayer;

/// Handle to a UDP syslog writer.
pub struct SyslogUdpHandle {
    pub join: tokio::task::JoinHandle<()>,
    tx_keepalive: Option<mpsc::Sender<Vec<u8>>>,
    counters: Arc<SyslogCounters>,
}

impl SyslogUdpHandle {
    pub fn counters(&self) -> Arc<SyslogCounters> {
        Arc::clone(&self.counters)
    }

    pub async fn shutdown(mut self) {
        drop(self.tx_keepalive.take());
        let _ = self.join.await;
    }
}

/// Errors during UDP syslog writer startup.
#[derive(Debug, thiserror::Error)]
pub enum SyslogUdpError {
    #[error("queue_max_records must be greater than zero")]
    EmptyQueue,
}

pub fn spawn_writer(
    cfg: SyslogUdpConfig,
) -> Result<(RemoteSyslogUdpLayer, SyslogUdpHandle), SyslogUdpError> {
    if cfg.queue_max_records == 0 {
        return Err(SyslogUdpError::EmptyQueue);
    }
    let counters = Arc::new(SyslogCounters::default());
    let (tx, rx) = mpsc::channel::<Vec<u8>>(cfg.queue_max_records);
    let render = SyslogRenderConfig {
        app_name: cfg.app_name.clone(),
        hostname: cfg.hostname.clone(),
        facility: cfg.facility,
        enterprise_id: cfg.enterprise_id,
        redact: cfg.redact,
    };
    let layer = SyslogLayer::new(
        tx.clone(),
        render,
        Arc::clone(&counters),
        Some(cfg.max_datagram_bytes),
    );
    let task_counters = Arc::clone(&counters);
    let join = tokio::spawn(async move {
        run_writer(cfg, rx, task_counters).await;
    });
    Ok((
        layer,
        SyslogUdpHandle {
            join,
            tx_keepalive: Some(tx),
            counters,
        },
    ))
}

/// Send one already-rendered RFC 5424 record over UDP.
pub async fn send_one(cfg: &SyslogUdpConfig, mut payload: Vec<u8>) -> io::Result<()> {
    if payload.len() > cfg.max_datagram_bytes {
        payload.truncate(cfg.max_datagram_bytes);
    }
    let remote = resolve_one(&cfg.host, cfg.port).await?;
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    tokio::time::timeout(cfg.timeout, socket.send_to(&payload, remote))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "udp send timeout"))??;
    Ok(())
}

async fn run_writer(
    cfg: SyslogUdpConfig,
    mut rx: mpsc::Receiver<Vec<u8>>,
    counters: Arc<SyslogCounters>,
) {
    let remote = match resolve_one(&cfg.host, cfg.port).await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::warn!(error = %e, "syslog-udp resolve failed; dropping queued records");
            while rx.recv().await.is_some() {
                counters.inc_send_error();
            }
            return;
        }
    };
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(e) => {
            tracing::warn!(error = %e, "syslog-udp bind failed; dropping queued records");
            while rx.recv().await.is_some() {
                counters.inc_send_error();
            }
            return;
        }
    };

    while let Some(payload) = rx.recv().await {
        let send = socket.send_to(&payload, remote);
        match tokio::time::timeout(cfg.timeout, send).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                counters.inc_send_error();
                tracing::debug!(error = %e, "syslog-udp send failed");
            }
            Err(_) => {
                counters.inc_send_error();
                tracing::debug!("syslog-udp send timed out");
            }
        }
    }
}

async fn resolve_one(host: &str, port: u16) -> io::Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addrs resolved"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn udp_writer_sends_one_rfc5424_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = receiver.local_addr().unwrap().port();
        let cfg = SyslogUdpConfig {
            host: "127.0.0.1".into(),
            port,
            app_name: "spt".into(),
            hostname: "host".into(),
            facility: 16,
            enterprise_id: DEFAULT_ENTERPRISE_ID,
            timeout: Duration::from_secs(1),
            queue_max_records: 8,
            max_datagram_bytes: 8192,
            redact: RedactionMode::Standard,
        };
        let (layer, handle) = spawn_writer(cfg).unwrap();
        layer
            .try_send_raw(b"<134>1 2026-01-01T00:00:00.000Z host spt 1 - - hello".to_vec())
            .unwrap();

        let mut buf = [0_u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.starts_with("<134>1 "));
        assert!(got.ends_with("hello"));
        drop(layer);
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn udp_layer_truncates_before_queueing() {
        let cfg = SyslogUdpConfig {
            host: "127.0.0.1".into(),
            port: 9,
            max_datagram_bytes: 4,
            ..SyslogUdpConfig::new("127.0.0.1", 9)
        };
        let (layer, handle) = spawn_writer(cfg).unwrap();
        layer.try_send_raw(b"abcdef".to_vec()).unwrap();
        assert_eq!(layer.counters().snapshot().truncated, 1);
        drop(layer);
        handle.shutdown().await;
    }
}
