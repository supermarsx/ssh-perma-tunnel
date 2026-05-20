//! HTTPS-JSONL log layer.
//!
//! Buffers serialised log records in memory; on flush trigger (batch size or
//! interval), the records are joined with `\n` and `POST`ed as
//! `application/x-ndjson`. Failures spool to disk for retry.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::Mutex as PlMutex;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use spt_core::{redact, RedactionMode};
use spt_state::{DiskSpool, SpoolConfig};
use tokio::sync::{mpsc, Mutex};
use tokio::time::interval;
use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Authorization mode for the HTTPS endpoint.
#[derive(Debug, Clone, Default)]
pub enum HttpsAuth {
    /// No auth.
    #[default]
    None,
    /// `Authorization: Bearer <token>`.
    Bearer(String),
    /// `Authorization: Basic <pre-encoded base64>`.
    Basic(String),
}

/// Configuration for [`HttpsJsonlLayer`].
#[derive(Debug, Clone)]
pub struct HttpsJsonlConfig {
    /// HTTPS endpoint to POST to.
    pub url: String,
    /// Auth mode.
    pub auth: HttpsAuth,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Max records per POST.
    pub batch_size: usize,
    /// Max time to buffer records before flushing.
    pub flush_interval: Duration,
    /// Spool dir for retries.
    pub spool_dir: PathBuf,
    /// Spool capacity.
    pub spool: SpoolConfig,
    /// Redaction mode applied to every string field before serialisation.
    pub redact: RedactionMode,
    /// SPKI SHA-256 pin set (each pin in `SHA256:<base64>` or hex form).
    /// Empty = no pin enforcement (strict system-roots still apply).
    /// t5-e2.
    pub pin_spki_sha256: Vec<String>,
    /// Allow self-signed certificates. Requires a non-empty pin set
    /// (the underlying [`spt_trust::PinnedTlsConnector`] refuses to
    /// disable verification entirely). t5-e2.
    pub allow_self_signed: bool,
    /// Maximum certificate-chain depth. `None` ⇒
    /// [`spt_trust::DEFAULT_CHAIN_DEPTH_CAP`] (`Some(5)`). t5-e2 / t5-e10.
    pub max_cert_chain_depth: Option<u32>,
}

impl HttpsJsonlConfig {
    /// New with defaults.
    pub fn new(url: impl Into<String>, spool_dir: PathBuf) -> Self {
        Self {
            url: url.into(),
            auth: HttpsAuth::None,
            timeout: Duration::from_secs(10),
            batch_size: 100,
            flush_interval: Duration::from_secs(5),
            spool_dir,
            spool: SpoolConfig::default(),
            redact: RedactionMode::Standard,
            pin_spki_sha256: Vec::new(),
            allow_self_signed: false,
            max_cert_chain_depth: None,
        }
    }
}

/// Errors during [`spawn`].
#[derive(Debug, thiserror::Error)]
pub enum HttpsJsonlError {
    /// Spool open error.
    #[error("spool: {0}")]
    Spool(#[from] spt_core::Error),
    /// reqwest client build error.
    #[error("reqwest: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// Pinned-TLS config build error.
    #[error("pinned tls: {0}")]
    PinnedTls(String),
}

/// Tracing layer that posts NDJSON batches to an HTTPS endpoint.
pub struct HttpsJsonlLayer {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    redact: RedactionMode,
}

/// Handle to the writer task.
pub struct HttpsJsonlHandle {
    /// Background task join handle.
    pub join: tokio::task::JoinHandle<()>,
    tx_keepalive: PlMutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
}

impl HttpsJsonlHandle {
    /// Stop accepting new records and wait for the writer to drain.
    pub async fn shutdown(self) {
        // Drop sender to break the loop.
        drop(self.tx_keepalive.lock().take());
        let _ = self.join.await;
    }
}

/// Spawn the writer task.
#[allow(clippy::needless_pass_by_value)]
pub fn spawn(
    cfg: HttpsJsonlConfig,
) -> Result<(HttpsJsonlLayer, HttpsJsonlHandle), HttpsJsonlError> {
    let spool = DiskSpool::open(cfg.spool_dir.clone(), cfg.spool.clone())?;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    if let Some(hv) = auth_header(&cfg.auth) {
        headers.insert(AUTHORIZATION, hv);
    }
    // t5-e2: route through `PinnedTlsConnector` so the chain-depth cap +
    // SPKI pin set + allow_self_signed flag are honoured.
    let rustls_cfg = spt_trust::PinnedTlsConnector::from_config_parts(
        &cfg.pin_spki_sha256,
        cfg.allow_self_signed,
        cfg.max_cert_chain_depth,
    )
    .map_err(|e| HttpsJsonlError::PinnedTls(e.to_string()))?;
    let cfg_inner = (*rustls_cfg).clone();
    let client = Client::builder()
        .use_preconfigured_tls(cfg_inner)
        .default_headers(headers)
        .timeout(cfg.timeout)
        .build()?;

    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let layer = HttpsJsonlLayer {
        tx: tx.clone(),
        redact: cfg.redact,
    };

    let task_cfg = cfg.clone();
    let join = tokio::spawn(async move {
        if let Err(e) = run_writer(task_cfg, client, rx, spool).await {
            tracing::warn!(error=%e, "https-jsonl writer exited");
        }
    });

    Ok((
        layer,
        HttpsJsonlHandle {
            join,
            tx_keepalive: PlMutex::new(Some(tx)),
        },
    ))
}

fn auth_header(auth: &HttpsAuth) -> Option<HeaderValue> {
    match auth {
        HttpsAuth::None => None,
        HttpsAuth::Bearer(t) => HeaderValue::from_str(&format!("Bearer {t}")).ok(),
        HttpsAuth::Basic(t) => HeaderValue::from_str(&format!("Basic {t}")).ok(),
    }
}

async fn run_writer(
    cfg: HttpsJsonlConfig,
    client: Client,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    spool: DiskSpool,
) -> Result<(), HttpsJsonlError> {
    let spool = Arc::new(Mutex::new(spool));
    let mut buf: Vec<Vec<u8>> = Vec::with_capacity(cfg.batch_size);
    let mut tick = interval(cfg.flush_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // skip first

    loop {
        tokio::select! {
            biased;
            msg = rx.recv() => {
                match msg {
                    Some(bytes) => {
                        buf.push(bytes);
                        if buf.len() >= cfg.batch_size {
                            flush(&client, &cfg, &mut buf, &spool).await;
                        }
                    }
                    None => {
                        // Sender closed: final flush + drain spool, then exit.
                        if !buf.is_empty() {
                            flush(&client, &cfg, &mut buf, &spool).await;
                        }
                        drain_spool(&client, &cfg, &spool).await;
                        return Ok(());
                    }
                }
            }
            _ = tick.tick() => {
                if !buf.is_empty() {
                    flush(&client, &cfg, &mut buf, &spool).await;
                }
                drain_spool(&client, &cfg, &spool).await;
            }
        }
    }
}

async fn flush(
    client: &Client,
    cfg: &HttpsJsonlConfig,
    buf: &mut Vec<Vec<u8>>,
    spool: &Arc<Mutex<DiskSpool>>,
) {
    if buf.is_empty() {
        return;
    }
    let body = join_ndjson(buf.drain(..));
    if !post(client, &cfg.url, &body).await {
        spool.lock().await.push(&body).ok();
    }
}

async fn drain_spool(client: &Client, cfg: &HttpsJsonlConfig, spool: &Arc<Mutex<DiskSpool>>) {
    loop {
        let entry = {
            let mut s = spool.lock().await;
            match s.pop() {
                Ok(Some(e)) => e,
                _ => return,
            }
        };
        if !post(client, &cfg.url, &entry.payload).await {
            // Push back at the end (FIFO will resume).
            spool.lock().await.push(&entry.payload).ok();
            return;
        }
    }
}

async fn post(client: &Client, url: &str, body: &[u8]) -> bool {
    match client.post(url).body(body.to_vec()).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

fn join_ndjson<I: IntoIterator<Item = Vec<u8>>>(items: I) -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);
    for (i, mut bytes) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        out.append(&mut bytes);
    }
    out
}

#[derive(Serialize)]
struct Record<'a> {
    timestamp: String,
    level: &'a str,
    target: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    fields: serde_json::Map<String, Value>,
}

impl<S> Layer<S> for HttpsJsonlLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut v = JsonVisitor::default();
        event.record(&mut v);
        let meta = event.metadata();

        // Apply redaction to message + each string field.
        let message = v.message.map(|m| redact(&m, self.redact).into_owned());
        let mut fields = serde_json::Map::new();
        for (k, val) in v.fields {
            let scrubbed = match val {
                Value::String(s) => Value::String(redact(&s, self.redact).into_owned()),
                other => other,
            };
            fields.insert(k, scrubbed);
        }
        let rec = Record {
            timestamp: Utc::now().to_rfc3339(),
            level: meta.level().as_str(),
            target: meta.target(),
            message,
            fields,
        };
        if let Ok(bytes) = serde_json::to_vec(&rec) {
            let _ = self.tx.send(bytes);
        }
    }
}

#[derive(Default)]
struct JsonVisitor {
    message: Option<String>,
    fields: Vec<(String, Value)>,
}

impl Visit for JsonVisitor {
    fn record_str(&mut self, f: &Field, v: &str) {
        if f.name() == "message" {
            self.message = Some(v.to_string());
        } else {
            self.fields
                .push((f.name().to_string(), Value::String(v.to_string())));
        }
    }
    fn record_i64(&mut self, f: &Field, v: i64) {
        self.fields
            .push((f.name().to_string(), Value::Number(v.into())));
    }
    fn record_u64(&mut self, f: &Field, v: u64) {
        self.fields
            .push((f.name().to_string(), Value::Number(v.into())));
    }
    fn record_bool(&mut self, f: &Field, v: bool) {
        self.fields.push((f.name().to_string(), Value::Bool(v)));
    }
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        let s = format!("{v:?}");
        if f.name() == "message" {
            self.message = Some(s);
        } else {
            self.fields.push((f.name().to_string(), Value::String(s)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndjson_join_separates_with_newline() {
        let out = join_ndjson([b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(out, b"a\nb\nc");
    }

    #[test]
    fn auth_header_bearer() {
        let h = auth_header(&HttpsAuth::Bearer("xyz".into())).unwrap();
        assert_eq!(h.to_str().unwrap(), "Bearer xyz");
        let h = auth_header(&HttpsAuth::Basic("dXNlcjpwYXNz".into())).unwrap();
        assert_eq!(h.to_str().unwrap(), "Basic dXNlcjpwYXNz");
        assert!(auth_header(&HttpsAuth::None).is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_spools_when_post_fails() {
        let tmp = tempfile::tempdir().unwrap();
        // 127.0.0.1:1 → unreachable; reqwest will fail with connection refused.
        let cfg = HttpsJsonlConfig {
            url: "http://127.0.0.1:1/sink".into(),
            auth: HttpsAuth::None,
            timeout: Duration::from_millis(100),
            batch_size: 2,
            flush_interval: Duration::from_millis(50),
            spool_dir: tmp.path().to_path_buf(),
            spool: SpoolConfig::default(),
            redact: RedactionMode::Standard,
            pin_spki_sha256: Vec::new(),
            allow_self_signed: false,
            max_cert_chain_depth: None,
        };
        let (layer, handle) = spawn(cfg).unwrap();
        // Push 4 records → 2 batches → both should fail and spool.
        for _ in 0..4 {
            let _ = layer.tx.send(br#"{"x":1}"#.to_vec());
        }
        // Wait for at least one tick + flush.
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Trigger shutdown.
        drop(layer);
        handle.shutdown().await;
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bin"))
            .collect();
        assert!(!entries.is_empty(), "expected spooled batches");
    }

    // ---------- t5-e2: PinnedTlsConnector wiring -----------------

    #[test]
    fn pinned_self_signed_without_pin_rejects() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = HttpsJsonlConfig::new("https://localhost/", tmp.path().to_path_buf());
        cfg.allow_self_signed = true;
        let r = spawn(cfg);
        assert!(
            matches!(r, Err(HttpsJsonlError::PinnedTls(_))),
            "expected PinnedTls error, got {:?}",
            r.err()
        );
    }

    #[test]
    fn pinned_config_default_fields_present() {
        // Sanity check that the t5-e2 fields are wired into defaults.
        let cfg = HttpsJsonlConfig::new("https://x", PathBuf::from("/tmp"));
        assert!(cfg.pin_spki_sha256.is_empty());
        assert!(!cfg.allow_self_signed);
        assert_eq!(cfg.max_cert_chain_depth, None);
    }

    #[test]
    fn pinned_config_accepts_explicit_pin_and_depth_cap() {
        // Builds via spt_trust directly — covers the runtime contract
        // without spinning up the writer task that would otherwise hang
        // waiting for a TLS peer.
        let pin =
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let r = spt_trust::PinnedTlsConnector::from_config_parts(&[pin], true, Some(5));
        assert!(r.is_ok(), "pinned tls: {:?}", r.err());
    }
}
