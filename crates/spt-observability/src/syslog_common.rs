//! Shared RFC 5424 syslog formatting and bounded tracing layer support.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{SecondsFormat, Utc};
use spt_core::{redact, RedactionMode};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Default private enterprise ID used for RFC 5424 structured data.
pub const DEFAULT_ENTERPRISE_ID: u32 = 32_473;

/// RFC 5424 rendering options shared by all syslog transports.
#[derive(Debug, Clone)]
pub struct SyslogRenderConfig {
    pub app_name: String,
    pub hostname: String,
    pub facility: u8,
    pub enterprise_id: u32,
    pub redact: RedactionMode,
}

impl SyslogRenderConfig {
    pub fn new(redact: RedactionMode) -> Self {
        Self {
            app_name: "spt".into(),
            hostname: hostname_or("localhost"),
            facility: 16,
            enterprise_id: DEFAULT_ENTERPRISE_ID,
            redact,
        }
    }
}

/// Monotonic counters for a remote syslog sink.
#[derive(Debug, Default)]
pub struct SyslogCounters {
    enqueued: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_closed: AtomicU64,
    truncated: AtomicU64,
    send_errors: AtomicU64,
    spooled: AtomicU64,
    reconnects: AtomicU64,
}

/// Snapshot of [`SyslogCounters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyslogCounterSnapshot {
    pub enqueued: u64,
    pub dropped_queue_full: u64,
    pub dropped_closed: u64,
    pub truncated: u64,
    pub send_errors: u64,
    pub spooled: u64,
    pub reconnects: u64,
}

impl SyslogCounters {
    pub fn snapshot(&self) -> SyslogCounterSnapshot {
        SyslogCounterSnapshot {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            dropped_queue_full: self.dropped_queue_full.load(Ordering::Relaxed),
            dropped_closed: self.dropped_closed.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            spooled: self.spooled.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn inc_truncated(&self) {
        self.truncated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_spooled(&self) {
        self.spooled.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bounded tracing layer used by the remote syslog writers.
pub struct SyslogLayer {
    pub(crate) tx: mpsc::Sender<Vec<u8>>,
    cfg: Arc<SyslogRenderConfig>,
    counters: Arc<SyslogCounters>,
    max_payload_bytes: Option<usize>,
}

impl SyslogLayer {
    pub(crate) fn new(
        tx: mpsc::Sender<Vec<u8>>,
        cfg: SyslogRenderConfig,
        counters: Arc<SyslogCounters>,
        max_payload_bytes: Option<usize>,
    ) -> Self {
        Self {
            tx,
            cfg: Arc::new(cfg),
            counters,
            max_payload_bytes,
        }
    }

    /// Queue an already-rendered record. Used by tests and CLI probes.
    pub fn try_send_raw(
        &self,
        mut payload: Vec<u8>,
    ) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        if let Some(max) = self.max_payload_bytes {
            if payload.len() > max {
                payload.truncate(max);
                self.counters.inc_truncated();
            }
        }
        match self.tx.try_send(payload) {
            Ok(()) => {
                self.counters.enqueued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(payload)) => {
                self.counters
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                Err(mpsc::error::TrySendError::Full(payload))
            }
            Err(mpsc::error::TrySendError::Closed(payload)) => {
                self.counters.dropped_closed.fetch_add(1, Ordering::Relaxed);
                Err(mpsc::error::TrySendError::Closed(payload))
            }
        }
    }

    pub fn counters(&self) -> Arc<SyslogCounters> {
        Arc::clone(&self.counters)
    }
}

impl<S> Layer<S> for SyslogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let payload = render_record(event, &self.cfg);
        let _ = self.try_send_raw(payload);
    }
}

pub(crate) fn hostname_or(default: &str) -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| default.into())
}

pub(crate) fn severity_code(level: tracing::Level) -> u8 {
    match level {
        tracing::Level::ERROR => 3,
        tracing::Level::WARN => 4,
        tracing::Level::INFO => 6,
        tracing::Level::DEBUG | tracing::Level::TRACE => 7,
    }
}

pub(crate) fn render_record(event: &Event<'_>, cfg: &SyslogRenderConfig) -> Vec<u8> {
    let meta = event.metadata();
    let facility = cfg.facility.min(23);
    let pri = u16::from(facility) * 8 + u16::from(severity_code(*meta.level()));
    let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

    let mut fields = FieldVisitor::default();
    event.record(&mut fields);
    let msg = fields.message.unwrap_or_else(|| meta.target().to_string());
    let msg_red = redact(&msg, cfg.redact);

    let sd = if fields.kvs.is_empty() {
        "-".to_string()
    } else {
        let mut s = format!("[spt@{}", cfg.enterprise_id);
        for (k, v) in &fields.kvs {
            s.push(' ');
            s.push_str(&sanitize_sd_name(k));
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

pub(crate) fn escape_sd_value(v: &str) -> String {
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

pub(crate) fn sanitize_token(s: &str, max: usize) -> String {
    let s: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '<' && *c != '>')
        .collect();
    if s.is_empty() {
        return "-".to_string();
    }
    if s.len() > max {
        s.chars().take(max).collect()
    } else {
        s
    }
}

fn sanitize_sd_name(s: &str) -> String {
    let out = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect::<String>();
    if out.is_empty() {
        "field".into()
    } else {
        out
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
    fn helper_formatting_matches_rfc5424_expectations() {
        let cfg = SyslogRenderConfig {
            app_name: "spt".into(),
            hostname: "host".into(),
            facility: 16,
            enterprise_id: DEFAULT_ENTERPRISE_ID,
            redact: RedactionMode::Standard,
        };
        let pri = u16::from(cfg.facility) * 8 + u16::from(severity_code(tracing::Level::INFO));
        assert_eq!(pri, 16 * 8 + 6);
        assert_eq!(escape_sd_value("a]b\"c"), "a\\]b\\\"c");
        assert_eq!(sanitize_token("a b", 10), "ab");
        assert_eq!(sanitize_token("", 10), "-");
        assert!(redact("hello world", cfg.redact).contains("hello"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_layer_drops_when_queue_full() {
        let (tx, mut rx) = mpsc::channel(1);
        let counters = Arc::new(SyslogCounters::default());
        let layer = SyslogLayer::new(
            tx,
            SyslogRenderConfig::new(RedactionMode::Standard),
            Arc::clone(&counters),
            None,
        );
        layer.try_send_raw(b"one".to_vec()).unwrap();
        assert!(matches!(
            layer.try_send_raw(b"two".to_vec()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(counters.snapshot().dropped_queue_full, 1);
        assert_eq!(rx.recv().await.unwrap(), b"one");
    }
}
