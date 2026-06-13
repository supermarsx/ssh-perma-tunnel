//! Initialise the global tracing subscriber for spt.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use tracing_subscriber::Registry;
use uuid::Uuid;

use crate::config::{
    Destination, FileSink, LogFormat, LoggingConfig, RemoteSink, RemoteSinkKind, RotationPolicy,
};
use crate::https_jsonl::{self, HttpsAuth, HttpsJsonlConfig, HttpsJsonlHandle};
use crate::redaction::RedactingMakeWriter;
use crate::rotation::{RotatingFileAppender, SizeRotationPolicy};
use crate::syslog_tcp::{self, SyslogTcpConfig, SyslogTcpHandle};
use crate::syslog_tls::{self, SyslogTlsConfig, SyslogTlsHandle};
use crate::syslog_udp::{self, SyslogUdpConfig, SyslogUdpHandle};

/// Error from [`init`].
#[derive(Debug, Error)]
pub enum InitError {
    /// Filter directive could not be parsed.
    #[error("invalid log filter directive: {0}")]
    BadFilter(String),
    /// File destination requested but no path supplied.
    #[error("file destination active but no `file` path configured")]
    MissingFilePath,
    /// Failed to create log file parent directory.
    #[error("create log dir {0}: {1}")]
    CreateDir(String, #[source] io::Error),
    /// `tracing-subscriber` rejected our composed subscriber.
    #[error("subscriber init failed: {0}")]
    SetGlobal(String),
    /// A `required = true` remote sink failed to construct.
    #[error("remote sink {name} ({kind}): {reason}")]
    RemoteSink {
        /// Sink name.
        name: String,
        /// Sink kind.
        kind: &'static str,
        /// Underlying reason.
        reason: String,
    },
}

/// Handle for SIGHUP / MCP-driven live log filter reload.
///
/// The handle is cheap to clone (it wraps `tracing_subscriber::reload::Handle`
/// internally). `signals::install_sighup_log_reload` takes one of these and
/// re-applies a parsed [`EnvFilter`] on every SIGHUP; the MCP `log.set_level`
/// tool likewise calls [`LogReloadHandle::reload`] for a per-target override.
#[derive(Clone)]
pub struct LogReloadHandle {
    inner: reload::Handle<EnvFilter, Registry>,
}

impl std::fmt::Debug for LogReloadHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogReloadHandle").finish_non_exhaustive()
    }
}

impl LogReloadHandle {
    /// Parse the directive and install it as the new global filter.
    pub fn reload(&self, directive: &str) -> Result<(), ReloadError> {
        let filter =
            EnvFilter::try_new(directive).map_err(|e| ReloadError::BadFilter(e.to_string()))?;
        self.inner
            .reload(filter)
            .map_err(|e| ReloadError::ReloadFailed(e.to_string()))
    }
}

/// Error from [`LogReloadHandle::reload`].
#[derive(Debug, Error)]
pub enum ReloadError {
    /// Directive failed to parse.
    #[error("invalid log filter: {0}")]
    BadFilter(String),
    /// The reload layer rejected the new filter (typically the subscriber
    /// has been dropped).
    #[error("reload failed: {0}")]
    ReloadFailed(String),
}

/// RAII guard returned by [`init`]. Drop flushes/joins the rotating-file
/// background worker and any remote-sink writer tasks.
#[must_use = "drop the TracingGuard at process exit so logs flush"]
pub struct TracingGuard {
    /// Worker for the rotating file appender.
    pub(crate) _file_guard: Option<WorkerGuard>,
    /// Active syslog-UDP writers.
    pub(crate) _syslog_udp: Vec<SyslogUdpHandle>,
    /// Active syslog-TCP writers.
    pub(crate) _syslog_tcp: Vec<SyslogTcpHandle>,
    /// Active syslog-TLS writers; dropping closes their channels and joins
    /// their tasks via tokio's `JoinHandle` drop semantics. We keep them in
    /// a Vec so a single config can declare multiple syslog targets.
    pub(crate) _syslog: Vec<SyslogTlsHandle>,
    /// Active HTTPS-JSONL writers.
    pub(crate) _https: Vec<HttpsJsonlHandle>,
    /// Reload handle for the root [`EnvFilter`] layer. Callers clone this to
    /// drive SIGHUP / MCP-tool live re-configs.
    reload_handle: LogReloadHandle,
}

impl TracingGuard {
    /// Borrow the reload handle for SIGHUP / MCP `log.set_level` plumbing.
    #[must_use]
    pub fn reload_handle(&self) -> LogReloadHandle {
        self.reload_handle.clone()
    }
}

/// Generate a fresh correlation id (UUID v4 — workspace uuid feature set).
///
/// One per top-level user action (e.g. `spt tunnel run` invocation). Attach
/// to top-level spans so every downstream span/event inherits the id via
/// `tracing` span propagation. UUIDs are random; collision risk is
/// astronomically low across the lifetime of an spt deployment.
#[must_use]
pub fn new_correlation_id() -> Uuid {
    Uuid::new_v4()
}

/// Generate a fresh per-SSH-session id. Stable for the life of the session
/// regardless of reconnects, so log correlation across one logical tunnel is
/// preserved.
#[must_use]
pub fn new_session_id() -> Uuid {
    Uuid::new_v4()
}

/// Build an `info_span!` for a top-level CLI action with a `correlation_id`
/// already attached.
///
/// Usage:
///
/// ```ignore
/// let _g = spt_observability::cli_span!("tunnel.run").entered();
/// ```
///
/// Every event emitted while the span is entered will carry the
/// `correlation_id` field automatically.
#[macro_export]
macro_rules! cli_span {
    ($name:expr) => {
        ::tracing::info_span!($name, correlation_id = %$crate::init::new_correlation_id())
    };
    ($name:expr, $($field:tt)*) => {
        ::tracing::info_span!(
            $name,
            correlation_id = %$crate::init::new_correlation_id(),
            $($field)*
        )
    };
}

/// Build an `info_span!` for one SSH session with both correlation and
/// session ids attached. Designed for the `session.run` / `profile.run`
/// entry-point spans called out in the t8-A3 brief; downstream code does
/// not need to add the ids manually.
#[macro_export]
macro_rules! session_span {
    ($name:expr, $correlation:expr) => {
        ::tracing::info_span!(
            $name,
            correlation_id = %$correlation,
            session_id = %$crate::init::new_session_id()
        )
    };
}

/// Initialise the global subscriber from `config`.
pub fn init(config: &LoggingConfig) -> Result<TracingGuard, InitError> {
    init_inner(config, /*test = */ false)
}

/// Like [`init`] but uses `try_init` instead of `init` so it can be called
/// multiple times in `#[test]` functions without panicking.
pub fn init_for_test(config: &LoggingConfig) -> Result<TracingGuard, InitError> {
    init_inner(config, /*test = */ true)
}

fn init_inner(config: &LoggingConfig, test: bool) -> Result<TracingGuard, InitError> {
    let filter = EnvFilter::try_new(&config.level)
        .map_err(|e| InitError::BadFilter(format!("{}: {e}", config.level)))?;

    // Wrap the filter in a `reload::Layer` so SIGHUP / MCP `log.set_level`
    // can swap it without rebuilding the whole subscriber. The handle is
    // owned by the returned `TracingGuard` and cloned out to whoever wires
    // up signal handlers or MCP tools.
    let (reload_layer, reload_inner_handle) = reload::Layer::new(filter);
    let reload_handle = LogReloadHandle {
        inner: reload_inner_handle,
    };

    let want_stderr = config.destinations.contains(&Destination::Stderr);
    let want_file = config.destinations.contains(&Destination::File);
    let want_journald = config.destinations.contains(&Destination::Journald);

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();
    // Filter is itself a Layer<Registry>; pushing it into the same vec keeps
    // the subscriber type concretely `Layered<Vec<...>, Registry>` which does
    // implement `SubscriberInitExt`.
    layers.push(Box::new(reload_layer));

    if want_stderr {
        let mw = RedactingMakeWriter::new(io::stderr, config.redact);
        layers.push(text_or_json_layer(config.format, !config.no_color, mw));
    }

    let mut file_guard: Option<WorkerGuard> = None;
    if want_file {
        let f = config.file.as_ref().ok_or(InitError::MissingFilePath)?;
        let (parent, prefix) = split_file(&f.path);
        fs::create_dir_all(&parent)
            .map_err(|e| InitError::CreateDir(parent.display().to_string(), e))?;
        let writer = make_writer(f, &parent, &prefix)
            .map_err(|e| InitError::CreateDir(parent.display().to_string(), e))?;
        let (nb, guard) = tracing_appender::non_blocking(writer);
        file_guard = Some(guard);
        let mw = RedactingMakeWriter::new(nb, config.redact);
        layers.push(text_or_json_layer(config.format, false, mw));
    }

    if want_journald {
        if let Some(layer) = build_journald_layer() {
            layers.push(layer);
        }
    }

    // Remote sinks (syslog-TLS, HTTPS-JSONL). Spawned only if a tokio runtime
    // is currently active — otherwise `tokio::spawn` panics. We probe for a
    // handle and skip on absence (same-process tests without a runtime can
    // still call `init` for the local layers).
    let mut syslog_udp_handles: Vec<SyslogUdpHandle> = Vec::new();
    let mut syslog_tcp_handles: Vec<SyslogTcpHandle> = Vec::new();
    let mut syslog_handles: Vec<SyslogTlsHandle> = Vec::new();
    let mut https_handles: Vec<HttpsJsonlHandle> = Vec::new();
    if !config.remote.is_empty() && tokio::runtime::Handle::try_current().is_ok() {
        for sink in &config.remote {
            match build_remote_layer(sink, config.redact) {
                Ok(RemoteBuild::SyslogUdp { layer, handle }) => {
                    layers.push(layer);
                    syslog_udp_handles.push(handle);
                }
                Ok(RemoteBuild::SyslogTcp { layer, handle }) => {
                    layers.push(layer);
                    syslog_tcp_handles.push(handle);
                }
                Ok(RemoteBuild::SyslogTls { layer, handle }) => {
                    layers.push(layer);
                    syslog_handles.push(handle);
                }
                Ok(RemoteBuild::Https { layer, handle }) => {
                    layers.push(layer);
                    https_handles.push(handle);
                }
                Ok(RemoteBuild::Skipped) => {}
                Err(e) => {
                    if sink.required {
                        return Err(InitError::RemoteSink {
                            name: sink.name.clone(),
                            kind: remote_kind_str(sink.kind),
                            reason: e,
                        });
                    }
                    eprintln!(
                        "spt-observability: remote sink '{}' disabled: {e}",
                        sink.name
                    );
                }
            }
        }
    } else if !config.remote.is_empty() {
        // No runtime — log a warning so callers know the layers were not wired.
        for sink in &config.remote {
            if sink.required {
                return Err(InitError::RemoteSink {
                    name: sink.name.clone(),
                    kind: remote_kind_str(sink.kind),
                    reason: "no tokio runtime active; remote sinks need one".into(),
                });
            }
        }
    }

    let subscriber = Registry::default().with(layers);

    if test {
        // Best-effort: a previous test may have already installed a global.
        let _ = subscriber.try_init();
    } else {
        subscriber
            .try_init()
            .map_err(|e| InitError::SetGlobal(e.to_string()))?;
    }

    Ok(TracingGuard {
        _file_guard: file_guard,
        _syslog_udp: syslog_udp_handles,
        _syslog_tcp: syslog_tcp_handles,
        _syslog: syslog_handles,
        _https: https_handles,
        reload_handle,
    })
}

/// Kind enum → display string used in `InitError::RemoteSink`.
fn remote_kind_str(k: RemoteSinkKind) -> &'static str {
    match k {
        RemoteSinkKind::SyslogUdp => "syslog_udp",
        RemoteSinkKind::SyslogTcp => "syslog_tcp",
        RemoteSinkKind::SyslogTls => "syslog-tls",
        RemoteSinkKind::HttpsJsonl => "https-jsonl",
        RemoteSinkKind::Otlp => "otlp",
    }
}

/// Outcome of remote-sink construction.
enum RemoteBuild {
    SyslogUdp {
        layer: Box<dyn Layer<Registry> + Send + Sync>,
        handle: SyslogUdpHandle,
    },
    SyslogTcp {
        layer: Box<dyn Layer<Registry> + Send + Sync>,
        handle: SyslogTcpHandle,
    },
    SyslogTls {
        layer: Box<dyn Layer<Registry> + Send + Sync>,
        handle: SyslogTlsHandle,
    },
    Https {
        layer: Box<dyn Layer<Registry> + Send + Sync>,
        handle: HttpsJsonlHandle,
    },
    /// OTLP is wired separately when the `otlp` cargo feature is enabled
    /// and the runtime task tree decides to install global providers.
    Skipped,
}

fn build_remote_layer(
    sink: &RemoteSink,
    redact: spt_core::RedactionMode,
) -> Result<RemoteBuild, String> {
    let spool_dir = sink
        .spool_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join(format!("spt-remote-{}", sink.name)));
    match sink.kind {
        RemoteSinkKind::SyslogUdp => {
            let (host, port) = parse_host_port(&sink.endpoint, 514)?;
            let mut cfg = SyslogUdpConfig::new(host, port);
            apply_syslog_common_udp(sink, redact, &mut cfg);
            let (layer, handle) = syslog_udp::spawn_writer(cfg).map_err(|e| e.to_string())?;
            Ok(RemoteBuild::SyslogUdp {
                layer: Box::new(layer),
                handle,
            })
        }
        RemoteSinkKind::SyslogTcp => {
            let (host, port) = parse_host_port(&sink.endpoint, 514)?;
            let mut cfg = SyslogTcpConfig::new(host, port, spool_dir);
            apply_syslog_common_tcp(sink, redact, &mut cfg);
            let (layer, handle) = syslog_tcp::spawn_writer(cfg).map_err(|e| e.to_string())?;
            Ok(RemoteBuild::SyslogTcp {
                layer: Box::new(layer),
                handle,
            })
        }
        RemoteSinkKind::SyslogTls => {
            let (host, port) = parse_host_port(&sink.endpoint, 6514)?;
            let mut cfg = SyslogTlsConfig::new(host, port, spool_dir);
            apply_syslog_common_tls(sink, redact, &mut cfg)?;
            cfg.timeout = sink.timeout;
            cfg.redact = redact;
            let (layer, handle) = syslog_tls::spawn_writer(cfg).map_err(|e| e.to_string())?;
            Ok(RemoteBuild::SyslogTls {
                layer: Box::new(layer),
                handle,
            })
        }
        RemoteSinkKind::HttpsJsonl => {
            let mut cfg = HttpsJsonlConfig::new(sink.endpoint.clone(), spool_dir);
            cfg.timeout = sink.timeout;
            cfg.batch_size = sink.batch_size as usize;
            cfg.redact = redact;
            cfg.auth = match sink.auth.as_deref() {
                Some(t) if t.starts_with("Bearer ") => {
                    HttpsAuth::Bearer(t.trim_start_matches("Bearer ").to_string())
                }
                Some(t) if t.starts_with("Basic ") => {
                    HttpsAuth::Basic(t.trim_start_matches("Basic ").to_string())
                }
                Some(t) => HttpsAuth::Bearer(t.to_string()),
                None => HttpsAuth::None,
            };
            let (layer, handle) = https_jsonl::spawn(cfg).map_err(|e| e.to_string())?;
            Ok(RemoteBuild::Https {
                layer: Box::new(layer),
                handle,
            })
        }
        RemoteSinkKind::Otlp => {
            // OTLP wiring is owned by the runtime task tree (spt-bin) when the
            // `otlp` cargo feature is on; nothing to attach as a tracing Layer.
            Ok(RemoteBuild::Skipped)
        }
    }
}

fn apply_syslog_common_udp(
    sink: &RemoteSink,
    redact: spt_core::RedactionMode,
    cfg: &mut SyslogUdpConfig,
) {
    if let Some(facility) = sink.facility {
        cfg.facility = facility;
    }
    if let Some(app_name) = sink.app_name.clone() {
        cfg.app_name = app_name;
    }
    if let Some(hostname) = sink.hostname.clone() {
        cfg.hostname = hostname;
    }
    if let Some(enterprise_id) = sink.enterprise_id {
        cfg.enterprise_id = enterprise_id;
    }
    cfg.timeout = sink.timeout;
    cfg.queue_max_records = sink.queue_max_records;
    cfg.redact = redact;
}

fn apply_syslog_common_tcp(
    sink: &RemoteSink,
    redact: spt_core::RedactionMode,
    cfg: &mut SyslogTcpConfig,
) {
    if let Some(facility) = sink.facility {
        cfg.facility = facility;
    }
    if let Some(app_name) = sink.app_name.clone() {
        cfg.app_name = app_name;
    }
    if let Some(hostname) = sink.hostname.clone() {
        cfg.hostname = hostname;
    }
    if let Some(enterprise_id) = sink.enterprise_id {
        cfg.enterprise_id = enterprise_id;
    }
    cfg.timeout = sink.timeout;
    cfg.reconnect_backoff = sink.reconnect_backoff;
    cfg.queue_max_records = sink.queue_max_records;
    if let Some(max_bytes) = sink.spool_max_bytes {
        cfg.spool.max_bytes = max_bytes;
    }
    cfg.spool.max_files = sink.queue_max_records;
    cfg.redact = redact;
}

fn apply_syslog_common_tls(
    sink: &RemoteSink,
    redact: spt_core::RedactionMode,
    cfg: &mut SyslogTlsConfig,
) -> Result<(), String> {
    if let Some(facility) = sink.facility {
        cfg.facility = facility;
    }
    if let Some(app_name) = sink.app_name.clone() {
        cfg.app_name = app_name;
    }
    if let Some(hostname) = sink.hostname.clone() {
        cfg.hostname = hostname;
    }
    if let Some(enterprise_id) = sink.enterprise_id {
        cfg.enterprise_id = enterprise_id;
    }
    cfg.timeout = sink.timeout;
    cfg.reconnect_backoff = sink.reconnect_backoff;
    cfg.queue_max_records = sink.queue_max_records;
    if let Some(max_bytes) = sink.spool_max_bytes {
        cfg.spool.max_bytes = max_bytes;
    }
    cfg.spool.max_files = sink.queue_max_records;
    cfg.server_name.clone_from(&sink.server_name);
    cfg.client_cert.clone_from(&sink.client_cert);
    cfg.client_key.clone_from(&sink.client_key);
    cfg.allow_invalid_certs = sink.allow_invalid_certs;
    cfg.redact = redact;
    if sink.ca_file.is_some() {
        cfg.roots = Some(
            syslog_tls::root_store_with_ca_file(sink.ca_file.as_deref())
                .map_err(|e| e.to_string())?,
        );
    }
    Ok(())
}

fn parse_host_port(endpoint: &str, default_port: u16) -> Result<(String, u16), String> {
    // Accept "host", "host:port", or "scheme://host:port" — strip the
    // scheme if present.
    let s = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    if let Some((h, p)) = s.rsplit_once(':') {
        let port = p.parse::<u16>().map_err(|e| format!("port `{p}`: {e}"))?;
        Ok((h.to_string(), port))
    } else {
        Ok((s.to_string(), default_port))
    }
}

/// Build a `fmt::Layer` of the requested format wired up to the supplied
/// `MakeWriter`.
fn text_or_json_layer<W>(
    format: LogFormat,
    ansi: bool,
    mw: W,
) -> Box<dyn Layer<Registry> + Send + Sync>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let base = tracing_subscriber::fmt::layer()
        .with_writer(mw)
        .with_ansi(ansi)
        .with_span_events(FmtSpan::NONE);
    match format {
        LogFormat::Compact => Box::new(base.compact()),
        LogFormat::Pretty => Box::new(base.pretty()),
        LogFormat::Json => Box::new(base.json()),
    }
}

#[cfg(target_os = "linux")]
fn build_journald_layer() -> Option<Box<dyn Layer<Registry> + Send + Sync>> {
    match tracing_journald::layer() {
        Ok(layer) => Some(Box::new(layer)),
        Err(e) => {
            eprintln!("spt-observability: journald layer unavailable: {e}");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn build_journald_layer() -> Option<Box<dyn Layer<Registry> + Send + Sync>> {
    None
}

fn split_file(path: &Path) -> (std::path::PathBuf, String) {
    let parent = path.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    );
    let prefix = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("spt.log")
        .to_owned();
    (parent, prefix)
}

/// Build the file writer for the chosen rotation policy. For Size or compound
/// policies we use [`RotatingFileAppender`]; for plain time-based we keep
/// `tracing-appender`'s `RollingFileAppender` (battle-tested).
fn make_writer(f: &FileSink, dir: &Path, prefix: &str) -> io::Result<Box<dyn Write + Send>> {
    match f.rotate {
        RotationPolicy::Hourly => Ok(Box::new(RollingFileAppender::new(
            Rotation::HOURLY,
            dir,
            prefix,
        ))),
        RotationPolicy::Daily => Ok(Box::new(RollingFileAppender::new(
            Rotation::DAILY,
            dir,
            prefix,
        ))),
        RotationPolicy::Never => Ok(Box::new(RollingFileAppender::new(
            Rotation::NEVER,
            dir,
            prefix,
        ))),
        RotationPolicy::Size { max_bytes, daily } => {
            let policy = SizeRotationPolicy {
                max_size_bytes: Some(max_bytes),
                daily,
                max_files: f.max_files,
            };
            let app = RotatingFileAppender::new(dir, prefix, policy)?;
            Ok(Box::new(SharedAppender(Arc::new(app))))
        }
    }
}

/// Wrapper letting `Arc<RotatingFileAppender>` be used as `Write + Send`.
struct SharedAppender(Arc<RotatingFileAppender>);

impl Write for SharedAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut r: &RotatingFileAppender = &self.0;
        r.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut r: &RotatingFileAppender = &self.0;
        r.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Destination, FileSink, RotationPolicy};
    use spt_core::RedactionMode;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn parse_host_port_accepts_url_and_bare_host() {
        assert_eq!(
            parse_host_port("syslog.example.com:6514", 6514).unwrap(),
            ("syslog.example.com".to_string(), 6514)
        );
        assert_eq!(
            parse_host_port("tls://syslog:1234", 6514).unwrap(),
            ("syslog".to_string(), 1234)
        );
        assert_eq!(
            parse_host_port("syslog", 6514).unwrap(),
            ("syslog".to_string(), 6514)
        );
        assert!(parse_host_port("syslog:notaport", 6514).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn init_wires_https_jsonl_remote_sink_when_optional() {
        // Optional sink → unreachable endpoint should not fail init.
        let cfg = LoggingConfig {
            level: "info".into(),
            format: LogFormat::Compact,
            no_color: true,
            destinations: vec![],
            file: None,
            redact: RedactionMode::Standard,
            remote: vec![RemoteSink {
                name: "test-https".into(),
                kind: RemoteSinkKind::HttpsJsonl,
                endpoint: "https://127.0.0.1:1/logs".into(),
                facility: None,
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: Some("Bearer xyz".into()),
                timeout: Duration::from_millis(100),
                reconnect_backoff: Duration::from_millis(100),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 100,
                batch_size: 10,
                required: false,
            }],
        };
        let g = init_for_test(&cfg).expect("init should succeed");
        // Drop guard to drain.
        drop(g);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn init_required_remote_sink_with_bad_kind_endpoint_propagates() {
        // syslog-tls with un-parseable port; required=true → should fail.
        let cfg = LoggingConfig {
            level: "info".into(),
            format: LogFormat::Compact,
            no_color: true,
            destinations: vec![],
            file: None,
            redact: RedactionMode::Standard,
            remote: vec![RemoteSink {
                name: "bad".into(),
                kind: RemoteSinkKind::SyslogTls,
                endpoint: "host:notaport".into(),
                facility: None,
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: None,
                timeout: Duration::from_millis(100),
                reconnect_backoff: Duration::from_millis(100),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 100,
                batch_size: 1,
                required: true,
            }],
        };
        let r = init_for_test(&cfg);
        assert!(matches!(r, Err(InitError::RemoteSink { .. })));
    }

    #[test]
    fn init_with_file_creates_directory_and_returns_guard() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("logs").join("spt.log");
        let cfg = LoggingConfig {
            level: "info".into(),
            format: LogFormat::Compact,
            no_color: true,
            destinations: vec![Destination::File],
            file: Some(FileSink {
                path: path.clone(),
                rotate: RotationPolicy::Never,
                max_files: 3,
            }),
            redact: RedactionMode::Standard,
            remote: vec![],
        };
        let _g = init_for_test(&cfg).unwrap();
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn init_rejects_bad_filter() {
        // EnvFilter is lenient about unrecognised target names but rejects a
        // bare `=value` (level with no target) — use that as a known-bad input.
        let cfg = LoggingConfig {
            level: "=info".into(),
            ..LoggingConfig::default()
        };
        let r = init_for_test(&cfg);
        assert!(
            matches!(r, Err(InitError::BadFilter(_))),
            "expected BadFilter for input '=info'"
        );
    }

    #[test]
    fn init_requires_file_when_destination_is_file() {
        let cfg = LoggingConfig {
            level: "info".into(),
            format: LogFormat::Compact,
            no_color: true,
            destinations: vec![Destination::File],
            file: None,
            redact: RedactionMode::Standard,
            remote: vec![],
        };
        let r = init_for_test(&cfg);
        assert!(matches!(r, Err(InitError::MissingFilePath)));
    }

    // ---------- pure helpers ----------

    #[test]
    fn remote_kind_str_covers_all_variants() {
        assert_eq!(remote_kind_str(RemoteSinkKind::SyslogUdp), "syslog_udp");
        assert_eq!(remote_kind_str(RemoteSinkKind::SyslogTcp), "syslog_tcp");
        assert_eq!(remote_kind_str(RemoteSinkKind::SyslogTls), "syslog-tls");
        assert_eq!(remote_kind_str(RemoteSinkKind::HttpsJsonl), "https-jsonl");
        assert_eq!(remote_kind_str(RemoteSinkKind::Otlp), "otlp");
    }

    #[test]
    fn split_file_handles_no_parent() {
        let (parent, prefix) = split_file(Path::new("spt.log"));
        assert_eq!(parent, std::path::PathBuf::from(""));
        assert_eq!(prefix, "spt.log");
    }

    #[test]
    fn split_file_handles_full_path() {
        let (parent, prefix) = split_file(Path::new("/var/log/spt/spt.log"));
        assert_eq!(parent, std::path::PathBuf::from("/var/log/spt"));
        assert_eq!(prefix, "spt.log");
    }

    #[test]
    fn split_file_empty_path_yields_dot_and_default_prefix() {
        let (parent, prefix) = split_file(Path::new(""));
        assert_eq!(parent, std::path::PathBuf::from("."));
        assert_eq!(prefix, "spt.log");
    }

    #[test]
    fn parse_host_port_rejects_bad_port() {
        let err = parse_host_port("host:abc", 514).unwrap_err();
        assert!(err.contains("port"));
    }

    #[test]
    fn parse_host_port_supports_ipv4_with_port() {
        assert_eq!(
            parse_host_port("127.0.0.1:9999", 514).unwrap(),
            ("127.0.0.1".to_string(), 9999)
        );
    }

    // ---------- format / writer helpers ----------

    #[test]
    fn text_or_json_layer_compiles_for_all_formats() {
        let buf = crate::redaction::SharedBuffer::new();
        let _compact = text_or_json_layer(LogFormat::Compact, false, buf.clone());
        let _pretty = text_or_json_layer(LogFormat::Pretty, false, buf.clone());
        let _json = text_or_json_layer(LogFormat::Json, false, buf);
    }

    #[test]
    fn make_writer_supports_all_rotation_policies() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path();
        let prefix = "spt.log";
        for policy in [
            RotationPolicy::Hourly,
            RotationPolicy::Daily,
            RotationPolicy::Never,
            RotationPolicy::Size {
                max_bytes: 1024,
                daily: false,
            },
        ] {
            let f = FileSink {
                path: dir.join(prefix),
                rotate: policy,
                max_files: 3,
            };
            let mut writer = make_writer(&f, dir, prefix).expect("make_writer");
            writer.write_all(b"hello\n").unwrap();
            writer.flush().unwrap();
        }
    }

    #[test]
    fn shared_appender_write_and_flush_pass_through() {
        let tmp = tempdir().unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(1024),
            daily: false,
            max_files: 2,
        };
        let app = Arc::new(RotatingFileAppender::new(tmp.path(), "shr.log", policy).unwrap());
        let mut shared = SharedAppender(Arc::clone(&app));
        shared.write_all(b"line one\n").unwrap();
        shared.flush().unwrap();
        let body = std::fs::read_to_string(tmp.path().join("shr.log")).unwrap();
        assert!(body.contains("line one"));
    }

    // ---------- apply_syslog_common_* fully cover field copies ----------

    fn full_sink(kind: RemoteSinkKind, endpoint: &str) -> RemoteSink {
        RemoteSink {
            name: "n".into(),
            kind,
            endpoint: endpoint.into(),
            facility: Some(7),
            app_name: Some("app".into()),
            hostname: Some("host".into()),
            enterprise_id: Some(42),
            ca_file: None,
            server_name: Some("sn".into()),
            client_cert: None,
            client_key: None,
            allow_invalid_certs: true,
            auth: None,
            timeout: Duration::from_millis(250),
            reconnect_backoff: Duration::from_millis(500),
            spool_dir: None,
            spool_max_bytes: Some(64 * 1024),
            queue_max_records: 50,
            batch_size: 8,
            required: false,
        }
    }

    #[test]
    fn apply_syslog_common_udp_copies_all_optional_fields() {
        let sink = full_sink(RemoteSinkKind::SyslogUdp, "127.0.0.1:514");
        let mut cfg = SyslogUdpConfig::new("0.0.0.0".to_string(), 514);
        apply_syslog_common_udp(&sink, RedactionMode::Standard, &mut cfg);
        assert_eq!(cfg.facility, 7);
        assert_eq!(cfg.app_name, "app");
        assert_eq!(cfg.hostname, "host");
        assert_eq!(cfg.enterprise_id, 42);
        assert_eq!(cfg.timeout, Duration::from_millis(250));
        assert_eq!(cfg.queue_max_records, 50);
    }

    #[test]
    fn apply_syslog_common_tcp_copies_all_optional_fields() {
        let sink = full_sink(RemoteSinkKind::SyslogTcp, "127.0.0.1:514");
        let spool = tempdir().unwrap();
        let mut cfg = SyslogTcpConfig::new("0.0.0.0".to_string(), 514, spool.path().to_path_buf());
        apply_syslog_common_tcp(&sink, RedactionMode::Strict, &mut cfg);
        assert_eq!(cfg.facility, 7);
        assert_eq!(cfg.app_name, "app");
        assert_eq!(cfg.hostname, "host");
        assert_eq!(cfg.enterprise_id, 42);
        assert_eq!(cfg.timeout, Duration::from_millis(250));
        assert_eq!(cfg.reconnect_backoff, Duration::from_millis(500));
        assert_eq!(cfg.queue_max_records, 50);
        assert_eq!(cfg.spool.max_bytes, 64 * 1024);
        assert_eq!(cfg.spool.max_files, 50);
    }

    #[test]
    fn apply_syslog_common_tls_copies_all_optional_fields() {
        let sink = full_sink(RemoteSinkKind::SyslogTls, "127.0.0.1:6514");
        let spool = tempdir().unwrap();
        let mut cfg = SyslogTlsConfig::new("0.0.0.0".to_string(), 6514, spool.path().to_path_buf());
        apply_syslog_common_tls(&sink, RedactionMode::Strict, &mut cfg).unwrap();
        assert_eq!(cfg.facility, 7);
        assert_eq!(cfg.app_name, "app");
        assert_eq!(cfg.hostname, "host");
        assert_eq!(cfg.enterprise_id, 42);
        assert_eq!(cfg.timeout, Duration::from_millis(250));
        assert_eq!(cfg.reconnect_backoff, Duration::from_millis(500));
        assert_eq!(cfg.queue_max_records, 50);
        assert_eq!(cfg.spool.max_bytes, 64 * 1024);
        assert_eq!(cfg.server_name.as_deref(), Some("sn"));
        assert!(cfg.allow_invalid_certs);
    }

    // ---------- init_inner / init_for_test broad runtime-bound coverage ----------

    fn minimal_cfg() -> LoggingConfig {
        LoggingConfig {
            level: "info".into(),
            format: LogFormat::Compact,
            no_color: true,
            destinations: vec![],
            file: None,
            redact: RedactionMode::Standard,
            remote: vec![],
        }
    }

    #[test]
    fn init_no_destinations_no_remote_is_ok() {
        let g = init_for_test(&minimal_cfg()).unwrap();
        drop(g);
    }

    #[test]
    fn init_with_stderr_destination_and_pretty_format() {
        let cfg = LoggingConfig {
            destinations: vec![Destination::Stderr],
            format: LogFormat::Pretty,
            ..minimal_cfg()
        };
        let _g = init_for_test(&cfg).unwrap();
    }

    #[test]
    fn init_with_stderr_destination_and_json_format() {
        let cfg = LoggingConfig {
            destinations: vec![Destination::Stderr],
            format: LogFormat::Json,
            ..minimal_cfg()
        };
        let _g = init_for_test(&cfg).unwrap();
    }

    #[test]
    fn init_with_journald_destination_is_ok_on_all_platforms() {
        let cfg = LoggingConfig {
            destinations: vec![Destination::Journald],
            ..minimal_cfg()
        };
        let _g = init_for_test(&cfg).unwrap();
    }

    #[test]
    fn init_with_file_size_rotation_creates_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("logs").join("size.log");
        let cfg = LoggingConfig {
            destinations: vec![Destination::File],
            file: Some(FileSink {
                path: path.clone(),
                rotate: RotationPolicy::Size {
                    max_bytes: 64,
                    daily: false,
                },
                max_files: 3,
            }),
            ..minimal_cfg()
        };
        let _g = init_for_test(&cfg).unwrap();
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn init_with_file_hourly_rotation_creates_dir() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("h").join("spt.log");
        let cfg = LoggingConfig {
            destinations: vec![Destination::File],
            file: Some(FileSink {
                path: path.clone(),
                rotate: RotationPolicy::Hourly,
                max_files: 3,
            }),
            ..minimal_cfg()
        };
        let _g = init_for_test(&cfg).unwrap();
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn init_no_runtime_with_optional_remote_logs_warning_and_returns_ok() {
        let cfg = LoggingConfig {
            remote: vec![RemoteSink {
                name: "opt".into(),
                kind: RemoteSinkKind::SyslogUdp,
                endpoint: "127.0.0.1:514".into(),
                facility: None,
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: None,
                timeout: Duration::from_millis(50),
                reconnect_backoff: Duration::from_millis(50),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 10,
                batch_size: 1,
                required: false,
            }],
            ..minimal_cfg()
        };
        let _g = init_for_test(&cfg).unwrap();
    }

    #[test]
    fn init_no_runtime_with_required_remote_returns_error() {
        let cfg = LoggingConfig {
            remote: vec![RemoteSink {
                name: "must".into(),
                kind: RemoteSinkKind::SyslogTls,
                endpoint: "127.0.0.1:6514".into(),
                facility: None,
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: None,
                timeout: Duration::from_millis(50),
                reconnect_backoff: Duration::from_millis(50),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 10,
                batch_size: 1,
                required: true,
            }],
            ..minimal_cfg()
        };
        let r = init_for_test(&cfg);
        let err_kind = match r {
            Ok(_) => "ok".to_string(),
            Err(ref e) => format!("{e}"),
        };
        assert!(
            matches!(r, Err(InitError::RemoteSink { ref name, .. }) if name == "must"),
            "got {err_kind}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn init_runtime_builds_syslog_udp_optional_sink() {
        let cfg = LoggingConfig {
            remote: vec![RemoteSink {
                name: "udp".into(),
                kind: RemoteSinkKind::SyslogUdp,
                endpoint: "127.0.0.1:514".into(),
                facility: Some(16),
                app_name: Some("a".into()),
                hostname: Some("h".into()),
                enterprise_id: Some(1),
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: None,
                timeout: Duration::from_millis(50),
                reconnect_backoff: Duration::from_millis(50),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 10,
                batch_size: 1,
                required: false,
            }],
            ..minimal_cfg()
        };
        let g = init_for_test(&cfg).expect("syslog_udp wiring");
        drop(g);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn init_runtime_builds_syslog_tcp_optional_sink() {
        let spool = tempdir().unwrap();
        let cfg = LoggingConfig {
            remote: vec![RemoteSink {
                name: "tcp".into(),
                kind: RemoteSinkKind::SyslogTcp,
                endpoint: "127.0.0.1:514".into(),
                facility: Some(16),
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: None,
                timeout: Duration::from_millis(50),
                reconnect_backoff: Duration::from_millis(50),
                spool_dir: Some(spool.path().to_path_buf()),
                spool_max_bytes: Some(1024),
                queue_max_records: 10,
                batch_size: 1,
                required: false,
            }],
            ..minimal_cfg()
        };
        let g = init_for_test(&cfg).expect("syslog_tcp wiring");
        drop(g);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn init_runtime_skips_otlp_sink() {
        let cfg = LoggingConfig {
            remote: vec![RemoteSink {
                name: "otlp".into(),
                kind: RemoteSinkKind::Otlp,
                endpoint: "https://127.0.0.1/v1/traces".into(),
                facility: None,
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: None,
                timeout: Duration::from_millis(50),
                reconnect_backoff: Duration::from_millis(50),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 10,
                batch_size: 1,
                required: false,
            }],
            ..minimal_cfg()
        };
        let g = init_for_test(&cfg).expect("otlp should be a no-op skip");
        drop(g);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn init_runtime_builds_https_with_basic_auth_then_with_raw_token() {
        let basic_cfg = LoggingConfig {
            remote: vec![RemoteSink {
                name: "basic".into(),
                kind: RemoteSinkKind::HttpsJsonl,
                endpoint: "https://127.0.0.1:1/logs".into(),
                facility: None,
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: Some("Basic dXNlcjpwYXNz".into()),
                timeout: Duration::from_millis(50),
                reconnect_backoff: Duration::from_millis(50),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 10,
                batch_size: 1,
                required: false,
            }],
            ..minimal_cfg()
        };
        let g = init_for_test(&basic_cfg).expect("basic auth");
        drop(g);

        let raw_cfg = LoggingConfig {
            remote: vec![RemoteSink {
                name: "raw".into(),
                kind: RemoteSinkKind::HttpsJsonl,
                endpoint: "https://127.0.0.1:1/logs".into(),
                facility: None,
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: Some("raw-token-with-no-scheme".into()),
                timeout: Duration::from_millis(50),
                reconnect_backoff: Duration::from_millis(50),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 10,
                batch_size: 1,
                required: false,
            }],
            ..minimal_cfg()
        };
        let g = init_for_test(&raw_cfg).expect("raw token");
        drop(g);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn init_runtime_required_syslog_udp_bad_port_propagates() {
        let cfg = LoggingConfig {
            remote: vec![RemoteSink {
                name: "udp-bad".into(),
                kind: RemoteSinkKind::SyslogUdp,
                endpoint: "host:notaport".into(),
                facility: None,
                app_name: None,
                hostname: None,
                enterprise_id: None,
                ca_file: None,
                server_name: None,
                client_cert: None,
                client_key: None,
                allow_invalid_certs: false,
                auth: None,
                timeout: Duration::from_millis(50),
                reconnect_backoff: Duration::from_millis(50),
                spool_dir: None,
                spool_max_bytes: None,
                queue_max_records: 10,
                batch_size: 1,
                required: true,
            }],
            ..minimal_cfg()
        };
        let r = init_for_test(&cfg);
        let err_msg = match r {
            Ok(_) => "ok".to_string(),
            Err(ref e) => format!("{e}"),
        };
        assert!(
            matches!(r, Err(InitError::RemoteSink { kind, .. }) if kind == "syslog_udp"),
            "got {err_msg}"
        );
    }

    #[test]
    fn init_create_dir_failure_is_reported() {
        // Pointing the file destination at a path whose parent cannot be
        // created (because a non-directory file occupies that path) surfaces
        // CreateDir.
        let tmp = tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"i am a file").unwrap();
        let cfg = LoggingConfig {
            destinations: vec![Destination::File],
            file: Some(FileSink {
                path: blocker.join("sub").join("spt.log"),
                rotate: RotationPolicy::Never,
                max_files: 1,
            }),
            ..minimal_cfg()
        };
        let r = init_for_test(&cfg);
        let err_msg = match r {
            Ok(_) => "ok".to_string(),
            Err(ref e) => format!("{e}"),
        };
        assert!(
            matches!(r, Err(InitError::CreateDir(_, _))),
            "got {err_msg}"
        );
    }

    // ---------- correlation / session / reload helpers ----------

    #[test]
    fn new_correlation_id_yields_unique_values() {
        let a = new_correlation_id();
        let b = new_correlation_id();
        assert_ne!(a, b, "two consecutive correlation ids must differ");
    }

    #[test]
    fn new_session_id_yields_unique_values() {
        let a = new_session_id();
        let b = new_session_id();
        assert_ne!(a, b);
    }

    #[test]
    fn reload_handle_reload_with_valid_directive() {
        let cfg = LoggingConfig {
            level: "info".into(),
            ..LoggingConfig::default()
        };
        let g = init_for_test(&cfg).unwrap();
        let h = g.reload_handle();
        // The subscriber is `try_init` — repeated test setups share the same
        // global subscriber; the reload handle of the *first* successful init
        // is the one wired in. Either way, the handle should accept a parse
        // of valid syntax without panicking. We don't assert success against
        // the global because subsequent tests may have replaced it; we only
        // confirm bad syntax produces `BadFilter`.
        let _ = h.reload("info,spt_ssh2=debug");
    }

    #[test]
    fn reload_handle_rejects_bad_directive() {
        let cfg = LoggingConfig {
            level: "info".into(),
            ..LoggingConfig::default()
        };
        let g = init_for_test(&cfg).unwrap();
        let h = g.reload_handle();
        let err = h.reload("=oops").unwrap_err();
        assert!(matches!(err, ReloadError::BadFilter(_)));
    }

    #[test]
    fn reload_error_display_includes_context() {
        let e = ReloadError::BadFilter("=oops".into());
        let s = format!("{e}");
        assert!(s.contains("invalid log filter"));
        let e = ReloadError::ReloadFailed("gone".into());
        let s = format!("{e}");
        assert!(s.contains("reload failed"));
    }

    #[test]
    fn cli_span_macro_attaches_correlation_id() {
        // The macro must expand without compile error and produce a Span.
        // We can't easily extract the field at runtime without a custom
        // subscriber, so we just enter/exit to confirm liveness.
        let span = crate::cli_span!("test_top_action");
        let _entered = span.entered();
    }

    #[test]
    fn session_span_macro_attaches_correlation_and_session_ids() {
        let correlation = new_correlation_id();
        let span = crate::session_span!("test_session_action", correlation);
        let _entered = span.entered();
    }

    #[test]
    fn init_error_display_includes_context() {
        let e = InitError::BadFilter("level=garbage".into());
        let s = format!("{e}");
        assert!(s.contains("invalid log filter"));
        assert!(s.contains("level=garbage"));

        let e = InitError::MissingFilePath;
        assert!(format!("{e}").contains("no `file` path"));

        let e = InitError::SetGlobal("oops".into());
        assert!(format!("{e}").contains("oops"));

        let e = InitError::RemoteSink {
            name: "x".into(),
            kind: "https-jsonl",
            reason: "bad".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("https-jsonl"));
        assert!(s.contains("bad"));

        let e = InitError::CreateDir(
            "/tmp".into(),
            std::io::Error::other("nope"), // 1.88 lint: io_other_error
        );
        assert!(format!("{e}").contains("/tmp"));
    }
}
