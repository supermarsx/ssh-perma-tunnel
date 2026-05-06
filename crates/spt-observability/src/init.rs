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
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use tracing_subscriber::Registry;

use crate::config::{
    Destination, FileSink, LogFormat, LoggingConfig, RemoteSink, RemoteSinkKind, RotationPolicy,
};
use crate::https_jsonl::{self, HttpsAuth, HttpsJsonlConfig, HttpsJsonlHandle};
use crate::redaction::RedactingMakeWriter;
use crate::rotation::{RotatingFileAppender, SizeRotationPolicy};
use crate::syslog_tls::{self, SyslogTlsConfig, SyslogTlsHandle};

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

/// RAII guard returned by [`init`]. Drop flushes/joins the rotating-file
/// background worker and any remote-sink writer tasks.
#[must_use = "drop the TracingGuard at process exit so logs flush"]
pub struct TracingGuard {
    /// Worker for the rotating file appender.
    pub(crate) _file_guard: Option<WorkerGuard>,
    /// Active syslog-TLS writers; dropping closes their channels and joins
    /// their tasks via tokio's `JoinHandle` drop semantics. We keep them in
    /// a Vec so a single config can declare multiple syslog targets.
    pub(crate) _syslog: Vec<SyslogTlsHandle>,
    /// Active HTTPS-JSONL writers.
    pub(crate) _https: Vec<HttpsJsonlHandle>,
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

    let want_stderr = config.destinations.contains(&Destination::Stderr);
    let want_file = config.destinations.contains(&Destination::File);
    let want_journald = config.destinations.contains(&Destination::Journald);

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();
    // Filter is itself a Layer<Registry>; pushing it into the same vec keeps
    // the subscriber type concretely `Layered<Vec<...>, Registry>` which does
    // implement `SubscriberInitExt`.
    layers.push(Box::new(filter));

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
    let mut syslog_handles: Vec<SyslogTlsHandle> = Vec::new();
    let mut https_handles: Vec<HttpsJsonlHandle> = Vec::new();
    if !config.remote.is_empty() && tokio::runtime::Handle::try_current().is_ok() {
        for sink in &config.remote {
            match build_remote_layer(sink, config.redact) {
                Ok(RemoteBuild::Syslog { layer, handle }) => {
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
        _syslog: syslog_handles,
        _https: https_handles,
    })
}

/// Kind enum → display string used in `InitError::RemoteSink`.
fn remote_kind_str(k: RemoteSinkKind) -> &'static str {
    match k {
        RemoteSinkKind::SyslogTls => "syslog-tls",
        RemoteSinkKind::HttpsJsonl => "https-jsonl",
        RemoteSinkKind::Otlp => "otlp",
    }
}

/// Outcome of remote-sink construction.
enum RemoteBuild {
    Syslog {
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
    let spool_dir = std::env::temp_dir().join(format!("spt-remote-{}", sink.name));
    match sink.kind {
        RemoteSinkKind::SyslogTls => {
            let (host, port) = parse_host_port(&sink.endpoint, 6514)?;
            let mut cfg = SyslogTlsConfig::new(host, port, spool_dir);
            cfg.timeout = sink.timeout;
            cfg.redact = redact;
            let (layer, handle) =
                syslog_tls::spawn_writer(cfg).map_err(|e| e.to_string())?;
            Ok(RemoteBuild::Syslog {
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
            let (layer, handle) =
                https_jsonl::spawn(cfg).map_err(|e| e.to_string())?;
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

fn parse_host_port(endpoint: &str, default_port: u16) -> Result<(String, u16), String> {
    // Accept "host", "host:port", or "scheme://host:port" — strip the
    // scheme if present.
    let s = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    if let Some((h, p)) = s.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|e| format!("port `{p}`: {e}"))?;
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
    let parent = path
        .parent()
        .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf);
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
fn make_writer(
    f: &FileSink,
    dir: &Path,
    prefix: &str,
) -> io::Result<Box<dyn Write + Send>> {
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
                ca_file: None,
                auth: Some("Bearer xyz".into()),
                timeout: Duration::from_millis(100),
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
                ca_file: None,
                auth: None,
                timeout: Duration::from_millis(100),
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
}
