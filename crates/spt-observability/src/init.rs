//! Initialise the global tracing subscriber for spt.

use std::fs;
use std::io;
use std::path::Path;

use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use tracing_subscriber::Registry;

use crate::config::{Destination, FileSink, LogFormat, LoggingConfig, RotationPolicy};
use crate::redaction::RedactingMakeWriter;

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
}

/// RAII guard returned by [`init`]. Drop flushes/joins the rotating-file
/// background worker.
#[must_use = "drop the TracingGuard at process exit so logs flush"]
pub struct TracingGuard {
    /// Worker for the rotating file appender.
    pub(crate) _file_guard: Option<WorkerGuard>,
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
        let appender = make_appender(f, &parent, &prefix);
        let (nb, guard) = tracing_appender::non_blocking(appender);
        file_guard = Some(guard);
        let mw = RedactingMakeWriter::new(nb, config.redact);
        layers.push(text_or_json_layer(config.format, false, mw));
    }

    if want_journald {
        if let Some(layer) = build_journald_layer() {
            layers.push(layer);
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
    })
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

fn make_appender(f: &FileSink, dir: &Path, prefix: &str) -> RollingFileAppender {
    // Note: `tracing-appender` rotates by time (hourly/daily/never). The
    // workspace-config schema also offers size-based rotation; that is
    // handled by future custom appenders. See the deviations log.
    let _ = f.max_files; // retention is the appender's job in newer versions; emulate elsewhere if needed
    match f.rotate {
        RotationPolicy::Hourly => RollingFileAppender::new(Rotation::HOURLY, dir, prefix),
        RotationPolicy::Daily => RollingFileAppender::new(Rotation::DAILY, dir, prefix),
        RotationPolicy::Never => RollingFileAppender::new(Rotation::NEVER, dir, prefix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Destination, FileSink, RotationPolicy};
    use spt_core::RedactionMode;
    use tempfile::tempdir;

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
