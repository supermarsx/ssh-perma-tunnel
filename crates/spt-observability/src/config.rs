//! Local config types for the observability stack.
//!
//! These are not parsed from TOML directly — `spt-bin` is responsible for
//! translating `spt_config::schema::Logging` into a [`LoggingConfig`]. Keeping
//! a separate type here lets this crate be tested standalone and avoids
//! tracking schema-rename churn from `spt-config`.

use std::path::PathBuf;
use std::time::Duration;

use spt_core::RedactionMode;

/// Configuration for [`crate::init`].
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log filter directive (`"info"`, `"info,spt_ssh2=debug"`, etc).
    pub level: String,
    /// Output format: text or JSON.
    pub format: LogFormat,
    /// Whether to emit ANSI escape codes on stderr. Honored only when stderr
    /// is a destination AND `no_color` is `false`. CLIs SHOULD set this to
    /// `false` when `NO_COLOR` is set in the environment.
    pub no_color: bool,
    /// Active destinations.
    pub destinations: Vec<Destination>,
    /// Optional file destination.
    pub file: Option<FileSink>,
    /// Redaction profile applied to every sink before bytes hit disk/network.
    pub redact: RedactionMode,
    /// Remote sinks (parsed from `[[logging.remote]]`).
    pub remote: Vec<RemoteSink>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Compact,
            no_color: false,
            destinations: vec![Destination::Stderr],
            file: None,
            redact: RedactionMode::Standard,
            remote: Vec::new(),
        }
    }
}

/// Log destinations supported by [`crate::init`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// Standard error.
    Stderr,
    /// File at [`LoggingConfig::file`].
    File,
    /// systemd journald (Linux only).
    Journald,
}

/// Format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Default compact text format.
    Compact,
    /// Pretty multi-line text.
    Pretty,
    /// One JSON object per line.
    Json,
}

/// File destination spec.
#[derive(Debug, Clone)]
pub struct FileSink {
    /// Absolute path to the active log file (e.g. `…/spt.log`).
    pub path: PathBuf,
    /// Rotation policy.
    pub rotate: RotationPolicy,
    /// Maximum retained rotated files.
    pub max_files: u32,
}

/// Rotation policy for the file destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPolicy {
    /// Hourly rotation (`spt.log.YYYY-MM-DD-HH`).
    Hourly,
    /// Daily rotation (`spt.log.YYYY-MM-DD`).
    Daily,
    /// Never rotate.
    Never,
    /// Size-based rotation; file rotated when active size would exceed
    /// `max_bytes`. Combined with daily rotation when `daily` is true.
    Size {
        /// Byte cap before rotation triggers.
        max_bytes: u64,
        /// Whether to also rotate at local-midnight.
        daily: bool,
    },
}

/// Remote log sink spec consumed by `init` (only used to construct sink layers
/// — wire transports themselves live in dedicated modules and are out of
/// scope for the unit tests in this crate).
#[derive(Debug, Clone)]
pub struct RemoteSink {
    pub name: String,
    pub kind: RemoteSinkKind,
    pub endpoint: String,
    pub ca_file: Option<PathBuf>,
    pub auth: Option<String>,
    pub timeout: Duration,
    pub batch_size: u32,
    pub required: bool,
}

/// Kinds of remote log sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSinkKind {
    /// RFC-5424 over TLS-on-TCP.
    SyslogTls,
    /// HTTPS POST of newline-delimited JSON.
    HttpsJsonl,
    /// OpenTelemetry OTLP.
    Otlp,
}
