//! Minimal tracing initialiser used by every `spt` invocation.
//!
//! Long-running commands (`tunnel run`, `service run`, `mcp serve`) replace
//! this with the full `spt-observability` pipeline once they own the parsed
//! config. This bootstrap subscriber only writes to stderr.

use spt_cli::GlobalOpts;
use spt_observability::{
    config::{
        Destination, FileSink, LogFormat, LoggingConfig, RemoteSink, RemoteSinkKind, RotationPolicy,
    },
    init, init_for_test, TracingGuard,
};

/// Initialise a stderr-only tracing subscriber. Returns the guard owned by
/// `main` for lifetime control.
pub fn init_minimal(global: &GlobalOpts) -> Option<TracingGuard> {
    let level = crate::log_level_directive(global.log_level, global.verbose);
    let cfg = LoggingConfig {
        level,
        format: if global.json {
            LogFormat::Json
        } else {
            LogFormat::Compact
        },
        no_color: global.no_color || matches!(global.color, spt_cli::ColorMode::Never),
        destinations: vec![Destination::Stderr],
        file: None,
        redact: spt_core::RedactionMode::Standard,
        remote: Vec::new(),
    };
    // Use init_for_test which uses try_init under the hood, so re-entry from
    // tests doesn't panic. Real init failures are warned about and ignored —
    // a logging failure must not block the CLI.
    init_for_test(&cfg)
        .map_err(|e| {
            eprintln!("spt: tracing init warning: {e}");
            e
        })
        .ok()
}

/// Initialise the full logging pipeline from `[logging]`.
pub fn init_from_config(
    global: &GlobalOpts,
    cfg: &spt_config::schema::Config,
    state_dir: &std::path::Path,
) -> spt_core::Result<TracingGuard> {
    let logging = cfg.logging.as_ref();
    let level = logging
        .and_then(|l| l.level.clone())
        .unwrap_or_else(|| crate::log_level_directive(global.log_level, global.verbose));
    let format = logging
        .and_then(|l| l.format.as_deref())
        .map(parse_log_format)
        .transpose()?
        .unwrap_or(if global.json {
            LogFormat::Json
        } else {
            LogFormat::Compact
        });
    let destinations = logging
        .and_then(|l| l.destinations.as_ref())
        .map(|items| {
            items
                .iter()
                .map(|item| parse_destination(item))
                .collect::<spt_core::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_else(|| vec![Destination::Stderr, Destination::File]);

    let file = if destinations.contains(&Destination::File) {
        let path = logging
            .and_then(|l| l.file.as_ref())
            .map_or_else(|| state_dir.join("spt.log"), std::path::PathBuf::from);
        let rotate = logging
            .and_then(|l| l.rotate.as_deref())
            .map(|rotate| parse_rotation(rotate, logging.and_then(|l| l.max_size.as_deref())))
            .transpose()?
            .unwrap_or(RotationPolicy::Daily);
        Some(FileSink {
            path,
            rotate,
            max_files: logging.and_then(|l| l.max_files).unwrap_or(7),
        })
    } else {
        None
    };

    let remote = logging
        .map(|l| {
            l.remote
                .iter()
                .map(|sink| convert_remote_sink(sink, state_dir))
                .collect::<spt_core::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    let obs_cfg = LoggingConfig {
        level,
        format,
        no_color: global.no_color || matches!(global.color, spt_cli::ColorMode::Never),
        destinations,
        file,
        redact: spt_core::RedactionMode::Standard,
        remote,
    };
    init(&obs_cfg).map_err(|e| spt_core::Error::RuntimeFailure(format!("logging init: {e}")))
}

fn parse_log_format(value: &str) -> spt_core::Result<LogFormat> {
    match value {
        "compact" | "text" => Ok(LogFormat::Compact),
        "pretty" => Ok(LogFormat::Pretty),
        "json" => Ok(LogFormat::Json),
        other => Err(spt_core::Error::InvalidConfig(format!(
            "logging.format `{other}` is invalid"
        ))),
    }
}

fn parse_destination(value: &str) -> spt_core::Result<Destination> {
    match value {
        "stderr" | "console" => Ok(Destination::Stderr),
        "file" => Ok(Destination::File),
        "journald" => Ok(Destination::Journald),
        other => Err(spt_core::Error::InvalidConfig(format!(
            "logging.destinations entry `{other}` is invalid"
        ))),
    }
}

fn parse_rotation(value: &str, max_size: Option<&str>) -> spt_core::Result<RotationPolicy> {
    match value {
        "hourly" => Ok(RotationPolicy::Hourly),
        "daily" => Ok(RotationPolicy::Daily),
        "none" | "never" => Ok(RotationPolicy::Never),
        "size" => {
            let max_bytes = max_size
                .map(spt_core::size::parse_size)
                .transpose()?
                .unwrap_or(10 * 1024 * 1024);
            Ok(RotationPolicy::Size {
                max_bytes,
                daily: false,
            })
        }
        other => Err(spt_core::Error::InvalidConfig(format!(
            "logging.rotate `{other}` is invalid"
        ))),
    }
}

fn convert_remote_sink(
    sink: &spt_config::schema::LoggingRemote,
    state_dir: &std::path::Path,
) -> spt_core::Result<RemoteSink> {
    let kind = match sink.kind.as_str() {
        "syslog_udp" | "syslog-udp" => RemoteSinkKind::SyslogUdp,
        "syslog_tcp" | "syslog-tcp" => RemoteSinkKind::SyslogTcp,
        "syslog_tls" | "syslog-tls" => RemoteSinkKind::SyslogTls,
        "https_jsonl" | "https-jsonl" => RemoteSinkKind::HttpsJsonl,
        "otlp" => RemoteSinkKind::Otlp,
        other => {
            return Err(spt_core::Error::InvalidConfig(format!(
                "logging.remote `{}` has invalid type `{other}`",
                sink.name
            )));
        }
    };
    let timeout = sink
        .timeout
        .as_deref()
        .map(spt_core::duration::parse_duration)
        .transpose()?
        .unwrap_or_else(|| std::time::Duration::from_secs(5));
    let reconnect_backoff = sink
        .reconnect_backoff
        .as_deref()
        .map(spt_core::duration::parse_duration)
        .transpose()?
        .unwrap_or_else(|| std::time::Duration::from_millis(500));
    let spool_max_bytes = sink
        .spool_max_bytes
        .as_deref()
        .map(spt_core::size::parse_size)
        .transpose()?;
    let queue_max_records = sink.queue_max_records.unwrap_or(1024) as usize;
    let spool_dir = sink.spool_dir.as_ref().map_or_else(
        || Some(state_dir.join("remote-log-spool").join(&sink.name)),
        |p| Some(std::path::PathBuf::from(p)),
    );

    Ok(RemoteSink {
        name: sink.name.clone(),
        kind,
        endpoint: sink.endpoint.clone().unwrap_or_default(),
        facility: sink.facility,
        app_name: sink.app_name.clone(),
        hostname: sink.hostname.clone(),
        enterprise_id: sink.enterprise_id,
        ca_file: sink.ca_file.as_ref().map(std::path::PathBuf::from),
        server_name: sink.server_name.clone(),
        client_cert: sink.client_cert.as_ref().map(std::path::PathBuf::from),
        client_key: sink.client_key.as_ref().map(std::path::PathBuf::from),
        allow_invalid_certs: sink.allow_invalid_certs.unwrap_or(false),
        auth: sink.auth.clone(),
        timeout,
        reconnect_backoff,
        spool_dir,
        spool_max_bytes,
        queue_max_records,
        batch_size: sink.batch_size.unwrap_or(100),
        required: sink.required.unwrap_or(false),
    })
}
