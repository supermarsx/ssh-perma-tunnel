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
///
/// Filter directive precedence (highest first):
///
/// 1. `SPT_LOG` env var — accepted by `EnvFilter` natively, so per-module
///    syntax like `SPT_LOG=info,spt_ssh2=debug,spt_supervisor=trace` works
///    out of the box.
/// 2. `--log-level` / `--verbose` CLI flags translated via
///    [`crate::log_level_directive`].
pub fn init_minimal(global: &GlobalOpts) -> Option<TracingGuard> {
    let level = resolve_filter_directive(global);
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
        .unwrap_or_else(|| resolve_filter_directive(global));
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

/// Pick the filter directive: `SPT_LOG` env var wins if it parses; otherwise
/// fall back to the CLI flags. Validation happens inside
/// `spt-observability`'s init (`EnvFilter::try_new`), so bad `SPT_LOG`
/// values cause the CLI to fall back to flag-derived defaults rather than
/// failing the whole process.
pub(crate) fn resolve_filter_directive(global: &GlobalOpts) -> String {
    if let Some(raw) = std::env::var_os("SPT_LOG") {
        if let Some(s) = raw.to_str() {
            // Probe the directive without retaining the result: bad values
            // shouldn't blow up the binary; we silently fall through.
            if tracing_subscriber::filter::EnvFilter::try_new(s).is_ok() {
                return s.to_owned();
            }
        }
    }
    crate::log_level_directive(global.log_level, global.verbose)
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

#[cfg(test)]
mod tests {
    use super::{resolve_filter_directive, GlobalOpts};
    use crate::test_locks::spt_log_env;

    // SPT_LOG env-var mutation is process-global. Cargo runs tests in parallel
    // by default, so without a mutex one test's `set_env` races with another's
    // `resolve_filter_directive` read. The lock is CRATE-shared (not a local
    // static) so it also serialises against `signals.rs`, which mutates the
    // same `SPT_LOG` var in the same test binary. Each test holds the guard
    // for its full body.

    fn defaults() -> GlobalOpts {
        // Parse an empty arg list through clap to get a GlobalOpts populated
        // with every default. This avoids hard-coding all global field names
        // here (the struct surface is owned by `spt-cli`).
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            g: GlobalOpts,
        }
        Wrap::parse_from(["test"]).g
    }

    fn set_env(key: &str, value: Option<&str>) {
        // Tests in this module run sequentially and only mutate `SPT_LOG`,
        // which the wider observability/test surface does not read.
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn resolve_filter_falls_back_to_cli_when_env_unset() {
        let _g = spt_log_env();
        set_env("SPT_LOG", None);
        let g = defaults();
        assert_eq!(resolve_filter_directive(&g), "info");
    }

    #[test]
    fn resolve_filter_uses_env_per_module_syntax() {
        let _guard = spt_log_env();
        set_env("SPT_LOG", Some("warn,spt_ssh2=trace,spt_supervisor=debug"));
        let g = defaults();
        let d = resolve_filter_directive(&g);
        assert!(d.contains("spt_ssh2=trace"));
        assert!(d.contains("spt_supervisor=debug"));
        set_env("SPT_LOG", None);
    }

    #[test]
    fn resolve_filter_ignores_bad_env_value() {
        let _guard = spt_log_env();
        // `=garbage` is rejected by EnvFilter; we fall back to CLI defaults.
        set_env("SPT_LOG", Some("=garbage"));
        let mut g = defaults();
        g.verbose = 1;
        assert_eq!(resolve_filter_directive(&g), "debug");
        set_env("SPT_LOG", None);
    }

    #[test]
    fn resolve_filter_simple_module_level() {
        let _guard = spt_log_env();
        set_env("SPT_LOG", Some("spt_supervisor=debug"));
        let g = defaults();
        let d = resolve_filter_directive(&g);
        assert_eq!(d, "spt_supervisor=debug");
        set_env("SPT_LOG", None);
    }

    #[test]
    fn resolve_filter_global_off_then_per_module_on() {
        let _guard = spt_log_env();
        set_env("SPT_LOG", Some("off,spt_ssh2=info"));
        let g = defaults();
        let d = resolve_filter_directive(&g);
        assert!(d.starts_with("off"));
        assert!(d.contains("spt_ssh2=info"));
        set_env("SPT_LOG", None);
    }

    #[test]
    fn resolve_filter_three_module_combination() {
        let _guard = spt_log_env();
        set_env(
            "SPT_LOG",
            Some("info,spt_ssh2=trace,spt_supervisor=debug,spt_mcp=warn"),
        );
        let g = defaults();
        let d = resolve_filter_directive(&g);
        assert!(d.contains("spt_mcp=warn"));
        set_env("SPT_LOG", None);
    }

    #[test]
    fn resolve_filter_with_verbose_two_flag_only() {
        let _guard = spt_log_env();
        set_env("SPT_LOG", None);
        let mut g = defaults();
        g.verbose = 2;
        assert_eq!(resolve_filter_directive(&g), "trace");
    }

    #[test]
    fn resolve_filter_env_takes_precedence_over_verbose() {
        let _guard = spt_log_env();
        set_env("SPT_LOG", Some("warn"));
        let mut g = defaults();
        g.verbose = 2;
        assert_eq!(resolve_filter_directive(&g), "warn");
        set_env("SPT_LOG", None);
    }
}
