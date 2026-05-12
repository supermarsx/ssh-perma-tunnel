//! `spt log {test, export}` operations.
//!
//! `test` constructs a single sink from `[[events.sinks]]` (or
//! `[[logging.remote]]`), fires one synthetic event/line through it, and
//! reports OK/FAIL with timing.
//!
//! `export` reads `<state_dir>/events/*.jsonl`, filters by `--since` /
//! `--until`, and streams the records as JSONL (default) or wrapped JSON to
//! `--to <path>` or stdout.

#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::missing_errors_doc)]

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use spt_cli::GlobalOpts;
use spt_config::schema::EventSink;
use spt_core::{Error, Result};

/// Output format for [`export`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogExportFormat {
    /// One JSON record per line (native event-ring format).
    Jsonl,
    /// Wrap all matching records into a single JSON array.
    Json,
}

impl Default for LogExportFormat {
    fn default() -> Self {
        Self::Jsonl
    }
}

/// Args for [`test()`].
#[derive(Debug, Clone, Default)]
pub struct LogTestArgs {
    /// Sink name (must match `[[events.sinks]].name` or
    /// `[[logging.remote]].name`).
    pub sink: String,
    /// Emit JSON instead of plain text.
    pub json: bool,
}

/// Args for [`export`].
#[derive(Debug, Clone, Default)]
pub struct LogExportArgs {
    /// Lower bound (inclusive). Accepts ISO-8601 (`2026-05-05T00:00:00Z`) or a
    /// relative duration (`1h`, `7d`).
    pub since: Option<String>,
    /// Upper bound (exclusive). Same parsing rules as `since`.
    pub until: Option<String>,
    /// Destination path; `None` writes to stdout.
    pub to: Option<PathBuf>,
    /// Output shape (jsonl native, or wrapped json array).
    pub format: LogExportFormat,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// `spt log test --sink <name>` — fire one synthetic event/log line through
/// the named sink and report success/failure with elapsed time.
pub async fn test(global: &GlobalOpts, args: LogTestArgs) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _w) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;

    // Search [[events.sinks]] first, then fall back to [[logging.remote]] —
    // both surfaces define a "named remote target" semantically.
    let started = Instant::now();
    let outcome: std::result::Result<&'static str, String> = if let Some(sink) = cfg
        .events
        .as_ref()
        .and_then(|e| e.sinks.iter().find(|s| s.name == args.sink))
    {
        fire_synthetic_event_sink(sink)
            .await
            .map(|_| "events.sinks")
    } else if let Some(remote) = cfg
        .logging
        .as_ref()
        .and_then(|l| l.remote.iter().find(|r| r.name == args.sink))
    {
        fire_synthetic_remote_log(remote)
            .await
            .map(|_| "logging.remote")
    } else {
        return Err(Error::InvalidArgs(format!(
            "no sink named `{}` found in `[[events.sinks]]` or `[[logging.remote]]`",
            args.sink
        )));
    };
    let elapsed_ms = started.elapsed().as_millis();

    let (ok, surface, err) = match outcome {
        Ok(s) => (true, s.to_string(), None),
        Err(e) => (false, "unknown".to_string(), Some(e)),
    };

    if args.json {
        let v = json!({
            "sink": args.sink,
            "surface": surface,
            "ok": ok,
            "elapsed_ms": elapsed_ms,
            "error": err,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else if ok {
        println!("ok: sink `{}` ({}) in {}ms", args.sink, surface, elapsed_ms);
    } else {
        println!(
            "FAIL: sink `{}` in {}ms — {}",
            args.sink,
            elapsed_ms,
            err.as_deref().unwrap_or("unknown error")
        );
    }
    if !ok {
        return Err(Error::RuntimeFailure(format!(
            "log test for `{}` failed",
            args.sink
        )));
    }
    Ok(())
}

/// `spt log export --since <ts> [--until <ts>] [--to <path>]` — stream the
/// event-ring jsonl files in the requested window.
pub async fn export(global: &GlobalOpts, args: LogExportArgs) -> Result<()> {
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let now = Utc::now();
    let since = args
        .since
        .as_deref()
        .map(|s| parse_time_bound(s, now))
        .transpose()?;
    let until = args
        .until
        .as_deref()
        .map(|s| parse_time_bound(s, now))
        .transpose()?;

    let edir = spt_state::paths::events_dir(&state_dir);
    let mut writer: Box<dyn Write> = match &args.to {
        Some(p) => {
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        Error::RuntimeFailure(format!("mkdir `{}`: {e}", parent.display()))
                    })?;
                }
            }
            Box::new(
                File::create(p)
                    .map_err(|e| Error::RuntimeFailure(format!("create `{}`: {e}", p.display())))?,
            )
        }
        None => Box::new(std::io::stdout().lock()),
    };

    let files = list_event_files(&edir)?;
    let mut count: usize = 0;
    let mut first_array = true;

    if matches!(args.format, LogExportFormat::Json) {
        writer
            .write_all(b"[\n")
            .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
    }

    for path in files {
        let f = match File::open(&path) {
            Ok(f) => f,
            Err(_) => continue, // file may have been pruned mid-iteration
        };
        for line in BufReader::new(f).lines() {
            let line = match line {
                Ok(s) => s,
                Err(_) => continue,
            };
            if line.trim().is_empty() {
                continue;
            }
            // Parse just enough to get `ts` for the time-window filter.
            let v: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !time_in_window(&v, since.as_ref(), until.as_ref()) {
                continue;
            }
            match args.format {
                LogExportFormat::Jsonl => {
                    writer
                        .write_all(line.as_bytes())
                        .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
                    writer
                        .write_all(b"\n")
                        .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
                }
                LogExportFormat::Json => {
                    if !first_array {
                        writer
                            .write_all(b",\n")
                            .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
                    }
                    writer
                        .write_all(line.as_bytes())
                        .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
                    first_array = false;
                }
            }
            count += 1;
        }
    }
    if matches!(args.format, LogExportFormat::Json) {
        writer
            .write_all(b"\n]\n")
            .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
    drop(writer);
    if args.to.is_some() {
        eprintln!("exported {count} record(s)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_config_path(global: &GlobalOpts) -> Result<PathBuf> {
    global.config.clone().ok_or_else(|| {
        Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
    })
}

fn list_event_files(edir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(edir) {
        Ok(rd) => rd,
        Err(_) => return Ok(out), // no events dir means no events
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
        {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

fn time_in_window(v: &Value, since: Option<&DateTime<Utc>>, until: Option<&DateTime<Utc>>) -> bool {
    if since.is_none() && until.is_none() {
        return true;
    }
    let Some(ts_str) = v.get("ts").and_then(|x| x.as_str()) else {
        return false;
    };
    let Ok(ts) = DateTime::parse_from_rfc3339(ts_str) else {
        return false;
    };
    let ts = ts.with_timezone(&Utc);
    if let Some(s) = since {
        if &ts < s {
            return false;
        }
    }
    if let Some(u) = until {
        if &ts >= u {
            return false;
        }
    }
    true
}

fn parse_time_bound(s: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>> {
    if let Ok(ts) = DateTime::parse_from_rfc3339(s) {
        return Ok(ts.with_timezone(&Utc));
    }
    if let Ok(d) = spt_core::duration::parse_duration(s) {
        let dur = chrono::Duration::from_std(d)
            .map_err(|e| Error::InvalidArgs(format!("duration `{s}` out of range: {e}")))?;
        return Ok(now - dur);
    }
    Err(Error::InvalidArgs(format!(
        "`{s}` is not a valid ISO-8601 timestamp or relative duration"
    )))
}

async fn fire_synthetic_event_sink(sc: &EventSink) -> std::result::Result<(), String> {
    use spt_events::{
        event::{EventBuilder, EventKind, Severity},
        Sink,
    };

    let evt = Arc::new(
        EventBuilder::new(EventKind::new("synthetic.test"), Severity::Info)
            .message("synthetic event from `spt log test`")
            .build(),
    );

    match sc.kind.as_str() {
        "webpush" => {
            use spt_events::sinks::push::{Subscription, VapidIdentity, WebPushSink};
            let key = sc
                .vapid_private_key
                .as_deref()
                .ok_or_else(|| "webpush: missing vapid_private_key".to_owned())?;
            let subject = sc
                .vapid_subject
                .as_deref()
                .ok_or_else(|| "webpush: missing vapid_subject".to_owned())?;
            let vapid = VapidIdentity::from_base64url(key, subject)
                .map_err(|e| format!("webpush: vapid: {e}"))?;
            let subs_cfg = sc
                .subscriptions
                .as_ref()
                .ok_or_else(|| "webpush: missing subscriptions".to_owned())?;
            let subs: Vec<Subscription> = subs_cfg
                .iter()
                .map(|s| Subscription {
                    endpoint: s.endpoint.clone(),
                    p256dh_key: s.p256dh.clone(),
                    auth_secret: s.auth.clone(),
                })
                .collect();
            let transport: Arc<dyn spt_events::sinks::http::HttpTransport> = Arc::new(
                spt_events::sinks::http::reqwest_transport::ReqwestTransport::new(
                    std::time::Duration::from_secs(10),
                )
                .map_err(|e| format!("webpush: transport: {e}"))?,
            );
            let body = sc
                .body_template
                .clone()
                .unwrap_or_else(|| "{{message}}".into());
            let sink = WebPushSink::new(sc.name.clone(), body, subs, vapid, transport);
            sink.deliver(evt).await.map_err(|e| e.to_string())
        }
        other => Err(format!(
            "sink kind `{other}` not yet supported by `spt log test` \
             (use one of: webpush; events.sinks of other kinds are exercised \
             via `spt event sink test`)"
        )),
    }
}

async fn fire_synthetic_remote_log(
    remote: &spt_config::schema::LoggingRemote,
) -> std::result::Result<(), String> {
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    // Probe TCP reachability against the configured endpoint. We do **not**
    // actually emit a syslog frame or HTTPS POST — that would require pinning
    // the live remote-sink writer task. A 1s connect probe is enough to
    // surface an obviously misconfigured endpoint (DNS failure, wrong port)
    // without depending on TLS handshake nuances.
    let endpoint = remote
        .endpoint
        .as_deref()
        .ok_or_else(|| format!("sink `{}` has no endpoint configured", remote.name))?;

    let (host, port) = parse_endpoint(endpoint, default_port_for_kind(&remote.kind))
        .map_err(|e| format!("endpoint `{endpoint}`: {e}"))?;

    match timeout(
        Duration::from_secs(1),
        TcpStream::connect(format!("{host}:{port}")),
    )
    .await
    {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(e)) => Err(format!("connect {host}:{port}: {e}")),
        Err(_) => Err(format!("connect {host}:{port}: timed out after 1s")),
    }
}

fn default_port_for_kind(kind: &str) -> u16 {
    match kind {
        "syslog_tls" | "syslog-tls" => 6514,
        "https_jsonl" | "https-jsonl" => 443,
        "otlp" => 4317,
        _ => 0,
    }
}

fn parse_endpoint(endpoint: &str, default_port: u16) -> std::result::Result<(String, u16), String> {
    // Strip an optional URL scheme.
    let s = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    // Strip any path / query suffix.
    let s = s.split(['/', '?']).next().unwrap_or(s);
    if let Some((h, p)) = s.rsplit_once(':') {
        let port: u16 = p.parse().map_err(|e| format!("invalid port `{p}`: {e}"))?;
        Ok((h.to_string(), port))
    } else if default_port != 0 {
        Ok((s.to_string(), default_port))
    } else {
        Err(format!(
            "no port in `{endpoint}` and no default for sink kind"
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use spt_cli::{ColorMode, LogLevel, OutputFormat};
    use tempfile::tempdir;

    fn opts(config: Option<PathBuf>, state: Option<PathBuf>) -> GlobalOpts {
        GlobalOpts {
            config,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: state,
            profile: None,
            output: OutputFormat::Human,
            json: false,
            log_level: LogLevel::Info,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: true,
            dry_run: false,
        }
    }

    #[test]
    fn parse_time_bound_accepts_iso_and_duration() {
        let now = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let one_hour_ago = parse_time_bound("1h", now).unwrap();
        assert_eq!(one_hour_ago, now - chrono::Duration::hours(1));
        let iso = parse_time_bound("2026-05-05T11:00:00Z", now).unwrap();
        assert_eq!(iso, now - chrono::Duration::hours(1));
        assert!(parse_time_bound("not-a-time", now).is_err());
    }

    #[test]
    fn time_in_window_filters_correctly() {
        let v: Value =
            serde_json::from_str(r#"{"ts":"2026-05-05T12:00:00Z","kind":"k","severity":"info"}"#)
                .unwrap();
        let early = Utc.with_ymd_and_hms(2026, 5, 5, 11, 0, 0).unwrap();
        let late = Utc.with_ymd_and_hms(2026, 5, 5, 13, 0, 0).unwrap();
        assert!(time_in_window(&v, Some(&early), Some(&late)));
        assert!(!time_in_window(&v, Some(&late), None));
        assert!(!time_in_window(&v, None, Some(&early)));
        assert!(time_in_window(&v, None, None));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_writes_filtered_jsonl_to_target_file() {
        let tmp = tempdir().unwrap();
        let edir = tmp.path().join("events");
        std::fs::create_dir_all(&edir).unwrap();
        let mut f = File::create(edir.join("2026-05-05.jsonl")).unwrap();
        writeln!(
            f,
            r#"{{"ts":"2026-05-05T10:00:00Z","kind":"k","severity":"info"}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts":"2026-05-05T14:00:00Z","kind":"k","severity":"info"}}"#
        )
        .unwrap();
        drop(f);

        let out = tmp.path().join("export.jsonl");
        let g = opts(None, Some(tmp.path().to_path_buf()));
        let args = LogExportArgs {
            since: Some("2026-05-05T11:00:00Z".to_string()),
            until: None,
            to: Some(out.clone()),
            format: LogExportFormat::Jsonl,
        };
        export(&g, args).await.unwrap();
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("14:00:00"), "body: {body}");
        assert!(!body.contains("10:00:00"), "body: {body}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_with_no_events_dir_is_ok() {
        let tmp = tempdir().unwrap();
        let g = opts(None, Some(tmp.path().to_path_buf()));
        let args = LogExportArgs::default();
        export(&g, args).await.expect("ok with no events");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_returns_invalid_args_for_unknown_sink() {
        // Need a config path to exercise sink lookup.
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(&cfg, "version = 1\n").unwrap();
        let g = opts(Some(cfg), None);
        let args = LogTestArgs {
            sink: "missing-sink".to_string(),
            json: false,
        };
        let err = test(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_succeeds_for_logging_remote_sink_lookup() {
        // Spawn a loopback TCP listener so the probe can connect.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept_task = tokio::spawn(async move {
            // Accept and immediately drop, just enough to satisfy the probe.
            let _ = listener.accept().await;
        });

        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(
            &cfg,
            format!(
                r#"
version = 1

[logging]
level = "info"

[[logging.remote]]
name = "remote-syslog"
type = "syslog_tls"
endpoint = "{addr}"
required = false
"#
            ),
        )
        .unwrap();
        let g = opts(Some(cfg), None);
        let args = LogTestArgs {
            sink: "remote-syslog".to_string(),
            json: true,
        };
        test(&g, args).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fails_for_unreachable_remote_endpoint() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(
            &cfg,
            r#"
version = 1

[logging]
level = "info"

[[logging.remote]]
name = "remote-syslog"
type = "syslog_tls"
endpoint = "127.0.0.1:1"
required = false
"#,
        )
        .unwrap();
        let g = opts(Some(cfg), None);
        let args = LogTestArgs {
            sink: "remote-syslog".to_string(),
            json: true,
        };
        let err = test(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }
}
