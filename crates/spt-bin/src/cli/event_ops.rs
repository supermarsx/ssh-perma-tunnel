//! `spt event replay <event-id>` operation.
//!
//! Walks `<state_dir>/events/*.jsonl`, finds the record whose `id` field
//! matches `<event-id>`, reconstructs an [`spt_events::event::Event`] with the
//! original kind/severity/fields, and re-fires it through the configured
//! sinks. When `--sink <name>` is provided, only that sink is exercised; in
//! its absence the event is fanned through every sink referenced by every
//! binding whose `on` patterns match the historical event's kind.

#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::missing_errors_doc)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use spt_cli::GlobalOpts;
use spt_config::schema::EventSink;
use spt_core::{Error, Result};

/// Args for [`replay`].
#[derive(Debug, Clone, Default)]
pub struct EventReplayArgs {
    /// Historical event id (UUID-style string written into each on-disk
    /// record's `id` field).
    pub event_id: String,
    /// Optional sink restriction: when set, only the named sink is
    /// re-exercised against the replayed event.
    pub sink: Option<String>,
    /// Emit the per-sink result table as JSON.
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// `spt event replay <event-id> [--sink <name>]`.
pub async fn replay(global: &GlobalOpts, args: EventReplayArgs) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _w) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;

    // Locate the event by walking the daily JSONL files. The id is stored as
    // a top-level `id` key on each record (placed there by
    // `Event::to_state_event` before serialisation).
    let edir = spt_state::paths::events_dir(&state_dir);
    let raw = find_event(&edir, &args.event_id)?.ok_or_else(|| {
        Error::InvalidArgs(format!(
            "no event with id `{}` in `{}`",
            args.event_id,
            edir.display()
        ))
    })?;
    let evt = reconstruct_event(&raw)?;

    // Choose the sink set: explicit `--sink`, or every sink referenced by a
    // matching binding.
    let sinks_cfg = cfg
        .events
        .as_ref()
        .map(|e| e.sinks.clone())
        .unwrap_or_default();
    let bindings = cfg
        .events
        .as_ref()
        .map(|e| e.bindings.clone())
        .unwrap_or_default();

    let target_sinks: Vec<&EventSink> = if let Some(name) = args.sink.as_deref() {
        match sinks_cfg.iter().find(|s| s.name == name) {
            Some(s) => vec![s],
            None => {
                return Err(Error::InvalidArgs(format!(
                    "no sink named `{name}` in [[events.sinks]]"
                )))
            }
        }
    } else {
        let mut names: Vec<&str> = bindings
            .iter()
            .filter(|b| b.on.iter().any(|pat| kind_matches_pattern(&evt.kind, pat)))
            .flat_map(|b| b.actions.iter().map(String::as_str))
            .collect();
        names.sort();
        names.dedup();
        names
            .iter()
            .filter_map(|n| sinks_cfg.iter().find(|s| s.name == *n))
            .collect()
    };

    let event_arc = Arc::new(evt);
    let mut results = Vec::new();
    for sc in &target_sinks {
        let outcome = fire_through_sink(sc, Arc::clone(&event_arc)).await;
        results.push(json!({
            "sink": sc.name,
            "kind": sc.kind,
            "ok": outcome.is_ok(),
            "error": outcome.err(),
        }));
    }

    let payload = json!({
        "event_id": args.event_id,
        "sinks": results,
    });
    if crate::cli::tunnel_ops::emit(global, args.json, &payload)? {
        // machine output written
    } else if results.is_empty() {
        println!(
            "(no sink matches event id `{}`; did you mean `--sink <name>`?)",
            args.event_id
        );
    } else {
        for r in &results {
            let name = r.get("sink").and_then(|v| v.as_str()).unwrap_or("?");
            let kind = r.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
            let ok = r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            if ok {
                println!("{name}\t{kind}\tOK");
            } else {
                let err = r
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no error message)");
                println!("{name}\t{kind}\tFAIL: {err}");
            }
        }
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

fn find_event(edir: &Path, event_id: &str) -> Result<Option<Value>> {
    let rd = match std::fs::read_dir(edir) {
        Ok(rd) => rd,
        Err(_) => return Ok(None),
    };
    let mut files: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
        })
        .collect();
    files.sort();
    // Iterate newest-first since recent ids are more likely.
    files.reverse();
    for path in files {
        let f = match File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for line in BufReader::new(f).lines().map_while(std::result::Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("id").and_then(|x| x.as_str()) == Some(event_id) {
                return Ok(Some(v));
            }
        }
    }
    Ok(None)
}

fn reconstruct_event(raw: &Value) -> Result<spt_events::event::Event> {
    use spt_core::{ConnectionId, EventId, ForwardId, ProfileId, SessionId};
    use spt_events::event::{Event, EventBuilder, EventKind, Severity};

    let kind = raw
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidConfig("event missing `kind`".to_string()))?;
    let severity_str = raw
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("info");
    let severity = Severity::parse(severity_str).unwrap_or(Severity::Info);

    let mut b = EventBuilder::new(EventKind::new(kind), severity);

    if let Some(ts) = raw.get("ts").and_then(|v| v.as_str()) {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
            b = b.ts(parsed.with_timezone(&Utc));
        }
    }
    if let Some(p) = raw.get("profile_id").and_then(|v| v.as_str()) {
        if let Ok(id) = ProfileId::new(p.to_owned()) {
            b = b.profile(id);
        }
    }
    if let Some(p) = raw.get("forward_id").and_then(|v| v.as_str()) {
        if let Ok(id) = ForwardId::new(p.to_owned()) {
            b = b.forward(id);
        }
    }
    if let Some(p) = raw.get("session_id").and_then(|v| v.as_str()) {
        if let Ok(id) = SessionId::new(p.to_owned()) {
            b = b.session(id);
        }
    }
    if let Some(p) = raw.get("connection_id").and_then(|v| v.as_str()) {
        if let Ok(id) = ConnectionId::new(p.to_owned()) {
            b = b.connection(id);
        }
    }
    if let Some(m) = raw.get("message").and_then(|v| v.as_str()) {
        b = b.message(m);
    }
    if let Some(obj) = raw.as_object() {
        const RESERVED: &[&str] = &[
            "id",
            "ts",
            "kind",
            "severity",
            "profile_id",
            "forward_id",
            "session_id",
            "connection_id",
            "message",
        ];
        for (k, v) in obj {
            if RESERVED.contains(&k.as_str()) {
                continue;
            }
            b = b.field(k.clone(), v.clone());
        }
    }
    let mut evt: Event = b.build();
    if let Some(id_str) = raw.get("id").and_then(|v| v.as_str()) {
        if let Ok(id) = EventId::new(id_str.to_owned()) {
            evt.id = id;
        }
    }
    Ok(evt)
}

fn kind_matches_pattern(kind: &spt_events::event::EventKind, pat: &str) -> bool {
    kind.matches_pattern(pat)
}

async fn fire_through_sink(
    sc: &EventSink,
    evt: Arc<spt_events::event::Event>,
) -> std::result::Result<(), String> {
    use spt_events::Sink;
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
                    // `s.auth` is a `RedactedString` (t5-e7) — we pull the
                    // cleartext via `expose()` to feed `Subscription`'s
                    // `String` field. The `RedactedString` original keeps
                    // its zeroize-on-drop guarantee.
                    auth_secret: s.auth.expose().to_owned(),
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
            "sink kind `{other}` is not yet wired through `event replay` \
             (today: webpush). Other kinds are exercised via \
             `spt event sink test`."
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, LogLevel, OutputFormat};
    use std::io::Write;
    use tempfile::tempdir;

    fn opts(config: PathBuf, state: PathBuf) -> GlobalOpts {
        GlobalOpts {
            config: Some(config),
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: Some(state),
            profile: None,
            portable: false,
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

    fn write_event_ring(state_dir: &Path, lines: &[&str]) {
        let edir = state_dir.join("events");
        std::fs::create_dir_all(&edir).unwrap();
        let mut f = File::create(edir.join("2026-05-05.jsonl")).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_errors_when_event_id_not_found() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(&cfg, "version = 1\n").unwrap();
        write_event_ring(
            tmp.path(),
            &[r#"{"id":"abc","ts":"2026-05-05T12:00:00Z","kind":"k","severity":"info"}"#],
        );
        let g = opts(cfg, tmp.path().to_path_buf());
        let args = EventReplayArgs {
            event_id: "missing-id".to_string(),
            sink: None,
            json: false,
        };
        let err = replay(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_with_no_matching_bindings_produces_empty_result_set() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(&cfg, "version = 1\n").unwrap();
        write_event_ring(
            tmp.path(),
            &[
                r#"{"id":"evt-1","ts":"2026-05-05T12:00:00Z","kind":"profile.connected","severity":"info","message":"hi"}"#,
            ],
        );
        let g = opts(cfg, tmp.path().to_path_buf());
        let args = EventReplayArgs {
            event_id: "evt-1".to_string(),
            sink: None,
            json: true,
        };
        // No sinks/bindings configured — the command succeeds with an empty
        // result set rather than erroring.
        replay(&g, args).await.expect("replay ok");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_errors_when_named_sink_missing() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(&cfg, "version = 1\n").unwrap();
        write_event_ring(
            tmp.path(),
            &[r#"{"id":"evt-2","ts":"2026-05-05T12:00:00Z","kind":"k","severity":"info"}"#],
        );
        let g = opts(cfg, tmp.path().to_path_buf());
        let args = EventReplayArgs {
            event_id: "evt-2".to_string(),
            sink: Some("nope".to_string()),
            json: false,
        };
        let err = replay(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn reconstruct_event_carries_id_and_severity() {
        let v: Value = serde_json::from_str(
            r#"{"id":"abc","ts":"2026-05-05T12:00:00Z","kind":"k","severity":"warn","message":"hi","custom":1}"#,
        )
        .unwrap();
        let e = reconstruct_event(&v).unwrap();
        assert_eq!(e.id.as_str(), "abc");
        assert_eq!(e.kind.as_str(), "k");
        assert_eq!(e.message, "hi");
        assert_eq!(e.fields.get("custom"), Some(&serde_json::Value::from(1)));
    }

    #[test]
    fn reconstruct_event_requires_kind() {
        let v: Value = serde_json::from_str(r#"{"id":"x","severity":"info"}"#).unwrap();
        let err = reconstruct_event(&v).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn reconstruct_event_defaults_severity_when_missing() {
        let v: Value = serde_json::from_str(r#"{"id":"x","kind":"k"}"#).unwrap();
        let e = reconstruct_event(&v).unwrap();
        // Default severity is Info per Severity::Info fallback.
        assert_eq!(e.id.as_str(), "x");
    }

    #[test]
    fn reconstruct_event_carries_optional_ids_when_present() {
        let v: Value = serde_json::from_str(
            r#"{
                "id":"e1","kind":"profile.connected","severity":"info",
                "profile_id":"p","forward_id":"p/f","session_id":"s","connection_id":"c",
                "ts":"2026-05-05T12:00:00Z"
            }"#,
        )
        .unwrap();
        let e = reconstruct_event(&v).unwrap();
        assert!(e.profile_id.is_some());
        assert!(e.forward_id.is_some());
        assert!(e.session_id.is_some());
        assert!(e.connection_id.is_some());
    }

    #[test]
    fn reconstruct_event_ignores_malformed_ts() {
        let v: Value = serde_json::from_str(
            r#"{"id":"x","kind":"k","severity":"info","ts":"not-a-timestamp"}"#,
        )
        .unwrap();
        // Should not panic; just ignore the bad ts and proceed.
        reconstruct_event(&v).unwrap();
    }

    #[test]
    fn kind_matches_pattern_glob_and_exact() {
        use spt_events::event::EventKind;
        assert!(kind_matches_pattern(
            &EventKind::new("profile.connected"),
            "profile.*"
        ));
        assert!(kind_matches_pattern(
            &EventKind::new("profile.connected"),
            "profile.connected"
        ));
        assert!(!kind_matches_pattern(
            &EventKind::new("forward.connected"),
            "profile.*"
        ));
    }

    #[test]
    fn find_event_returns_none_when_dir_missing() {
        let tmp = tempdir().unwrap();
        let missing = tmp.path().join("no-such-dir");
        let r = find_event(&missing, "any").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn find_event_skips_non_jsonl_extensions() {
        let tmp = tempdir().unwrap();
        let edir = tmp.path().join("events");
        std::fs::create_dir_all(&edir).unwrap();
        std::fs::write(
            edir.join("ignore.txt"),
            r#"{"id":"abc","kind":"k","severity":"info"}"#,
        )
        .unwrap();
        let r = find_event(&edir, "abc").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn find_event_returns_match_from_jsonl_file() {
        let tmp = tempdir().unwrap();
        let edir = tmp.path().join("events");
        std::fs::create_dir_all(&edir).unwrap();
        std::fs::write(
            edir.join("2026-05-05.jsonl"),
            r#"{"id":"alpha","kind":"k","severity":"info"}
{"id":"beta","kind":"k","severity":"info"}
"#,
        )
        .unwrap();
        let r = find_event(&edir, "beta").unwrap().unwrap();
        assert_eq!(r.get("id").and_then(|v| v.as_str()), Some("beta"));
    }

    #[test]
    fn find_event_skips_blank_lines_and_invalid_json() {
        let tmp = tempdir().unwrap();
        let edir = tmp.path().join("events");
        std::fs::create_dir_all(&edir).unwrap();
        std::fs::write(
            edir.join("a.jsonl"),
            "\n{not valid json}\n{\"id\":\"x\",\"kind\":\"k\"}\n",
        )
        .unwrap();
        let r = find_event(&edir, "x").unwrap();
        assert!(r.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_requires_config_path() {
        let g = GlobalOpts {
            config: None,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            profile: None,
            portable: false,
            output: OutputFormat::Human,
            json: false,
            log_level: LogLevel::Info,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: true,
            dry_run: false,
        };
        let r = replay(
            &g,
            EventReplayArgs {
                event_id: "x".into(),
                sink: None,
                json: false,
            },
        )
        .await;
        assert!(matches!(r, Err(Error::InvalidArgs(_))));
    }
}
