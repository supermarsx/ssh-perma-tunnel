//! `spt profile {set, enable, disable, test}` operations.
//!
//! The dispatch wiring lives in `cli_dispatch.rs` (Phase B). This module
//! provides the four async functions consumed there.
//!
//! Design notes:
//!
//! * **Atomic mutation.** Edits go through [`spt_config::mutate::Document`]
//!   which serialises the document with `toml_edit` (preserving comments) and
//!   writes via [`atomicwrites`]. We *parse + validate before writing*, so a
//!   rejected edit never reaches disk — the file on disk is always either the
//!   pre-edit version or a fully-validated post-edit version.
//! * **Dotted field paths.** `spt-config::mutate` only exposes top-level
//!   profile mutators today. We walk the `toml_edit::Item` tree ourselves to
//!   support `connection.host`, `keepalive.interval`,
//!   `auth.methods.0.public_key.key`, etc. Numeric path segments index into
//!   array-of-tables.
//! * **Hot reload on enable/disable.** If the supervisor's MCP loopback is
//!   reachable we call `tunnel_reload` so the change takes effect immediately;
//!   otherwise we print a friendly note and rely on the change being picked up
//!   the next time `spt tunnel run` starts.
//! * **`profile test`.** Builds the protocol bundle via
//!   [`crate::profile_factory::build`], iterates endpoints in priority order,
//!   times each `connect()`, and reports per-endpoint status. No forwards
//!   opened.

#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use spt_cli::{groups::profile, GlobalOpts, OutputFormat};
use spt_config::mutate::Document;
use spt_core::{escape_control, Error, Result};
use spt_protocol::Endpoint;
use toml_edit::{value, Item, Value};

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Default per-endpoint connect timeout for `profile test` when the profile
/// does not set one.
const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `spt profile set <name> KEY=VALUE [KEY=VALUE …]`.
pub async fn set(global: &GlobalOpts, args: profile::ProfileSet) -> Result<()> {
    let path = require_config_path(global)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;

    // Parse + validate the *current* state once. We compare new validation
    // diagnostics against this baseline so an edit that's neutral against
    // pre-existing warnings does not get rejected for someone else's bug.
    let baseline_errors = baseline_error_count(&raw);

    let mut doc = Document::parse(&raw)?;
    let mut changes: Vec<ChangeRecord> = Vec::with_capacity(args.overrides.len());

    for ov in &args.overrides {
        let (field, val) = parse_override(ov)?;
        let old = read_field(&mut doc, &args.name, field);
        write_field(&mut doc, &args.name, field, val)?;
        changes.push(ChangeRecord {
            field: field.to_owned(),
            old,
            new: val.to_owned(),
        });
    }

    // Validate the post-edit document. Reject if it introduces *new* errors;
    // do not write to disk in that case.
    let rendered = doc.to_string();
    let (cfg, _warnings) = spt_config::load_str(&rendered, false)
        .map_err(|e| Error::InvalidConfig(format!("post-edit parse failed: {e}")))?;
    let diags = spt_config::validate(&cfg);
    if diags.errors.len() > baseline_errors {
        let first = diags
            .errors
            .first()
            .map_or_else(|| "validation failed".to_owned(), |e| e.to_string());
        return Err(Error::InvalidConfig(format!(
            "edit rejected: post-edit config fails validation: {first}"
        )));
    }

    doc.write_atomic(&path)?;

    emit_set_report(global, &args.name, &changes);
    Ok(())
}

/// `spt profile configure --no-tui [--field K=V ...] [--from FILE]`.
///
/// Non-interactive profile editor. Two input modes (composable):
///
/// * `--field key=value` repeated: dotted-path overrides, identical to
///   `profile set` but without requiring a positional name argument.
/// * `--from FILE`: TOML file whose top-level keys (or single `[profile]`
///   table) are merged into the addressed profile.
///
/// Validates the post-edit document and refuses to write if the edit
/// introduces *new* validation errors over the on-disk baseline. On success
/// the previous file content is copied to `<config>.bak` (overwritten each
/// time) and the new content is atomically written via `atomicwrites`.
pub async fn configure_non_interactive(
    global: &GlobalOpts,
    args: profile::ProfileConfigure,
) -> Result<()> {
    let path = require_config_path(global)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;

    let baseline = baseline_error_count(&raw);
    let mut doc = Document::parse(&raw)?;

    // The profile must be addressable. We accept either an explicit `--name`
    // or a single existing profile in the config (so `spt profile configure
    // --no-tui --field host=…` works in single-profile setups without extra
    // ceremony).
    let name = resolve_profile_name(&mut doc, args.name.as_deref())?;

    let mut applied = Vec::<String>::new();

    if let Some(file) = args.from.as_ref() {
        let body = std::fs::read_to_string(file)
            .map_err(|e| Error::InvalidArgs(format!("read `{}`: {e}", file.display())))?;
        let n = apply_toml_patch(&mut doc, &name, &body)?;
        applied.push(format!("--from `{}` ({n} fields)", file.display()));
    }

    for ov in &args.fields {
        let (field, val) = parse_override(ov)?;
        write_field(&mut doc, &name, field, val)?;
        applied.push(format!("{field}={val}"));
    }

    if applied.is_empty() {
        return Err(Error::InvalidArgs(
            "no edits supplied: pass `--field KEY=VALUE` and/or `--from FILE` \
             (or omit `--no-tui` to launch the interactive editor)"
                .into(),
        ));
    }

    // Reject if the new document fails validation harder than the baseline.
    let rendered = doc.to_string();
    let (cfg, _w) = spt_config::load_str(&rendered, false)
        .map_err(|e| Error::InvalidConfig(format!("post-edit parse failed: {e}")))?;
    let diags = spt_config::validate(&cfg);
    if diags.errors.len() > baseline {
        let first = diags
            .errors
            .first()
            .map_or_else(|| "validation failed".to_owned(), |e| e.to_string());
        return Err(Error::InvalidConfig(format!(
            "edit rejected: post-edit config fails validation: {first}"
        )));
    }

    // Validation passed — write the backup *before* atomic-replacing the
    // primary so a crash mid-write leaves a recoverable copy. The backup is
    // a snapshot of the pre-edit on-disk content (`raw`).
    let bak = backup_path(&path);
    std::fs::write(&bak, &raw)
        .map_err(|e| Error::InvalidConfig(format!("write backup `{}`: {e}", bak.display())))?;
    doc.write_atomic(&path)?;

    if use_json(global) {
        let v = json!({
            "ok": true,
            "profile": name,
            "applied": applied,
            "backup": bak.display().to_string(),
        });
        println!("{v}");
    } else {
        println!(
            "ok: profile `{name}` configured ({n} edit{s}); backup at `{bak}`",
            n = applied.len(),
            s = if applied.len() == 1 { "" } else { "s" },
            bak = bak.display(),
        );
    }
    Ok(())
}

/// `spt profile enable <name>`.
pub async fn enable(global: &GlobalOpts, args: profile::ProfileName) -> Result<()> {
    toggle_enabled(global, &args.name, true).await
}

/// `spt profile disable <name>`.
pub async fn disable(global: &GlobalOpts, args: profile::ProfileName) -> Result<()> {
    toggle_enabled(global, &args.name, false).await
}

/// `spt profile test <name>` — build the profile bundle, attempt one
/// `connect()` per endpoint in priority order, and report timing.
pub async fn test(global: &GlobalOpts, args: profile::ProfileTest) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _w) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let prof = cfg
        .profiles
        .iter()
        .find(|p| p.name == args.name)
        .ok_or_else(|| Error::InvalidArgs(format!("no profile named `{}`", args.name)))?;

    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let resolver = crate::secrets_bridge::build_resolver(cfg.secrets.as_ref(), &state_dir)?;
    let bundle = crate::profile_factory::build_with_config(prof, &resolver, &cfg)?;

    if bundle.endpoints.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "profile `{}` has no endpoints (set `host` or `[[profiles.endpoints]]`)",
            args.name
        )));
    }

    let mut endpoints = bundle.endpoints.clone();
    endpoints.sort_by_key(|e| e.priority);

    let timeout = profile_connect_timeout(prof).unwrap_or(DEFAULT_TEST_TIMEOUT);

    let mut results: Vec<EndpointResult> = Vec::with_capacity(endpoints.len());
    for ep in &endpoints {
        let r = test_one_endpoint(Arc::clone(&bundle.protocol), ep, &bundle.auth, timeout).await;
        results.push(r);
    }

    emit_test_report(global, &args.name, &results);
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ChangeRecord {
    field: String,
    old: Option<String>,
    new: String,
}

#[derive(Debug)]
struct EndpointResult {
    id: String,
    host: String,
    port: u16,
    status: EndpointStatus,
    latency_ms: u128,
}

#[derive(Debug)]
enum EndpointStatus {
    Connected { peer_version: Option<String> },
    Failed(String),
}

fn parse_override(ov: &str) -> Result<(&str, &str)> {
    let (k, v) = ov.split_once('=').ok_or_else(|| {
        Error::InvalidArgs(format!("invalid override `{ov}` (expected `KEY=VALUE`)"))
    })?;
    let key = k.trim();
    let val = v.trim();
    if key.is_empty() {
        return Err(Error::InvalidArgs(format!(
            "invalid override `{ov}`: empty key"
        )));
    }
    Ok((key, val))
}

fn baseline_error_count(raw: &str) -> usize {
    spt_config::load_str(raw, false)
        .ok()
        .map(|(c, _)| spt_config::validate(&c).errors.len())
        .unwrap_or(0)
}

async fn toggle_enabled(global: &GlobalOpts, name: &str, on: bool) -> Result<()> {
    let path = require_config_path(global)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
    let baseline = baseline_error_count(&raw);

    let mut doc = Document::parse(&raw)?;
    write_field(&mut doc, name, "enabled", if on { "true" } else { "false" })?;

    let rendered = doc.to_string();
    let (cfg, _w) = spt_config::load_str(&rendered, false)
        .map_err(|e| Error::InvalidConfig(format!("post-edit parse: {e}")))?;
    let diags = spt_config::validate(&cfg);
    if diags.errors.len() > baseline {
        let first = diags
            .errors
            .first()
            .map_or_else(|| "validation failed".to_owned(), |e| e.to_string());
        return Err(Error::InvalidConfig(format!("edit rejected: {first}")));
    }

    doc.write_atomic(&path)?;

    let json_out = use_json(global);
    let action = if on { "enabled" } else { "disabled" };

    // Best-effort hot reload via MCP. If the supervisor isn't running we
    // simply note that and exit success.
    let reloaded = try_mcp_reload(global).await;

    if json_out {
        let msg = json!({
            "ok": true,
            "profile": name,
            "enabled": on,
            "reloaded": reloaded.is_ok(),
            "reload_error": reloaded.as_ref().err().map(ToString::to_string),
        });
        println!("{msg}");
    } else {
        // Color the action verb: enabled→green, disabled→dim.
        let st = crate::styler(global);
        let action_col = if on { st.green(action) } else { st.dim(action) };
        match reloaded {
            Ok(()) => println!("ok: profile `{name}` {action_col} (supervisor reloaded)"),
            Err(_) => println!(
                "ok: profile `{name}` {action_col} (supervisor not running; will apply on next start)"
            ),
        }
    }
    Ok(())
}

/// Fire `tunnel_reload` against the running supervisor.
async fn try_mcp_reload(global: &GlobalOpts) -> std::result::Result<(), String> {
    let state_dir =
        spt_state::resolve_state_dir(global.state_dir.as_deref()).map_err(|e| e.to_string())?;
    let mut client = crate::mcp_client::McpClient::connect_from_state_dir(&state_dir)
        .await
        .map_err(|e| e.to_string())?;
    client.initialize().await.map_err(|e| e.to_string())?;
    client
        .call_tool("tunnel_reload", json!({}))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn test_one_endpoint(
    protocol: Arc<dyn spt_protocol::TunnelProtocol>,
    endpoint: &Endpoint,
    auth: &spt_auth::AuthConfig,
    timeout: Duration,
) -> EndpointResult {
    let id = format!("{}:{}", endpoint.host, endpoint.port);
    let start = Instant::now();
    let outcome = tokio::time::timeout(timeout, protocol.connect(endpoint, auth)).await;
    let elapsed = start.elapsed().as_millis();

    match outcome {
        Ok(Ok(session)) => {
            let info = session.session_info();
            // Drain the session cleanly. Errors here are non-fatal: connect
            // succeeded, which is what the test reports on.
            let _ = session.close().await;
            EndpointResult {
                id,
                host: endpoint.host.clone(),
                port: endpoint.port,
                status: EndpointStatus::Connected {
                    peer_version: info.peer_version,
                },
                latency_ms: elapsed,
            }
        }
        Ok(Err(e)) => EndpointResult {
            id,
            host: endpoint.host.clone(),
            port: endpoint.port,
            status: EndpointStatus::Failed(e.to_string()),
            latency_ms: elapsed,
        },
        Err(_) => EndpointResult {
            id,
            host: endpoint.host.clone(),
            port: endpoint.port,
            status: EndpointStatus::Failed(format!("timeout after {}ms", timeout.as_millis())),
            latency_ms: elapsed,
        },
    }
}

fn profile_connect_timeout(p: &spt_config::schema::Profile) -> Option<Duration> {
    let raw = p
        .connection
        .as_ref()
        .and_then(|c| c.connect_timeout.clone())
        .or_else(|| p.connect_timeout.clone())?;
    spt_core::duration::parse_duration(&raw).ok()
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn use_json(global: &GlobalOpts) -> bool {
    global.json || matches!(global.output, OutputFormat::Json | OutputFormat::Jsonl)
}

fn emit_set_report(global: &GlobalOpts, profile: &str, changes: &[ChangeRecord]) {
    if use_json(global) {
        let arr: Vec<_> = changes
            .iter()
            .map(|c| {
                json!({
                    "field": c.field,
                    "old": c.old,
                    "new": c.new,
                })
            })
            .collect();
        let v = json!({
            "ok": true,
            "profile": profile,
            "changes": arr,
        });
        println!("{v}");
    } else {
        for c in changes {
            println!(
                "ok: profile {profile}.{field} = {new} (was {old})",
                field = c.field,
                new = display_for_human(&c.new),
                old = c
                    .old
                    .as_deref()
                    .map(display_for_human)
                    .unwrap_or_else(|| "<unset>".to_owned()),
            );
        }
    }
}

fn display_for_human(s: &str) -> String {
    if s.contains(char::is_whitespace) {
        format!("\"{s}\"")
    } else {
        s.to_owned()
    }
}

fn emit_test_report(global: &GlobalOpts, profile: &str, results: &[EndpointResult]) {
    if use_json(global) {
        let arr: Vec<_> = results
            .iter()
            .map(|r| match &r.status {
                EndpointStatus::Connected { peer_version } => json!({
                    "id": r.id,
                    "host": r.host,
                    "port": r.port,
                    "status": "connected",
                    "latency_ms": r.latency_ms,
                    "peer_version": peer_version,
                }),
                EndpointStatus::Failed(err) => json!({
                    "id": r.id,
                    "host": r.host,
                    "port": r.port,
                    "status": "failed",
                    "latency_ms": r.latency_ms,
                    "error": err,
                }),
            })
            .collect();
        let v = json!({ "profile": profile, "endpoints": arr });
        println!("{v}");
    } else {
        let st = crate::styler(global);
        for r in results {
            println!("{}", format_test_line(st, r));
        }
    }
}

/// Render one endpoint test result as a human-facing line.
///
/// Server-controlled fields — the peer SSH identification banner
/// (`peer_version`) and the connect-error text (which can embed
/// server-supplied strings) — are passed through [`escape_control`] so a
/// malicious peer cannot inject ANSI/terminal escape sequences into the
/// operator's terminal. The endpoint id is operator-derived (`host:port` from
/// config) and left as-is. Behavior-preserving for clean input.
fn format_test_line(st: crate::cli::style::Styler, r: &EndpointResult) -> String {
    match &r.status {
        EndpointStatus::Connected { peer_version } => format!(
            "endpoint {id}: {status} in {ms}ms{peer}",
            id = r.id,
            status = st.green("connected"),
            ms = r.latency_ms,
            peer = peer_version
                .as_ref()
                .map(|v| format!(" (peer: {})", escape_control(v)))
                .unwrap_or_default(),
        ),
        EndpointStatus::Failed(err) => format!(
            "endpoint {id}: {status} in {ms}ms — {err}",
            id = r.id,
            status = st.red("failed"),
            ms = r.latency_ms,
            err = escape_control(err),
        ),
    }
}

// ---------------------------------------------------------------------------
// Dotted-path TOML mutation
// ---------------------------------------------------------------------------

fn require_config_path(global: &GlobalOpts) -> Result<PathBuf> {
    global.config.clone().ok_or_else(|| {
        Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
    })
}

/// Resolve `profile` into a mutable reference to its `[[profiles]]` table.
fn profile_table_mut<'a>(doc: &'a mut Document, name: &str) -> Result<&'a mut toml_edit::Table> {
    let arr = match doc
        .document_mut()
        .entry("profiles")
        .or_insert_with(|| Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
    {
        Item::ArrayOfTables(arr) => arr,
        _ => {
            return Err(Error::InvalidConfig(
                "[[profiles]] is not an array of tables".into(),
            ))
        }
    };
    let idx = (0..arr.len()).find(|&i| {
        arr.get(i)
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            == Some(name)
    });
    let idx =
        idx.ok_or_else(|| Error::InvalidConfig(format!("profile `{name}` does not exist")))?;
    Ok(arr.get_mut(idx).expect("index in range"))
}

/// Best-effort read of `profile.<field>` from `doc`. Returns `None` if any
/// segment is missing — never errors, since reading is informational only.
fn read_field(doc: &mut Document, profile: &str, field: &str) -> Option<String> {
    let arr = match doc.document_mut().get("profiles")? {
        Item::ArrayOfTables(a) => a,
        _ => return None,
    };
    let prof_tbl = arr
        .iter()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(profile))?;

    let mut cur: &Item = prof_tbl.get(field.split('.').next()?)?;
    let mut segs = field.split('.');
    let _ = segs.next(); // first already consumed above
    for seg in segs {
        cur = descend(cur, seg)?;
    }
    Some(item_to_display(cur))
}

fn descend<'a>(item: &'a Item, seg: &str) -> Option<&'a Item> {
    if let Ok(idx) = seg.parse::<usize>() {
        if let Some(arr) = item.as_array_of_tables() {
            // `ArrayOfTables::get` returns &Table; we need &Item. There is no
            // direct conversion in toml_edit, so descent into AOT entries
            // happens by the *caller* using the table as the next root.
            // For the read path we accept losing the index step here —
            // diagnostics are best-effort.
            let _ = arr.get(idx);
            return None;
        }
    }
    if let Some(tbl) = item.as_table() {
        return tbl.get(seg);
    }
    None
}

fn item_to_display(item: &Item) -> String {
    if let Some(v) = item.as_value() {
        match v {
            Value::String(s) => s.value().clone(),
            other => other.to_string().trim().to_owned(),
        }
    } else {
        item.to_string().trim().to_owned()
    }
}

/// Walk the dotted path and overwrite the leaf with `val`. Numeric path
/// segments index into arrays-of-tables; string segments descend into
/// regular tables.
fn write_field(doc: &mut Document, profile: &str, field: &str, val: &str) -> Result<()> {
    let prof_tbl = profile_table_mut(doc, profile)?;
    write_field_in_table(prof_tbl, field, val)
}

fn write_field_in_table(tbl: &mut toml_edit::Table, field: &str, val: &str) -> Result<()> {
    let segs: Vec<&str> = field.split('.').collect();
    if segs.is_empty() || segs.iter().any(|s| s.is_empty()) {
        return Err(Error::InvalidArgs(format!("invalid field path `{field}`")));
    }
    write_path(tbl, &segs, val, field)
}

fn write_path(tbl: &mut toml_edit::Table, segs: &[&str], val: &str, full_path: &str) -> Result<()> {
    if segs.len() == 1 {
        let leaf = segs[0];
        if leaf.parse::<usize>().is_ok() {
            return Err(Error::InvalidArgs(format!(
                "invalid field path `{full_path}`: cannot assign to numeric leaf in a table"
            )));
        }
        tbl.insert(leaf, value_for(val));
        return Ok(());
    }

    let head = segs[0];
    let rest = &segs[1..];

    if let Ok(idx) = head.parse::<usize>() {
        // Numeric segment at this position is meaningful only when the
        // *previous* level resolved to an array-of-tables. Descending
        // through a numeric segment from a regular table is a path error.
        return Err(Error::InvalidArgs(format!(
            "invalid field path `{full_path}`: numeric segment `{idx}` requires an array-of-tables parent"
        )));
    }

    // Look ahead to decide whether `head` should be an array-of-tables or a
    // plain subtable.
    let next_is_index = rest.first().is_some_and(|s| s.parse::<usize>().is_ok());

    if next_is_index {
        let arr_idx: usize = rest[0].parse().expect("checked above");
        let inner_rest = &rest[1..];
        let entry = tbl
            .entry(head)
            .or_insert_with(|| Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
        let arr = entry.as_array_of_tables_mut().ok_or_else(|| {
            Error::InvalidConfig(format!(
                "field path `{full_path}`: `{head}` exists but is not an array of tables"
            ))
        })?;
        while arr.len() <= arr_idx {
            arr.push(toml_edit::Table::new());
        }
        let inner = arr.get_mut(arr_idx).expect("just sized");
        if inner_rest.is_empty() {
            return Err(Error::InvalidArgs(format!(
                "invalid field path `{full_path}`: trailing array index without a leaf field"
            )));
        }
        return write_path(inner, inner_rest, val, full_path);
    }

    let entry = tbl
        .entry(head)
        .or_insert_with(|| Item::Table(toml_edit::Table::new()));
    let sub = entry.as_table_mut().ok_or_else(|| {
        Error::InvalidConfig(format!(
            "field path `{full_path}`: `{head}` exists but is not a table"
        ))
    })?;
    write_path(sub, rest, val, full_path)
}

fn value_for(s: &str) -> Item {
    // Try integer, then float, then bool, finally string. This matches a
    // user typing `port=2222` (integer) vs `host=example.com` (string) vs
    // `enabled=true` (bool).
    if let Ok(i) = s.parse::<i64>() {
        return value(i);
    }
    if let Ok(f) = s.parse::<f64>() {
        if !f.is_nan() && f.is_finite() && s.contains('.') {
            return value(f);
        }
    }
    match s {
        "true" => return value(true),
        "false" => return value(false),
        _ => {}
    }
    value(s)
}

// ---------------------------------------------------------------------------
// Non-interactive `configure` helpers
// ---------------------------------------------------------------------------

fn backup_path(p: &std::path::Path) -> PathBuf {
    let mut name = p
        .file_name()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from("config.toml"));
    name.push(".bak");
    p.with_file_name(name)
}

fn resolve_profile_name(doc: &mut Document, requested: Option<&str>) -> Result<String> {
    if let Some(n) = requested {
        return Ok(n.to_owned());
    }
    let arr = match doc.document_mut().get("profiles") {
        Some(Item::ArrayOfTables(a)) => a,
        _ => {
            return Err(Error::InvalidArgs(
                "no profiles in config and `--name` not supplied".into(),
            ))
        }
    };
    if arr.len() == 1 {
        if let Some(n) = arr
            .get(0)
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
        {
            return Ok(n.to_owned());
        }
    }
    Err(Error::InvalidArgs(format!(
        "config has {} profiles; pass `--name <PROFILE>` to select one",
        arr.len()
    )))
}

/// Apply a TOML patch document to `profile`. Accepts either:
///
/// * a top-level `[profile]` table (its keys overwrite profile fields), or
/// * a bare key/value document (top-level keys overwrite profile fields).
///
/// Sub-tables and arrays-of-tables are deep-merged via dotted-path writes
/// onto the leaf scalars. Returns the count of leaf assignments applied.
fn apply_toml_patch(doc: &mut Document, profile: &str, body: &str) -> Result<usize> {
    use toml_edit::DocumentMut;
    let patch: DocumentMut = body
        .parse()
        .map_err(|e| Error::InvalidArgs(format!("parse `--from` toml: {e}")))?;

    // Unwrap a leading `[profile]` if present.
    let root: &toml_edit::Table = match patch.as_table().get("profile") {
        Some(Item::Table(t)) => t,
        _ => patch.as_table(),
    };

    let mut count = 0usize;
    walk_patch_leaves(root, "", profile, doc, &mut count)?;
    if count == 0 {
        return Err(Error::InvalidArgs(
            "`--from` TOML patch contained no scalar assignments".into(),
        ));
    }
    Ok(count)
}

fn walk_patch_leaves(
    tbl: &toml_edit::Table,
    prefix: &str,
    profile: &str,
    doc: &mut Document,
    count: &mut usize,
) -> Result<()> {
    for (k, item) in tbl {
        let path = if prefix.is_empty() {
            k.to_owned()
        } else {
            format!("{prefix}.{k}")
        };
        match item {
            Item::Value(v) => {
                let s = value_to_assignment_str(v);
                write_field(doc, profile, &path, &s)?;
                *count += 1;
            }
            Item::Table(sub) => {
                walk_patch_leaves(sub, &path, profile, doc, count)?;
            }
            Item::ArrayOfTables(arr) => {
                for (i, t) in arr.iter().enumerate() {
                    let inner_prefix = format!("{path}.{i}");
                    walk_patch_leaves(t, &inner_prefix, profile, doc, count)?;
                }
            }
            Item::None => {}
        }
    }
    Ok(())
}

/// Render a `Value` back to the `KEY=VALUE` payload understood by
/// [`write_field`] / [`value_for`]. Preserves native scalar typing.
fn value_to_assignment_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.value().clone(),
        Value::Integer(i) => i.value().to_string(),
        Value::Float(f) => f.value().to_string(),
        Value::Boolean(b) => b.value().to_string(),
        // Datetimes and arrays render via toml_edit's display impl, trimmed.
        other => other.to_string().trim().to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, LogLevel, OutputFormat as OF};
    use std::path::Path;

    const RAW: &str = r#"version = 1

[[profiles]]
name = "p"
protocol = "ssh2"
host = "example.com"
port = 22
user = "alice"

[profiles.connection]
connect_timeout = "5s"
"#;

    fn global_with_path(p: &Path) -> GlobalOpts {
        GlobalOpts {
            config: Some(p.to_path_buf()),
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            portable: false,
            profile: None,
            output: OF::Human,
            json: false,
            log_level: LogLevel::Info,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: false,
            dry_run: false,
        }
    }

    fn write_tmp(raw: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, raw).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn set_changes_top_level_field() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = profile::ProfileSet {
            name: "p".into(),
            overrides: vec!["port=2222".into()],
        };
        set(&g, args).await.unwrap();
        let new_raw = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = spt_config::load_str(&new_raw, false).unwrap();
        assert_eq!(cfg.profiles[0].port, Some(2222));
    }

    #[tokio::test]
    async fn set_changes_nested_field() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = profile::ProfileSet {
            name: "p".into(),
            overrides: vec!["connection.connect_timeout=10s".into()],
        };
        set(&g, args).await.unwrap();
        let new_raw = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = spt_config::load_str(&new_raw, false).unwrap();
        assert_eq!(
            cfg.profiles[0]
                .connection
                .as_ref()
                .and_then(|c| c.connect_timeout.clone())
                .as_deref(),
            Some("10s")
        );
    }

    #[tokio::test]
    async fn set_creates_missing_subtable() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = profile::ProfileSet {
            name: "p".into(),
            overrides: vec!["keepalive.interval=30s".into()],
        };
        set(&g, args).await.unwrap();
        let new_raw = std::fs::read_to_string(&path).unwrap();
        assert!(new_raw.contains("interval = \"30s\""));
    }

    #[tokio::test]
    async fn set_manages_endpoint_and_failover_policy() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = profile::ProfileSet {
            name: "p".into(),
            overrides: vec![
                "endpoints.0.name=primary".into(),
                "endpoints.0.host=gw-a.example".into(),
                "endpoints.0.port=22".into(),
                "endpoints.0.priority=10".into(),
                "endpoints.0.weight=80".into(),
                "endpoints.1.name=dr".into(),
                "endpoints.1.host=gw-b.example".into(),
                "endpoints.1.port=2222".into(),
                "endpoints.1.priority=20".into(),
                "endpoints.1.weight=20".into(),
                "failover.mode=weighted".into(),
                "failover.fail_after=3".into(),
                "failover.restore_after=30s".into(),
            ],
        };
        set(&g, args).await.unwrap();
        let new_raw = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = spt_config::load_str(&new_raw, false).unwrap();
        let profile = &cfg.profiles[0];
        assert_eq!(profile.endpoints.len(), 2);
        assert_eq!(profile.endpoints[0].name, "primary");
        assert_eq!(profile.endpoints[0].host, "gw-a.example");
        assert_eq!(profile.endpoints[0].priority, Some(10));
        assert_eq!(profile.endpoints[0].weight, Some(80));
        assert_eq!(profile.endpoints[1].name, "dr");
        assert_eq!(profile.endpoints[1].port, 2222);
        let failover = profile.failover.as_ref().unwrap();
        assert_eq!(failover.mode.as_deref(), Some("weighted"));
        assert_eq!(failover.fail_after, Some(3));
        assert_eq!(failover.restore_after.as_deref(), Some("30s"));
    }

    #[tokio::test]
    async fn set_invalid_field_path_rejected() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = profile::ProfileSet {
            name: "p".into(),
            overrides: vec!["=value".into()], // empty key
        };
        let err = set(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn set_unknown_profile_rejected() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = profile::ProfileSet {
            name: "nope".into(),
            overrides: vec!["port=2222".into()],
        };
        let err = set(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
        // File untouched.
        let same = std::fs::read_to_string(&path).unwrap();
        assert!(same.contains("port = 22"));
    }

    #[tokio::test]
    async fn set_validation_failure_does_not_write() {
        // Setting `protocol` to an unsupported value triggers
        // `validate::check_profiles`. The on-disk file must remain identical.
        let (_d, path) = write_tmp(RAW);
        let original = std::fs::read_to_string(&path).unwrap();
        let g = global_with_path(&path);
        let args = profile::ProfileSet {
            name: "p".into(),
            overrides: vec!["protocol=carrier-pigeon".into()],
        };
        let err = set(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(original, after);
    }

    #[tokio::test]
    async fn enable_disable_round_trip() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);

        disable(&g, profile::ProfileName { name: "p".into() })
            .await
            .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = spt_config::load_str(&raw, false).unwrap();
        assert_eq!(cfg.profiles[0].enabled, Some(false));

        enable(&g, profile::ProfileName { name: "p".into() })
            .await
            .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = spt_config::load_str(&raw, false).unwrap();
        assert_eq!(cfg.profiles[0].enabled, Some(true));
    }

    // ---- profile test ------------------------------------------------------

    #[tokio::test]
    async fn test_reports_connected_for_mock_protocol() {
        // Drive `test_one_endpoint` directly against a MockTunnelProtocol.
        let proto: Arc<dyn spt_protocol::TunnelProtocol> =
            Arc::new(spt_forward::testing::MockTunnelProtocol::new());
        let ep = Endpoint::new("127.0.0.1", 22);
        let auth = spt_auth::AuthConfig::new("u".to_owned(), Vec::new());
        let r = test_one_endpoint(proto, &ep, &auth, Duration::from_secs(5)).await;
        assert!(matches!(r.status, EndpointStatus::Connected { .. }));
    }

    #[tokio::test]
    async fn test_reports_failed_when_protocol_errors() {
        let mock = spt_forward::testing::MockTunnelProtocol::new();
        mock.set_connect_fails(true);
        let proto: Arc<dyn spt_protocol::TunnelProtocol> = Arc::new(mock);
        let ep = Endpoint::new("127.0.0.1", 22);
        let auth = spt_auth::AuthConfig::new("u".to_owned(), Vec::new());
        let r = test_one_endpoint(proto, &ep, &auth, Duration::from_secs(5)).await;
        assert!(matches!(r.status, EndpointStatus::Failed(_)));
    }

    // ---- value_for / parse_override ---------------------------------------

    #[test]
    fn value_for_picks_native_type() {
        assert_eq!(value_for("42").to_string().trim(), "42");
        assert_eq!(value_for("true").to_string().trim(), "true");
        assert_eq!(value_for("false").to_string().trim(), "false");
        assert_eq!(value_for("hello").to_string().trim(), "\"hello\"");
        assert_eq!(value_for("30s").to_string().trim(), "\"30s\"");
        assert_eq!(value_for("1.5").to_string().trim(), "1.5");
    }

    #[test]
    fn parse_override_splits_on_first_equals() {
        let (k, v) = parse_override("a=b=c").unwrap();
        assert_eq!(k, "a");
        assert_eq!(v, "b=c");
    }

    #[test]
    fn parse_override_rejects_missing_equals() {
        assert!(parse_override("noequals").is_err());
    }

    // ---- configure_non_interactive ----------------------------------------

    fn configure_args(
        name: Option<&str>,
        fields: &[&str],
        from: Option<&Path>,
    ) -> profile::ProfileConfigure {
        profile::ProfileConfigure {
            name: name.map(ToOwned::to_owned),
            tui: false,
            no_tui: true,
            from_template: None,
            fields: fields.iter().map(|s| (*s).to_owned()).collect(),
            from: from.map(Path::to_path_buf),
        }
    }

    #[tokio::test]
    async fn configure_non_interactive_applies_field_overrides() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = configure_args(Some("p"), &["port=2345", "host=new.example"], None);
        configure_non_interactive(&g, args).await.unwrap();

        let new_raw = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = spt_config::load_str(&new_raw, false).unwrap();
        assert_eq!(cfg.profiles[0].port, Some(2345));
        assert_eq!(cfg.profiles[0].host.as_deref(), Some("new.example"));

        // Backup file written and contains the *pre-edit* content.
        let bak = backup_path(&path);
        let bak_raw = std::fs::read_to_string(&bak).unwrap();
        assert!(bak_raw.contains("port = 22"));
        assert!(bak_raw.contains("example.com"));
    }

    #[tokio::test]
    async fn configure_non_interactive_applies_from_file_patch() {
        let (d, path) = write_tmp(RAW);
        let patch_path = d.path().join("patch.toml");
        std::fs::write(
            &patch_path,
            r#"port = 4242
[connection]
connect_timeout = "9s"
"#,
        )
        .unwrap();

        let g = global_with_path(&path);
        let args = configure_args(Some("p"), &[], Some(&patch_path));
        configure_non_interactive(&g, args).await.unwrap();

        let new_raw = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = spt_config::load_str(&new_raw, false).unwrap();
        assert_eq!(cfg.profiles[0].port, Some(4242));
        assert_eq!(
            cfg.profiles[0]
                .connection
                .as_ref()
                .and_then(|c| c.connect_timeout.clone())
                .as_deref(),
            Some("9s"),
        );
    }

    #[tokio::test]
    async fn configure_non_interactive_accepts_profile_table_wrapper() {
        let (d, path) = write_tmp(RAW);
        let patch_path = d.path().join("patch.toml");
        std::fs::write(
            &patch_path,
            r#"[profile]
port = 7777
user = "bob"
"#,
        )
        .unwrap();

        let g = global_with_path(&path);
        let args = configure_args(Some("p"), &[], Some(&patch_path));
        configure_non_interactive(&g, args).await.unwrap();

        let (cfg, _) = spt_config::load(&path, false).unwrap();
        assert_eq!(cfg.profiles[0].port, Some(7777));
        assert_eq!(cfg.profiles[0].user.as_deref(), Some("bob"));
    }

    #[tokio::test]
    async fn configure_non_interactive_requires_some_edit() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = configure_args(Some("p"), &[], None);
        let err = configure_non_interactive(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn configure_non_interactive_validation_failure_does_not_write() {
        let (_d, path) = write_tmp(RAW);
        let original = std::fs::read_to_string(&path).unwrap();
        let g = global_with_path(&path);
        let args = configure_args(Some("p"), &["protocol=carrier-pigeon"], None);
        let err = configure_non_interactive(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));

        // Primary untouched, no backup created (we abort before backup).
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, original);
        assert!(!backup_path(&path).exists());
    }

    #[tokio::test]
    async fn configure_non_interactive_infers_single_profile_name() {
        let (_d, path) = write_tmp(RAW);
        let g = global_with_path(&path);
        let args = configure_args(None, &["port=2345"], None);
        configure_non_interactive(&g, args).await.unwrap();
        let (cfg, _) = spt_config::load(&path, false).unwrap();
        assert_eq!(cfg.profiles[0].port, Some(2345));
    }

    #[tokio::test]
    async fn configure_non_interactive_rejects_missing_from_file() {
        let (_d, path) = write_tmp(RAW);
        let bogus = path.with_file_name("does-not-exist.toml");
        let g = global_with_path(&path);
        let args = configure_args(Some("p"), &[], Some(&bogus));
        let err = configure_non_interactive(&g, args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn backup_path_appends_bak_suffix() {
        let p = Path::new("/etc/spt/spt.toml");
        assert_eq!(backup_path(p), Path::new("/etc/spt/spt.toml.bak"));
    }

    // ──────── M2: escape server-controlled peer banner / error text ─────────

    fn plain_styler() -> crate::cli::style::Styler {
        crate::cli::style::Styler::new(false)
    }

    #[test]
    fn format_test_line_escapes_peer_banner() {
        // A malicious SSH identification banner with ESC/CR/newline must be
        // neutralized before it reaches the operator's terminal.
        let r = EndpointResult {
            id: "evil.example:22".into(),
            host: "evil.example".into(),
            port: 22,
            status: EndpointStatus::Connected {
                peer_version: Some("SSH-2.0-x\x1b[31m\r\nLEAK".into()),
            },
            latency_ms: 12,
        };
        let line = format_test_line(plain_styler(), &r);
        assert!(!line.contains('\x1b'), "ESC must be escaped: {line:?}");
        assert!(!line.contains('\n'), "newline must be escaped: {line:?}");
        assert!(!line.contains('\r'), "CR must be escaped: {line:?}");
        assert!(line.contains("\\u{1b}") && line.contains("\\r") && line.contains("\\n"));
    }

    #[test]
    fn format_test_line_escapes_failure_text() {
        let r = EndpointResult {
            id: "h:22".into(),
            host: "h".into(),
            port: 22,
            status: EndpointStatus::Failed("auth failed\x1b]0;pwned\x07".into()),
            latency_ms: 5,
        };
        let line = format_test_line(plain_styler(), &r);
        assert!(!line.contains('\x1b'), "ESC must be escaped: {line:?}");
        assert!(!line.contains('\x07'), "BEL must be escaped: {line:?}");
    }

    #[test]
    fn format_test_line_clean_input_preserved() {
        let connected = EndpointResult {
            id: "ok:22".into(),
            host: "ok".into(),
            port: 22,
            status: EndpointStatus::Connected {
                peer_version: Some("SSH-2.0-OpenSSH_9.6".into()),
            },
            latency_ms: 7,
        };
        assert_eq!(
            format_test_line(plain_styler(), &connected),
            "endpoint ok:22: connected in 7ms (peer: SSH-2.0-OpenSSH_9.6)"
        );

        let failed = EndpointResult {
            id: "ok:22".into(),
            host: "ok".into(),
            port: 22,
            status: EndpointStatus::Failed("connection refused".into()),
            latency_ms: 3,
        };
        assert_eq!(
            format_test_line(plain_styler(), &failed),
            "endpoint ok:22: failed in 3ms — connection refused"
        );
    }

    #[test]
    fn format_test_line_no_peer_version() {
        let r = EndpointResult {
            id: "ok:22".into(),
            host: "ok".into(),
            port: 22,
            status: EndpointStatus::Connected { peer_version: None },
            latency_ms: 1,
        };
        assert_eq!(
            format_test_line(plain_styler(), &r),
            "endpoint ok:22: connected in 1ms"
        );
    }
}
