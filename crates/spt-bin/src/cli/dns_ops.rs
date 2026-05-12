//! `spt dns` operational subcommands: `serve`, `status`, `query`, `upstream`,
//! `record`.
//!
//! Each entry point is a thin operation that drives the `spt-dns` crate. The
//! `serve` command runs a foreground resolver bound on a config-derived (or
//! `--bind`-overridden) address, useful for testing per-machine DNS without
//! spinning up a full `tunnel run`. `status`/`query` read from the running
//! supervisor's snapshot or talk to it over loopback UDP. `upstream` and
//! `record` enumerate or mutate the `[dns]` config block via the
//! comment-preserving [`spt_config::mutate::Document`] mutator.
//!
//! Mirrors the orchestration plan `cli-fill-final.md` (`dns_ops` section).

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::default_trait_access)]
// Several entry points are `async` for symmetry with `cli_dispatch::*` even
// when their body does not await — mirrors the convention used by
// `tunnel_ops`/`config_ops` so the dispatch layer can call them uniformly.
#![allow(clippy::unused_async)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use spt_cli::groups::dns::{
    DnsQuery, DnsRecord, DnsRecordAdd, DnsRecordRemove, DnsRecordSub, DnsServe, DnsStatus,
    DnsUpstream, DnsUpstreamSet, DnsUpstreamSub, RecordType,
};
use spt_cli::GlobalOpts;
use spt_config::schema::{Config, Dns, DnsRecord as ConfigDnsRecord};
use spt_core::{Error, Result};
use spt_dns::{DnsServerBuilder, ManagedZone, Record, RecordKind};

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// `spt dns serve` — run the split-horizon resolver in the foreground.
///
/// Honors `--config <PATH>` (overrides the global `--config`). The bind
/// address comes from `[dns].bind` (default `127.0.0.1:5353`). Logs each
/// startup line at info level. Ctrl-C triggers a graceful shutdown.
pub async fn serve(global: &GlobalOpts, args: DnsServeArgs) -> Result<()> {
    let cfg = load_config_for(global, args.config.as_deref())?;
    let dns_cfg = cfg.dns.clone().unwrap_or_default();

    if matches!(dns_cfg.enabled, Some(false)) {
        // Honor an explicit `enabled = false`. `serve` is a debug helper, so
        // we still allow opt-in via the `--config` override; surface a clear
        // error rather than silently binding nothing.
        return Err(Error::InvalidConfig(
            "dns disabled in config (`[dns].enabled = false`); pass `--config` with a config that enables it".into(),
        ));
    }

    let bind = parse_bind(dns_cfg.bind.as_deref(), DEFAULT_DNS_BIND)?;
    let upstream = parse_upstream_list(dns_cfg.upstream.as_deref().unwrap_or(&[]))?;
    let zone = build_managed_zone(&dns_cfg)?;

    let mut builder = DnsServerBuilder::new().bind(bind).upstream(upstream);
    if !zone.records.is_empty() {
        builder = builder.add_zone(zone);
    }
    let handle = builder
        .run()
        .await
        .map_err(|e| Error::DnsFailed(format!("dns serve: {e}")))?;

    tracing::info!(
        udp = %handle.udp_addr(),
        tcp = %handle.tcp_addr(),
        "spt dns serve: foreground resolver bound; press Ctrl-C to stop"
    );
    if !args.quiet {
        eprintln!(
            "spt dns serve: bound udp={} tcp={} (Ctrl-C to stop)",
            handle.udp_addr(),
            handle.tcp_addr()
        );
    }

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let _ = (&mut ctrl_c).await;
    handle.shutdown().await;
    if !args.quiet {
        eprintln!("spt dns serve: stopped");
    }
    Ok(())
}

/// `spt dns status` — report whether the running spt's resolver is bound.
///
/// Reads `<state_dir>/status.json`. Exit code 1 if no spt is running or the
/// resolver is not enabled; 0 otherwise.
pub async fn status(global: &GlobalOpts, args: DnsStatusArgs) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let snap_path = spt_state::paths::status_path(&state_dir);
    let snap_raw = std::fs::read_to_string(&snap_path).ok();

    // Pull the bind address from config too (status.json doesn't currently
    // include the DNS bind — it's derived from [dns].bind in the loaded cfg).
    let cfg = load_config_for(global, None).ok();
    let bind = cfg
        .as_ref()
        .and_then(|c| c.dns.as_ref())
        .and_then(|d| d.bind.clone());
    let enabled = cfg
        .as_ref()
        .and_then(|c| c.dns.as_ref())
        .and_then(|d| d.enabled)
        .unwrap_or(false);

    let parsed_records: Vec<spt_state::status::DnsRecordStatus> = snap_raw
        .as_ref()
        .and_then(|s| serde_json::from_str::<spt_state::status::StatusSnapshot>(s).ok())
        .map(|s| s.dns_records)
        .unwrap_or_default();

    let active = snap_raw.is_some() && enabled;
    let report = StatusReport {
        active,
        bound: if active { bind.clone() } else { None },
        managed_records: parsed_records.len(),
        recent_query_rate: None, // not tracked in status.json yet.
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| Error::RuntimeFailure(format!("serialize status: {e}")))?
        );
    } else if !active {
        println!("DNS resolver not active");
    } else {
        println!(
            "DNS resolver active: bound={} managed_records={}",
            report.bound.as_deref().unwrap_or("(unknown)"),
            report.managed_records
        );
    }

    if !active {
        return Err(Error::RuntimeFailure("dns resolver not active".to_string()));
    }
    Ok(())
}

/// `spt dns query <name>` — issue a one-shot query against the running
/// resolver (or the configured upstream when `upstream = true`).
pub async fn query(global: &GlobalOpts, args: DnsQueryArgs) -> Result<()> {
    let kind = args.kind.unwrap_or(RecordKind::A);
    let cfg = load_config_for(global, None).ok();

    let target = if args.upstream {
        let upstreams = cfg
            .as_ref()
            .and_then(|c| c.dns.as_ref())
            .and_then(|d| d.upstream.clone())
            .unwrap_or_default();
        if upstreams.is_empty() {
            return Err(Error::InvalidArgs(
                "no upstream resolvers configured ([dns].upstream is empty)".into(),
            ));
        }
        parse_one_addr(&upstreams[0])?
    } else {
        // Default: query the running spt's loopback resolver. Fall back to
        // the config bind if status.json is missing.
        let bind = cfg
            .as_ref()
            .and_then(|c| c.dns.as_ref())
            .and_then(|d| d.bind.clone())
            .unwrap_or_else(|| DEFAULT_DNS_BIND.to_string());
        parse_bind(Some(&bind), DEFAULT_DNS_BIND)?
    };

    let answers = spt_dns::query_resolver(target, &args.name, kind)
        .await
        .map_err(|e| Error::DnsFailed(format!("dns query: {e}")))?;

    if args.json {
        let body = QueryReport {
            name: &args.name,
            kind: kind_label(kind),
            target: target.to_string(),
            answers: answers
                .iter()
                .map(|a| QueryAnswer {
                    kind: kind_label(a.kind),
                    value: a.value.clone(),
                    ttl_seconds: a.ttl.as_secs(),
                })
                .collect(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&body)
                .map_err(|e| Error::RuntimeFailure(format!("serialize query: {e}")))?
        );
        return Ok(());
    }

    println!(
        ";; QUERY {} {} (resolver {})",
        args.name,
        kind_label(kind),
        target
    );
    println!(";; ANSWER SECTION");
    if answers.is_empty() {
        println!("(no records)");
    } else {
        for a in &answers {
            println!(
                "{}\t{}\t{}\t{}",
                args.name,
                a.ttl.as_secs(),
                kind_label(a.kind),
                a.value
            );
        }
    }
    Ok(())
}

/// `spt dns upstream` — `set` (replace the upstream list, persisted to disk)
/// or `list` (the configured upstreams; default when no subcommand is wired
/// in).
pub async fn upstream(global: &GlobalOpts, args: DnsUpstreamArgs) -> Result<()> {
    match args.action {
        DnsUpstreamAction::List => {
            let cfg = load_config_for(global, None)?;
            let list = cfg
                .dns
                .as_ref()
                .and_then(|d| d.upstream.clone())
                .unwrap_or_default();
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&list)
                        .map_err(|e| Error::RuntimeFailure(format!("serialize upstream: {e}")))?
                );
            } else if list.is_empty() {
                println!("(no upstream resolvers configured)");
            } else {
                for u in &list {
                    println!("{u}");
                }
            }
            Ok(())
        }
        DnsUpstreamAction::Set(values) => {
            // Validate each entry parses to a SocketAddr before mutating.
            parse_upstream_list(&values)?;
            let path = require_config_path(global)?;
            let mut doc = spt_config::mutate::Document::read(&path)?;
            set_upstream_in_doc(doc.document_mut(), &values);
            doc.write_atomic(&path)?;
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "upstream": values,
                    }))
                    .map_err(|e| Error::RuntimeFailure(format!("serialize upstream: {e}")))?
                );
            } else {
                println!("upstream: set ({})", values.join(", "));
            }
            Ok(())
        }
    }
}

/// `spt dns record add | remove` — atomic edits to `[[dns.records]]` via the
/// comment-preserving mutator. After persisting, also lists the resulting
/// records when human output is requested.
pub async fn record(global: &GlobalOpts, args: DnsRecordArgs) -> Result<()> {
    match args.action {
        DnsRecordAction::List => {
            let cfg = load_config_for(global, None)?;
            let records = cfg
                .dns
                .as_ref()
                .map(|d| d.records.clone())
                .unwrap_or_default();
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&records)
                        .map_err(|e| Error::RuntimeFailure(format!("serialize records: {e}")))?
                );
            } else if records.is_empty() {
                println!("(no managed records)");
            } else {
                println!("NAME\tTYPE\tVALUE\tTTL");
                for r in &records {
                    println!(
                        "{}\t{}\t{}\t{}",
                        r.name,
                        r.kind,
                        r.value,
                        r.ttl.as_deref().unwrap_or("-")
                    );
                }
            }
            Ok(())
        }
        DnsRecordAction::Add(add) => {
            let path = require_config_path(global)?;
            // Validate first.
            let kind = guess_kind_from_value(&add.value).ok_or_else(|| {
                Error::InvalidArgs(format!(
                    "cannot infer record type from value `{}` (use a dotted IPv4 or hex IPv6)",
                    add.value
                ))
            })?;
            let r = Record {
                name: add.name.clone(),
                kind,
                value: add.value.clone(),
                ttl: parse_ttl(add.ttl.as_deref()).unwrap_or(Duration::from_secs(60)),
                answer_policy: spt_dns::AnswerPolicy::AlwaysAnswer,
                forward_id: None,
            };
            r.validate()
                .map_err(|e| Error::InvalidArgs(format!("invalid record: {e}")))?;

            let mut doc = spt_config::mutate::Document::read(&path)?;
            add_record_in_doc(doc.document_mut(), &add)?;
            doc.write_atomic(&path)?;

            // Best-effort: if a supervisor is running with MCP enabled, ask
            // it to reload. Failure is logged, not fatal.
            best_effort_reload(global).await;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true, "name": add.name, "value": add.value,
                    }))
                    .map_err(|e| Error::RuntimeFailure(format!("serialize record: {e}")))?
                );
            } else {
                println!("record added: {} -> {}", add.name, add.value);
            }
            Ok(())
        }
        DnsRecordAction::Remove(rm) => {
            let path = require_config_path(global)?;
            let mut doc = spt_config::mutate::Document::read(&path)?;
            let removed = remove_record_in_doc(doc.document_mut(), &rm.name);
            if !removed {
                return Err(Error::InvalidArgs(format!(
                    "record `{}` not found",
                    rm.name
                )));
            }
            doc.write_atomic(&path)?;
            best_effort_reload(global).await;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true, "name": rm.name,
                    }))
                    .map_err(|e| Error::RuntimeFailure(format!("serialize record: {e}")))?
                );
            } else {
                println!("record removed: {}", rm.name);
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Arg wrapper types — kept separate from clap structs so the dispatch layer
// can pass either a parsed clap struct or a synthesized one (tests).
// ---------------------------------------------------------------------------

/// Parsed args for `dns serve`.
#[derive(Debug, Default, Clone)]
pub struct DnsServeArgs {
    /// Override config path.
    pub config: Option<PathBuf>,
    /// Suppress non-essential output.
    pub quiet: bool,
}

impl From<DnsServe> for DnsServeArgs {
    fn from(v: DnsServe) -> Self {
        Self {
            config: v.config,
            quiet: !v.foreground, // when not foreground we still run, just quietly
        }
    }
}

/// Parsed args for `dns status`.
#[derive(Debug, Default, Clone)]
pub struct DnsStatusArgs {
    pub json: bool,
}

impl From<DnsStatus> for DnsStatusArgs {
    fn from(v: DnsStatus) -> Self {
        Self { json: v.json }
    }
}

/// Parsed args for `dns query`.
#[derive(Debug, Clone)]
pub struct DnsQueryArgs {
    pub name: String,
    pub kind: Option<RecordKind>,
    /// Bypass spt and ask the configured upstream directly.
    pub upstream: bool,
    pub json: bool,
}

impl From<DnsQuery> for DnsQueryArgs {
    fn from(v: DnsQuery) -> Self {
        Self {
            name: v.name,
            kind: v.r#type.map(record_type_to_kind),
            upstream: false,
            json: false,
        }
    }
}

/// Parsed args for `dns upstream`.
#[derive(Debug, Clone)]
pub struct DnsUpstreamArgs {
    pub action: DnsUpstreamAction,
    pub json: bool,
}

/// `spt dns upstream` action.
#[derive(Debug, Clone)]
pub enum DnsUpstreamAction {
    /// Print the configured upstream list.
    List,
    /// Replace the upstream list.
    Set(Vec<String>),
}

impl From<DnsUpstream> for DnsUpstreamArgs {
    fn from(v: DnsUpstream) -> Self {
        match v.command {
            DnsUpstreamSub::Set(DnsUpstreamSet { upstreams }) => Self {
                action: DnsUpstreamAction::Set(upstreams),
                json: false,
            },
        }
    }
}

/// Parsed args for `dns record`.
#[derive(Debug, Clone)]
pub struct DnsRecordArgs {
    pub action: DnsRecordAction,
    pub json: bool,
}

/// `spt dns record` action.
#[derive(Debug, Clone)]
pub enum DnsRecordAction {
    /// Print all managed records.
    List,
    /// Add a record.
    Add(DnsRecordAddArgs),
    /// Remove a record by name.
    Remove(DnsRecordRemoveArgs),
}

/// Owned form of [`DnsRecordAdd`] for use in tests / non-clap callers.
#[derive(Debug, Default, Clone)]
pub struct DnsRecordAddArgs {
    pub name: String,
    pub value: String,
    pub ttl: Option<String>,
}

impl From<DnsRecordAdd> for DnsRecordAddArgs {
    fn from(v: DnsRecordAdd) -> Self {
        Self {
            name: v.name,
            value: v.addr,
            ttl: v.ttl,
        }
    }
}

/// Owned form of [`DnsRecordRemove`].
#[derive(Debug, Default, Clone)]
pub struct DnsRecordRemoveArgs {
    pub name: String,
}

impl From<DnsRecordRemove> for DnsRecordRemoveArgs {
    fn from(v: DnsRecordRemove) -> Self {
        Self { name: v.name }
    }
}

impl From<DnsRecord> for DnsRecordArgs {
    fn from(v: DnsRecord) -> Self {
        match v.command {
            DnsRecordSub::Add(a) => Self {
                action: DnsRecordAction::Add(a.into()),
                json: false,
            },
            DnsRecordSub::Remove(r) => Self {
                action: DnsRecordAction::Remove(r.into()),
                json: false,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// JSON output shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct StatusReport {
    active: bool,
    bound: Option<String>,
    managed_records: usize,
    recent_query_rate: Option<f64>,
}

#[derive(Debug, Serialize)]
struct QueryReport<'a> {
    name: &'a str,
    kind: &'static str,
    target: String,
    answers: Vec<QueryAnswer>,
}

#[derive(Debug, Serialize)]
struct QueryAnswer {
    kind: &'static str,
    value: String,
    ttl_seconds: u64,
}

// ---------------------------------------------------------------------------
// Helpers — config / state / parsing
// ---------------------------------------------------------------------------

const DEFAULT_DNS_BIND: &str = "127.0.0.1:5353";

fn resolve_state_dir_for_read(global: &GlobalOpts) -> Result<PathBuf> {
    spt_state::resolve_state_dir(global.state_dir.as_deref())
}

fn require_config_path(global: &GlobalOpts) -> Result<PathBuf> {
    global.config.clone().ok_or_else(|| {
        Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
    })
}

fn load_config_for(global: &GlobalOpts, override_path: Option<&Path>) -> Result<Config> {
    let path = override_path
        .map(Path::to_path_buf)
        .or_else(|| global.config.clone())
        .ok_or_else(|| {
            Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
        })?;
    let (cfg, _warnings) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    Ok(cfg)
}

fn parse_bind(s: Option<&str>, fallback: &str) -> Result<SocketAddr> {
    let raw = s.unwrap_or(fallback);
    raw.parse::<SocketAddr>()
        .map_err(|e| Error::InvalidConfig(format!("invalid bind `{raw}`: {e}")))
}

fn parse_one_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    // Allow bare IPs by defaulting to port 53.
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(Error::InvalidConfig(format!(
        "invalid resolver address `{s}`"
    )))
}

fn parse_upstream_list(items: &[String]) -> Result<Vec<SocketAddr>> {
    items.iter().map(|s| parse_one_addr(s)).collect()
}

fn parse_ttl(s: Option<&str>) -> Option<Duration> {
    s.and_then(|raw| spt_core::duration::parse_duration(raw).ok())
}

fn build_managed_zone(d: &Dns) -> Result<ManagedZone> {
    let suffix = d.zone.clone().unwrap_or_else(|| "tunnel.local.".into());
    let default_ttl = parse_ttl(d.ttl.as_deref()).unwrap_or(Duration::from_secs(60));
    let mut zone = ManagedZone::new(suffix);
    for rec in &d.records {
        let kind = parse_record_kind(&rec.kind)?;
        let ttl = parse_ttl(rec.ttl.as_deref()).unwrap_or(default_ttl);
        let value = canonical_value(rec, kind);
        let r = Record {
            name: rec.name.clone(),
            kind,
            value,
            ttl,
            answer_policy: spt_dns::AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        zone.add(r)
            .map_err(|e| Error::InvalidConfig(format!("dns.records: {e}")))?;
    }
    Ok(zone)
}

fn parse_record_kind(s: &str) -> Result<RecordKind> {
    Ok(match s.to_ascii_uppercase().as_str() {
        "A" => RecordKind::A,
        "AAAA" => RecordKind::AAAA,
        "SRV" => RecordKind::SRV,
        "TXT" => RecordKind::TXT,
        other => {
            return Err(Error::InvalidConfig(format!(
                "unknown dns record type `{other}`"
            )))
        }
    })
}

/// Canonical record value: SRV records may be specified via separate
/// `priority`/`weight`/`port` fields in `[[dns.records]]`. Reassemble them.
fn canonical_value(rec: &ConfigDnsRecord, kind: RecordKind) -> String {
    if kind == RecordKind::SRV {
        if let (Some(p), Some(w), Some(port)) = (rec.priority, rec.weight, rec.port) {
            return format!("{p} {w} {port} {}", rec.value);
        }
    }
    rec.value.clone()
}

fn record_type_to_kind(t: RecordType) -> RecordKind {
    match t {
        RecordType::A => RecordKind::A,
        RecordType::Aaaa => RecordKind::AAAA,
        RecordType::Srv => RecordKind::SRV,
        RecordType::Txt => RecordKind::TXT,
    }
}

fn kind_label(k: RecordKind) -> &'static str {
    match k {
        RecordKind::A => "A",
        RecordKind::AAAA => "AAAA",
        RecordKind::SRV => "SRV",
        RecordKind::TXT => "TXT",
    }
}

fn guess_kind_from_value(v: &str) -> Option<RecordKind> {
    if v.parse::<Ipv4Addr>().is_ok() {
        Some(RecordKind::A)
    } else if v.parse::<Ipv6Addr>().is_ok() {
        Some(RecordKind::AAAA)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers — toml_edit mutators
// ---------------------------------------------------------------------------

fn set_upstream_in_doc(doc: &mut toml_edit::DocumentMut, values: &[String]) {
    use toml_edit::{value, Array, Item, Table};
    let dns = doc
        .entry("dns")
        .or_insert_with(|| Item::Table(Table::new()));
    let Item::Table(tbl) = dns else { return };
    let mut arr = Array::new();
    for v in values {
        arr.push(v.as_str());
    }
    tbl["upstream"] = value(arr);
}

fn add_record_in_doc(doc: &mut toml_edit::DocumentMut, add: &DnsRecordAddArgs) -> Result<()> {
    use toml_edit::{value, ArrayOfTables, Item, Table};

    let kind = guess_kind_from_value(&add.value).ok_or_else(|| {
        Error::InvalidArgs(format!("cannot infer record type from `{}`", add.value))
    })?;

    let dns = doc
        .entry("dns")
        .or_insert_with(|| Item::Table(Table::new()));
    let Item::Table(dns_tbl) = dns else {
        return Err(Error::InvalidConfig("`dns` must be a table".into()));
    };

    // `[[dns.records]]` is an implicit-key array-of-tables nested under [dns].
    let recs_item = dns_tbl
        .entry("records")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
    let Item::ArrayOfTables(recs) = recs_item else {
        return Err(Error::InvalidConfig(
            "`dns.records` must be an array of tables".into(),
        ));
    };

    // Reject duplicate name+value pairs to keep idempotence trivial.
    for r in recs.iter() {
        let same_name = r.get("name").and_then(|v| v.as_str()) == Some(add.name.as_str());
        let same_value = r.get("value").and_then(|v| v.as_str()) == Some(add.value.as_str());
        if same_name && same_value {
            return Err(Error::InvalidArgs(format!(
                "record `{}` -> `{}` already exists",
                add.name, add.value
            )));
        }
    }

    let mut tbl = Table::new();
    tbl["name"] = value(&add.name);
    tbl["type"] = value(kind_label(kind));
    tbl["value"] = value(&add.value);
    if let Some(ttl) = &add.ttl {
        tbl["ttl"] = value(ttl.as_str());
    }
    recs.push(tbl);
    Ok(())
}

fn remove_record_in_doc(doc: &mut toml_edit::DocumentMut, name: &str) -> bool {
    use toml_edit::Item;
    let Some(Item::Table(dns_tbl)) = doc.get_mut("dns") else {
        return false;
    };
    let Some(Item::ArrayOfTables(recs)) = dns_tbl.get_mut("records") else {
        return false;
    };
    let mut idx_to_remove: Option<usize> = None;
    for (i, r) in recs.iter().enumerate() {
        if r.get("name").and_then(|v| v.as_str()) == Some(name) {
            idx_to_remove = Some(i);
            break;
        }
    }
    if let Some(i) = idx_to_remove {
        recs.remove(i);
        true
    } else {
        false
    }
}

async fn best_effort_reload(global: &GlobalOpts) {
    let Ok(state_dir) = resolve_state_dir_for_read(global) else {
        return;
    };
    if let Ok(mut client) = crate::mcp_client::McpClient::connect_from_state_dir(&state_dir).await {
        if client.initialize().await.is_ok() {
            // Best-effort; ignore the response.
            let _ = client
                .call_tool("config_reload", serde_json::json!({}))
                .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spt_config::schema::DnsRecord as ConfigDnsRecord;

    #[test]
    fn parse_bind_falls_back_when_none() {
        let a = parse_bind(None, DEFAULT_DNS_BIND).unwrap();
        assert_eq!(a.to_string(), DEFAULT_DNS_BIND);
        let a = parse_bind(Some("127.0.0.1:0"), DEFAULT_DNS_BIND).unwrap();
        assert_eq!(a.port(), 0);
    }

    #[test]
    fn parse_bind_rejects_garbage() {
        let err = parse_bind(Some("not-an-addr"), DEFAULT_DNS_BIND).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn parse_one_addr_accepts_bare_ip_and_socket() {
        let a = parse_one_addr("8.8.8.8").unwrap();
        assert_eq!(a.port(), 53);
        let a = parse_one_addr("8.8.8.8:5353").unwrap();
        assert_eq!(a.port(), 5353);
    }

    #[test]
    fn build_managed_zone_round_trips_records() {
        let dns = Dns {
            enabled: Some(true),
            zone: Some("tunnel.local.".into()),
            ttl: Some("60s".into()),
            records: vec![
                ConfigDnsRecord {
                    name: "a.tunnel.local.".into(),
                    kind: "A".into(),
                    value: "10.0.0.1".into(),
                    ..Default::default()
                },
                ConfigDnsRecord {
                    name: "_smtp._tcp.tunnel.local.".into(),
                    kind: "SRV".into(),
                    value: "mail.tunnel.local.".into(),
                    ttl: Some("5m".into()),
                    priority: Some(10),
                    weight: Some(5),
                    port: Some(25),
                },
            ],
            ..Default::default()
        };
        let zone = build_managed_zone(&dns).unwrap();
        assert_eq!(zone.records.len(), 2);
        assert_eq!(zone.records[0].kind, RecordKind::A);
        assert_eq!(zone.records[1].kind, RecordKind::SRV);
        // Canonical SRV value: "<priority> <weight> <port> <target>".
        assert_eq!(zone.records[1].value, "10 5 25 mail.tunnel.local.");
    }

    #[test]
    fn build_managed_zone_rejects_invalid_kind() {
        let dns = Dns {
            zone: Some("z.".into()),
            records: vec![ConfigDnsRecord {
                name: "n.z.".into(),
                kind: "BOGUS".into(),
                value: "1.2.3.4".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = build_managed_zone(&dns).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn guess_kind_from_value_ipv4_v6() {
        assert_eq!(guess_kind_from_value("10.0.0.1"), Some(RecordKind::A));
        assert_eq!(guess_kind_from_value("fd00::1"), Some(RecordKind::AAAA));
        assert_eq!(guess_kind_from_value("not-an-ip"), None);
    }

    #[test]
    fn add_and_remove_record_in_doc_round_trip() {
        let raw = r#"
[dns]
enabled = true
zone = "tunnel.local."
"#;
        let mut doc: toml_edit::DocumentMut = raw.parse().unwrap();
        add_record_in_doc(
            &mut doc,
            &DnsRecordAddArgs {
                name: "alpha.tunnel.local.".into(),
                value: "10.0.0.1".into(),
                ttl: Some("5m".into()),
            },
        )
        .unwrap();
        let s = doc.to_string();
        assert!(s.contains("alpha.tunnel.local."), "got:\n{s}");
        assert!(s.contains("10.0.0.1"));

        // Re-parse and delete; confirm gone.
        let removed = remove_record_in_doc(&mut doc, "alpha.tunnel.local.");
        assert!(removed);
        let removed_again = remove_record_in_doc(&mut doc, "alpha.tunnel.local.");
        assert!(!removed_again);
    }

    #[test]
    fn add_record_rejects_duplicate() {
        let raw = "[dns]\n";
        let mut doc: toml_edit::DocumentMut = raw.parse().unwrap();
        let a = DnsRecordAddArgs {
            name: "n.".into(),
            value: "1.2.3.4".into(),
            ttl: None,
        };
        add_record_in_doc(&mut doc, &a).unwrap();
        let err = add_record_in_doc(&mut doc, &a).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn set_upstream_creates_array() {
        let raw = "";
        let mut doc: toml_edit::DocumentMut = raw.parse().unwrap();
        set_upstream_in_doc(&mut doc, &["1.1.1.1:53".into(), "8.8.8.8:53".into()]);
        let s = doc.to_string();
        assert!(s.contains("[dns]"), "{s}");
        assert!(s.contains("1.1.1.1:53"));
        assert!(s.contains("8.8.8.8:53"));
    }

    // --- Async tests against a real DnsServer ---------------------------

    #[tokio::test]
    async fn serve_then_query_managed_record() {
        use spt_dns::testing::{FakeZone, LocalhostResolver};
        let zone = FakeZone::new("tunnel.local.")
            .a("alpha.tunnel.local.", "10.0.0.1".parse().unwrap())
            .build();
        let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
        let addr = resolver.udp_addr();

        let answers = spt_dns::query_resolver(addr, "alpha.tunnel.local.", RecordKind::A)
            .await
            .unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].value, "10.0.0.1");
        assert_eq!(answers[0].kind, RecordKind::A);
        resolver.shutdown().await;
    }

    #[tokio::test]
    async fn query_returns_empty_for_missing_record() {
        use spt_dns::testing::{FakeZone, LocalhostResolver};
        let zone = FakeZone::new("tunnel.local.")
            .a("alpha.tunnel.local.", "10.0.0.1".parse().unwrap())
            .build();
        let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
        let addr = resolver.udp_addr();
        // Ask for a name that does not exist in the zone (and has no
        // upstream), should come back empty without error.
        let answers = spt_dns::query_resolver(addr, "nope.tunnel.local.", RecordKind::A)
            .await
            .unwrap();
        assert!(answers.is_empty());
        resolver.shutdown().await;
    }

    #[tokio::test]
    async fn status_no_running_supervisor_errors() {
        let global = make_global_with_state(tempfile::tempdir().unwrap().path().to_path_buf());
        let err = status(&global, DnsStatusArgs { json: false })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }

    fn make_global_with_state(dir: PathBuf) -> GlobalOpts {
        // Build a minimal GlobalOpts. We only set the fields we need; other
        // fields use their type's default via clap's default_value_t, but
        // we have to provide them explicitly here.
        GlobalOpts {
            config: None,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: Some(dir),
            profile: None,
            output: spt_cli::OutputFormat::Human,
            json: false,
            log_level: spt_cli::LogLevel::Info,
            color: spt_cli::ColorMode::Auto,
            quiet: true,
            verbose: 0,
            no_color: false,
            dry_run: false,
        }
    }
}
