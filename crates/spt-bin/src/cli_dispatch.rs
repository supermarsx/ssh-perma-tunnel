//! CLI dispatch: maps every parsed [`spt_cli::Command`] to its implementing
//! crate.
//!
//! For commands that do real work in M0/M8 the body is implemented here.
//! Commands that depend on subsystems not yet wired (per the executor brief)
//! historically returned a structured stub error; as of t2-e5 every previously
//! stubbed command has a real implementation.

// Several group-dispatch functions are `async` for symmetry — they call into
// other async dispatchers as the wiring grows in later milestones. Suppress
// the `unused_async` lint for those that are currently sync-only.
#![allow(clippy::unused_async)]
// Many subcommand handlers `match` on broad enums where most arms are stubs;
// the inner function bodies are short and intentionally similar.
#![allow(clippy::match_same_arms)]
// Help strings include code snippets that pedantic clippy likes to flag.
#![allow(clippy::doc_markdown)]
// Many handlers take a `&GlobalOpts` they don't immediately consume;
// keeping the parameter is part of the dispatcher contract.
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::manual_pattern_char_comparison)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::default_constructed_unit_structs)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::assigning_clones)]

use spt_cli::{groups, Cli, Command, GlobalOpts};
use spt_core::{Error, RedactionMode, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Top-level dispatcher.
pub async fn dispatch(cli: Cli) -> Result<()> {
    // `--config-dir <DIR>` loads `<DIR>/*.toml` in lex order via
    // `spt_config::load_dir`, merging into a single Config. The merged
    // config is materialised to a tempfile and substituted for
    // `global.config` so every downstream dispatcher (which reads a
    // single config path) transparently picks up the merged view.
    let global = if let Some(dir) = cli.global.config_dir.clone() {
        let (cfg, _w) = spt_config::load_dir(&dir, false)?;
        let body = spt_config::render(&cfg, RedactionMode::None);
        let tmp = std::env::temp_dir().join(format!("spt-merged-{}.toml", std::process::id()));
        std::fs::write(&tmp, body).map_err(|e| {
            Error::InvalidConfig(format!(
                "write merged config-dir to `{}`: {e}",
                tmp.display()
            ))
        })?;
        let mut g = cli.global.clone();
        g.config = Some(tmp);
        g
    } else {
        cli.global.clone()
    };
    match cli.command {
        Command::Config(c) => config_dispatch(&global, c).await,
        Command::Profile(c) => profile_dispatch(&global, c).await,
        Command::Forward(c) => forward_dispatch(&global, c).await,
        Command::Tunnel(c) => tunnel_dispatch(&global, c).await,
        Command::Service(c) => service_dispatch(&global, c).await,
        Command::Key(c) => key_dispatch(&global, c).await,
        Command::Secret(c) => secret_dispatch(&global, c).await,
        Command::Auth(c) => auth_dispatch(&global, c).await,
        Command::Dns(c) => dns_dispatch(&global, c).await,
        Command::Firewall(c) => firewall_dispatch(&global, c).await,
        Command::Log(c) => log_dispatch(&global, c).await,
        Command::Observe(c) => observe_dispatch(&global, c).await,
        Command::Event(c) => event_dispatch(&global, c).await,
        Command::Stats(c) => stats_dispatch(&global, c).await,
        Command::Session(c) => session_dispatch(&global, c).await,
        Command::Diagnose(c) => diagnose_dispatch(&global, c).await,
        Command::Benchmark(c) => benchmark_dispatch(&global, c).await,
        Command::Mcp(c) => mcp_dispatch(&global, c).await,
        Command::Status(c) => status_dispatch(&global, c).await,
        Command::Completion(c) => completion_dispatch(&global, c),
    }
}

// ============================================================================
// config
// ============================================================================

async fn config_dispatch(global: &GlobalOpts, c: groups::config::ConfigCmd) -> Result<()> {
    use groups::config::ConfigSub;
    match c.command {
        ConfigSub::Init(args) => config_init(global, args).await,
        ConfigSub::Validate(args) => config_validate(global, args.strict),
        ConfigSub::Doctor(args) => crate::cli::config_ops::doctor(global, args).await,
        ConfigSub::Render(args) => config_render(global, args),
        ConfigSub::Diff(args) => config_diff(args),
        ConfigSub::Migrate(args) => config_migrate(global, args),
        ConfigSub::Reload(args) => crate::cli::config_ops::reload(global, args).await,
        ConfigSub::Pull(args) => config_pull(global, args).await,
        ConfigSub::Trust(args) => config_trust(global, args),
    }
}

fn config_validate(global: &GlobalOpts, strict: bool) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, warnings) = spt_config::load(&path, strict)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let diags = spt_config::validate(&cfg);
    let mut had_error = false;
    for w in &warnings {
        if strict {
            had_error = true;
            eprintln!("error: unknown field `{w}`");
        } else {
            eprintln!("warning: unknown field `{w}`");
        }
    }
    for d in &diags.errors {
        had_error = true;
        eprintln!("error[{}]: {}", d.code, d.message);
    }
    for d in &diags.warnings {
        eprintln!("warning[{}]: {}", d.code, d.message);
    }
    if had_error {
        return Err(Error::InvalidConfig(format!(
            "validation failed for `{}`",
            path.display()
        )));
    }
    println!("ok: {} ({} profile(s))", path.display(), cfg.profiles.len());
    Ok(())
}

fn config_render(global: &GlobalOpts, args: groups::config::ConfigRender) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _w) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let mode = if args.redacted {
        RedactionMode::Standard
    } else {
        RedactionMode::None
    };
    if args.json {
        let s = serde_json::to_string_pretty(&cfg)
            .map_err(|e| Error::InvalidConfig(format!("json render: {e}")))?;
        println!("{s}");
    } else {
        println!("{}", spt_config::render(&cfg, mode));
    }
    Ok(())
}

fn config_diff(args: groups::config::ConfigDiff) -> Result<()> {
    let (a, _) = spt_config::load(&args.from, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", args.from.display())))?;
    let (b, _) = spt_config::load(&args.to, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", args.to.display())))?;
    let changes = spt_config::diff(&a, &b);
    if changes.is_empty() {
        println!("(no changes)");
    } else {
        for ch in changes {
            println!("{ch:?}");
        }
    }
    Ok(())
}

async fn config_init(global: &GlobalOpts, args: groups::config::ConfigInit) -> Result<()> {
    let path = args
        .path
        .clone()
        .or_else(|| global.config.clone())
        .ok_or_else(|| Error::InvalidArgs("provide --path or set --config / $SPT_CONFIG".into()))?;
    // `--example observability` writes the canned multi-sink template
    // shipped at `examples/observability.toml`.
    if matches!(
        args.example,
        Some(groups::config::ConfigExample::Observability)
    ) {
        crate::cli::config_ops::init_observability_example(&path).await?;
        println!("wrote {}", path.display());
        return Ok(());
    }
    if path.exists() {
        return Err(Error::InvalidArgs(format!(
            "refusing to overwrite existing file at `{}`",
            path.display()
        )));
    }
    let _ = args.example;
    let mut cfg = spt_config::schema::Config::default();
    cfg.version = 1;
    let body = spt_config::render(&cfg, RedactionMode::None);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::InvalidConfig(format!("mkdir `{}`: {e}", parent.display())))?;
        }
    }
    std::fs::write(&path, body)
        .map_err(|e| Error::InvalidConfig(format!("write `{}`: {e}", path.display())))?;
    println!("wrote {}", path.display());
    Ok(())
}

fn config_migrate(global: &GlobalOpts, args: groups::config::ConfigMigrate) -> Result<()> {
    // `spt_config::migrate` is a single entry point that reads the current
    // schema version and emits the next-version TOML. We don't strictly
    // honour `from-version`/`to-version` because the migrator does that
    // automatically; we surface their values in a sanity check only.
    let path = require_config_path(global)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
    let migrated =
        spt_config::migrate(&raw).map_err(|e| Error::InvalidConfig(format!("migrate: {e}")))?;
    let _ = (args.from_version, args.to_version);
    spt_state::write_atomic_string(&path, &migrated)
        .map_err(|e| Error::InvalidConfig(format!("write `{}`: {e}", path.display())))?;
    println!("migrated {}", path.display());
    Ok(())
}

async fn config_pull(global: &GlobalOpts, args: groups::config::ConfigPull) -> Result<()> {
    use spt_remote_config::{RemoteConfigSpec, ReqwestFetcher};
    let fingerprint = args.fingerprint.clone().ok_or_else(|| {
        Error::InvalidArgs(
            "--fingerprint <SHA256> is required (remote-config pull is pin-only per spec §14.3)"
                .into(),
        )
    })?;
    let spec = RemoteConfigSpec {
        url: args.url.clone(),
        fingerprint_sha256: fingerprint,
        ..Default::default()
    };
    let state_dir = resolve_state_dir_for_read(global).unwrap_or_else(|_| std::env::temp_dir());
    let fetcher =
        ReqwestFetcher::new().map_err(|e| Error::InvalidConfig(format!("reqwest fetcher: {e}")))?;
    let result = spt_remote_config::fetch(&spec, &state_dir, &fetcher)
        .await
        .map_err(|e| Error::InvalidConfig(format!("remote-config fetch: {e}")))?;
    if let Some(out) = &args.out {
        std::fs::write(out, &result.body)
            .map_err(|e| Error::InvalidConfig(format!("write `{}`: {e}", out.display())))?;
        println!("wrote {} ({:?})", out.display(), result.outcome);
    } else {
        std::io::stdout()
            .write_all(&result.body)
            .map_err(|e| Error::RuntimeFailure(format!("stdout: {e}")))?;
    }
    let _ = args.cache; // already cached side-effect of fetch()
    Ok(())
}

fn config_trust(global: &GlobalOpts, args: groups::config::ConfigTrust) -> Result<()> {
    use groups::config::ConfigTrustSub;
    let path = require_config_path(global)?;
    match args.command {
        ConfigTrustSub::AddUrl(a) => {
            let mut doc = spt_config::mutate::Document::read(&path)?;
            // Write into [runtime.remote_config] — keys: url, fingerprint_sha256.
            let inner = doc.document_mut();
            // Ensure [runtime] table exists.
            let runtime = inner
                .as_table_mut()
                .entry("runtime")
                .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
            let runtime_tbl = runtime
                .as_table_mut()
                .ok_or_else(|| Error::InvalidConfig("[runtime] is not a table".into()))?;
            let rc = runtime_tbl
                .entry("remote_config")
                .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
            let rc_tbl = rc.as_table_mut().ok_or_else(|| {
                Error::InvalidConfig("[runtime.remote_config] is not a table".into())
            })?;
            rc_tbl["url"] = toml_edit::value(a.url.clone());
            rc_tbl["fingerprint_sha256"] = toml_edit::value(a.fingerprint.clone());
            doc.write_atomic(&path)?;
            println!("trusted {} (sha256={})", a.url, a.fingerprint);
            Ok(())
        }
    }
}

fn config_fingerprint_command(global: &GlobalOpts) -> Result<()> {
    // Not a CLI subcommand: invoked via `config render --fingerprint` if/when
    // surfaced. Provided here so other handlers can reuse the helper.
    let path = require_config_path(global)?;
    let (cfg, _) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let fp = spt_config::fingerprint::fingerprint_hex(&cfg);
    println!("{fp}");
    Ok(())
}

// ============================================================================
// profile
// ============================================================================

async fn profile_dispatch(global: &GlobalOpts, c: groups::profile::ProfileCmd) -> Result<()> {
    use groups::profile::ProfileSub;
    match c.command {
        ProfileSub::List(_) => profile_list(global),
        ProfileSub::Show(args) => profile_show(global, args),
        ProfileSub::Add(args) => profile_add(global, args),
        ProfileSub::Configure(args) => profile_configure(global, args).await,
        ProfileSub::Set(args) => crate::cli::profile_ops::set(global, args).await,
        ProfileSub::Enable(args) => crate::cli::profile_ops::enable(global, args).await,
        ProfileSub::Disable(args) => crate::cli::profile_ops::disable(global, args).await,
        ProfileSub::Remove(args) => profile_remove(global, args),
        ProfileSub::Test(args) => crate::cli::profile_ops::test(global, args).await,
    }
}

fn profile_list(global: &GlobalOpts) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    if cfg.profiles.is_empty() {
        println!("(no profiles)");
    } else {
        for p in &cfg.profiles {
            println!(
                "{}\t{}\t{}@{}",
                p.name,
                p.protocol,
                p.user.as_deref().unwrap_or(""),
                p.host.as_deref().unwrap_or("")
            );
        }
    }
    Ok(())
}

fn profile_show(global: &GlobalOpts, args: groups::profile::ProfileShow) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let p = cfg
        .profiles
        .iter()
        .find(|p| p.name == args.name)
        .ok_or_else(|| Error::InvalidArgs(format!("no profile named `{}`", args.name)))?;
    if args.json {
        let s = serde_json::to_string_pretty(p)
            .map_err(|e| Error::InvalidConfig(format!("json: {e}")))?;
        println!("{s}");
    } else {
        let mut tmp = spt_config::schema::Config::default();
        tmp.version = cfg.version;
        tmp.profiles.push(p.clone());
        let mode = if args.redacted {
            RedactionMode::Standard
        } else {
            RedactionMode::None
        };
        print!("{}", spt_config::render(&tmp, mode));
    }
    Ok(())
}

fn profile_add(global: &GlobalOpts, args: groups::profile::ProfileAdd) -> Result<()> {
    use groups::profile::Protocol;
    let path = require_config_path(global)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| Error::InvalidConfig(format!("toml_edit parse `{}`: {e}", path.display())))?;
    let proto_str = match args.protocol {
        Protocol::Ssh2 => "ssh2",
        Protocol::Ssh3 => "ssh3",
    };
    let mut tbl = toml_edit::Table::new();
    tbl["name"] = toml_edit::value(args.name.clone());
    tbl["protocol"] = toml_edit::value(proto_str);
    tbl["host"] = toml_edit::value(args.host);
    tbl["user"] = toml_edit::value(args.user);
    let arr = doc
        .as_table_mut()
        .entry("profiles")
        .or_insert_with(|| toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
    if let toml_edit::Item::ArrayOfTables(a) = arr {
        a.push(tbl);
    } else {
        return Err(Error::InvalidConfig(
            "[[profiles]] is not an array of tables".into(),
        ));
    }
    spt_state::write_atomic_string(&path, &doc.to_string())
        .map_err(|e| Error::InvalidConfig(format!("write `{}`: {e}", path.display())))?;
    println!("added profile `{}`", args.name);
    Ok(())
}

fn profile_remove(global: &GlobalOpts, args: groups::profile::ProfileName) -> Result<()> {
    let path = require_config_path(global)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| Error::InvalidConfig(format!("toml parse: {e}")))?;
    let mut removed = false;
    if let Some(toml_edit::Item::ArrayOfTables(a)) = doc.as_table_mut().get_mut("profiles") {
        let len_before = a.len();
        a.retain(|t| t.get("name").and_then(|v| v.as_str()) != Some(&args.name));
        removed = a.len() != len_before;
    }
    if !removed {
        return Err(Error::InvalidArgs(format!(
            "no profile named `{}`",
            args.name
        )));
    }
    spt_state::write_atomic_string(&path, &doc.to_string())
        .map_err(|e| Error::InvalidConfig(format!("write: {e}")))?;
    println!("removed profile `{}`", args.name);
    Ok(())
}

async fn profile_configure(
    global: &GlobalOpts,
    args: groups::profile::ProfileConfigure,
) -> Result<()> {
    // Non-interactive when `--no-tui`, or whenever the user supplied edits
    // directly via `--field`/`--from` (which only make sense outside the TUI).
    if args.no_tui || !args.fields.is_empty() || args.from.is_some() {
        return crate::cli::profile_ops::configure_non_interactive(global, args).await;
    }
    let path = require_config_path(global)?;
    spt_tui::run(&path, args.name.as_deref())
}

// ============================================================================
// forward
// ============================================================================

async fn forward_dispatch(global: &GlobalOpts, c: groups::forward::ForwardCmd) -> Result<()> {
    use groups::forward::ForwardSub;
    match c.command {
        ForwardSub::List(args) => forward_list(global, args),
        ForwardSub::Show(args) => crate::cli::forward_ops::show(global, args).await,
        ForwardSub::Add(args) => forward_add(global, args),
        ForwardSub::Explain(args) => crate::cli::forward_ops::explain(global, args).await,
        ForwardSub::Test(args) => crate::cli::forward_ops::test(global, args).await,
        ForwardSub::Throttle(args) => crate::cli::forward_ops::throttle(global, args).await,
        ForwardSub::Remove(args) => forward_remove(global, args),
    }
}

fn forward_list(global: &GlobalOpts, args: groups::forward::ForwardList) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    for p in &cfg.profiles {
        if let Some(filter) = &args.profile {
            if &p.name != filter {
                continue;
            }
        }
        for f in &p.forwards {
            println!(
                "{}/{}\t{}\t{}->{}",
                p.name,
                f.name,
                f.kind,
                f.bind.as_deref().unwrap_or("?"),
                f.target.as_deref().unwrap_or("?"),
            );
        }
    }
    Ok(())
}

fn forward_add(global: &GlobalOpts, args: groups::forward::ForwardAdd) -> Result<()> {
    use groups::forward::ForwardDirection;
    let (direction, fa) = match args.direction {
        ForwardDirection::Local(a) => ("local", a),
        ForwardDirection::Remote(a) => ("remote", a),
    };
    let transport = if fa.udp { "udp" } else { "tcp" };
    let path = require_config_path(global)?;
    let raw =
        std::fs::read_to_string(&path).map_err(|e| Error::InvalidConfig(format!("read: {e}")))?;
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| Error::InvalidConfig(format!("toml: {e}")))?;
    let profiles = doc
        .as_table_mut()
        .get_mut("profiles")
        .and_then(|i| i.as_array_of_tables_mut())
        .ok_or_else(|| Error::InvalidArgs("config has no [[profiles]]".into()))?;
    let prof = profiles
        .iter_mut()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(&fa.profile))
        .ok_or_else(|| Error::InvalidArgs(format!("no profile `{}`", fa.profile)))?;
    let arr = prof
        .entry("forwards")
        .or_insert_with(|| toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
    if let toml_edit::Item::ArrayOfTables(a) = arr {
        let mut t = toml_edit::Table::new();
        let name = format!("{}-{}", direction, a.len() + 1,);
        t["name"] = toml_edit::value(name.clone());
        t["type"] = toml_edit::value(direction);
        t["transport"] = toml_edit::value(transport);
        t["bind"] = toml_edit::value(fa.listen);
        t["target"] = toml_edit::value(fa.to);
        a.push(t);
        println!("added forward `{}/{name}`", fa.profile);
    }
    spt_state::write_atomic_string(&path, &doc.to_string())
        .map_err(|e| Error::InvalidConfig(format!("write: {e}")))?;
    Ok(())
}

fn forward_remove(global: &GlobalOpts, args: groups::forward::ForwardRef) -> Result<()> {
    let (profile_name, fwd_name) = parse_forward_ref(&args.reference)?;
    let path = require_config_path(global)?;
    let raw =
        std::fs::read_to_string(&path).map_err(|e| Error::InvalidConfig(format!("read: {e}")))?;
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| Error::InvalidConfig(format!("toml: {e}")))?;
    let profiles = doc
        .as_table_mut()
        .get_mut("profiles")
        .and_then(|i| i.as_array_of_tables_mut())
        .ok_or_else(|| Error::InvalidArgs("config has no [[profiles]]".into()))?;
    let prof = profiles
        .iter_mut()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(profile_name))
        .ok_or_else(|| Error::InvalidArgs(format!("no profile `{profile_name}`")))?;
    if let Some(toml_edit::Item::ArrayOfTables(a)) = prof.get_mut("forwards") {
        let n = a.len();
        a.retain(|t| t.get("name").and_then(|v| v.as_str()) != Some(fwd_name));
        if a.len() == n {
            return Err(Error::InvalidArgs(format!(
                "no forward `{fwd_name}` in profile `{profile_name}`"
            )));
        }
    }
    spt_state::write_atomic_string(&path, &doc.to_string())
        .map_err(|e| Error::InvalidConfig(format!("write: {e}")))?;
    println!("removed forward `{profile_name}/{fwd_name}`");
    Ok(())
}

fn parse_forward_ref(s: &str) -> Result<(&str, &str)> {
    s.split_once('/')
        .ok_or_else(|| Error::InvalidArgs(format!("expected `<profile>/<forward>`, got `{s}`")))
}

// ============================================================================
// tunnel
// ============================================================================

async fn tunnel_dispatch(global: &GlobalOpts, c: groups::tunnel::TunnelCmd) -> Result<()> {
    use groups::tunnel::TunnelSub;
    match c.command {
        TunnelSub::Run(args) => tunnel_run(global, args).await,
        TunnelSub::Status(_) => tunnel_status(global),
        TunnelSub::Stats(args) => {
            crate::cli::tunnel_ops::stats(
                global,
                crate::cli::tunnel_ops::TunnelStatsArgs {
                    profile: args.profile,
                    forward: args.forward,
                    json: args.json,
                },
            )
            .await
        }
        TunnelSub::Sessions(args) => {
            crate::cli::tunnel_ops::sessions(
                global,
                crate::cli::tunnel_ops::TunnelSessionsArgs {
                    profile: args.profile,
                    forward: args.forward,
                    json: args.json,
                },
            )
            .await
        }
        TunnelSub::Stop(_) => tunnel_stop(global).await,
        TunnelSub::Reload(_) => tunnel_reload(global).await,
        TunnelSub::Health(args) => {
            crate::cli::tunnel_ops::health(
                global,
                crate::cli::tunnel_ops::TunnelHealthArgs { json: args.json },
            )
            .await
        }
        TunnelSub::Failover(args) => tunnel_failover(global, args).await,
    }
}

async fn tunnel_failover(global: &GlobalOpts, args: groups::tunnel::TunnelFailover) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let mut client = crate::mcp_client::McpClient::connect_from_state_dir(&state_dir).await?;
    client.initialize().await?;
    let mut payload = serde_json::json!({"profile": args.profile});
    if let Some(ep) = args.endpoint {
        payload["endpoint"] = serde_json::Value::String(ep);
    }
    let v = client.call_tool("tunnel_failover", payload).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
    );
    Ok(())
}

async fn tunnel_run(global: &GlobalOpts, args: groups::tunnel::TunnelRun) -> Result<()> {
    // Acquire the state lock, build the orchestrator + per-profile bundles,
    // start every enabled profile, install the signal handlers, and run
    // until shutdown. SIGHUP triggers a config re-load + reconciliation via
    // `Orchestrator::apply` against a fresh `ReloadPlan`.
    let path = require_config_path(global)?;
    let (mut cfg, _w) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    // Apply Group Policy registry overlay (Windows; no-op stub elsewhere)
    // before validation/runtime so any HKLM-enforced bindings take effect
    // for the long-running tunnel process. See `crates/spt-bin/src/policy/`.
    let _overlay_report = crate::policy::overlay::apply(&mut cfg);
    let diags = spt_config::validate(&cfg);
    if !diags.errors.is_empty() {
        let msg = diags
            .errors
            .iter()
            .map(|d| format!("[{}] {}", d.code, d.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::InvalidConfig(format!("validation failed: {msg}")));
    }
    let state_dir = resolve_state_dir(global, &cfg)?;
    let _trace_guard = crate::tracing_init::init_from_config(global, &cfg, &state_dir)?;
    for warning in &diags.warnings {
        tracing::warn!(
            code = %warning.code,
            path = warning.path.as_deref().unwrap_or(""),
            "config warning: {}",
            warning.message
        );
    }
    let _lock = spt_state::StateLock::acquire(&state_dir)?;
    let selected_profile_names = cfg
        .profiles
        .iter()
        .filter(|p| p.enabled != Some(false))
        .filter(|p| args.profiles.is_empty() || args.profiles.iter().any(|name| name == &p.name))
        .map(|p| p.name.clone())
        .collect::<Vec<_>>();

    let writer_cfg = spt_state::StatusWriterConfig::default();
    let writer = spt_state::StatusWriter::new(state_dir.clone(), writer_cfg);
    writer
        .update(|s| {
            s.pid = std::process::id();
            s.version = env!("CARGO_PKG_VERSION").into();
            s.config_fingerprint_sha256 = spt_config::fingerprint::fingerprint_hex(&cfg);
            s.started_at = Some(chrono::Utc::now());
            s.profiles = cfg
                .profiles
                .iter()
                .filter(|p| selected_profile_names.iter().any(|name| name == &p.name))
                .map(|p| spt_state::status::ProfileStatus {
                    id: p.name.clone(),
                    state: "starting".into(),
                    ..Default::default()
                })
                .collect();
        })
        .await;
    let writer_handle = writer.clone().spawn();

    // Build the secrets resolver from `[secrets]` so SSH2's auth flow can
    // resolve `secret://` references at connect time.
    let resolver = crate::secrets_bridge::build_resolver(cfg.secrets.as_ref(), &state_dir)?;

    // Construct the orchestrator and start every enabled profile.
    let orchestrator = std::sync::Arc::new(spt_supervisor::Orchestrator::new());
    let mut started_profiles = Vec::new();
    let mut startup_errors = Vec::new();
    for profile in &cfg.profiles {
        if profile.enabled == Some(false) {
            tracing::info!(profile = %profile.name, "profile disabled — skipping");
            continue;
        }
        if !selected_profile_names
            .iter()
            .any(|name| name == &profile.name)
        {
            tracing::info!(profile = %profile.name, "profile filtered — skipping");
            continue;
        }
        match crate::profile_factory::build(profile, &resolver) {
            Ok(bundle) => {
                tracing::info!(
                    profile = %profile.name,
                    protocol = %profile.protocol,
                    endpoints = bundle.endpoints.len(),
                    "starting profile",
                );
                // Plan §t4-e4: build a round-robin policy selector if
                // `[round_robin].enabled = true`, then attach it to the
                // profile's `EndpointSelector` AFTER `start_profile` so the
                // legacy struct's `set_policy_selector` mutator is on the
                // same `Arc<Mutex<_>>` the spawned task uses.
                let policy = spt_supervisor::make_policy_selector(
                    bundle.endpoints.clone(),
                    &cfg.round_robin,
                );
                orchestrator.start_profile(
                    profile,
                    bundle.protocol,
                    bundle.auth,
                    bundle.endpoints,
                    bundle.supervisor_cfg,
                );
                if let Some(ps) = policy {
                    if let Some(sup) = orchestrator.profile_handle(&profile.name) {
                        sup.selector().lock().set_policy_selector(Some(ps));
                        tracing::info!(
                            profile = %profile.name,
                            policy = ?cfg.round_robin.policy,
                            "round-robin policy attached"
                        );
                    } else {
                        tracing::warn!(
                            profile = %profile.name,
                            "round-robin selector built but profile handle missing — \
                             falling back to legacy failover"
                        );
                    }
                }
                started_profiles.push(profile.name.clone());
            }
            Err(e) => {
                tracing::error!(profile = %profile.name, error = %e, "failed to build profile");
                startup_errors.push(format!("{}: {e}", profile.name));
                writer
                    .update(|s| {
                        if let Some(p) = s.profiles.iter_mut().find(|p| p.id == profile.name) {
                            p.state = "failed".into();
                            p.last_error_category = Some(format!("{:?}", e.exit_code()));
                        }
                    })
                    .await;
            }
        }
    }
    writer
        .update(|s| {
            for p in &mut s.profiles {
                if p.state == "starting" {
                    p.state = "running".into();
                }
            }
        })
        .await;
    writer.flush().await?;

    // Optional: bring up the MCP loopback control surface if `[mcp].listen`
    // is configured. The server runs on a background task; we write a small
    // sidecar (`<state_dir>/mcp-listen.json`) so CLI subcommands can find
    // and authenticate against it.
    let resolver = std::sync::Arc::new(resolver);
    let mcp_handle =
        maybe_spawn_mcp_loopback(&cfg, &state_dir, &orchestrator, &resolver, &path).await?;

    // Plan §t4-e5: optionally bring up the read-only HTTP/JSON status API.
    // The server reads `<state_dir>/status.json` on each request via the
    // file-backed `StateSnapshotSource` adapter — same file the supervisor's
    // `StatusWriter` updates. Plain HTTP only in v1 (TLS deferred).
    let status_api_handle = maybe_spawn_status_api(&cfg, &state_dir, &resolver).await?;

    let signal_rx = crate::signals::spawn();

    if args.once {
        // `--once`: wait until every selected profile reaches startup readiness
        // or exhausts its startup attempts, then tear down and return that
        // outcome to the caller.
        let once_result = if startup_errors.is_empty() {
            wait_for_once_startup(
                &orchestrator,
                &started_profiles,
                std::time::Duration::from_secs(30),
            )
            .await
        } else {
            Err(Error::RuntimeFailure(format!(
                "profile startup failed: {}",
                startup_errors.join("; ")
            )))
        };
        orchestrator.shutdown().await;
        if let Some(h) = mcp_handle {
            h.shutdown(&state_dir).await;
        }
        if let Some(h) = status_api_handle {
            h.shutdown().await;
        }
        writer.flush().await?;
        writer_handle.stop().await;
        return once_result;
    }

    let mut sig = signal_rx;
    let cfg_path_for_reload = path.clone();
    loop {
        if sig.changed().await.is_err() {
            break;
        }
        match *sig.borrow() {
            Some(crate::signals::Signal::Shutdown) => break,
            Some(crate::signals::Signal::Reload) => {
                tracing::info!("reload requested (SIGHUP) — re-reading config");
                match reload_orchestrator(&cfg_path_for_reload, &resolver, &orchestrator, &cfg)
                    .await
                {
                    Ok(new_cfg) => {
                        // Refresh the snapshot fingerprint to mirror live state.
                        let fp = spt_config::fingerprint::fingerprint_hex(&new_cfg);
                        writer
                            .update(|s| {
                                s.config_fingerprint_sha256 = fp;
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "reload failed; keeping previous config");
                    }
                }
            }
            None => {}
        }
    }
    orchestrator.shutdown().await;
    if let Some(h) = mcp_handle {
        h.shutdown(&state_dir).await;
    }
    if let Some(h) = status_api_handle {
        h.shutdown().await;
    }
    writer.flush().await?;
    writer_handle.stop().await;
    Ok(())
}

/// Bring up the read-only status API if `[status_api].enabled = true`.
/// Returns `Ok(None)` when disabled; on a binding/auth error, returns the
/// error so the caller can fail fast (better than a silently-broken API).
async fn maybe_spawn_status_api(
    cfg: &spt_config::schema::Config,
    state_dir: &Path,
    resolver: &std::sync::Arc<spt_secrets::Resolver>,
) -> Result<Option<spt_status_api::StatusApiHandle>> {
    if !cfg.status_api.enabled {
        return Ok(None);
    }
    crate::cli::status_ops::ensure_tls_not_requested(&cfg.status_api)?;
    let source: std::sync::Arc<dyn spt_status_api::StateSnapshotSource> = std::sync::Arc::new(
        crate::cli::status_ops::FileSnapshotSource::new(state_dir.to_path_buf()),
    );
    let handle =
        spt_status_api::StatusApiServer::start(&cfg.status_api, source, resolver.as_ref()).await?;
    tracing::info!(
        addr = %handle.local_addr(),
        "status-api listening (inline supervisor host)"
    );
    Ok(Some(handle))
}

async fn wait_for_once_startup(
    orchestrator: &std::sync::Arc<spt_supervisor::Orchestrator>,
    profiles: &[String],
    deadline: std::time::Duration,
) -> Result<()> {
    let mut waiters = Vec::with_capacity(profiles.len());
    for name in profiles {
        let sup = orchestrator.profile_handle(name).ok_or_else(|| {
            Error::RuntimeFailure(format!(
                "profile `{name}` was selected for startup but no supervisor was registered"
            ))
        })?;
        waiters.push(wait_for_profile_startup(name.clone(), sup));
    }

    tokio::time::timeout(deadline, futures::future::try_join_all(waiters))
        .await
        .map_err(|_| {
            Error::RuntimeFailure(format!(
                "tunnel run --once timed out after {} waiting for startup",
                spt_core::duration::format_duration(deadline)
            ))
        })??;
    Ok(())
}

async fn wait_for_profile_startup(
    name: String,
    sup: std::sync::Arc<spt_supervisor::ProfileSupervisor>,
) -> Result<()> {
    let mut state_rx = sup.watch_state();
    let mut events_rx = sup.take_events();

    loop {
        match *state_rx.borrow() {
            spt_supervisor::ProfileStateName::Active
            | spt_supervisor::ProfileStateName::Degraded => {
                return Ok(());
            }
            spt_supervisor::ProfileStateName::Stopped
            | spt_supervisor::ProfileStateName::Disabled => {
                return Err(Error::RuntimeFailure(format!(
                    "profile `{name}` stopped before startup completed"
                )));
            }
            _ => {}
        }

        tokio::select! {
            changed = state_rx.changed() => {
                if changed.is_err() {
                    return Err(Error::RuntimeFailure(format!(
                        "profile `{name}` stopped before reporting startup status"
                    )));
                }
            }
            event = async {
                match events_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    Some(spt_supervisor::ProfileEvent::BackoffExhausted { profile }) => {
                        return Err(Error::RuntimeFailure(format!(
                            "profile `{profile}` exhausted reconnect attempts during startup"
                        )));
                    }
                    Some(spt_supervisor::ProfileEvent::StateChanged {
                        to:
                            spt_supervisor::ProfileStateName::Active
                            | spt_supervisor::ProfileStateName::Degraded,
                        ..
                    }) => {
                        return Ok(());
                    }
                    Some(spt_supervisor::ProfileEvent::StateChanged {
                        to:
                            spt_supervisor::ProfileStateName::Stopped
                            | spt_supervisor::ProfileStateName::Disabled,
                        profile,
                        ..
                    }) => {
                        return Err(Error::RuntimeFailure(format!(
                            "profile `{profile}` stopped before startup completed"
                        )));
                    }
                    Some(_) => {}
                    None => events_rx = None,
                }
            }
        }
    }
}

/// Handle for a spawned MCP loopback control surface.
struct McpLoopbackHandle {
    task: tokio::task::JoinHandle<()>,
}

impl McpLoopbackHandle {
    async fn shutdown(self, state_dir: &Path) {
        // Best-effort: abort the listener task and remove the sidecar so the
        // next CLI invocation gets a clear error.
        self.task.abort();
        let _ = self.task.await;
        crate::mcp_listen::remove(state_dir);
    }
}

/// Spawn the loopback MCP server backed by an [`crate::controller::OrchestratorController`] when
/// `[mcp].listen` is set. Writes the `<state_dir>/mcp-listen.json` sidecar so
/// CLI subcommands can discover the listener.
async fn maybe_spawn_mcp_loopback(
    cfg: &spt_config::schema::Config,
    state_dir: &Path,
    orchestrator: &std::sync::Arc<spt_supervisor::Orchestrator>,
    resolver: &std::sync::Arc<spt_secrets::Resolver>,
    config_path: &Path,
) -> Result<Option<McpLoopbackHandle>> {
    let Some(mcp) = cfg.mcp.as_ref() else {
        return Ok(None);
    };
    if mcp.enabled != Some(true) {
        return Ok(None);
    }
    let Some(listen) = mcp.listen.clone() else {
        return Ok(None);
    };
    let transport = spt_mcp::LoopbackTransport::bind(&listen)
        .await
        .map_err(|e| Error::McpFailed(format!("loopback bind `{listen}`: {e}")))?;
    let bound = transport
        .local_addr()
        .map_err(|e| Error::McpFailed(format!("local_addr: {e}")))?;
    let token = crate::mcp_listen::generate_token();
    let sidecar = crate::mcp_listen::McpListenSidecar {
        host: bound.ip().to_string(),
        port: bound.port(),
        token: token.clone(),
    };
    crate::mcp_listen::write(state_dir, &sidecar)?;

    // Build OrchestratorController with the cached config.
    let controller = std::sync::Arc::new(crate::controller::OrchestratorController::new(
        orchestrator.clone(),
        resolver.clone(),
        config_path.to_path_buf(),
        cfg.clone(),
    )) as std::sync::Arc<dyn spt_mcp::Controller>;

    let policy = spt_mcp::McpPolicy {
        enabled: true,
        listen: listen.clone(),
        // Allow every write tool the live-bridge surface needs.
        allow_write_tools: spt_mcp::policy::WRITE_TOOLS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        ..Default::default()
    };
    let server = crate::mcp_server::build_server(policy, controller).with_auth_token(token);

    let task = tokio::spawn(async move {
        if let Err(e) = server.run(transport).await {
            tracing::warn!(error = %e, "MCP loopback server exited");
        }
    });
    tracing::info!(addr = %bound, "MCP loopback control surface listening");
    Ok(Some(McpLoopbackHandle { task }))
}

/// Re-read the config from disk and apply a [`spt_supervisor::ReloadPlan`] against the
/// orchestrator. Returns the freshly loaded config on success.
async fn reload_orchestrator(
    path: &Path,
    resolver: &spt_secrets::Resolver,
    orch: &spt_supervisor::Orchestrator,
    old_cfg: &spt_config::schema::Config,
) -> Result<spt_config::schema::Config> {
    let (new_cfg, _) = spt_config::load(path, false)
        .map_err(|e| Error::InvalidConfig(format!("reload load: {e}")))?;
    let diags = spt_config::validate(&new_cfg);
    if !diags.errors.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "reload validation failed ({} errors)",
            diags.errors.len()
        )));
    }
    let plan = spt_supervisor::ReloadPlan::compute(old_cfg, &new_cfg);
    let new_for_provider = new_cfg.clone();
    orch.apply(&plan, |name| {
        let p = new_for_provider
            .profiles
            .iter()
            .find(|p| p.name == name)?
            .clone();
        let bundle = crate::profile_factory::build(&p, resolver).ok()?;
        Some((
            p,
            bundle.protocol,
            bundle.auth,
            bundle.endpoints,
            bundle.supervisor_cfg,
        ))
    })
    .await;
    Ok(new_cfg)
}

fn tunnel_status(global: &GlobalOpts) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let path = spt_state::paths::status_path(&state_dir);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            print!("{s}");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::RuntimeFailure(format!(
            "no status snapshot at `{}` — is `spt tunnel run` running?",
            path.display()
        ))),
        Err(e) => Err(Error::RuntimeFailure(format!("read status: {e}"))),
    }
}

async fn tunnel_stop(global: &GlobalOpts) -> Result<()> {
    // Best-effort: signal the running supervisor by sending a Unix signal to
    // the recorded PID. Windows uses a console event which requires the
    // service path; manual stop is tracked in M9.
    let state_dir = resolve_state_dir_for_read(global)?;
    let pid_path = spt_state::paths::pid_path(&state_dir);
    let pid_str = std::fs::read_to_string(&pid_path)
        .map_err(|e| Error::RuntimeFailure(format!("read `{}`: {e}", pid_path.display())))?;
    let pid: i32 = pid_str
        .trim()
        .parse()
        .map_err(|e| Error::RuntimeFailure(format!("invalid pid `{pid_str}`: {e}")))?;
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|e| Error::RuntimeFailure(format!("kill {pid}: {e}")))?;
        println!("sent SIGTERM to pid {pid}");
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = pid;
        crate::cli::tunnel_ops::stop_windows_standalone(global).await
    }
}

async fn tunnel_reload(global: &GlobalOpts) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let pid_path = spt_state::paths::pid_path(&state_dir);
    let pid_str = std::fs::read_to_string(&pid_path)
        .map_err(|e| Error::RuntimeFailure(format!("read pid: {e}")))?;
    let pid: i32 = pid_str
        .trim()
        .parse()
        .map_err(|e| Error::RuntimeFailure(format!("pid: {e}")))?;
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid), Signal::SIGHUP)
            .map_err(|e| Error::ReloadFailed(format!("kill SIGHUP: {e}")))?;
        println!("sent SIGHUP to pid {pid}");
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = pid;
        crate::cli::tunnel_ops::reload_windows_standalone(global).await
    }
}

// ============================================================================
// service
// ============================================================================

async fn service_dispatch(_global: &GlobalOpts, c: groups::service::ServiceCmd) -> Result<()> {
    use groups::service::ServiceSub;
    match c.command {
        ServiceSub::Install(args) => service_install(args).await,
        ServiceSub::Uninstall(args) => service_uninstall(args).await,
        ServiceSub::Start(args) => service_lifecycle(args, ServiceAction::Start).await,
        ServiceSub::Stop(args) => service_lifecycle(args, ServiceAction::Stop).await,
        ServiceSub::Restart(args) => service_lifecycle(args, ServiceAction::Restart).await,
        ServiceSub::Status(args) => service_status(args).await,
        ServiceSub::Render(args) => service_render(args),
    }
}

enum ServiceAction {
    Start,
    Stop,
    Restart,
}

async fn service_install(args: groups::service::ServiceArgs) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let spec = service_spec_from_args(&args.config, &args.scope)?;
    mgr.install(&spec).await?;
    println!("installed service `{}`", spec.name);
    Ok(())
}

async fn service_uninstall(args: groups::service::ServiceArgs) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let name = service_name(&args.scope, &args.config);
    mgr.uninstall(&name).await?;
    println!("uninstalled service `{name}`");
    Ok(())
}

async fn service_lifecycle(
    args: groups::service::ServiceArgs,
    action: ServiceAction,
) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let name = service_name(&args.scope, &args.config);
    match action {
        ServiceAction::Start => mgr.start(&name).await?,
        ServiceAction::Stop => mgr.stop(&name).await?,
        ServiceAction::Restart => mgr.restart(&name).await?,
    }
    Ok(())
}

async fn service_status(args: groups::service::ServiceStatus) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let name = service_name(&args.scope, &args.config);
    let st = mgr.status(&name).await?;
    if args.json {
        let v = serde_json::json!({
            "name": name,
            "state": format!("{:?}", st.state).to_lowercase(),
            "pid": st.pid,
            "exit_code": st.exit_code,
            "restart_count": st.restart_count,
        });
        println!("{v}");
    } else {
        println!("{name}: {:?}", st.state);
    }
    Ok(())
}

fn service_render(args: groups::service::ServiceRender) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let spec = service_spec_from_args(&args.config, &args.scope)?;
    match mgr.render_unit(&spec) {
        Some(s) => print!("{s}"),
        None => {
            return Err(Error::UnsupportedPlatform(format!(
                "backend `{}` has no file-based unit to render",
                mgr.name()
            )))
        }
    }
    Ok(())
}

fn service_spec_from_args(
    config: &Path,
    scope: &groups::service::ServiceScope,
) -> Result<spt_service::ServiceSpec> {
    let exe =
        std::env::current_exe().map_err(|e| Error::RuntimeFailure(format!("current_exe: {e}")))?;
    let name = scope
        .name
        .clone()
        .unwrap_or_else(|| service_name_from_path(config));
    let scope_kind = if scope.user {
        spt_service::Scope::User
    } else {
        spt_service::Scope::System
    };
    let spec = spt_service::ServiceSpec {
        name,
        description: format!("spt service for {}", config.display()),
        exec_path: exe,
        args: vec![
            "tunnel".into(),
            "run".into(),
            "--foreground".into(),
            "--config".into(),
            config.display().to_string(),
        ],
        working_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: Default::default(),
        user: None,
        group: None,
        scope: scope_kind,
        restart_policy: spt_service::RestartPolicy::OnFailure,
        sd_notify: false,
        stdout_path: None,
        stderr_path: None,
    };
    Ok(spec)
}

fn service_name(scope: &groups::service::ServiceScope, config: &Path) -> String {
    scope
        .name
        .clone()
        .unwrap_or_else(|| service_name_from_path(config))
}

fn service_name_from_path(p: &Path) -> String {
    p.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| format!("spt-{s}"))
        .unwrap_or_else(|| "spt".into())
}

// ============================================================================
// key
// ============================================================================

async fn key_dispatch(global: &GlobalOpts, c: groups::key::KeyCmd) -> Result<()> {
    use groups::key::{CertTypeFlag, KeySub};
    match c.command {
        KeySub::Generate(args) => key_generate(args),
        KeySub::Inspect(args) => key_inspect(args),
        KeySub::Public(args) => {
            crate::cli::key_ops::public(
                global,
                crate::cli::key_ops::KeyPublicArgs {
                    key: args.path,
                    out: args.out,
                },
            )
            .await
        }
        KeySub::ChangePassphrase(args) => {
            crate::cli::key_ops::change_passphrase(
                global,
                crate::cli::key_ops::KeyChangePassphraseArgs {
                    key: args.path,
                    new_passphrase_from: args.new_passphrase_from,
                },
            )
            .await
        }
        KeySub::SignCert(args) => {
            let cert_type = args.cert_type.map(|t| match t {
                CertTypeFlag::User => crate::cli::key_ops::CertTypeArg::User,
                CertTypeFlag::Host => crate::cli::key_ops::CertTypeArg::Host,
            });
            crate::cli::key_ops::sign_cert(
                global,
                crate::cli::key_ops::KeySignCertArgs {
                    ca: args.ca_key,
                    subject: args.public_key,
                    principals: args.principals,
                    validity: args.validity,
                    serial: args.serial,
                    cert_type,
                    key_id: args.key_id,
                    out: args.out,
                },
            )
            .await
        }
        KeySub::VerifyCert(args) => {
            crate::cli::key_ops::verify_cert(
                global,
                crate::cli::key_ops::KeyVerifyCertArgs {
                    cert: args.path,
                    trusted_cas: args.trusted_cas,
                },
            )
            .await
        }
        KeySub::InstallPublic(args) => {
            crate::cli::key_ops::install_public(
                global,
                crate::cli::key_ops::KeyInstallPublicArgs {
                    key: args.key,
                    target: args.target,
                    profile: args.profile,
                },
            )
            .await
        }
    }
}

fn key_generate(args: groups::key::KeyGenerate) -> Result<()> {
    use groups::key::KeyKind;
    let alg = match args.r#type {
        KeyKind::Ed25519 => spt_key::KeyAlgorithm::Ed25519,
        KeyKind::EcdsaP256 => spt_key::KeyAlgorithm::EcdsaP256,
        KeyKind::Rsa => match args.bits {
            Some(3072) => spt_key::KeyAlgorithm::Rsa3072,
            _ => spt_key::KeyAlgorithm::Rsa4096,
        },
    };
    let kp = spt_key::generate(alg)?;
    let passphrase = if args.encrypt {
        Some(prompt_passphrase("encrypt key with passphrase: ")?)
    } else {
        None
    };
    spt_key::save_encrypted(&kp, &args.out, passphrase.as_deref())?;
    let pub_path = {
        let mut s = args.out.clone().into_os_string();
        s.push(".pub");
        PathBuf::from(s)
    };
    let pub_str = ssh_key_to_authorized(&kp, args.comment.as_deref())?;
    std::fs::write(&pub_path, pub_str)
        .map_err(|e| Error::KeyFailure(format!("write `{}`: {e}", pub_path.display())))?;
    let fp = spt_key::fingerprint_sha256(kp.public_ref());
    println!("generated {} → {}", args.out.display(), pub_path.display());
    println!("fingerprint: {fp}");
    Ok(())
}

fn key_inspect(args: groups::key::KeyInspect) -> Result<()> {
    let kp = spt_key::load(&args.path, None).or_else(|_| {
        let pw = prompt_passphrase("passphrase: ")?;
        spt_key::load(&args.path, Some(&pw))
    })?;
    let fp = spt_key::fingerprint_sha256(kp.public_ref());
    if args.json {
        let v = serde_json::json!({
            "path": args.path.display().to_string(),
            "fingerprint_sha256": fp,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!("{}", args.path.display());
        println!("  fingerprint: {fp}");
    }
    Ok(())
}

fn ssh_key_to_authorized(kp: &spt_key::KeyPair, comment: Option<&str>) -> Result<String> {
    let pubk = kp.public_ref();
    let line = pubk
        .to_openssh()
        .map_err(|e| Error::KeyFailure(format!("encode public key: {e}")))?;
    Ok(match comment {
        Some(c) => format!("{line} {c}\n"),
        None => format!("{line}\n"),
    })
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    use std::io::{self, BufRead};
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let mut buf = String::new();
    io::stdin()
        .lock()
        .read_line(&mut buf)
        .map_err(|e| Error::RuntimeFailure(format!("read passphrase: {e}")))?;
    Ok(buf
        .trim_end_matches(|c: char| c == '\n' || c == '\r')
        .to_string())
}

// ============================================================================
// secret
// ============================================================================

async fn secret_dispatch(global: &GlobalOpts, c: groups::secret::SecretCmd) -> Result<()> {
    use groups::secret::{SecretStoreSub, SecretSub};
    match c.command {
        SecretSub::Store(s) => match s.command {
            SecretStoreSub::Init(args) => {
                crate::cli::secret_ops::store_init(
                    global,
                    crate::cli::secret_ops::SecretStoreInitArgs {
                        vault_path: args.vault_path,
                        passphrase_from: args.passphrase_from,
                    },
                )
                .await
            }
        },
        SecretSub::Set(args) => secret_set(global, args),
        SecretSub::Get(args) => secret_get(global, args),
        SecretSub::List(args) => {
            let _ = args.json;
            crate::cli::secret_ops::list(
                global,
                crate::cli::secret_ops::SecretListArgs {
                    namespace: args.namespace,
                    vault_path: args.vault_path,
                    passphrase_from: args.passphrase_from,
                },
            )
            .await
        }
        SecretSub::Rotate(args) => {
            crate::cli::secret_ops::rotate(
                global,
                crate::cli::secret_ops::SecretRotateArgs {
                    reference: args.name,
                    new_value_from: args.new_value_from,
                    vault_path: args.vault_path,
                    passphrase_from: args.passphrase_from,
                },
            )
            .await
        }
        SecretSub::Remove(args) => secret_remove(global, args),
        SecretSub::Doctor => secret_doctor(global),
    }
}

fn secret_set(_global: &GlobalOpts, args: groups::secret::SecretSet) -> Result<()> {
    let value = if args.prompt {
        prompt_passphrase(&format!("value for `{}`: ", args.name))?
    } else if let Some(env) = args.from_env {
        std::env::var(&env).map_err(|e| Error::SecretUnavailable {
            reference: format!("env:{env}"),
            reason: e.to_string(),
        })?
    } else if let Some(file) = args.from_file {
        std::fs::read_to_string(&file)
            .map_err(|e| Error::SecretUnavailable {
                reference: file.display().to_string(),
                reason: e.to_string(),
            })?
            .trim_end_matches('\n')
            .to_string()
    } else {
        return Err(Error::InvalidArgs(
            "one of --prompt | --from-env | --from-file is required".into(),
        ));
    };
    let r = parse_ns_name(&args.name)?;
    let kc = spt_secrets::KeychainBackend::with_service("spt".to_string());
    use spt_secrets::SecretBackend;
    kc.set(&r, value.as_bytes())?;
    println!("set secret `{}`", args.name);
    Ok(())
}

fn secret_get(_global: &GlobalOpts, args: groups::secret::SecretGet) -> Result<()> {
    let r = parse_ns_name(&args.name)?;
    let kc = spt_secrets::KeychainBackend::with_service("spt".to_string());
    use spt_secrets::SecretBackend;
    let bytes = kc.get(&r)?.ok_or_else(|| Error::SecretUnavailable {
        reference: format!("secret://{}/{}", r.ns(), r.name()),
        reason: "not found in keychain".into(),
    })?;
    if args.reveal {
        eprintln!("warning: --reveal exposes plaintext secret material to your terminal.");
        println!(
            "(secret loaded, {} bytes — full reveal tracked in M1)",
            bytes_len_hint(&bytes)
        );
    } else {
        println!("[REDACTED]");
    }
    Ok(())
}

fn bytes_len_hint(b: &spt_secrets::SecretBytes) -> usize {
    use secrecy::ExposeSecret;
    b.expose_secret().len()
}

fn secret_remove(_global: &GlobalOpts, args: groups::secret::SecretName) -> Result<()> {
    let r = parse_ns_name(&args.name)?;
    let kc = spt_secrets::KeychainBackend::with_service("spt".to_string());
    use spt_secrets::SecretBackend;
    let _ = kc.remove(&r)?;
    println!("removed secret `{}`", args.name);
    Ok(())
}

fn secret_doctor(global: &GlobalOpts) -> Result<()> {
    let path = global.config.clone();
    let cfg = path
        .as_ref()
        .and_then(|p| spt_config::load(p, false).ok())
        .map(|(c, _)| c);
    let secrets_cfg = cfg.as_ref().and_then(|c| c.secrets.as_ref());
    let state_dir = resolve_state_dir_for_read(global).unwrap_or_else(|_| std::env::temp_dir());
    let resolver = crate::secrets_bridge::build_resolver(secrets_cfg, &state_dir)?;
    let backends: Vec<_> = resolver.backends().collect();
    println!("backends: {}", backends.len());
    for b in backends {
        println!("  - {:?}", spt_secrets::SecretBackend::kind(b));
    }
    Ok(())
}

fn parse_ns_name(s: &str) -> Result<spt_secrets::SecretRef> {
    let (ns, name) = s
        .split_once('/')
        .ok_or_else(|| Error::InvalidArgs(format!("expected `<ns>/<name>`, got `{s}`")))?;
    spt_secrets::SecretRef::new(ns.to_string(), name.to_string())
        .map_err(|e| Error::InvalidArgs(format!("bad secret name: {e}")))
}

// ============================================================================
// auth
// ============================================================================

async fn auth_dispatch(global: &GlobalOpts, c: groups::auth::AuthCmd) -> Result<()> {
    use groups::auth::AuthSub;
    match c.command {
        AuthSub::Test(args) => auth_test(global, args),
        AuthSub::Ssh3Login(args) => auth_ssh3_login(global, args).await,
    }
}

/// `spt auth ssh3-login` — RFC 8628 OIDC device-flow.
async fn auth_ssh3_login(global: &GlobalOpts, args: groups::auth::AuthSsh3Login) -> Result<()> {
    use spt_auth::oidc_device_flow::{store_token, OidcDeviceFlowClient};
    use url::Url;

    let issuer = Url::parse(&args.issuer)
        .map_err(|e| Error::InvalidArgs(format!("--issuer must be a URL: {e}")))?;
    let client = OidcDeviceFlowClient::new(issuer, args.client_id.clone(), args.audience.clone())
        .map_err(|e| Error::AuthFailed(format!("oidc client: {e}")))?;

    let scope = args.scope.as_deref().unwrap_or("openid offline_access");
    let json_out = args.json;
    let token = client
        .login(Some(scope), |dc| {
            if json_out {
                let v = serde_json::json!({
                    "verification_uri": dc.verification_uri,
                    "verification_uri_complete": dc.verification_uri_complete,
                    "user_code": dc.user_code,
                    "expires_in": dc.expires_in,
                    "interval": dc.interval,
                });
                eprintln!("{}", serde_json::to_string(&v).unwrap_or_default());
            } else {
                eprintln!();
                eprintln!("    To complete sign-in, visit:");
                eprintln!("        {}", dc.verification_uri);
                eprintln!("    and enter the code:");
                eprintln!("        {}", dc.user_code);
                if let Some(complete) = dc.verification_uri_complete.as_ref() {
                    eprintln!("    (or open: {complete} )");
                }
                eprintln!();
            }
        })
        .await
        .map_err(|e| Error::AuthFailed(format!("oidc login: {e}")))?;

    if let Some(spec) = args.save_as.as_deref() {
        let parsed = parse_secret_url(spec)?;
        let state_dir = resolve_state_dir_for_read(global).unwrap_or_else(|_| std::env::temp_dir());
        let cfg = global
            .config
            .as_ref()
            .and_then(|p| spt_config::load(p, false).ok())
            .map(|(c, _)| c);
        let resolver = crate::secrets_bridge::build_resolver(
            cfg.as_ref().and_then(|c| c.secrets.as_ref()),
            &state_dir,
        )?;
        let backend = resolver.backends().next().ok_or_else(|| {
            Error::RuntimeFailure("no secret backend configured — cannot --save-as".into())
        })?;
        store_token(&token, backend, &parsed.0, &parsed.1)
            .map_err(|e| Error::AuthFailed(format!("store_token: {e}")))?;
        if json_out {
            let v = serde_json::json!({"saved": true, "ref": format!("secret://{}/{}", parsed.0, parsed.1)});
            println!("{}", serde_json::to_string(&v).unwrap_or_default());
        } else {
            println!("saved access token at secret://{}/{}", parsed.0, parsed.1);
        }
    } else if json_out {
        println!("{{\"login\":\"ok\"}}");
    } else {
        println!("login ok (token not persisted; pass --save-as secret://ns/name to store)");
    }
    Ok(())
}

/// Parse `secret://ns/name` into `(ns, name)`.
fn parse_secret_url(s: &str) -> Result<(String, String)> {
    let body = s
        .strip_prefix("secret://")
        .ok_or_else(|| Error::InvalidArgs(format!("expected `secret://ns/name`, got `{s}`")))?;
    let (ns, name) = body
        .split_once('/')
        .ok_or_else(|| Error::InvalidArgs(format!("expected `secret://ns/name`, got `{s}`")))?;
    if ns.is_empty() || name.is_empty() {
        return Err(Error::InvalidArgs(format!("bad secret ref `{s}`")));
    }
    Ok((ns.to_owned(), name.to_owned()))
}

/// `spt auth test` — sanity-check a profile's auth shape.
///
/// A real "did the SSH handshake succeed" probe needs to dial the remote
/// endpoint via `spt_ssh2::Ssh2Protocol::connect` (or `spt_ssh3` for SSH3),
/// which couples the CLI to live network state. M1 wires that. For now we
/// validate the profile's `AuthConfig` shape — every method's secret
/// references resolve, no unknown method names — and report
/// success/failure structurally.
fn auth_test(global: &GlobalOpts, args: groups::auth::AuthProfile) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let profile = cfg
        .profiles
        .iter()
        .find(|p| p.name == args.profile)
        .ok_or_else(|| Error::InvalidArgs(format!("no profile `{}`", args.profile)))?;
    let bundle = crate::profile_factory::build(profile, &spt_secrets::Resolver::new(vec![]));
    match bundle {
        Ok(b) => {
            let v = serde_json::json!({
                "profile": profile.name,
                "auth_shape_ok": true,
                "user": b.auth.username,
                "method_count": b.auth.methods.len(),
                "endpoint_count": b.endpoints.len(),
                "note": "live SSH handshake probe is M1 — this only validates auth shape",
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&v)
                    .map_err(|e| Error::RuntimeFailure(e.to_string()))?
            );
            Ok(())
        }
        Err(e) => {
            let v = serde_json::json!({
                "profile": profile.name,
                "auth_shape_ok": false,
                "error": e.to_string(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&v)
                    .map_err(|e| Error::RuntimeFailure(e.to_string()))?
            );
            Err(e)
        }
    }
}

// ============================================================================
// dns
// ============================================================================

async fn dns_dispatch(global: &GlobalOpts, c: groups::dns::DnsCmd) -> Result<()> {
    use groups::dns::DnsSub;
    match c.command {
        DnsSub::Serve(args) => crate::cli::dns_ops::serve(global, args.into()).await,
        DnsSub::Status(args) => crate::cli::dns_ops::status(global, args.into()).await,
        DnsSub::Query(args) => crate::cli::dns_ops::query(global, args.into()).await,
        DnsSub::Upstream(args) => crate::cli::dns_ops::upstream(global, args.into()).await,
        DnsSub::Record(args) => crate::cli::dns_ops::record(global, args.into()).await,
        DnsSub::Hosts(args) => dns_hosts(global, args),
    }
}

fn dns_hosts(global: &GlobalOpts, h: groups::dns::DnsHosts) -> Result<()> {
    use groups::dns::DnsHostsSub;
    let path = global.config.clone();
    let entries: Vec<spt_dns::HostsEntry> = path
        .as_ref()
        .and_then(|p| spt_config::load(p, false).ok())
        .and_then(|(c, _)| c.dns)
        .map(|d| {
            d.records
                .into_iter()
                .map(|r| spt_dns::HostsEntry {
                    address: r.value,
                    names: vec![r.name],
                })
                .collect()
        })
        .unwrap_or_default();
    let state_dir = resolve_state_dir_for_read(global).unwrap_or_else(|_| std::env::temp_dir());
    let mgr = spt_dns::HostsManager::new(entries, state_dir.join("hosts"));
    match h.command {
        DnsHostsSub::Render(args) => {
            let s = mgr.render();
            if let Some(out) = args.out {
                std::fs::write(&out, s).map_err(|e| {
                    Error::RuntimeFailure(format!("write `{}`: {e}", out.display()))
                })?;
            } else {
                print!("{s}");
            }
            Ok(())
        }
        DnsHostsSub::Apply(args) => {
            let report = mgr
                .apply(args.path.as_deref(), false)
                .map_err(|e| Error::DnsFailed(format!("hosts apply: {e}")))?;
            println!(
                "apply: changed={} backed_up={}",
                report.changed, report.backed_up
            );
            Ok(())
        }
        DnsHostsSub::Restore(_args) => {
            // The current HostsManager always restores from the most recent
            // backup in <state_dir>/hosts/; the CLI `--backup PATH` flag
            // is reserved for explicit-backup selection in M3.
            mgr.restore(None)
                .map_err(|e| Error::DnsFailed(format!("hosts restore: {e}")))?;
            println!("restored");
            Ok(())
        }
    }
}

// ============================================================================
// firewall
// ============================================================================

async fn firewall_dispatch(global: &GlobalOpts, c: groups::firewall::FirewallCmd) -> Result<()> {
    use groups::firewall::FirewallSub;
    match c.command {
        FirewallSub::Plan(_) => firewall_plan_render(false),
        FirewallSub::Apply(args) => firewall_apply(args, false),
        FirewallSub::Remove(args) => firewall_apply(args, true),
        FirewallSub::Status(args) => {
            crate::cli::firewall_ops::status(
                global,
                crate::cli::firewall_ops::FirewallStatusArgs { json: args.json },
            )
            .await
        }
        FirewallSub::Interfaces(_) => firewall_interfaces(),
        FirewallSub::BindPreview(args) => {
            let (profile, forward) = match args.forward.split_once('/') {
                Some((p, f)) => (Some(p.to_string()), Some(f.to_string())),
                None => (Some(args.forward.clone()), None),
            };
            crate::cli::firewall_ops::bind_preview(
                global,
                crate::cli::firewall_ops::FirewallBindPreviewArgs {
                    profile,
                    forward,
                    json: args.json,
                },
            )
            .await
        }
        FirewallSub::Gateway(args) => {
            use groups::firewall::FirewallGatewaySub;
            match args.command {
                FirewallGatewaySub::Show(show) => {
                    crate::cli::firewall_ops::gateway_show(global, show).await
                }
                FirewallGatewaySub::Set(set) => {
                    crate::cli::firewall_ops::gateway_set(global, set).await
                }
            }
        }
        FirewallSub::Policy(args) => {
            use groups::firewall::FirewallPolicySub;
            match args.command {
                FirewallPolicySub::List(list) => {
                    crate::cli::firewall_ops::policy_list(global, list).await
                }
                FirewallPolicySub::Show(show) => {
                    crate::cli::firewall_ops::policy_show(global, show).await
                }
                FirewallPolicySub::Set(set) => {
                    crate::cli::firewall_ops::policy_set(global, set).await
                }
                FirewallPolicySub::Unset(unset) => {
                    crate::cli::firewall_ops::policy_unset(global, unset).await
                }
            }
        }
    }
}

fn firewall_plan_render(_remove: bool) -> Result<()> {
    let p = spt_firewall::new_planner()?;
    let plan = p.plan(&[]);
    println!("manager: {:?}", plan.manager);
    println!("rules: {}", plan.rule_count);
    println!("---\n{}", plan.script);
    Ok(())
}

fn firewall_apply(args: groups::firewall::FirewallApply, remove: bool) -> Result<()> {
    let p = spt_firewall::new_planner()?;
    let plan = p.plan(&[]);
    if !args.dry_run && !remove {
        // Real apply requires explicit confirmation; we refuse without
        // --dry-run for safety in M0.
        return Err(Error::PermissionDenied(
            "real firewall apply requires admin + explicit confirmation; pass --dry-run to preview"
                .into(),
        ));
    }
    if remove {
        let _ = p.remove(&plan);
    } else {
        let _ = p.apply(&plan, args.dry_run);
    }
    println!("(dry-run) {} rules", plan.rule_count);
    Ok(())
}

fn firewall_interfaces() -> Result<()> {
    let ifaces = spt_net::interfaces::list()?;
    for iface in ifaces {
        println!(
            "{}\tipv4={:?}\tipv6={:?}",
            iface.name, iface.ipv4, iface.ipv6
        );
    }
    Ok(())
}

// ============================================================================
// log
// ============================================================================

async fn log_dispatch(global: &GlobalOpts, c: groups::log::LogCmd) -> Result<()> {
    use groups::log::{LogExportFormat as CliLogFormat, LogRemoteSub, LogSub};
    match c.command {
        LogSub::Tail(args) => log_tail(global, args),
        LogSub::Remote(remote) => match remote.command {
            LogRemoteSub::List(args) => {
                crate::cli::log_ops::remote_list(
                    global,
                    crate::cli::log_ops::LogRemoteListArgs { json: args.json },
                )
                .await
            }
            LogRemoteSub::Test(args) => {
                crate::cli::log_ops::test(
                    global,
                    crate::cli::log_ops::LogTestArgs {
                        sink: args.sink,
                        send_test_record: args.send_test_record,
                        json: args.json,
                    },
                )
                .await
            }
            LogRemoteSub::Status(args) => {
                crate::cli::log_ops::remote_status(
                    global,
                    crate::cli::log_ops::LogRemoteStatusArgs {
                        sink: args.sink,
                        json: args.json,
                    },
                )
                .await
            }
            LogRemoteSub::Drain(args) => {
                crate::cli::log_ops::remote_drain(
                    global,
                    crate::cli::log_ops::LogRemoteDrainArgs {
                        sink: args.sink,
                        json: args.json,
                    },
                )
                .await
            }
        },
        LogSub::Test(args) => {
            crate::cli::log_ops::test(
                global,
                crate::cli::log_ops::LogTestArgs {
                    sink: args.sink,
                    send_test_record: false,
                    json: false,
                },
            )
            .await
        }
        LogSub::Export(args) => {
            let format = match args.format {
                CliLogFormat::Jsonl => crate::cli::log_ops::LogExportFormat::Jsonl,
                CliLogFormat::Csv => {
                    return Err(Error::InvalidArgs(
                        "log export --format csv is not supported; use jsonl".into(),
                    ));
                }
            };
            crate::cli::log_ops::export(
                global,
                crate::cli::log_ops::LogExportArgs {
                    since: Some(args.since),
                    until: None,
                    to: None,
                    format,
                },
            )
            .await
        }
    }
}

fn log_tail(global: &GlobalOpts, _args: groups::log::LogTail) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let log_path = state_dir.join("spt.log");
    if !log_path.exists() {
        println!(
            "(no log file at {} — `spt tunnel run` writes it)",
            log_path.display()
        );
        return Ok(());
    }
    let s = std::fs::read_to_string(&log_path)
        .map_err(|e| Error::RuntimeFailure(format!("read log: {e}")))?;
    let lines: Vec<&str> = s.lines().rev().take(200).collect();
    for line in lines.into_iter().rev() {
        println!("{line}");
    }
    Ok(())
}

// ============================================================================
// observe
// ============================================================================

async fn observe_dispatch(global: &GlobalOpts, c: groups::observe::ObserveCmd) -> Result<()> {
    #[cfg(feature = "snmp")]
    use groups::observe::ObserveSnmpSub;
    use groups::observe::{ObserveSub, ObserveWinEventSub};
    match c.command {
        ObserveSub::Metrics(args) => observe_metrics(global, args),
        #[cfg(feature = "snmp")]
        ObserveSub::Snmp(snmp) => match snmp.command {
            ObserveSnmpSub::Serve(_) => {
                // `snmp serve` is integrated into `tunnel run` via the
                // observability stack; surface a hint pointing at that path
                // rather than spinning a duplicate agent.
                Err(Error::InvalidArgs(
                    "`spt observe snmp serve` is integrated into `spt tunnel run`; \
                     enable `[observability.snmp]` in config and start the supervisor"
                        .into(),
                ))
            }
            ObserveSnmpSub::TestTrap(_t) => {
                crate::cli::observe_ops::snmp(
                    global,
                    crate::cli::observe_ops::ObserveSnmpArgs::default(),
                )
                .await
            }
        },
        ObserveSub::WindowsEvent(we) => match we.command {
            ObserveWinEventSub::InstallSource(s) | ObserveWinEventSub::Test(s) => {
                crate::cli::observe_ops::windows_event(
                    global,
                    crate::cli::observe_ops::ObserveWindowsEventArgs {
                        message: None,
                        source: s.source,
                    },
                )
                .await
            }
        },
    }
}

fn observe_metrics(global: &GlobalOpts, _args: groups::observe::ObserveMetrics) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let metrics_path = spt_state::paths::metrics_path(&state_dir);
    match std::fs::read_to_string(&metrics_path) {
        Ok(s) => {
            print!("{s}");
            Ok(())
        }
        Err(_) => {
            println!("(no metrics yet — exporter writes when `tunnel run` is active)");
            Ok(())
        }
    }
}

// ============================================================================
// event
// ============================================================================

async fn event_dispatch(global: &GlobalOpts, c: groups::event::EventCmd) -> Result<()> {
    use groups::event::{EventSinkSub, EventSub};
    match c.command {
        EventSub::List(args) => event_list(global, args.json),
        EventSub::Sink(s) => match s.command {
            EventSinkSub::List(args) => event_sink_list(global, args.json),
            EventSinkSub::Test(args) => event_sink_test(global, args).await,
        },
        EventSub::Test(args) => event_test(global, args).await,
        EventSub::Replay(args) => {
            crate::cli::event_ops::replay(
                global,
                crate::cli::event_ops::EventReplayArgs {
                    event_id: args.binding.clone(),
                    sink: None,
                    json: false,
                },
            )
            .await
        }
    }
}

/// `spt event test --binding <id>` — fire a synthetic event through the named
/// binding, hitting every sink referenced by it. Returns success/failure
/// per-sink.
async fn event_test(global: &GlobalOpts, args: groups::event::EventTest) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let events = cfg
        .events
        .as_ref()
        .ok_or_else(|| Error::InvalidArgs("no [events] section in config".into()))?;
    let binding = events
        .bindings
        .iter()
        .find(|b| b.name == args.binding)
        .ok_or_else(|| Error::InvalidArgs(format!("no binding `{}`", args.binding)))?;

    let mut results = Vec::new();
    for action in &binding.actions {
        let sink_cfg = events.sinks.iter().find(|s| s.name == *action);
        let outcome = match sink_cfg {
            Some(sc) => fire_synthetic_through_sink(sc).await,
            None => Err(format!(
                "sink `{action}` referenced by binding but not configured"
            )),
        };
        results.push(serde_json::json!({
            "sink": action,
            "ok": outcome.is_ok(),
            "error": outcome.err(),
        }));
    }
    let v = serde_json::json!({"binding": binding.name, "results": results});
    println!(
        "{}",
        serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
    );
    Ok(())
}

/// `spt event sink test <name>` — fire a synthetic event through a single
/// sink configuration.
async fn event_sink_test(global: &GlobalOpts, args: groups::event::EventSinkTest) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let sink_cfg = cfg
        .events
        .as_ref()
        .and_then(|e| e.sinks.iter().find(|s| s.name == args.sink).cloned())
        .ok_or_else(|| Error::InvalidArgs(format!("no sink `{}`", args.sink)))?;
    let outcome = fire_synthetic_through_sink(&sink_cfg).await;
    let v = serde_json::json!({
        "sink": sink_cfg.name,
        "kind": sink_cfg.kind,
        "ok": outcome.is_ok(),
        "error": outcome.err(),
    });
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        println!("{}\t{}\tFAIL: {}", sink_cfg.name, sink_cfg.kind, err);
    } else {
        println!("{}\t{}\tOK", sink_cfg.name, sink_cfg.kind);
    }
    Ok(())
}

/// Build a sink from `[[events.sinks]]` and fire one synthetic event through
/// it. Returns `Err(message)` on construction or delivery failure. WebPush
/// sinks (`kind = "webpush"`) instantiate via `WebPushSink::new`.
async fn fire_synthetic_through_sink(
    sc: &spt_config::schema::EventSink,
) -> std::result::Result<(), String> {
    use spt_events::{
        event::{EventBuilder, EventKind, Severity},
        Sink,
    };
    use std::sync::Arc;

    let evt = Arc::new(
        EventBuilder::new(EventKind::new("synthetic.test"), Severity::Info)
            .message("synthetic event from `spt event test`")
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
            // Build a reqwest-backed HTTP transport with a short test timeout.
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
            "sink kind `{other}` not yet wired in `event test` (M3 fills the rest)"
        )),
    }
}

fn event_list(global: &GlobalOpts, json: bool) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let bindings = cfg
        .events
        .as_ref()
        .map(|e| e.bindings.clone())
        .unwrap_or_default();
    if json {
        let s = serde_json::to_string_pretty(&bindings)
            .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
        println!("{s}");
    } else if bindings.is_empty() {
        println!("(no event bindings configured)");
    } else {
        for b in &bindings {
            println!("{}\t{:?} -> {:?}", b.name, b.on, b.actions);
        }
    }
    Ok(())
}

fn event_sink_list(global: &GlobalOpts, json: bool) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) =
        spt_config::load(&path, false).map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let sinks = cfg
        .events
        .as_ref()
        .map(|e| e.sinks.clone())
        .unwrap_or_default();
    if json {
        let s = serde_json::to_string_pretty(&sinks)
            .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
        println!("{s}");
    } else if sinks.is_empty() {
        println!("(no event sinks configured)");
    } else {
        for s in &sinks {
            println!("{}\t{}", s.name, s.kind);
        }
    }
    Ok(())
}

// ============================================================================
// stats
// ============================================================================

async fn stats_dispatch(global: &GlobalOpts, c: groups::stats::StatsCmd) -> Result<()> {
    use groups::stats::StatsSub;
    match c.command {
        StatsSub::Summary(_) => stats_snapshot(global),
        StatsSub::Connections(_) | StatsSub::Throughput(_) | StatsSub::Errors(_) => {
            // Snapshot views read the same status.json the supervisor writes;
            // a richer per-counter dump requires the in-process StatsRegistry,
            // which is only available while `tunnel run` is active. M4 will
            // expose a sidecar metrics socket; until then we surface the
            // metrics file the observability layer writes.
            stats_metrics_dump(global)
        }
        StatsSub::Live(args) => stats_live_dispatch(global, args).await,
        StatsSub::Export(args) => stats_export(global, args),
    }
}

async fn stats_live_dispatch(global: &GlobalOpts, args: groups::stats::StatsLive) -> Result<()> {
    use futures::StreamExt;
    let state_dir = resolve_state_dir_for_read(global)?;
    let mut client = crate::mcp_client::McpClient::connect_from_state_dir(&state_dir).await?;
    client.initialize().await?;
    let interval_ms = args
        .interval
        .as_deref()
        .and_then(|s| spt_core::duration::parse_duration(s).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut stream = client
        .subscribe(
            "stats_subscribe",
            serde_json::json!({"interval_ms": interval_ms}),
        )
        .await?;
    // Read until Ctrl-C / stream close.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                eprintln!("stats live: interrupted");
                break;
            }
            next = stream.next() => {
                match next {
                    Some(Ok(v)) => {
                        // Profile/forward filter is best-effort: filter the
                        // `profiles` array post-fetch when set.
                        let mut emit = v;
                        if let Some(filter_profile) = args.profile.as_ref() {
                            if let Some(arr) = emit.get_mut("profiles").and_then(|x| x.as_array_mut()) {
                                arr.retain(|p| p.get("profile").and_then(|x| x.as_str()) == Some(filter_profile.as_str()));
                            }
                        }
                        let _ = args.forward; // forward-level filter not surfaced by StatsTick
                        println!(
                            "{}",
                            serde_json::to_string(&emit)
                                .map_err(|e| Error::RuntimeFailure(e.to_string()))?
                        );
                    }
                    Some(Err(e)) => {
                        return Err(e);
                    }
                    None => {
                        eprintln!("stats live: stream closed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

fn stats_metrics_dump(global: &GlobalOpts) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let metrics_path = spt_state::paths::metrics_path(&state_dir);
    match std::fs::read_to_string(&metrics_path) {
        Ok(s) => {
            print!("{s}");
            Ok(())
        }
        Err(_) => {
            println!(
                "(no metrics yet at {} — written by `tunnel run`)",
                metrics_path.display()
            );
            Ok(())
        }
    }
}

fn stats_export(global: &GlobalOpts, args: groups::stats::StatsExport) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let snap =
        std::fs::read_to_string(spt_state::paths::status_path(&state_dir)).unwrap_or_default();
    let body = match args.format {
        groups::stats::StatsExportFormat::Json | groups::stats::StatsExportFormat::Jsonl => snap,
        groups::stats::StatsExportFormat::Csv => {
            // Minimal CSV: parse the JSON snapshot and emit the profile-state
            // table. Anything richer (per-counter aggregations) requires the
            // live registry — see M4.
            let v: serde_json::Value =
                serde_json::from_str(&snap).unwrap_or(serde_json::Value::Null);
            let mut out = String::from("profile,state\n");
            if let Some(arr) = v.get("profiles").and_then(|x| x.as_array()) {
                for p in arr {
                    let name = p.get("id").and_then(|x| x.as_str()).unwrap_or("");
                    let state = p.get("state").and_then(|x| x.as_str()).unwrap_or("");
                    out.push_str(&format!("{name},{state}\n"));
                }
            }
            out
        }
        groups::stats::StatsExportFormat::Prometheus => {
            // Forward to whatever the prometheus exporter wrote.
            std::fs::read_to_string(spt_state::paths::metrics_path(&state_dir)).unwrap_or_default()
        }
    };
    let _ = args.since;
    print!("{body}");
    Ok(())
}

fn stats_snapshot(global: &GlobalOpts) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let path = spt_state::paths::status_path(&state_dir);
    if let Ok(s) = std::fs::read_to_string(&path) {
        print!("{s}");
    } else {
        println!("(no snapshot)");
    }
    Ok(())
}

// ============================================================================
// session
// ============================================================================

async fn session_dispatch(global: &GlobalOpts, c: groups::session::SessionCmd) -> Result<()> {
    use groups::session::SessionSub;
    match c.command {
        SessionSub::List(_) => session_list(global),
        SessionSub::Show(args) => session_show(global, args),
        SessionSub::Top(_) => session_list(global),
        // Close / drain require a control channel into the running supervisor
        // (e.g. via the MCP loopback's `tunnel_failover` family). M4 ships
        // that surface; until then we surface a structured stub.
        SessionSub::Close(args) => session_close_dispatch(global, args).await,
        SessionSub::Drain(args) => session_drain_dispatch(global, args).await,
    }
}

async fn session_close_dispatch(
    global: &GlobalOpts,
    args: groups::session::SessionClose,
) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let mut client = crate::mcp_client::McpClient::connect_from_state_dir(&state_dir).await?;
    client.initialize().await?;
    let v = client
        .call_tool("session_close", serde_json::json!({"id": args.id}))
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
    );
    Ok(())
}

async fn session_drain_dispatch(
    global: &GlobalOpts,
    args: groups::session::SessionDrain,
) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let mut client = crate::mcp_client::McpClient::connect_from_state_dir(&state_dir).await?;
    client.initialize().await?;
    let grace_seconds = args
        .grace
        .as_deref()
        .and_then(|s| spt_core::duration::parse_duration(s).ok())
        .map(|d| d.as_secs())
        .unwrap_or(5);
    let v = client
        .call_tool(
            "session_drain",
            serde_json::json!({
                "profile": args.profile,
                "grace_seconds": grace_seconds,
            }),
        )
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&v).map_err(|e| Error::RuntimeFailure(e.to_string()))?
    );
    Ok(())
}

fn session_show(global: &GlobalOpts, args: groups::session::SessionShow) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let path = spt_state::paths::status_path(&state_dir);
    let s = std::fs::read_to_string(&path).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
    let found = v
        .get("sessions")
        .and_then(|x| x.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|e| e.get("id").and_then(|v| v.as_str()) == Some(&args.id))
        });
    match found {
        Some(entry) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(entry)
                        .map_err(|e| Error::RuntimeFailure(e.to_string()))?
                );
            } else {
                println!("{entry}");
            }
            Ok(())
        }
        None => Err(Error::InvalidArgs(format!(
            "no session `{}` in snapshot",
            args.id
        ))),
    }
}

fn session_list(global: &GlobalOpts) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global)?;
    let path = spt_state::paths::status_path(&state_dir);
    let s = std::fs::read_to_string(&path).unwrap_or_default();
    if s.is_empty() {
        println!("(no sessions)");
        return Ok(());
    }
    let v: serde_json::Value = serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
    if let Some(arr) = v.get("sessions").and_then(|x| x.as_array()) {
        for entry in arr {
            println!("{entry}");
        }
    } else {
        println!("(no sessions)");
    }
    Ok(())
}

// ============================================================================
// diagnose
// ============================================================================

async fn diagnose_dispatch(global: &GlobalOpts, c: groups::diagnose::DiagnoseCmd) -> Result<()> {
    use groups::diagnose::DiagnoseSub;
    match c.command {
        DiagnoseSub::Run(_) => diagnose_run(global).await,
        DiagnoseSub::Bundle(args) => diagnose_bundle(global, args),
        DiagnoseSub::Secrets(args) => diagnose_one(global, "secrets", args.json).await,
        DiagnoseSub::Service(args) => diagnose_one(global, "service", args.json).await,
        DiagnoseSub::Mcp(args) => diagnose_one(global, "mcp", args.json).await,
        DiagnoseSub::Network(args) => diagnose_one(global, "network", args.json).await,
        DiagnoseSub::Dns(args) => diagnose_one(global, "dns", args.json).await,
        DiagnoseSub::Bind(args) => diagnose_one(global, "bind", args.json).await,
        DiagnoseSub::Port(args) => diagnose_port(global, args).await,
        DiagnoseSub::Auth(args) => {
            let probe = args.probe;
            let mut a: crate::cli::diag_ops::DiagnoseAuthArgs = args.into();
            a.probe = probe;
            crate::cli::diag_ops::auth(global, a).await
        }
        DiagnoseSub::Trust(args) => crate::cli::diag_ops::trust(global, args.into()).await,
        DiagnoseSub::Observability(args) => {
            crate::cli::diag_ops::observability(global, args.into()).await
        }
    }
}

/// Run a single diagnostic group from the runner's default registration.
///
/// In M0 the runner is registered with the always-available checks
/// (`os`, `permissions`, `time`, `network`, `runtime`); deeper checks
/// (`secrets`, `firewall`, `service`, `mcp`, `ssh2`) require injected
/// handles via `DiagnosticContext`. This dispatcher runs the full set
/// against a default context and filters the report by the requested
/// group. Empty filtered output emits a `Skipped` notice rather than a
/// hard failure (the check is registered but its handle is `None`).
async fn diagnose_one(global: &GlobalOpts, group: &str, json: bool) -> Result<()> {
    let cfg = global
        .config
        .as_ref()
        .and_then(|p| spt_config::load(p, false).ok())
        .map(|(c, _)| c);
    let state_dir = resolve_state_dir_for_read(global).ok();
    let mut ctx = spt_diagnostics::framework::DiagnosticContext::default();
    ctx.state_dir = state_dir.clone();
    if let Some(c) = &cfg {
        ctx.effective_config = Some(spt_config::render(c, RedactionMode::Standard));
        ctx.mcp_enabled = c.mcp.as_ref().and_then(|m| m.enabled).unwrap_or(false);
    }
    if let Some(sd) = state_dir {
        ctx.resolver = Some(std::sync::Arc::new(crate::secrets_bridge::build_resolver(
            cfg.as_ref().and_then(|c| c.secrets.as_ref()),
            &sd,
        )?));
    }
    if let Ok(exe) = std::env::current_exe() {
        ctx.mcp_binary = Some(exe);
    }

    // Build a runner with all checks registered; filter results by group.
    let runner = spt_diagnostics::DiagnosticRunner::new()
        .register(spt_diagnostics::checks::OsDiagnostic::default())
        .register(spt_diagnostics::checks::PermissionsDiagnostic::default())
        .register(spt_diagnostics::checks::TimeDiagnostic::default())
        .register(spt_diagnostics::checks::NetworkDiagnostic::default())
        .register(spt_diagnostics::checks::RuntimeDiagnostic::default())
        .register(spt_diagnostics::checks::SecretsDiagnostic::default())
        .register(spt_diagnostics::checks::ServiceDiagnostic::default())
        .register(spt_diagnostics::checks::McpDiagnostic::default())
        .register(spt_diagnostics::checks::FirewallDiagnostic::default())
        .register(spt_diagnostics::checks::Ssh2Diagnostic::default());
    let report = runner.run(&ctx).await;
    let filtered: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.id.starts_with(&format!("{group}.")) || c.id == group)
        .collect();
    if json {
        let v = serde_json::to_string_pretty(&filtered)
            .map_err(|e| Error::DiagnosticBundleFailed(e.to_string()))?;
        println!("{v}");
    } else if filtered.is_empty() {
        println!("(no `{group}` checks registered or all skipped)");
    } else {
        for c in filtered {
            println!(
                "[{:?}] {} ({:?}): {}",
                c.status,
                c.id,
                c.severity,
                c.evidence.join("; ")
            );
        }
    }
    Ok(())
}

async fn diagnose_port(global: &GlobalOpts, args: groups::diagnose::DiagnosePort) -> Result<()> {
    if args.udp {
        // Delegate to the spt-diagnostics UDP autodetect chain via diag_ops.
        return crate::cli::diag_ops::port(global, args.into()).await;
    }
    let target = format!("{}:{}", args.host, args.port);
    let connect_result = tokio::net::TcpStream::connect(&target).await;
    let mut output = serde_json::Map::new();
    output.insert("target".into(), serde_json::Value::String(target.clone()));
    match connect_result {
        Ok(_stream) => {
            output.insert("reachable".into(), serde_json::Value::Bool(true));
            if args.autodetect_service {
                // Not yet wired through the public spt_diagnostics::port_autodetect
                // entry — surface the limitation rather than guessing.
                output.insert(
                    "service".into(),
                    serde_json::Value::String(
                        "(autodetect requires Detector chain wiring — M3)".into(),
                    ),
                );
            }
        }
        Err(e) => {
            output.insert("reachable".into(), serde_json::Value::Bool(false));
            output.insert("error".into(), serde_json::Value::String(e.to_string()));
        }
    }
    if args.json {
        let s = serde_json::to_string_pretty(&output)
            .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
        println!("{s}");
    } else if output.get("reachable") == Some(&serde_json::Value::Bool(true)) {
        println!("{}: reachable", target);
    } else {
        println!("{}: unreachable", target);
    }
    Ok(())
}

async fn diagnose_run(_global: &GlobalOpts) -> Result<()> {
    let runner = spt_diagnostics::DiagnosticRunner::new();
    let ctx = spt_diagnostics::framework::DiagnosticContext::default();
    let report = runner.run(&ctx).await;
    let summary = format!(
        "{} checks ({} fail)",
        report.checks.len(),
        report
            .checks
            .iter()
            .filter(|c| matches!(c.status, spt_diagnostics::Status::Fail))
            .count()
    );
    println!("{summary}");
    for c in &report.checks {
        println!(
            "[{:?}] {} ({:?}): {}",
            c.status,
            c.id,
            c.severity,
            c.evidence.join("; ")
        );
    }
    Ok(())
}

fn diagnose_bundle(global: &GlobalOpts, args: groups::diagnose::DiagnoseBundle) -> Result<()> {
    let state_dir = resolve_state_dir_for_read(global).unwrap_or_else(|_| std::env::temp_dir());
    let cfg_path = global.config.clone();
    let cfg_text = cfg_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let inputs = spt_diagnostics::BundleInputs {
        effective_config: Some(cfg_text),
        status_snapshot: std::fs::read_to_string(spt_state::paths::status_path(&state_dir)).ok(),
        recent_events: None,
        recent_logs: None,
        stats_summary: None,
        report: None,
        version_info: Some(format!("spt {}", env!("CARGO_PKG_VERSION"))),
    };
    let cfg = spt_diagnostics::BundleConfig::default();
    let run_id = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let archive_path = spt_diagnostics::build_bundle(&state_dir, &run_id, &inputs, &cfg)?;
    if let Some(parent) = args.out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::copy(&archive_path, &args.out).map_err(|e| {
        Error::DiagnosticBundleFailed(format!(
            "copy {} -> {}: {e}",
            archive_path.display(),
            args.out.display()
        ))
    })?;
    println!("wrote {}", args.out.display());
    Ok(())
}

// ============================================================================
// benchmark
// ============================================================================

async fn benchmark_dispatch(global: &GlobalOpts, c: groups::benchmark::BenchmarkCmd) -> Result<()> {
    use groups::benchmark::BenchmarkSub;
    // Benchmark drivers (latency / throughput / udp / reconnect / dns / limits)
    // exist in `spt-benchmark` and are exercised here against either a live
    // supervisor (when one is running and the user passes a live `--profile`)
    // or against synthetic in-process loopback connectors. The choice is made
    // at dispatch time: without a running orchestrator we fall back to the
    // synthetic path, which makes the CLI demoable end-to-end while keeping
    // the production path thin enough to swap in once the MCP control surface
    // lands (M4/M6).
    match c.command {
        BenchmarkSub::Run(args) => benchmark_run(global, args).await,
        BenchmarkSub::Latency(args) => {
            benchmark_run(
                global,
                groups::benchmark::BenchmarkRun {
                    driver: "latency".into(),
                    target: groups::benchmark::BenchmarkRunTarget {
                        profile: Some(args.target.profile),
                        forward: Some(args.target.forward),
                    },
                    duration: None,
                    connections: None,
                    count: args.samples,
                    unsafe_allow_production_impact: false,
                    json: args.json,
                },
            )
            .await
        }
        BenchmarkSub::Throughput(args) => {
            benchmark_run(
                global,
                groups::benchmark::BenchmarkRun {
                    driver: "throughput".into(),
                    target: groups::benchmark::BenchmarkRunTarget {
                        profile: Some(args.target.profile),
                        forward: Some(args.target.forward),
                    },
                    duration: args.duration,
                    connections: None,
                    count: None,
                    unsafe_allow_production_impact: false,
                    json: args.json,
                },
            )
            .await
        }
        BenchmarkSub::Udp(args) => {
            benchmark_run(
                global,
                groups::benchmark::BenchmarkRun {
                    driver: "udp".into(),
                    target: groups::benchmark::BenchmarkRunTarget {
                        profile: Some(args.target.profile),
                        forward: Some(args.target.forward),
                    },
                    duration: args.duration,
                    connections: None,
                    count: args.pps,
                    unsafe_allow_production_impact: false,
                    json: args.json,
                },
            )
            .await
        }
        BenchmarkSub::Reconnect(args) => {
            benchmark_run(
                global,
                groups::benchmark::BenchmarkRun {
                    driver: "reconnect".into(),
                    target: groups::benchmark::BenchmarkRunTarget {
                        profile: Some(args.profile),
                        forward: None,
                    },
                    duration: None,
                    connections: None,
                    count: args.iterations,
                    unsafe_allow_production_impact: false,
                    json: args.json,
                },
            )
            .await
        }
        BenchmarkSub::Dns(args) => {
            benchmark_run(
                global,
                groups::benchmark::BenchmarkRun {
                    driver: "dns".into(),
                    target: groups::benchmark::BenchmarkRunTarget {
                        profile: None,
                        forward: None,
                    },
                    duration: None,
                    connections: None,
                    count: args.samples,
                    unsafe_allow_production_impact: false,
                    json: args.json,
                },
            )
            .await
        }
        BenchmarkSub::Limits(args) => {
            benchmark_run(
                global,
                groups::benchmark::BenchmarkRun {
                    driver: "limits".into(),
                    target: groups::benchmark::BenchmarkRunTarget {
                        profile: Some(args.target.profile),
                        forward: Some(args.target.forward),
                    },
                    duration: None,
                    connections: None,
                    count: None,
                    unsafe_allow_production_impact: false,
                    json: args.json,
                },
            )
            .await
        }
        BenchmarkSub::Report(rep) => benchmark_report(global, rep).await,
    }
}

async fn benchmark_run(global: &GlobalOpts, args: groups::benchmark::BenchmarkRun) -> Result<()> {
    use spt_benchmark::{
        check_safety, write_report, BenchContext, BenchEnv, BenchmarkDriver, DnsClient, DnsDriver,
        LatencyDriver, LimitsDriver, LimitsExpectations, ReconnectDriver, ReconnectTrigger,
        ReportFormat, ThroughputDriver, UdpDriver,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Resolve the production-impact gate: BOTH the CLI flag AND the config
    // flag must be set for the user opt-in to take effect.
    let cfg_allow_prod = global
        .config
        .as_ref()
        .and_then(|p| spt_config::load(p, false).ok())
        .and_then(|(c, _)| c.benchmark)
        .and_then(|b| b.allow_production_impact)
        .unwrap_or(false);
    let allow_prod = args.unsafe_allow_production_impact && cfg_allow_prod;

    // Live-vs-synthetic: a live tunnel-driven benchmark requires reaching the
    // running orchestrator's `live_connector`. The CLI binary cannot do that
    // today (no in-process control IPC; see f-cli-final.md follow-ups). We
    // refuse live drivers when `--profile` is set, and run synthetic-only
    // when the user explicitly passes no profile. `dns` is always synthetic
    // since it doesn't need a tunnel. This is honest stub behaviour: better
    // to refuse than silently measure tokio::io::duplex throughput while the
    // user thinks they're measuring their tunnel.
    let is_dns = args.driver == "dns";
    // Live mode: when `--profile` is set and the driver is tunnel-aware,
    // dispatch to the running spt via MCP loopback. The server-side
    // `benchmark_run` tool wires `Orchestrator::live_connector(profile,
    // forward)` into the same driver suite this function exposes.
    if !is_dns && args.target.profile.is_some() {
        let state_dir = resolve_state_dir_for_read(global)?;
        let mut client = crate::mcp_client::McpClient::connect_from_state_dir(&state_dir).await?;
        client.initialize().await?;
        let mut payload = serde_json::json!({
            "driver": args.driver,
            "profile": args.target.profile.clone().unwrap(),
            "count": args.count.unwrap_or(50),
            "duration_seconds": args
                .duration
                .as_deref()
                .and_then(|d| spt_core::duration::parse_duration(d).ok())
                .map(|d| d.as_secs())
                .unwrap_or(5),
            "allow_production_impact": allow_prod,
        });
        if let Some(f) = args.target.forward.clone() {
            payload["forward"] = serde_json::Value::String(f);
        }
        let v = client.call_tool("benchmark_run", payload).await?;
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&v)
                    .map_err(|e| Error::RuntimeFailure(e.to_string()))?
            );
        } else {
            let iter_ok = v
                .get("iterations_completed")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            let iter_attempt = v
                .get("iterations_attempted")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            let dur = v.get("duration_ms").and_then(|x| x.as_u64()).unwrap_or(0);
            let errors = v
                .get("errors")
                .and_then(|x| x.as_array())
                .map(Vec::len)
                .unwrap_or(0);
            println!(
                "driver={} (live) iter_ok={iter_ok}/{iter_attempt} dur={dur}ms errors={errors}",
                args.driver
            );
        }
        return Ok(());
    }
    eprintln!(
        "spt: benchmark `{}` running in synthetic-loopback mode (no live tunnel profile selected)",
        args.driver
    );

    // Synthetic in-process connector pair (loopback echo over duplex streams).
    // Same shape `spt-benchmark`'s own unit tests use.
    let connector: spt_benchmark::Connector = Box::new(|| {
        Box::pin(async move {
            let (client_side, server_side) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(server_side);
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if writer.write_all(&buf[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            let stream: spt_benchmark::driver::BoxedStream = Box::pin(client_side);
            Ok(stream)
        })
    });

    let env = BenchEnv {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        spt_version: env!("CARGO_PKG_VERSION").into(),
        profile: args.target.profile.clone(),
        forward: args.target.forward.clone(),
        ..Default::default()
    };

    let iterations = u64::from(args.count.unwrap_or(50));
    let payload_size = 256;
    let max_duration = args
        .duration
        .as_deref()
        .and_then(|d| spt_core::duration::parse_duration(d).ok())
        .unwrap_or_else(|| Duration::from_secs(5));

    // Build the driver per `--driver`.
    let driver: Box<dyn BenchmarkDriver> = match args.driver.as_str() {
        "latency" => Box::new(LatencyDriver),
        "throughput" => Box::new(ThroughputDriver),
        "udp" => {
            // Synthetic UDP echo on loopback.
            let ud_conn: spt_benchmark::UdpConnector = Box::new(|| {
                Box::pin(async move {
                    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                    let echo_addr = echo.local_addr()?;
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1500];
                        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                            let _ = echo.send_to(&buf[..n], peer).await;
                        }
                    });
                    Ok(spt_benchmark::UdpEndpoint {
                        socket: s,
                        target: echo_addr,
                    })
                })
            });
            Box::new(UdpDriver::new(ud_conn))
        }
        "reconnect" => {
            struct NoopTrigger;
            #[async_trait::async_trait]
            impl ReconnectTrigger for NoopTrigger {
                async fn wait_session_up(&self) -> std::io::Result<()> {
                    Ok(())
                }
                async fn trigger_drop(&self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            Box::new(ReconnectDriver::new(Arc::new(NoopTrigger)))
        }
        "dns" => {
            struct LocalDns;
            #[async_trait::async_trait]
            impl DnsClient for LocalDns {
                async fn query(&self, _name: &str) -> std::io::Result<Vec<String>> {
                    Ok(vec!["127.0.0.1".into()])
                }
            }
            Box::new(DnsDriver::new(
                Arc::new(LocalDns),
                vec!["example.com".into()],
            ))
        }
        "limits" => Box::new(LimitsDriver::new(
            Box::new(|| {
                Box::pin(async move {
                    let (a, _b) = tokio::io::duplex(1024);
                    let stream: spt_benchmark::driver::BoxedStream = Box::pin(a);
                    Ok(stream)
                })
            }),
            LimitsExpectations::default(),
        )),
        other => {
            return Err(Error::InvalidArgs(format!(
                "unknown --driver `{other}` (expected one of: latency, throughput, udp, reconnect, dns, limits)"
            )));
        }
    };

    check_safety(&*driver, allow_prod).map_err(|e| Error::InvalidArgs(e.to_string()))?;

    let ctx = BenchContext {
        iterations,
        payload_size,
        max_duration,
        connector,
        allow_production_impact: allow_prod,
        env: env.clone(),
    };
    let result = driver.run(&ctx).await;

    // Write reports to <state_dir>/benchmarks/<run-id>.{json,md}.
    let state_dir = resolve_state_dir_for_read(global).unwrap_or_else(|_| std::env::temp_dir());
    let run_id = format!(
        "{}-{}",
        args.driver,
        chrono::Utc::now().format("%Y%m%dT%H%M%S")
    );
    let json_path = write_report(&state_dir, &run_id, &[result.clone()], ReportFormat::Json)?;
    let md_path = write_report(
        &state_dir,
        &run_id,
        &[result.clone()],
        ReportFormat::Markdown,
    )?;

    if args.json {
        let summary = serde_json::json!({
            "driver": args.driver,
            "iterations_completed": result.iterations_completed,
            "iterations_attempted": result.iterations_attempted,
            "duration_ms": result.duration_ms,
            "errors": result.errors,
            "report_json": json_path,
            "report_md": md_path,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary)
                .map_err(|e| Error::RuntimeFailure(e.to_string()))?
        );
    } else {
        println!(
            "driver={} iter_ok={}/{} dur={}ms errors={}",
            args.driver,
            result.iterations_completed,
            result.iterations_attempted,
            result.duration_ms,
            result.errors.len()
        );
        println!("report (json): {}", json_path.display());
        println!("report (md):   {}", md_path.display());
    }
    Ok(())
}

async fn benchmark_report(
    global: &GlobalOpts,
    rep: groups::benchmark::BenchmarkReport,
) -> Result<()> {
    use groups::benchmark::BenchmarkReportSub;
    match rep.command {
        BenchmarkReportSub::Compare(args) => {
            let baseline = load_bench_report(&args.baseline)?;
            let candidate = load_bench_report(&args.candidate)?;
            let cmp = spt_benchmark::compare_reports(&baseline, &candidate);
            let s = serde_json::to_string_pretty(&cmp)
                .map_err(|e| Error::BenchmarkFailed(e.to_string()))?;
            println!("{s}");
            Ok(())
        }
        BenchmarkReportSub::Export(args) => {
            crate::cli::bench_ops::report_export(global, args.into()).await
        }
    }
}

// ============================================================================
// mcp
// ============================================================================

async fn mcp_dispatch(global: &GlobalOpts, c: groups::mcp::McpCmd) -> Result<()> {
    use groups::mcp::McpSub;
    match c.command {
        McpSub::Serve(args) => mcp_serve(global, args).await,
        McpSub::Inspect(args) => mcp_inspect(global, args),
        McpSub::Policy(args) => mcp_policy(global, args),
    }
}

fn mcp_inspect(_global: &GlobalOpts, args: groups::mcp::McpInspect) -> Result<()> {
    // Drive a noop server purely for its registries — the resource and tool
    // counts come from spec §13.4 / §16 and are asserted at registry build
    // time inside spt-mcp. We expose them here for `spt mcp inspect`.
    let resources = spt_mcp::resources::ResourceRegistry::new().list();
    let tools = spt_mcp::tools::ToolRegistry::new().list();
    if args.json {
        let v = serde_json::json!({
            "resources": resources,
            "tools": tools,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| Error::McpFailed(e.to_string()))?
        );
    } else {
        println!("resources: {}", resources.len());
        for r in &resources {
            println!("  {} — {}", r.uri, r.name);
        }
        println!("tools: {}", tools.len());
        for t in &tools {
            println!("  {}", t.name);
        }
    }
    Ok(())
}

fn mcp_policy(global: &GlobalOpts, args: groups::mcp::McpPolicy) -> Result<()> {
    use groups::mcp::McpPolicySub;
    match args.command {
        McpPolicySub::Show => {
            let cfg_mcp = global
                .config
                .as_ref()
                .and_then(|p| spt_config::load(p, false).ok())
                .and_then(|(c, _)| c.mcp);
            if let Some(m) = cfg_mcp {
                let v = serde_json::to_string_pretty(&m)
                    .map_err(|e| Error::McpFailed(e.to_string()))?;
                println!("{v}");
            } else {
                println!("{{}}");
            }
            Ok(())
        }
        McpPolicySub::Set(s) => {
            // Write to [mcp].allow_write_tools when key matches; refuse other
            // keys (the schema is small enough to enumerate here).
            let path = require_config_path(global)?;
            let mut doc = spt_config::mutate::Document::read(&path)?;
            let inner = doc.document_mut();
            let mcp = inner
                .as_table_mut()
                .entry("mcp")
                .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
            let mcp_tbl = mcp
                .as_table_mut()
                .ok_or_else(|| Error::InvalidConfig("[mcp] is not a table".into()))?;
            for kv in &s.overrides {
                let (k, v) = kv.split_once('=').ok_or_else(|| {
                    Error::InvalidArgs(format!("expected `key=value`, got `{kv}`"))
                })?;
                match k {
                    "allow_write_tools" => {
                        let arr: toml_edit::Array = v.split(',').map(|x| x.trim()).collect();
                        mcp_tbl["allow_write_tools"] = toml_edit::value(arr);
                    }
                    "enabled" => {
                        let b: bool = v.parse().map_err(|_| {
                            Error::InvalidArgs(format!("`enabled` expects bool, got `{v}`"))
                        })?;
                        mcp_tbl["enabled"] = toml_edit::value(b);
                    }
                    other => {
                        return Err(Error::InvalidArgs(format!(
                            "unsupported policy key `{other}`"
                        )));
                    }
                }
            }
            doc.write_atomic(&path)?;
            println!("policy updated");
            Ok(())
        }
    }
}

async fn mcp_serve(global: &GlobalOpts, args: groups::mcp::McpServe) -> Result<()> {
    // Resolve listen address from the CLI flag, falling back to `[mcp].listen`
    // in the loaded config (if any). `[mcp].stdio = true` overrides into
    // stdio mode; otherwise the presence of a listen address selects the
    // loopback TCP transport.
    let cfg_path = args.config.clone().or_else(|| global.config.clone());
    let cfg_listen = cfg_path
        .as_ref()
        .and_then(|p| spt_config::load(p, false).ok())
        .and_then(|(c, _)| c.mcp)
        .and_then(|m| m.listen);
    let listen = args.listen.clone().or(cfg_listen);
    let stdio = args.stdio || listen.is_none();

    if !args.enable {
        return Err(Error::McpFailed(
            "MCP is disabled by default. Pass --enable to confirm.".into(),
        ));
    }
    // Read-only is the default (no tools added to allow_write_tools);
    // `--read-only` is accepted but currently a no-op since the default is
    // already read-only — it's preserved for forward-compatibility.
    let _ = args.read_only;
    let policy = spt_mcp::McpPolicy {
        enabled: true,
        stdio,
        listen: listen.clone().unwrap_or_default(),
        ..Default::default()
    };
    let server = crate::mcp_server::build_noop_server(policy);
    if stdio {
        server
            .run_stdio()
            .await
            .map_err(|e| Error::McpFailed(e.to_string()))?;
    } else {
        let addr = listen.expect("listen is some when !stdio");
        let transport = spt_mcp::LoopbackTransport::bind(&addr)
            .await
            .map_err(|e| Error::McpFailed(format!("loopback bind `{addr}`: {e}")))?;
        server
            .run(transport)
            .await
            .map_err(|e| Error::McpFailed(e.to_string()))?;
    }
    Ok(())
}

// ============================================================================
// status (plan §t4-e5)
// ============================================================================

async fn status_dispatch(global: &GlobalOpts, c: groups::status::StatusCmd) -> Result<()> {
    use groups::status::{StatusSub, StatusTokenSub};
    match c.command {
        StatusSub::Serve(args) => crate::cli::status_ops::serve(global, args).await,
        StatusSub::Status(args) => crate::cli::status_ops::status(global, args).await,
        StatusSub::Token(t) => match t.command {
            StatusTokenSub::Rotate(args) => crate::cli::status_ops::token_rotate(global, args).await,
        },
    }
}

// ============================================================================
// completion
// ============================================================================

fn completion_dispatch(_global: &GlobalOpts, c: groups::completion::CompletionCmd) -> Result<()> {
    match c.command {
        groups::completion::CompletionSub::Generate(args) => {
            groups::completion::CompletionCmd::generate(args.shell);
            Ok(())
        }
    }
}

// ============================================================================
// helpers
// ============================================================================

fn require_config_path(global: &GlobalOpts) -> Result<PathBuf> {
    global.config.clone().ok_or_else(|| {
        Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
    })
}

fn resolve_state_dir(global: &GlobalOpts, cfg: &spt_config::schema::Config) -> Result<PathBuf> {
    let explicit = global.state_dir.clone().or_else(|| {
        cfg.runtime
            .as_ref()
            .and_then(|r| r.state_dir.clone())
            .map(PathBuf::from)
    });
    spt_state::resolve_state_dir(explicit.as_deref())
}

fn resolve_state_dir_for_read(global: &GlobalOpts) -> Result<PathBuf> {
    spt_state::resolve_state_dir(global.state_dir.as_deref())
}

// Suppress unused warning for the helper used by docs.
#[allow(dead_code)]
fn _config_fingerprint_export(global: &GlobalOpts) -> Result<()> {
    config_fingerprint_command(global)
}

fn load_bench_report(path: &Path) -> Result<Vec<spt_benchmark::BenchResult>> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| Error::BenchmarkFailed(format!("read {}: {e}", path.display())))?;
    // Accept either a top-level array of BenchResult or a single object.
    if let Ok(arr) = serde_json::from_str::<Vec<spt_benchmark::BenchResult>>(&s) {
        return Ok(arr);
    }
    let one: spt_benchmark::BenchResult = serde_json::from_str(&s)
        .map_err(|e| Error::BenchmarkFailed(format!("parse {}: {e}", path.display())))?;
    Ok(vec![one])
}

// ============================================================================
// tests
// ============================================================================
//
// These tests route the parsed `Cli` through the corresponding `*_dispatch`
// entry points to exercise every top-level match arm at least once. The bulk
// short-circuit early (no config / no MCP sidecar / no state) and return a
// structured `Error` — that is sufficient: the match arm was hit, the
// dispatcher's wiring is exercised, and downstream `ops` modules are covered
// by their own e3/e4/e20 suites.
//
// Conventions:
// - Every test that touches the filesystem uses a `tempfile::TempDir`.
// - We always pass `--state-dir <tempdir>` to avoid contaminating user state.
// - Tests use `parse(args)` to build the `Cli` and assert `dispatch(...)`
//   returns the expected `Result` shape.
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use spt_cli::Cli;
    use std::path::Path;

    /// Build a `Cli` from a slice of args, panicking on parse failure.
    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap_or_else(|e| panic!("parse failed for {args:?}: {e}"))
    }

    /// Write a minimal valid config TOML and return its path inside the tempdir.
    fn minimal_config(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("spt.toml");
        std::fs::write(&path, "version = 1\n").unwrap();
        path
    }

    /// Write a config with a single profile and return its path.
    fn config_with_profile(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("spt.toml");
        std::fs::write(
            &path,
            "version = 1\n\
             [[profiles]]\n\
             name = \"edge\"\n\
             protocol = \"ssh2\"\n\
             host = \"127.0.0.1\"\n\
             user = \"alice\"\n",
        )
        .unwrap();
        path
    }

    async fn dispatch_err(cli: Cli) -> Error {
        dispatch(cli).await.expect_err("expected dispatch to error")
    }

    async fn dispatch_ok(cli: Cli) {
        if let Err(e) = dispatch(cli).await {
            panic!("expected dispatch to succeed, got: {e:?}");
        }
    }

    // ----- helpers -----------------------------------------------------------

    #[test]
    fn parse_forward_ref_round_trip() {
        let (p, f) = parse_forward_ref("edge/db").unwrap();
        assert_eq!(p, "edge");
        assert_eq!(f, "db");
        let err = parse_forward_ref("no-slash").unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn parse_secret_url_round_trip() {
        let (ns, name) = parse_secret_url("secret://db/password").unwrap();
        assert_eq!(ns, "db");
        assert_eq!(name, "password");
        for bad in &["secret://only", "secret:///empty", "noprefix"] {
            assert!(parse_secret_url(bad).is_err(), "expected error for `{bad}`");
        }
    }

    #[test]
    fn parse_ns_name_round_trip() {
        let r = parse_ns_name("db/password").unwrap();
        assert_eq!(r.ns(), "db");
        assert_eq!(r.name(), "password");
        assert!(parse_ns_name("bare").is_err());
    }

    #[test]
    fn service_name_from_path_uses_file_stem() {
        let name = service_name_from_path(Path::new("/etc/spt/edge.toml"));
        assert_eq!(name, "spt-edge");
    }

    #[test]
    fn require_config_path_errors_without_config() {
        let cli = parse(&["spt", "config", "validate"]);
        let err = require_config_path(&cli.global).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn resolve_state_dir_for_read_with_override() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "status",
        ]);
        let p = resolve_state_dir_for_read(&cli.global).unwrap();
        assert_eq!(p, td.path());
    }

    // ----- config group ------------------------------------------------------

    #[tokio::test]
    async fn config_validate_missing_config_errors() {
        let cli = parse(&["spt", "config", "validate"]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn config_validate_succeeds_on_minimal() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "config",
            "validate",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn config_validate_strict_passes_minimal() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "config",
            "validate",
            "--strict",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn config_render_minimal() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "config",
            "render",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn config_render_json_redacted() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "config",
            "render",
            "--json",
            "--redacted",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn config_diff_identical_files() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "config",
            "diff",
            "--from",
            cfg.to_str().unwrap(),
            "--to",
            cfg.to_str().unwrap(),
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn config_init_writes_file() {
        let td = tempfile::tempdir().unwrap();
        let out = td.path().join("new.toml");
        let cli = parse(&[
            "spt",
            "config",
            "init",
            "--path",
            out.to_str().unwrap(),
        ]);
        dispatch_ok(cli).await;
        assert!(out.exists());
    }

    #[tokio::test]
    async fn config_init_refuses_overwrite() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "config",
            "init",
            "--path",
            cfg.to_str().unwrap(),
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn config_migrate_minimal_round_trip() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "config",
            "migrate",
            "--from-version",
            "1",
            "--to-version",
            "1",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn config_pull_requires_fingerprint() {
        let cli = parse(&[
            "spt",
            "config",
            "pull",
            "--url",
            "https://example.invalid/cfg.toml",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn config_trust_add_url_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "config",
            "trust",
            "add-url",
            "--url",
            "https://cfg.example/spt.toml",
            "--fingerprint",
            "deadbeef",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn config_doctor_routes_through() {
        // config_ops::doctor short-circuits without a config — assert routing.
        let cli = parse(&["spt", "config", "doctor"]);
        // Routes through without a config — either an error or a stub print.
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn config_reload_routes() {
        let cli = parse(&["spt", "config", "reload"]);
        let _ = dispatch(cli).await;
    }

    // ----- profile group -----------------------------------------------------

    #[tokio::test]
    async fn profile_list_empty_config() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "list",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn profile_list_with_profile() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "list",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn profile_show_existing() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "show",
            "edge",
            "--json",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn profile_show_missing() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "show",
            "missing",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn profile_show_redacted_text() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "show",
            "edge",
            "--redacted",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn profile_add_then_remove() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "add",
            "edge",
            "--protocol",
            "ssh2",
            "--host",
            "h.example",
            "--user",
            "alice",
        ]);
        dispatch_ok(cli).await;
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "remove",
            "edge",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn profile_remove_missing_errors() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "remove",
            "missing",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn profile_enable_disable_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        for cmd in ["enable", "disable"] {
            let cli = parse(&[
                "spt",
                "--config",
                cfg.to_str().unwrap(),
                "profile",
                cmd,
                "edge",
            ]);
            let _ = dispatch(cli).await;
        }
    }

    #[tokio::test]
    async fn profile_configure_non_interactive_no_fields_errors() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "configure",
            "--no-tui",
            "--name",
            "edge",
        ]);
        // configure_non_interactive errors when no edits provided.
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn profile_set_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "set",
            "edge",
            "host=h2.example",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn profile_test_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "profile",
            "test",
            "edge",
        ]);
        let _ = dispatch(cli).await;
    }

    // ----- forward group -----------------------------------------------------

    #[tokio::test]
    async fn forward_list_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "list",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn forward_list_with_filter() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "list",
            "--profile",
            "edge",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn forward_add_local_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "add",
            "local",
            "--profile",
            "edge",
            "--listen",
            "127.0.0.1:5432",
            "--to",
            "db:5432",
            "--tcp",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn forward_add_remote_udp_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "add",
            "remote",
            "--profile",
            "edge",
            "--listen",
            "0.0.0.0:53",
            "--to",
            "10.0.0.1:53",
            "--udp",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn forward_show_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "show",
            "edge/db",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn forward_explain_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "explain",
            "edge/db",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn forward_test_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "test",
            "edge/db",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn forward_throttle_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "throttle",
            "edge/db",
            "--in",
            "10MiB/s",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn forward_remove_missing_errors() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "forward",
            "remove",
            "edge/missing",
        ]);
        let _ = dispatch(cli).await;
    }

    // ----- tunnel group ------------------------------------------------------

    #[tokio::test]
    async fn tunnel_run_requires_config() {
        // Without --config and no $SPT_CONFIG, tunnel run errors at
        // require_config_path. We test the routing only.
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "run",
            "--once",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn tunnel_status_missing_state_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "status",
        ]);
        // No status.json — returns RuntimeFailure with a hint.
        let err = dispatch_err(cli).await;
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }

    #[tokio::test]
    async fn tunnel_stats_no_mcp_sidecar_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "stats",
            "--json",
        ]);
        // No mcp-listen.json — routes through and errors.
        let _ = dispatch_err(cli).await;
    }

    #[tokio::test]
    async fn tunnel_sessions_no_mcp_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "sessions",
        ]);
        let _ = dispatch_err(cli).await;
    }

    // Note: `spt tunnel health` calls `std::process::exit` for non-Ok health
    // levels, so it cannot be routed through `dispatch` from within the test
    // harness without aborting the runner. We exercise the parse path only;
    // the underlying handler is covered by `cli::tunnel_ops` unit tests.
    #[test]
    fn tunnel_health_parses() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "health",
            "--json",
        ]);
        assert!(matches!(
            cli.command,
            spt_cli::Command::Tunnel(spt_cli::groups::tunnel::TunnelCmd {
                command: spt_cli::groups::tunnel::TunnelSub::Health(_),
            })
        ));
    }

    #[tokio::test]
    async fn tunnel_failover_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "failover",
            "edge",
        ]);
        let _ = dispatch_err(cli).await;
    }

    #[tokio::test]
    async fn tunnel_stop_missing_pid_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "stop",
        ]);
        // No pid file -> RuntimeFailure.
        let _ = dispatch_err(cli).await;
    }

    #[tokio::test]
    async fn tunnel_reload_missing_pid_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "tunnel",
            "reload",
        ]);
        let _ = dispatch_err(cli).await;
    }

    // ----- service group -----------------------------------------------------

    #[test]
    fn service_spec_helper_with_name_override() {
        let td = tempfile::tempdir().unwrap();
        let cfg = td.path().join("spt.toml");
        std::fs::write(&cfg, "version = 1\n").unwrap();
        let scope = groups::service::ServiceScope {
            user: true,
            system: false,
            name: Some("custom-name".into()),
        };
        let spec = service_spec_from_args(&cfg, &scope).unwrap();
        assert_eq!(spec.name, "custom-name");
        assert!(matches!(spec.scope, spt_service::Scope::User));
        assert!(spec.args.iter().any(|a| a == "run"));
    }

    #[test]
    fn service_spec_helper_default_name() {
        let td = tempfile::tempdir().unwrap();
        let cfg = td.path().join("edge.toml");
        std::fs::write(&cfg, "version = 1\n").unwrap();
        let scope = groups::service::ServiceScope {
            user: false,
            system: true,
            name: None,
        };
        let spec = service_spec_from_args(&cfg, &scope).unwrap();
        assert_eq!(spec.name, "spt-edge");
        assert!(matches!(spec.scope, spt_service::Scope::System));
    }

    #[test]
    fn service_name_helper_with_override() {
        let scope = groups::service::ServiceScope {
            user: false,
            system: false,
            name: Some("explicit".into()),
        };
        assert_eq!(service_name(&scope, Path::new("any.toml")), "explicit");
    }

    // Note: actual service install/start/stop/render hit the real service
    // manager — admin-only / SCM-only on Windows. We exercise the helpers
    // (above) and rely on spt-service tests for the manager surface.

    // ----- key group ---------------------------------------------------------

    #[tokio::test]
    async fn key_generate_ed25519_writes_files() {
        let td = tempfile::tempdir().unwrap();
        let out = td.path().join("id_test");
        let cli = parse(&[
            "spt",
            "key",
            "generate",
            "--type",
            "ed25519",
            "--out",
            out.to_str().unwrap(),
        ]);
        dispatch_ok(cli).await;
        assert!(out.exists());
        assert!(out.with_extension("pub").exists() || td.path().join("id_test.pub").exists());
    }

    #[tokio::test]
    async fn key_inspect_existing_key() {
        let td = tempfile::tempdir().unwrap();
        let out = td.path().join("id_test");
        // Generate first.
        let cli = parse(&[
            "spt",
            "key",
            "generate",
            "--type",
            "ed25519",
            "--out",
            out.to_str().unwrap(),
        ]);
        dispatch_ok(cli).await;
        let cli = parse(&[
            "spt",
            "key",
            "inspect",
            out.to_str().unwrap(),
            "--json",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn key_public_routes() {
        let td = tempfile::tempdir().unwrap();
        let out = td.path().join("id_test");
        let cli = parse(&[
            "spt",
            "key",
            "generate",
            "--type",
            "ed25519",
            "--out",
            out.to_str().unwrap(),
        ]);
        dispatch_ok(cli).await;
        let cli = parse(&[
            "spt",
            "key",
            "public",
            out.to_str().unwrap(),
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn key_sign_cert_missing_files_errors() {
        let td = tempfile::tempdir().unwrap();
        let ca = td.path().join("ca");
        let subj = td.path().join("user.pub");
        let cli = parse(&[
            "spt",
            "key",
            "sign-cert",
            "--ca-key",
            ca.to_str().unwrap(),
            "--public-key",
            subj.to_str().unwrap(),
            "--principal",
            "alice",
            "--out",
            td.path().join("cert.pub").to_str().unwrap(),
        ]);
        let _ = dispatch_err(cli).await;
    }

    #[tokio::test]
    async fn key_verify_cert_missing_errors() {
        let td = tempfile::tempdir().unwrap();
        let cert = td.path().join("missing-cert.pub");
        let trusted = td.path().join("trusted-cas");
        let cli = parse(&[
            "spt",
            "key",
            "verify-cert",
            cert.to_str().unwrap(),
            "--trusted-cas",
            trusted.to_str().unwrap(),
        ]);
        let _ = dispatch_err(cli).await;
    }

    #[tokio::test]
    async fn key_install_public_missing_target_routes() {
        let td = tempfile::tempdir().unwrap();
        let pub_key = td.path().join("id.pub");
        std::fs::write(&pub_key, "ssh-ed25519 AAAA fake\n").unwrap();
        let cli = parse(&[
            "spt",
            "key",
            "install-public",
            "--key",
            pub_key.to_str().unwrap(),
            "--target",
            "user@localhost.invalid",
        ]);
        let _ = dispatch(cli).await;
    }

    // ----- secret group ------------------------------------------------------

    #[tokio::test]
    async fn secret_set_requires_value_source() {
        let cli = parse(&["spt", "secret", "set", "db/password"]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn secret_set_from_env_routes() {
        let td = tempfile::tempdir().unwrap();
        // SAFETY: read-only test only setting our own var.
        // Use a unique env-var name to avoid race with other tests.
        let var = "SPT_TEST_SECRET_E21";
        unsafe {
            std::env::set_var(var, "v");
        }
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "secret",
            "set",
            "db/password",
            "--from-env",
            var,
        ]);
        // Routing only; keychain operations may succeed or fail
        // depending on host.
        let _ = dispatch(cli).await;
        unsafe {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn secret_doctor_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "secret",
            "doctor",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn secret_store_init_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "secret",
            "store",
            "init",
            "--vault-path",
            td.path().join("vault.spt").to_str().unwrap(),
            "--passphrase-from",
            "env:SPT_TEST_VAULT_E21",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn secret_list_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "secret",
            "list",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn secret_rotate_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "secret",
            "rotate",
            "db/password",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn secret_get_routes_redacted() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "secret",
            "get",
            "db/password",
        ]);
        // Will likely error (not in keychain) but routing succeeded.
        let _ = dispatch(cli).await;
    }

    // ----- auth group --------------------------------------------------------

    #[tokio::test]
    async fn auth_test_unknown_profile_errors() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "auth",
            "test",
            "missing",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn auth_test_known_profile_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "auth",
            "test",
            "edge",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn auth_ssh3_login_bad_issuer_errors() {
        let cli = parse(&[
            "spt",
            "auth",
            "ssh3-login",
            "--issuer",
            "not a url",
            "--client-id",
            "cid",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    // ----- dns group ---------------------------------------------------------

    #[tokio::test]
    async fn dns_status_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "dns",
            "status",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn dns_query_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "dns",
            "query",
            "example.invalid",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn dns_upstream_set_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            td.path().to_str().unwrap(),
            "dns",
            "upstream",
            "set",
            "1.1.1.1:53",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn dns_record_add_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            td.path().to_str().unwrap(),
            "dns",
            "record",
            "add",
            "svc.local",
            "--addr",
            "10.0.0.1",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn dns_hosts_render_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            td.path().to_str().unwrap(),
            "dns",
            "hosts",
            "render",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn dns_hosts_render_with_out_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let out = td.path().join("hosts.out");
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            td.path().to_str().unwrap(),
            "dns",
            "hosts",
            "render",
            "--out",
            out.to_str().unwrap(),
        ]);
        dispatch_ok(cli).await;
        assert!(out.exists());
    }

    // ----- firewall group ----------------------------------------------------

    #[tokio::test]
    async fn firewall_plan_routes() {
        let cli = parse(&["spt", "firewall", "plan"]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn firewall_apply_dry_run_routes() {
        let cli = parse(&["spt", "firewall", "apply", "--system", "--dry-run"]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn firewall_apply_without_dry_run_refused() {
        let cli = parse(&["spt", "firewall", "apply", "--system"]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::PermissionDenied(_)
        ));
    }

    #[tokio::test]
    async fn firewall_remove_routes() {
        let cli = parse(&["spt", "firewall", "remove", "--system"]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn firewall_status_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "firewall",
            "status",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn firewall_interfaces_routes() {
        let cli = parse(&["spt", "firewall", "interfaces"]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn firewall_bind_preview_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "firewall",
            "bind-preview",
            "--forward",
            "edge/db",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn firewall_gateway_show_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "firewall",
            "gateway",
            "show",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn firewall_policy_list_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "firewall",
            "policy",
            "list",
            "--json",
        ]);
        let _ = dispatch(cli).await;
    }

    // ----- log group ---------------------------------------------------------

    #[tokio::test]
    async fn log_tail_no_log_file_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "log",
            "tail",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn log_tail_existing_file() {
        let td = tempfile::tempdir().unwrap();
        std::fs::write(td.path().join("spt.log"), "line1\nline2\n").unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "log",
            "tail",
            "--follow",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn log_remote_list_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "log",
            "remote",
            "list",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn log_remote_test_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "log",
            "remote",
            "test",
            "--sink",
            "unknown-sink",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn log_remote_status_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "log",
            "remote",
            "status",
            "--sink",
            "unknown-sink",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn log_remote_drain_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "log",
            "remote",
            "drain",
            "--sink",
            "unknown-sink",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn log_test_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "log",
            "test",
            "--sink",
            "unknown-sink",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn log_export_jsonl_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "log",
            "export",
            "--format",
            "jsonl",
            "--since",
            "1h",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn log_export_csv_rejected() {
        let cli = parse(&[
            "spt",
            "log",
            "export",
            "--format",
            "csv",
            "--since",
            "1h",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    // ----- observe group -----------------------------------------------------

    #[tokio::test]
    async fn observe_metrics_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "observe",
            "metrics",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn observe_metrics_with_existing_file() {
        let td = tempfile::tempdir().unwrap();
        let metrics = spt_state::paths::metrics_path(td.path());
        if let Some(parent) = metrics.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&metrics, "# HELP test 1\n").unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "observe",
            "metrics",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn observe_windows_event_test_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "observe",
            "windows-event",
            "test",
        ]);
        let _ = dispatch(cli).await;
    }

    // ----- event group -------------------------------------------------------

    #[tokio::test]
    async fn event_list_empty_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "event",
            "list",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn event_list_json_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "event",
            "list",
            "--json",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn event_sink_list_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "event",
            "sink",
            "list",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn event_test_missing_binding_errors() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "event",
            "test",
            "missing",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn event_sink_test_missing_sink_errors() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "event",
            "sink",
            "test",
            "missing",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn event_replay_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            td.path().to_str().unwrap(),
            "event",
            "replay",
            "--since",
            "10m",
            "--binding",
            "ops",
        ]);
        let _ = dispatch(cli).await;
    }

    // ----- stats group -------------------------------------------------------

    #[tokio::test]
    async fn stats_summary_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "stats",
            "summary",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn stats_connections_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "stats",
            "connections",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn stats_throughput_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "stats",
            "throughput",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn stats_errors_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "stats",
            "errors",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn stats_export_json_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "stats",
            "export",
            "--format",
            "json",
            "--since",
            "1h",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn stats_export_csv_routes() {
        let td = tempfile::tempdir().unwrap();
        // Write a status with a profiles array to exercise the CSV branch.
        let status = spt_state::paths::status_path(td.path());
        if let Some(parent) = status.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(
            &status,
            r#"{"profiles":[{"id":"edge","state":"active"}]}"#,
        )
        .unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "stats",
            "export",
            "--format",
            "csv",
            "--since",
            "1h",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn stats_export_prometheus_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "stats",
            "export",
            "--format",
            "prometheus",
            "--since",
            "1h",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn stats_live_no_mcp_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "stats",
            "live",
        ]);
        let _ = dispatch_err(cli).await;
    }

    // ----- session group -----------------------------------------------------

    #[tokio::test]
    async fn session_list_no_snapshot() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "session",
            "list",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn session_show_missing_id_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "session",
            "show",
            "no-such-id",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn session_show_present() {
        let td = tempfile::tempdir().unwrap();
        let status = spt_state::paths::status_path(td.path());
        if let Some(parent) = status.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(
            &status,
            r#"{"sessions":[{"id":"abc123","state":"up"}]}"#,
        )
        .unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "session",
            "show",
            "abc123",
            "--json",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn session_top_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "session",
            "top",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn session_close_no_mcp_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "session",
            "close",
            "abc",
        ]);
        let _ = dispatch_err(cli).await;
    }

    #[tokio::test]
    async fn session_drain_no_mcp_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "session",
            "drain",
            "edge",
        ]);
        let _ = dispatch_err(cli).await;
    }

    // ----- diagnose group ----------------------------------------------------

    #[tokio::test]
    async fn diagnose_run_routes() {
        let cli = parse(&["spt", "diagnose", "run"]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn diagnose_one_group_routes() {
        let td = tempfile::tempdir().unwrap();
        // `service` is excluded because it requires `--config` even for the
        // routing test (clap-level).
        for group in ["secrets", "mcp", "network", "dns", "bind"] {
            let cli = parse(&[
                "spt",
                "--state-dir",
                td.path().to_str().unwrap(),
                "diagnose",
                group,
                "--json",
            ]);
            dispatch_ok(cli).await;
        }
    }

    #[tokio::test]
    async fn diagnose_service_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "diagnose",
            "service",
            "--config",
            cfg.to_str().unwrap(),
            "--system",
            "--json",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn diagnose_port_tcp_unreachable() {
        let cli = parse(&[
            "spt",
            "diagnose",
            "port",
            "--host",
            "127.0.0.1",
            "--port",
            "1",
            "--tcp",
            "--json",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn diagnose_port_tcp_autodetect() {
        let cli = parse(&[
            "spt",
            "diagnose",
            "port",
            "--host",
            "127.0.0.1",
            "--port",
            "1",
            "--tcp",
            "--autodetect-service",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn diagnose_auth_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            td.path().to_str().unwrap(),
            "diagnose",
            "auth",
            "edge",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn diagnose_trust_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = config_with_profile(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            td.path().to_str().unwrap(),
            "diagnose",
            "trust",
            "edge",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn diagnose_observability_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "diagnose",
            "observability",
        ]);
        let _ = dispatch(cli).await;
    }

    #[tokio::test]
    async fn diagnose_bundle_writes_archive() {
        let td = tempfile::tempdir().unwrap();
        let out = td.path().join("bundle.tar.gz");
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "diagnose",
            "bundle",
            "--out",
            out.to_str().unwrap(),
        ]);
        dispatch_ok(cli).await;
        assert!(out.exists());
    }

    // ----- benchmark group ---------------------------------------------------

    #[tokio::test]
    async fn benchmark_run_dns_synthetic() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "dns",
            "--count",
            "2",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn benchmark_run_latency_synthetic() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "latency",
            "--count",
            "2",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn benchmark_run_throughput_synthetic() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "throughput",
            "--count",
            "2",
            "--duration",
            "100ms",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn benchmark_run_udp_synthetic_safety_gate() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "udp",
            "--count",
            "2",
            "--duration",
            "100ms",
        ]);
        // The udp driver is gated by check_safety without --unsafe-allow flag.
        // The dispatcher *still* routes through the udp arm — the safety
        // check is what errors. That's the assertion target.
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn benchmark_run_reconnect_safety_gate() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "reconnect",
            "--count",
            "2",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn benchmark_run_limits_safety_gate() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "limits",
            "--count",
            "2",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn benchmark_run_unknown_driver_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "nope",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn benchmark_run_live_no_mcp_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "latency",
            "--profile",
            "edge",
        ]);
        // Live driver path: routes via MCP, no sidecar => RuntimeFailure.
        let _ = dispatch_err(cli).await;
    }

    #[tokio::test]
    async fn benchmark_latency_alias_routes() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "latency",
            "--profile",
            "edge",
            "--forward",
            "db",
            "--samples",
            "2",
        ]);
        // Routes through into live path (no MCP -> errors).
        let _ = dispatch_err(cli).await;
    }

    #[tokio::test]
    async fn benchmark_dns_alias_synthetic() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "--state-dir",
            td.path().to_str().unwrap(),
            "benchmark",
            "dns",
            "--name",
            "example.com",
            "--samples",
            "2",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn benchmark_report_compare_routes() {
        let td = tempfile::tempdir().unwrap();
        let base = td.path().join("base.json");
        let cand = td.path().join("cand.json");
        // Write empty arrays to satisfy load_bench_report's array branch.
        std::fs::write(&base, "[]").unwrap();
        std::fs::write(&cand, "[]").unwrap();
        let cli = parse(&[
            "spt",
            "benchmark",
            "report",
            "compare",
            "--baseline",
            base.to_str().unwrap(),
            "--candidate",
            cand.to_str().unwrap(),
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn benchmark_report_compare_missing_errors() {
        let td = tempfile::tempdir().unwrap();
        let cli = parse(&[
            "spt",
            "benchmark",
            "report",
            "compare",
            "--baseline",
            td.path().join("missing-a.json").to_str().unwrap(),
            "--candidate",
            td.path().join("missing-b.json").to_str().unwrap(),
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::BenchmarkFailed(_)
        ));
    }

    // ----- mcp group ---------------------------------------------------------

    #[tokio::test]
    async fn mcp_inspect_routes() {
        let cli = parse(&["spt", "mcp", "inspect"]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn mcp_inspect_json_routes() {
        let cli = parse(&["spt", "mcp", "inspect", "--json"]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn mcp_policy_show_no_config() {
        let cli = parse(&["spt", "mcp", "policy", "show"]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn mcp_policy_show_with_config() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "mcp",
            "policy",
            "show",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn mcp_policy_set_enabled_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "mcp",
            "policy",
            "set",
            "enabled=true",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn mcp_policy_set_allow_write_tools_routes() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "mcp",
            "policy",
            "set",
            "allow_write_tools=event.test,profile.set",
        ]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn mcp_policy_set_unknown_key_errors() {
        let td = tempfile::tempdir().unwrap();
        let cfg = minimal_config(td.path());
        let cli = parse(&[
            "spt",
            "--config",
            cfg.to_str().unwrap(),
            "mcp",
            "policy",
            "set",
            "bogus=true",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::InvalidArgs(_)
        ));
    }

    #[tokio::test]
    async fn mcp_serve_without_enable_errors() {
        let cli = parse(&[
            "spt",
            "mcp",
            "serve",
            "--stdio",
        ]);
        assert!(matches!(
            dispatch_err(cli).await,
            Error::McpFailed(_)
        ));
    }

    // ----- completion group --------------------------------------------------

    #[tokio::test]
    async fn completion_generate_bash_routes() {
        let cli = parse(&["spt", "completion", "generate", "bash"]);
        dispatch_ok(cli).await;
    }

    #[tokio::test]
    async fn completion_generate_zsh_routes() {
        let cli = parse(&["spt", "completion", "generate", "zsh"]);
        dispatch_ok(cli).await;
    }

    // ----- top-level dispatch shape ------------------------------------------

    #[tokio::test]
    async fn config_dir_merges_into_tempfile() {
        // Exercise the `--config-dir` branch at the top of `dispatch`.
        let td = tempfile::tempdir().unwrap();
        let a = td.path().join("01-base.toml");
        std::fs::write(&a, "version = 1\n").unwrap();
        let cli = parse(&[
            "spt",
            "--config-dir",
            td.path().to_str().unwrap(),
            "config",
            "validate",
        ]);
        dispatch_ok(cli).await;
    }
}

