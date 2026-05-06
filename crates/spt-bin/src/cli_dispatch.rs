//! CLI dispatch: maps every parsed [`spt_cli::Command`] to its implementing
//! crate.
//!
//! For commands that do real work in M0/M8 the body is implemented here.
//! Commands that depend on subsystems not yet wired (per the executor brief)
//! return [`crate::stub_err`] with a milestone reference rather than panicking.

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

use std::io::Write;
use std::path::{Path, PathBuf};
use spt_cli::{groups, Cli, Command, GlobalOpts};
use spt_core::{Error, RedactionMode, Result};

use crate::stub_err;

/// Top-level dispatcher.
pub async fn dispatch(cli: Cli) -> Result<()> {
    let global = cli.global.clone();
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
        Command::Completion(c) => completion_dispatch(&global, c),
    }
}

// ============================================================================
// config
// ============================================================================

async fn config_dispatch(global: &GlobalOpts, c: groups::config::ConfigCmd) -> Result<()> {
    use groups::config::ConfigSub;
    match c.command {
        ConfigSub::Init(_) => Err(stub_err("config init", "M0+")),
        ConfigSub::Validate(args) => config_validate(global, args.strict),
        ConfigSub::Doctor(_) => Err(stub_err("config doctor", "M3")),
        ConfigSub::Render(args) => config_render(global, args),
        ConfigSub::Diff(args) => config_diff(args),
        ConfigSub::Migrate(_) => Err(stub_err("config migrate", "M0+")),
        ConfigSub::Reload(_) => Err(stub_err("config reload", "M3")),
        ConfigSub::Pull(_) => Err(stub_err("config pull", "M5")),
        ConfigSub::Trust(_) => Err(stub_err("config trust", "M5")),
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
        ProfileSub::Configure(args) => profile_configure(global, args),
        ProfileSub::Set(_) => Err(stub_err("profile set", "M2")),
        ProfileSub::Enable(_) => Err(stub_err("profile enable", "M2")),
        ProfileSub::Disable(_) => Err(stub_err("profile disable", "M2")),
        ProfileSub::Remove(args) => profile_remove(global, args),
        ProfileSub::Test(_) => Err(stub_err("profile test", "M3")),
    }
}

fn profile_list(global: &GlobalOpts) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
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
    let (cfg, _) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
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
    let mut doc = raw.parse::<toml_edit::DocumentMut>().map_err(|e| {
        Error::InvalidConfig(format!("toml_edit parse `{}`: {e}", path.display()))
    })?;
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

fn profile_configure(global: &GlobalOpts, args: groups::profile::ProfileConfigure) -> Result<()> {
    if args.no_tui {
        return Err(stub_err("profile configure --no-tui", "M2"));
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
        ForwardSub::Show(_) => Err(stub_err("forward show", "M2")),
        ForwardSub::Add(args) => forward_add(global, args),
        ForwardSub::Explain(_) => Err(stub_err("forward explain", "M3")),
        ForwardSub::Test(_) => Err(stub_err("forward test", "M3")),
        ForwardSub::Throttle(_) => Err(stub_err("forward throttle", "M4")),
        ForwardSub::Remove(args) => forward_remove(global, args),
    }
}

fn forward_list(global: &GlobalOpts, args: groups::forward::ForwardList) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
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
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::InvalidConfig(format!("read: {e}")))?;
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
        let name = format!(
            "{}-{}",
            direction,
            a.len() + 1,
        );
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
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::InvalidConfig(format!("read: {e}")))?;
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
        TunnelSub::Stats(_) => Err(stub_err("tunnel stats", "M4")),
        TunnelSub::Sessions(_) => Err(stub_err("tunnel sessions", "M4")),
        TunnelSub::Stop(_) => tunnel_stop(global).await,
        TunnelSub::Reload(_) => tunnel_reload(global).await,
        TunnelSub::Health(_) => Err(stub_err("tunnel health", "M3")),
        TunnelSub::Failover(_) => Err(stub_err("tunnel failover", "M9")),
    }
}

async fn tunnel_run(global: &GlobalOpts, args: groups::tunnel::TunnelRun) -> Result<()> {
    // Acquire the state lock, build the orchestrator + per-profile bundles,
    // start every enabled profile, install the signal handlers, and run
    // until shutdown. SIGHUP triggers a config re-load + reconciliation via
    // `Orchestrator::apply` against a fresh `ReloadPlan`.
    let path = require_config_path(global)?;
    let (cfg, _w) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let state_dir = resolve_state_dir(global, &cfg)?;
    let _lock = spt_state::StateLock::acquire(&state_dir)?;

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
    for profile in &cfg.profiles {
        if profile.enabled == Some(false) {
            tracing::info!(profile = %profile.name, "profile disabled — skipping");
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
                orchestrator.start_profile(
                    profile,
                    bundle.protocol,
                    bundle.auth,
                    bundle.endpoints,
                    bundle.supervisor_cfg,
                );
            }
            Err(e) => {
                tracing::error!(profile = %profile.name, error = %e, "failed to build profile");
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

    let signal_rx = crate::signals::spawn();

    if args.once {
        // `--once`: bring everything up, then immediately tear down. Used in
        // CI / smoke tests to confirm a config can drive the orchestrator
        // through the start/stop lifecycle without blocking on a signal.
        orchestrator.shutdown().await;
        writer.flush().await?;
        writer_handle.stop().await;
        return Ok(());
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
                match reload_orchestrator(
                    &cfg_path_for_reload,
                    &resolver,
                    &orchestrator,
                    &cfg,
                )
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
    writer.flush().await?;
    writer_handle.stop().await;
    Ok(())
}

/// Re-read the config from disk and apply a [`ReloadPlan`] against the
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(Error::RuntimeFailure(format!(
                "no status snapshot at `{}` — is `spt tunnel run` running?",
                path.display()
            )))
        }
        Err(e) => Err(Error::RuntimeFailure(format!("read status: {e}"))),
    }
}

async fn tunnel_stop(global: &GlobalOpts) -> Result<()> {
    // Best-effort: signal the running supervisor by sending a Unix signal to
    // the recorded PID. Windows uses a console event which requires the
    // service path; manual stop is tracked in M9.
    let state_dir = resolve_state_dir_for_read(global)?;
    let pid_path = spt_state::paths::pid_path(&state_dir);
    let pid_str = std::fs::read_to_string(&pid_path).map_err(|e| {
        Error::RuntimeFailure(format!("read `{}`: {e}", pid_path.display()))
    })?;
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
        Err(stub_err("tunnel stop (Windows)", "M9"))
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
        Err(stub_err("tunnel reload (Windows)", "M9"))
    }
}

// ============================================================================
// service
// ============================================================================

async fn service_dispatch(_global: &GlobalOpts, c: groups::service::ServiceCmd) -> Result<()> {
    use groups::service::ServiceSub;
    match c.command {
        ServiceSub::Install(args) => service_install(args),
        ServiceSub::Uninstall(args) => service_uninstall(args),
        ServiceSub::Start(args) => service_lifecycle(args, ServiceAction::Start),
        ServiceSub::Stop(args) => service_lifecycle(args, ServiceAction::Stop),
        ServiceSub::Restart(args) => service_lifecycle(args, ServiceAction::Restart),
        ServiceSub::Status(args) => service_status(args),
        ServiceSub::Render(args) => service_render(args),
    }
}

enum ServiceAction {
    Start,
    Stop,
    Restart,
}

fn service_install(args: groups::service::ServiceArgs) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let spec = service_spec_from_args(&args.config, &args.scope)?;
    mgr.install(&spec)?;
    println!("installed service `{}`", spec.name);
    Ok(())
}

fn service_uninstall(args: groups::service::ServiceArgs) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let name = service_name(&args.scope, &args.config);
    mgr.uninstall(&name)?;
    println!("uninstalled service `{name}`");
    Ok(())
}

fn service_lifecycle(args: groups::service::ServiceArgs, action: ServiceAction) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let name = service_name(&args.scope, &args.config);
    match action {
        ServiceAction::Start => mgr.start(&name)?,
        ServiceAction::Stop => mgr.stop(&name)?,
        ServiceAction::Restart => mgr.restart(&name)?,
    }
    Ok(())
}

fn service_status(args: groups::service::ServiceStatus) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let name = service_name(&args.scope, &args.config);
    let st = mgr.status(&name)?;
    if args.json {
        let v = serde_json::json!({"name": name, "status": format!("{st:?}").to_lowercase()});
        println!("{v}");
    } else {
        println!("{name}: {st:?}");
    }
    Ok(())
}

fn service_render(args: groups::service::ServiceRender) -> Result<()> {
    let mgr = spt_service::new_default_manager()?;
    let spec = service_spec_from_args(&args.config, &args.scope)?;
    let s = mgr.render(&spec)?;
    print!("{s}");
    Ok(())
}

fn service_spec_from_args(
    config: &Path,
    scope: &groups::service::ServiceScope,
) -> Result<spt_service::ServiceSpec> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::RuntimeFailure(format!("current_exe: {e}")))?;
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

async fn key_dispatch(_global: &GlobalOpts, c: groups::key::KeyCmd) -> Result<()> {
    use groups::key::KeySub;
    match c.command {
        KeySub::Generate(args) => key_generate(args),
        KeySub::Inspect(args) => key_inspect(args),
        KeySub::Public(_) => Err(stub_err("key public", "M0+")),
        KeySub::ChangePassphrase(_) => Err(stub_err("key change-passphrase", "M1")),
        KeySub::SignCert(_) => Err(stub_err("key sign-cert", "M1")),
        KeySub::VerifyCert(_) => Err(stub_err("key verify-cert", "M1")),
        KeySub::InstallPublic(_) => Err(stub_err("key install-public", "M3")),
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
    Ok(buf.trim_end_matches(|c: char| c == '\n' || c == '\r').to_string())
}

// ============================================================================
// secret
// ============================================================================

async fn secret_dispatch(global: &GlobalOpts, c: groups::secret::SecretCmd) -> Result<()> {
    use groups::secret::SecretSub;
    match c.command {
        SecretSub::Store(_) => Err(stub_err("secret store", "M1")),
        SecretSub::Set(args) => secret_set(global, args),
        SecretSub::Get(args) => secret_get(global, args),
        SecretSub::List(args) => secret_list(global, args),
        SecretSub::Rotate(_) => Err(stub_err("secret rotate", "M1")),
        SecretSub::Remove(args) => secret_remove(global, args),
        SecretSub::Doctor => secret_doctor(global),
    }
}

fn secret_set(_global: &GlobalOpts, args: groups::secret::SecretSet) -> Result<()> {
    let value = if args.prompt {
        prompt_passphrase(&format!("value for `{}`: ", args.name))?
    } else if let Some(env) = args.from_env {
        std::env::var(&env)
            .map_err(|e| Error::SecretUnavailable {
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
        eprintln!(
            "warning: --reveal exposes plaintext secret material to your terminal."
        );
        println!("(secret loaded, {} bytes — full reveal tracked in M1)", bytes_len_hint(&bytes));
    } else {
        println!("[REDACTED]");
    }
    Ok(())
}

fn bytes_len_hint(b: &spt_secrets::SecretBytes) -> usize {
    use secrecy::ExposeSecret;
    b.expose_secret().len()
}

fn secret_list(_global: &GlobalOpts, _args: groups::secret::SecretList) -> Result<()> {
    Err(stub_err("secret list (vault enumeration)", "M1"))
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
    let (ns, name) = s.split_once('/').ok_or_else(|| {
        Error::InvalidArgs(format!("expected `<ns>/<name>`, got `{s}`"))
    })?;
    spt_secrets::SecretRef::new(ns.to_string(), name.to_string())
        .map_err(|e| Error::InvalidArgs(format!("bad secret name: {e}")))
}

// ============================================================================
// auth
// ============================================================================

async fn auth_dispatch(_global: &GlobalOpts, _c: groups::auth::AuthCmd) -> Result<()> {
    Err(stub_err("auth", "M1+"))
}

// ============================================================================
// dns
// ============================================================================

async fn dns_dispatch(global: &GlobalOpts, c: groups::dns::DnsCmd) -> Result<()> {
    use groups::dns::DnsSub;
    match c.command {
        DnsSub::Serve(_) => Err(stub_err("dns serve", "M2")),
        DnsSub::Status(_) => dns_status(global),
        DnsSub::Query(_) => Err(stub_err("dns query", "M2")),
        DnsSub::Upstream(_) => Err(stub_err("dns upstream", "M2")),
        DnsSub::Record(_) => Err(stub_err("dns record", "M2")),
        DnsSub::Hosts(args) => dns_hosts(global, args),
    }
}

fn dns_status(_global: &GlobalOpts) -> Result<()> {
    println!("(dns status: not implemented in M0; tracked in M2)");
    Ok(())
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
                std::fs::write(&out, s)
                    .map_err(|e| Error::RuntimeFailure(format!("write `{}`: {e}", out.display())))?;
            } else {
                print!("{s}");
            }
            Ok(())
        }
        DnsHostsSub::Apply(args) => {
            let report = mgr
                .apply(args.path.as_deref(), false)
                .map_err(|e| Error::DnsFailed(format!("hosts apply: {e}")))?;
            println!("apply: changed={} backed_up={}", report.changed, report.backed_up);
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

async fn firewall_dispatch(_global: &GlobalOpts, c: groups::firewall::FirewallCmd) -> Result<()> {
    use groups::firewall::FirewallSub;
    match c.command {
        FirewallSub::Plan(_) => firewall_plan_render(false),
        FirewallSub::Apply(args) => firewall_apply(args, false),
        FirewallSub::Remove(args) => firewall_apply(args, true),
        FirewallSub::Status(_) => Err(stub_err("firewall status", "M3")),
        FirewallSub::Interfaces(_) => firewall_interfaces(),
        FirewallSub::BindPreview(_) => Err(stub_err("firewall bind-preview", "M3")),
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
    use groups::log::LogSub;
    match c.command {
        LogSub::Tail(args) => log_tail(global, args),
        LogSub::Test(_) => Err(stub_err("log test", "M3")),
        LogSub::Export(_) => Err(stub_err("log export", "M3")),
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
    use groups::observe::ObserveSub;
    match c.command {
        ObserveSub::Metrics(args) => observe_metrics(global, args),
        ObserveSub::Snmp(_) => Err(stub_err("observe snmp", "M3")),
        ObserveSub::WindowsEvent(_) => Err(stub_err("observe windows-event", "M3")),
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

async fn event_dispatch(_global: &GlobalOpts, _c: groups::event::EventCmd) -> Result<()> {
    Err(stub_err("event", "M3"))
}

// ============================================================================
// stats
// ============================================================================

async fn stats_dispatch(global: &GlobalOpts, c: groups::stats::StatsCmd) -> Result<()> {
    use groups::stats::StatsSub;
    match c.command {
        StatsSub::Summary(_) => stats_snapshot(global),
        _ => Err(stub_err("stats (other)", "M4")),
    }
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
        SessionSub::Close(_) => Err(stub_err("session close", "M4")),
        _ => Err(stub_err("session (other)", "M4")),
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
        _ => Err(stub_err("diagnose (specific)", "M5")),
    }
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

async fn benchmark_dispatch(_global: &GlobalOpts, c: groups::benchmark::BenchmarkCmd) -> Result<()> {
    use groups::benchmark::BenchmarkSub;
    match c.command {
        BenchmarkSub::Run(_args) => benchmark_run_dryrun(),
        BenchmarkSub::Report(rep) => benchmark_report(rep),
        _ => Err(stub_err("benchmark (specific)", "M6")),
    }
}

fn benchmark_run_dryrun() -> Result<()> {
    println!("benchmark run (offline drivers): not yet wired to live tunnels — see M6.");
    Ok(())
}

fn benchmark_report(rep: groups::benchmark::BenchmarkReport) -> Result<()> {
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
        BenchmarkReportSub::Export(_) => Err(stub_err("benchmark report export", "M6")),
    }
}

// ============================================================================
// mcp
// ============================================================================

async fn mcp_dispatch(global: &GlobalOpts, c: groups::mcp::McpCmd) -> Result<()> {
    use groups::mcp::McpSub;
    match c.command {
        McpSub::Serve(args) => mcp_serve(global, args).await,
        McpSub::Inspect(_) => Err(stub_err("mcp inspect", "M7+")),
        McpSub::Policy(_) => Err(stub_err("mcp policy", "M7+")),
    }
}

async fn mcp_serve(_global: &GlobalOpts, args: groups::mcp::McpServe) -> Result<()> {
    if !args.enable {
        return Err(Error::McpFailed(
            "MCP is disabled by default. Pass --enable to confirm.".into(),
        ));
    }
    if args.listen.is_some() {
        return Err(Error::McpFailed(
            "loopback TCP transport is tracked in M8; only --stdio is wired in M7.".into(),
        ));
    }
    let policy = spt_mcp::McpPolicy {
        enabled: true,
        ..Default::default()
    };
    let server = crate::mcp_server::build_noop_server(policy);
    server
        .run()
        .await
        .map_err(|e| Error::McpFailed(e.to_string()))?;
    Ok(())
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
    global
        .config
        .clone()
        .ok_or_else(|| {
            Error::InvalidArgs(
                "no config path supplied (pass --config or set $SPT_CONFIG)".into(),
            )
        })
}

fn resolve_state_dir(global: &GlobalOpts, cfg: &spt_config::schema::Config) -> Result<PathBuf> {
    let explicit = global
        .state_dir
        .clone()
        .or_else(|| {
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
