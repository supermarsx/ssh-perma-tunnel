//! `spt status` command implementations.
//!
//! Three subcommands, all read-side helpers for the status API defined in
//! plan §t4-e5:
//!
//! * [`serve`] — foreground-host the status API (rare; supervisor normally
//!   does this when `[status_api].enabled = true`).
//! * [`status`] — report whether the API is enabled and how to reach it.
//! * [`token_rotate`] — rotate the bearer token in the configured vault.
//!
//! The [`FileSnapshotSource`] adapter lives here because it's the integration
//! seam between the status-api crate (which only knows the
//! [`StateSnapshotSource`] trait) and the on-disk
//! `<state_dir>/status.json` file written by the supervisor's
//! [`spt_state::StatusWriter`].

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use serde_json::json;
use spt_cli::groups::status::{
    StatusApiServeArgs, StatusApiShowArgs, StatusApiTokenRotateArgs, StatusCmd,
};
use spt_cli::{GlobalOpts, OutputFormat};
use spt_config::StatusApiAuthMode;
use spt_core::{Error, Result};
use spt_state::status::StatusSnapshot;
use spt_status_api::StateSnapshotSource;

// ---------------------------------------------------------------------------
// FileSnapshotSource — reads `<state_dir>/status.json` on every request.
// ---------------------------------------------------------------------------

/// File-backed [`StateSnapshotSource`] for v1.
///
/// Reads `<state_dir>/status.json` on every snapshot request. This is the
/// same file produced by [`spt_state::StatusWriter`] inside `tunnel run`,
/// so the API exposes a self-consistent view of the running supervisor.
/// Returns a default snapshot if the file does not exist (e.g. server
/// running standalone via `spt status serve` against an empty state dir).
pub struct FileSnapshotSource {
    state_dir: PathBuf,
}

impl FileSnapshotSource {
    /// Construct from a state directory path.
    #[must_use]
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
        }
    }
}

#[async_trait]
impl StateSnapshotSource for FileSnapshotSource {
    async fn snapshot(&self) -> StatusSnapshot {
        let path = spt_state::paths::status_path(&self.state_dir);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<StatusSnapshot>(&bytes).unwrap_or_default(),
            Err(_) => StatusSnapshot::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// `spt status serve`
// ---------------------------------------------------------------------------

/// Foreground-host the status API. Loads the config, builds a
/// [`FileSnapshotSource`] over the state dir, calls
/// [`spt_status_api::StatusApiServer::start`], and blocks until Ctrl-C / SIGTERM.
pub async fn serve(global: &GlobalOpts, args: StatusApiServeArgs) -> Result<()> {
    let cfg_path = args
        .config
        .clone()
        .or_else(|| global.config.clone())
        .ok_or_else(|| Error::InvalidArgs("--config required for `spt status serve`".into()))?;
    let (mut cfg, _w) = spt_config::load(&cfg_path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", cfg_path.display())))?;
    if let Some(bind) = args.bind.as_deref() {
        cfg.status_api.bind = bind
            .parse()
            .map_err(|e| Error::InvalidArgs(format!("invalid --bind `{bind}`: {e}")))?;
    }
    if !cfg.status_api.enabled {
        // Honour the operator intent — make it explicit that the serve path
        // forcibly enables the server (rare-use override).
        cfg.status_api.enabled = true;
    }
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let resolver = crate::secrets_bridge::build_resolver(cfg.secrets.as_ref(), &state_dir)?;

    let source: Arc<dyn StateSnapshotSource> = Arc::new(FileSnapshotSource::new(state_dir.clone()));
    // `launch` closes the deferred TLS/mTLS gate (see
    // `.orchestration/logs/f-status-tls.md`). For plain HTTP it delegates to
    // `StatusApiServer::start`, preserving the byte-identical wire behavior
    // of the t4-Bwire shipped path.
    let tcp_options = crate::net_offload::tcp_options(&cfg);
    let handle =
        crate::status_api_tls::launch(&cfg.status_api, source, &resolver, tcp_options).await?;
    let bound = handle.local_addr();
    match output_format(global) {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "listening": bound.to_string(),
                    "state_dir": state_dir.display().to_string(),
                }))
                .unwrap()
            );
        }
        OutputFormat::Yaml => {
            println!("listening: {bound}\nstate_dir: {}", state_dir.display());
        }
        OutputFormat::Human => {
            if !global.quiet {
                println!("status-api listening on {bound}");
                println!("ctrl-c to stop");
            }
        }
    }

    // Wait for ctrl-c (and on Unix, SIGTERM); then trigger graceful shutdown.
    wait_for_shutdown_signal().await;
    handle.shutdown().await;
    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

// ---------------------------------------------------------------------------
// `spt status status`
// ---------------------------------------------------------------------------

/// Report whether the status API is enabled and how to reach it.
pub async fn status(global: &GlobalOpts, args: StatusApiShowArgs) -> Result<()> {
    let cfg_path = require_config(global)?;
    let (cfg, _w) = spt_config::load(&cfg_path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", cfg_path.display())))?;
    let api = &cfg.status_api;

    let auth_mode = match &api.auth.mode {
        StatusApiAuthMode::None => "none",
        StatusApiAuthMode::Bearer { .. } => "bearer",
        StatusApiAuthMode::Basic { .. } => "basic",
        StatusApiAuthMode::MutualTls { .. } => "mtls",
    };

    let payload = json!({
        "enabled": api.enabled,
        "bind": api.bind.to_string(),
        "tls": api.tls.enabled,
        "auth": auth_mode,
        "expose_metrics": api.expose_metrics,
        "rate_limit_rps": api.rate_limit_rps,
    });

    match output_format(global) {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        }
        OutputFormat::Yaml => {
            // Hand-spell — avoid a serde_yaml round-trip for this tiny shape.
            println!("enabled: {}", api.enabled);
            println!("bind: {}", api.bind);
            println!("tls: {}", api.tls.enabled);
            println!("auth: {auth_mode}");
        }
        OutputFormat::Human => {
            if api.enabled {
                println!("status-api: enabled");
                println!("  bind:  {}", api.bind);
                println!("  auth:  {auth_mode}");
                println!("  tls:   {}", api.tls.enabled);
                if args.detail {
                    println!("  metrics:        {}", api.expose_metrics);
                    println!("  rate_limit_rps: {}", api.rate_limit_rps);
                }
            } else {
                println!("status-api: not enabled (`[status_api].enabled = false`)");
                println!("  bind would be: {}", api.bind);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `spt status token rotate`
// ---------------------------------------------------------------------------

/// Rotate the bearer token. Reads `[status_api].auth.token_from`, generates a
/// fresh random token, writes it via the vault backend, and prints the new
/// SecretRef. Errors cleanly if the auth mode is not bearer.
pub async fn token_rotate(global: &GlobalOpts, args: StatusApiTokenRotateArgs) -> Result<()> {
    use rand::RngCore;
    use spt_secrets::{KeychainBackend, SecretBackend, VaultBackend};

    if args.bytes == 0 || args.bytes > 1024 {
        return Err(Error::InvalidArgs(format!(
            "--bytes must be in 1..=1024 (got {})",
            args.bytes
        )));
    }
    let cfg_path = require_config(global)?;
    let (cfg, _w) = spt_config::load(&cfg_path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", cfg_path.display())))?;
    let token_ref = match &cfg.status_api.auth.mode {
        StatusApiAuthMode::Bearer { token_from } => token_from.clone(),
        other => {
            return Err(Error::InvalidConfig(format!(
                "spt status token rotate requires `auth.mode = \"bearer\"`; configured: {}",
                match other {
                    StatusApiAuthMode::None => "none",
                    StatusApiAuthMode::Bearer { .. } => unreachable!(),
                    StatusApiAuthMode::Basic { .. } => "basic",
                    StatusApiAuthMode::MutualTls { .. } => "mtls",
                }
            )));
        }
    };

    // Generate a fresh token. Both the random bytes and the encoded token are
    // secret-bearing; wrap in `Zeroizing` so they are scrubbed from the heap on
    // drop (defense-in-depth against core-dump / swap residue).
    let mut raw = zeroize::Zeroizing::new(vec![0u8; args.bytes]);
    rand::thread_rng().fill_bytes(&mut raw);
    let token =
        zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD_NO_PAD.encode(&*raw));

    // Write to the vault. Prefer the keychain-unlocked open path so we don't
    // prompt unnecessarily; fall back to a passphrase prompt if unavailable.
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let vault_dir = state_dir.join("vault");
    if !VaultBackend::vault_path(&vault_dir).exists() {
        return Err(Error::SecretUnavailable {
            reference: token_ref.to_string(),
            reason: format!(
                "no vault at `{}` — initialise with `spt secret store init`",
                vault_dir.display()
            ),
        });
    }
    let kc = KeychainBackend::with_service("spt".to_string());
    let vault = VaultBackend::open_with_keychain(&vault_dir, &kc)?;
    vault.set(&token_ref, token.as_bytes())?;

    match output_format(global) {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let mut v = json!({
                "rotated": true,
                "ref": token_ref.to_string(),
                "bytes": args.bytes,
            });
            if args.print_token {
                v["token"] = json!(token.as_str());
            }
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        OutputFormat::Yaml => {
            println!("rotated: true");
            println!("ref: {token_ref}");
            if args.print_token {
                println!("token: {}", token.as_str());
            }
        }
        OutputFormat::Human => {
            if !global.quiet {
                println!("rotated bearer token at {token_ref}");
                if args.print_token {
                    println!("token: {}", token.as_str());
                }
            }
        }
    }
    Ok(())
}

// ===========================================================================
// `spt status` — app-status overview (NEW; appstatus Wave 2)
// ===========================================================================
//
// Read-only: combines `<state_dir>/runtime.json` (daemon identity +
// subsystems, written by `tunnel_run`), `<state_dir>/status.json`
// (`StatusSnapshot`: profiles/forwards), and (optionally) the loaded config to
// render an elaborate overview. Never requires a running daemon — a missing
// `runtime.json` (or a dead/stale pid) is reported cleanly as NOT RUNNING.

/// Daemon liveness verdict derived from `runtime.json` + a pid-liveness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Liveness {
    /// `runtime.json` present, pid alive, and not stale.
    Running,
    /// No `runtime.json` (cleanly stopped, or never started).
    NotRunning,
    /// `runtime.json` present but the pid is dead (crashed without cleanup).
    Dead,
    /// `runtime.json` present + pid alive but the snapshot is stale.
    Stale,
}

impl Liveness {
    fn label(self) -> &'static str {
        match self {
            Liveness::Running => "RUNNING",
            Liveness::NotRunning => "NOT RUNNING",
            Liveness::Dead => "NOT RUNNING (crashed — pid not alive)",
            Liveness::Stale => "STALE (no recent heartbeat)",
        }
    }
    fn is_live(self) -> bool {
        matches!(self, Liveness::Running)
    }
}

/// `spt status` — render the combined app-status overview.
///
/// `--json` / `--output json|yaml` emit the machine structure; the default is a
/// concise human roll-up and `--detail` is the verbose per-component form.
/// `--watch` clears + re-renders every ~2s until Ctrl-C.
pub async fn status_overview(global: &GlobalOpts, cmd: StatusCmd) -> Result<()> {
    let fmt = overview_format(global, &cmd);
    // Color only ever applies to the human path; `styler` already honors
    // `--no-color` / `NO_COLOR` / `--color` / stdout is-terminal, so piped
    // output stays plain even on the human branch.
    let st = crate::styler(global);

    if cmd.watch {
        // Live refresh loop: clear screen + reprint until Ctrl-C / SIGTERM.
        // Watch only makes sense for human output; machine formats print once.
        if !matches!(fmt, OutputFormat::Human) {
            return Err(Error::InvalidArgs(
                "--watch is only supported with human output (drop --json/--output)".into(),
            ));
        }
        loop {
            let report = build_report(global)?;
            let svc = query_service_line(global).await;
            // Clear screen + home cursor, then reprint.
            print!("\x1b[2J\x1b[H");
            print!("{}", render_human(&report, cmd.detail, st, &svc));
            use std::io::Write;
            let _ = std::io::stdout().flush();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok(()),
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            }
        }
    }

    let report = build_report(global)?;
    match fmt {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // Machine output must never carry ANSI escapes.
            println!(
                "{}",
                serde_json::to_string_pretty(&report.to_json()).unwrap()
            );
        }
        OutputFormat::Yaml => {
            // Reuse the JSON structure through serde_yaml for a faithful machine dump.
            let yaml = serde_yaml::to_string(&report.to_json())
                .unwrap_or_else(|e| format!("# yaml render failed: {e}\n"));
            print!("{yaml}");
        }
        OutputFormat::Human => {
            let svc = query_service_line(global).await;
            print!("{}", render_human(&report, cmd.detail, st, &svc));
        }
    }
    Ok(())
}

/// Human-readable description of the OS service state for the Services
/// section. `label` is the displayed phrase (colored via
/// [`crate::cli::style::Styler::state`]); on a query error it already embeds a
/// short `unknown (<reason>)` parenthetical.
struct ServiceLine {
    label: String,
}

/// Probe the OS service state for the inline Services section. Never fails:
/// query errors collapse to `unknown (<reason>)`.
async fn query_service_line(global: &GlobalOpts) -> ServiceLine {
    match crate::cli_dispatch::probe_service_status(global.config.as_deref()).await {
        Ok((_name, st)) => {
            use spt_service::ServiceState;
            let label = match st.state {
                ServiceState::NotInstalled => "not installed".to_string(),
                ServiceState::Running => {
                    if let Some(pid) = st.pid {
                        format!("running (pid {pid})")
                    } else {
                        "running".to_string()
                    }
                }
                ServiceState::Stopped => "stopped".to_string(),
                ServiceState::Failed => "failed".to_string(),
                ServiceState::Unknown => "unknown".to_string(),
            };
            ServiceLine { label }
        }
        Err(reason) => {
            // Keep the reason short and single-line so the overview stays tidy.
            let short = reason.lines().next().unwrap_or(&reason).trim();
            ServiceLine {
                label: format!("unknown ({short})"),
            }
        }
    }
}

/// The combined, render-agnostic overview data.
struct OverviewReport {
    liveness: Liveness,
    state_dir: PathBuf,
    runtime: Option<spt_state::RuntimeStatus>,
    snapshot: Option<StatusSnapshot>,
    /// Subsystems configured-but-not-running (for the NOT-RUNNING hint), derived
    /// from the loaded config when available.
    configured_subsystems: Vec<String>,
    /// Whether a `--config` was loadable (so we can note its absence).
    config_loaded: bool,
}

/// Collect runtime.json + status.json + config and decide liveness.
fn build_report(global: &GlobalOpts) -> Result<OverviewReport> {
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;

    let runtime = spt_state::read_runtime(&state_dir).unwrap_or(None);
    let snapshot = read_snapshot(&state_dir);

    // Decide liveness from runtime.json + pid probe + staleness.
    let interval = spt_state::StatusWriterConfig::default().interval;
    let liveness = match &runtime {
        None => Liveness::NotRunning,
        Some(rs) => {
            if !crate::cli_dispatch::pid_is_alive(rs.pid()) {
                Liveness::Dead
            } else if rs.is_stale(interval) {
                Liveness::Stale
            } else {
                Liveness::Running
            }
        }
    };

    // Best-effort: load config (if `--config` given) to list configured-but-not-
    // running subsystems when the daemon is down. The renderer never *requires*
    // a daemon or a config.
    let (configured_subsystems, config_loaded) = match &global.config {
        Some(path) => match spt_config::load(path, false) {
            Ok((cfg, _w)) => (configured_subsystems_from_config(&cfg), true),
            Err(_) => (Vec::new(), false),
        },
        None => (Vec::new(), false),
    };

    Ok(OverviewReport {
        liveness,
        state_dir,
        runtime,
        snapshot,
        configured_subsystems,
        config_loaded,
    })
}

fn read_snapshot(state_dir: &std::path::Path) -> Option<StatusSnapshot> {
    let path = spt_state::paths::status_path(state_dir);
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice::<StatusSnapshot>(&bytes).ok()
}

/// Names of subsystems the config enables, for the NOT-RUNNING hint.
fn configured_subsystems_from_config(cfg: &spt_config::schema::Config) -> Vec<String> {
    let mut out = Vec::new();
    if cfg.status_api.enabled {
        out.push("status-api".to_string());
    }
    if cfg.mcp.as_ref().and_then(|m| m.listen.as_ref()).is_some()
        && cfg.mcp.as_ref().and_then(|m| m.enabled) == Some(true)
    {
        out.push("mcp".to_string());
    }
    if cfg.dns.as_ref().and_then(|d| d.enabled) == Some(true) {
        out.push("dns".to_string());
    }
    if cfg
        .runtime
        .as_ref()
        .and_then(|r| r.remote_config.as_ref())
        .and_then(|rc| rc.enabled)
        == Some(true)
    {
        out.push("remote-config-poller".to_string());
    }
    if cfg
        .events
        .as_ref()
        .map(|e| !e.sinks.is_empty())
        .unwrap_or(false)
    {
        out.push("events".to_string());
    }
    if cfg.mem_hygiene.as_ref().and_then(|m| m.enabled) == Some(true) {
        out.push("memory-monitor".to_string());
    }
    out
}

impl OverviewReport {
    /// Machine structure (for `--json` / `--output yaml`).
    fn to_json(&self) -> serde_json::Value {
        let mut v = json!({
            "daemon": {
                "state": match self.liveness {
                    Liveness::Running => "running",
                    Liveness::NotRunning => "not_running",
                    Liveness::Dead => "dead",
                    Liveness::Stale => "stale",
                },
                "live": self.liveness.is_live(),
            },
            "state_dir": self.state_dir.display().to_string(),
        });
        if let Some(rs) = &self.runtime {
            v["daemon"]["pid"] = json!(rs.pid());
            v["daemon"]["version"] = json!(rs.version);
            v["daemon"]["started_at"] = json!(rs.started_at.map(|t| t.to_rfc3339()));
            v["daemon"]["config_path"] = json!(rs.config_path);
            // Subsystems straight from the runtime model.
            v["subsystems"] = serde_json::to_value(&rs.subsystems).unwrap_or(json!({}));
        } else {
            v["configured_subsystems"] = json!(self.configured_subsystems);
        }
        if let Some(snap) = &self.snapshot {
            v["profiles"] = serde_json::to_value(&snap.profiles).unwrap_or(json!([]));
            v["forwards"] = serde_json::to_value(&snap.forwards).unwrap_or(json!([]));
            v["counters"] = serde_json::to_value(&snap.counters).unwrap_or(json!({}));
        }
        v
    }
}

/// Render the elaborate human report. `detail` widens per-component fields.
/// `st` colorizes the human path; `svc` carries the queried OS service line.
#[allow(clippy::too_many_lines)]
fn render_human(
    r: &OverviewReport,
    detail: bool,
    st: crate::cli::style::Styler,
    svc: &ServiceLine,
) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();

    // -- Daemon section -----------------------------------------------------
    let _ = writeln!(o, "{}", st.bold(&st.cyan("spt status")));
    let _ = writeln!(o, "==========");
    let _ = writeln!(o);
    let _ = writeln!(o, "Daemon: {}", st.state(r.liveness.label()));
    if let Some(rs) = &r.runtime {
        let _ = writeln!(o, "  pid:         {}", rs.pid());
        let _ = writeln!(o, "  version:     {}", rs.version);
        if let Some(started) = rs.started_at {
            let uptime = chrono::Utc::now().signed_duration_since(started);
            let _ = writeln!(
                o,
                "  started:     {} (uptime {})",
                started.to_rfc3339(),
                fmt_uptime(uptime)
            );
        }
        let _ = writeln!(o, "  config:      {}", rs.config_path);
    } else {
        let _ = writeln!(o, "  (no runtime.json — daemon is not running)");
        if !r.configured_subsystems.is_empty() {
            let _ = writeln!(
                o,
                "  configured (not running): {}",
                r.configured_subsystems.join(", ")
            );
        } else if !r.config_loaded {
            let _ = writeln!(
                o,
                "  (pass --config to list configured-but-not-running subsystems)"
            );
        }
    }
    let _ = writeln!(o, "  state dir:   {}", r.state_dir.display());

    // -- Profiles / Tunnels -------------------------------------------------
    let _ = writeln!(o);
    let _ = writeln!(o, "{}", st.bold(&st.cyan("Profiles / Tunnels:")));
    match r.snapshot.as_ref().filter(|s| !s.profiles.is_empty()) {
        None => {
            let _ = writeln!(o, "  (none reported)");
        }
        Some(snap) => {
            for p in &snap.profiles {
                let _ = writeln!(o, "  - {} [{}]", p.id, st.state(&p.state));
                if let Some(ep) = &p.active_endpoint {
                    let _ = writeln!(o, "      endpoint:   {ep}");
                }
                if detail {
                    let _ = writeln!(
                        o,
                        "      reconnects: {}  failovers: {}",
                        p.reconnect_count, p.failover_count
                    );
                    if let Some(at) = p.last_successful_connection_at {
                        let _ = writeln!(o, "      last ok:    {}", at.to_rfc3339());
                    }
                    if let Some(err) = &p.last_error_category {
                        let _ = writeln!(o, "      last error: {err}");
                    }
                }
            }
            let _ = writeln!(
                o,
                "  totals: bytes in {} / out {}, reconnects {}, failovers {}",
                snap.counters.bytes_in,
                snap.counters.bytes_out,
                snap.counters.reconnects,
                snap.counters.failovers
            );
        }
    }

    // -- Forwards -----------------------------------------------------------
    let _ = writeln!(o);
    let _ = writeln!(o, "{}", st.bold(&st.cyan("Forwards:")));
    match r.snapshot.as_ref().filter(|s| !s.forwards.is_empty()) {
        None => {
            let _ = writeln!(o, "  (none reported)");
        }
        Some(snap) => {
            for f in &snap.forwards {
                let listener = f.local_addr.as_deref().unwrap_or("?");
                let target = f.remote_addr.as_deref().unwrap_or("?");
                let _ = writeln!(
                    o,
                    "  - {} [{}] {} -> {}",
                    f.id,
                    st.state(&f.state),
                    listener,
                    target
                );
                if detail {
                    let _ = writeln!(
                        o,
                        "      {} / {}  conns {}  in {} out {}",
                        f.direction, f.transport, f.current_connections, f.bytes_in, f.bytes_out
                    );
                }
            }
        }
    }

    // -- Subsystems ---------------------------------------------------------
    let _ = writeln!(o);
    let _ = writeln!(o, "{}", st.bold(&st.cyan("Subsystems:")));
    match r.runtime.as_ref().map(|rs| &rs.subsystems) {
        None => {
            let _ = writeln!(o, "  (unknown — daemon not running)");
        }
        Some(sub) => {
            match &sub.status_api {
                Some(s) => {
                    let onoff = if s.enabled {
                        st.green("on")
                    } else {
                        st.dim("off")
                    };
                    let _ = writeln!(
                        o,
                        "  status API:    {} {}",
                        onoff,
                        s.bind.as_deref().unwrap_or("-")
                    );
                    if detail {
                        let _ = writeln!(
                            o,
                            "      auth: {}  tls: {}",
                            s.auth_mode.as_deref().unwrap_or("-"),
                            s.tls
                        );
                    }
                }
                None => {
                    let _ = writeln!(o, "  status API:    {}", st.dim("off"));
                }
            }
            match &sub.mcp {
                Some(m) => {
                    let _ = writeln!(
                        o,
                        "  MCP loopback:  {}",
                        st.green(m.bind.as_deref().unwrap_or("-"))
                    );
                }
                None => {
                    let _ = writeln!(o, "  MCP loopback:  {}", st.dim("off"));
                }
            }
            match &sub.dns {
                Some(d) => {
                    let _ = writeln!(
                        o,
                        "  DNS:           {} (mode {})",
                        st.green(d.bind.as_deref().unwrap_or("-")),
                        d.mode.as_deref().unwrap_or("-")
                    );
                }
                None => {
                    let _ = writeln!(o, "  DNS:           {}", st.dim("off"));
                }
            }
            match &sub.metrics {
                Some(m) => {
                    let _ = writeln!(
                        o,
                        "  Metrics:       {}",
                        st.green(m.path.as_deref().unwrap_or("-"))
                    );
                }
                None => {
                    let _ = writeln!(o, "  Metrics:       {}", st.dim("off"));
                }
            }
            match &sub.remote_config_poller {
                Some(rc) if rc.enabled => {
                    let _ = writeln!(
                        o,
                        "  Remote config: {} (every {}s)",
                        st.green("on"),
                        rc.interval_secs.unwrap_or(0)
                    );
                }
                _ => {
                    let _ = writeln!(o, "  Remote config: {}", st.dim("off"));
                }
            }
            match &sub.events {
                Some(e) => {
                    let _ = writeln!(o, "  Events:        {} sink(s)", e.sink_count);
                    if detail && !e.kinds.is_empty() {
                        let _ = writeln!(o, "      kinds: {}", e.kinds.join(", "));
                    }
                }
                None => {
                    let _ = writeln!(o, "  Events:        {}", st.dim("off"));
                }
            }
            // Memory monitor: present only when the runtime model carries it
            // (the supervisor sets the field only when the monitor is spawned).
            // When absent, emit nothing so existing no-monitor snapshots stay
            // byte-identical.
            if let Some(mm) = &sub.memory_monitor {
                let state = if mm.enabled {
                    st.green("on")
                } else {
                    st.dim("off")
                };
                let interval = mm
                    .interval_secs
                    .map_or_else(|| "-".to_string(), |s| format!("every {s}s"));
                let _ = writeln!(o, "  Memory monitor: {state} ({interval})");
                let _ = writeln!(o, "      samples: {}", mm.samples);
                if let Some(bytes) = mm.last_rss_bytes {
                    if detail {
                        let _ = writeln!(o, "      last RSS: {} ({bytes} bytes)", fmt_mib(bytes));
                    } else {
                        let _ = writeln!(o, "      last RSS: {}", fmt_mib(bytes));
                    }
                }
                match mm.last_flagged {
                    Some(at) => {
                        // Leak suspected — draw attention in red.
                        let _ = writeln!(o, "      last flagged: {}", st.red(&at.to_rfc3339()));
                    }
                    None => {
                        let _ = writeln!(o, "      {}", st.dim("no growth flagged"));
                    }
                }
            }
        }
    }

    // -- Services -----------------------------------------------------------
    let _ = writeln!(o);
    let _ = writeln!(o, "{}", st.bold(&st.cyan("Services:")));
    let _ = writeln!(o, "  OS service: {}", st.state(&svc.label));

    o
}

/// Humanize a byte count to MiB with one decimal (e.g. `42.0 MiB`). Used for
/// the memory-monitor RSS readout; the concise human path shows only this,
/// while `--detail` additionally prints the raw byte count.
fn fmt_mib(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let mib = bytes as f64 / (1024.0 * 1024.0);
    format!("{mib:.1} MiB")
}

/// Format a `chrono::Duration` uptime compactly (e.g. `3d 4h 5m 6s`).
fn fmt_uptime(d: chrono::Duration) -> String {
    let secs = d.num_seconds().max(0);
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m {s}s")
    } else if hours > 0 {
        format!("{hours}h {mins}m {s}s")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Resolve the overview output format honoring the command-local `--output` /
/// `--json` overrides over the global ones.
fn overview_format(global: &GlobalOpts, cmd: &StatusCmd) -> OutputFormat {
    if cmd.json || global.json {
        OutputFormat::Json
    } else if let Some(o) = cmd.output {
        o
    } else {
        global.output
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn output_format(global: &GlobalOpts) -> OutputFormat {
    if global.json {
        OutputFormat::Json
    } else {
        global.output
    }
}

fn require_config(global: &GlobalOpts) -> Result<PathBuf> {
    global
        .config
        .clone()
        .ok_or_else(|| Error::InvalidArgs("--config required".into()))
}

#[cfg(test)]
mod overview_tests {
    use super::*;
    use spt_cli::{ColorMode, LogLevel};

    fn global(state_dir: PathBuf) -> GlobalOpts {
        GlobalOpts {
            config: None,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: Some(state_dir),
            profile: None,
            portable: false,
            output: OutputFormat::Human,
            json: false,
            log_level: LogLevel::Error,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: true,
            dry_run: false,
        }
    }

    fn live_runtime(td: &std::path::Path) -> spt_state::RuntimeStatus {
        spt_state::RuntimeStatus::default()
            .with_identity(
                std::process::id(),
                "9.9.9",
                chrono::Utc::now(),
                "/etc/spt/spt.toml",
                td.display().to_string(),
            )
            .with_status_api(spt_state::StatusApiStatus {
                enabled: true,
                bind: Some("127.0.0.1:7878".into()),
                auth_mode: Some("bearer".into()),
                tls: true,
            })
            .with_metrics(spt_state::MetricsStatus {
                path: Some("metrics.prom".into()),
            })
            .with_events(spt_state::EventsStatus {
                sink_count: 2,
                kinds: vec!["email".into(), "http".into()],
            })
    }

    #[test]
    fn runtime_status_round_trips_through_write_read() {
        let td = tempfile::tempdir().unwrap();
        let rs = live_runtime(td.path());
        spt_state::write_runtime(td.path(), &rs).unwrap();
        let back = spt_state::read_runtime(td.path()).unwrap().unwrap();
        // `written_at` is stamped by the writer; everything else must match.
        assert_eq!(back.pid(), rs.pid());
        assert_eq!(back.version, "9.9.9");
        assert_eq!(
            back.subsystems.status_api.unwrap().bind.as_deref(),
            Some("127.0.0.1:7878")
        );
        assert!(back.written_at.is_some());
    }

    #[test]
    fn reports_not_running_with_no_runtime_json() {
        let td = tempfile::tempdir().unwrap();
        let g = global(td.path().to_path_buf());
        let report = build_report(&g).unwrap();
        assert_eq!(report.liveness, Liveness::NotRunning);
        let plain = crate::cli::style::Styler::new(false);
        let svc = ServiceLine {
            label: "not installed".into(),
        };
        let human = render_human(&report, false, plain, &svc);
        assert!(human.contains("NOT RUNNING"), "got:\n{human}");
        // The inline service line renders the NotInstalled common case.
        assert!(human.contains("OS service: not installed"), "got:\n{human}");
        // Plain styler must not inject any escapes.
        assert!(
            !human.contains('\x1b'),
            "plain output had escapes:\n{human}"
        );
        // JSON form must still be valid and mark the daemon not live.
        let v = report.to_json();
        assert_eq!(v["daemon"]["live"], serde_json::json!(false));
        assert_eq!(v["daemon"]["state"], serde_json::json!("not_running"));
        // Machine output (JSON) must never carry ANSI escapes.
        let s = serde_json::to_string_pretty(&v).unwrap();
        assert!(!s.contains('\x1b'), "json output had escapes:\n{s}");
    }

    #[test]
    fn reports_running_with_populated_runtime_and_live_pid() {
        let td = tempfile::tempdir().unwrap();
        // Use the current process pid so the liveness probe passes.
        let rs = live_runtime(td.path());
        spt_state::write_runtime(td.path(), &rs).unwrap();
        let g = global(td.path().to_path_buf());
        let report = build_report(&g).unwrap();
        assert_eq!(report.liveness, Liveness::Running);
        assert!(report.liveness.is_live());
        let plain = crate::cli::style::Styler::new(false);
        let svc = ServiceLine {
            label: "running (pid 42)".into(),
        };
        let human = render_human(&report, true, plain, &svc);
        assert!(human.contains("RUNNING"), "got:\n{human}");
        assert!(human.contains("status API"));
        assert!(human.contains("127.0.0.1:7878"));
        assert!(
            human.contains("OS service: running (pid 42)"),
            "got:\n{human}"
        );

        // Enabled styler must inject escapes and color the RUNNING daemon
        // label green and the service line green.
        let styled = crate::cli::style::Styler::new(true);
        let colored = render_human(&report, true, styled, &svc);
        assert!(colored.contains('\x1b'), "styled output had no escapes");
        // "RUNNING" daemon liveness → green.
        assert!(
            colored.contains("\x1b[32mRUNNING\x1b[0m"),
            "got:\n{colored}"
        );
    }

    #[test]
    fn json_overview_emits_valid_structure() {
        let td = tempfile::tempdir().unwrap();
        let rs = live_runtime(td.path());
        spt_state::write_runtime(td.path(), &rs).unwrap();
        let g = global(td.path().to_path_buf());
        let report = build_report(&g).unwrap();
        let v = report.to_json();
        // Re-serialize to confirm it is valid JSON and carries the daemon +
        // subsystems sections.
        let s = serde_json::to_string(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["daemon"]["live"], serde_json::json!(true));
        assert_eq!(
            parsed["daemon"]["pid"],
            serde_json::json!(std::process::id())
        );
        assert!(parsed["subsystems"]["status_api"].is_object());
        assert_eq!(
            parsed["subsystems"]["events"]["sink_count"],
            serde_json::json!(2)
        );
    }

    #[test]
    fn memory_monitor_block_renders_when_present_and_flagged() {
        let td = tempfile::tempdir().unwrap();
        let flagged = chrono::Utc::now();
        let rs =
            live_runtime(td.path()).with_memory_monitor(spt_state::runtime::MemoryMonitorStatus {
                enabled: true,
                interval_secs: Some(60),
                last_rss_bytes: Some(64 * 1024 * 1024),
                samples: 12,
                last_flagged: Some(flagged),
            });
        spt_state::write_runtime(td.path(), &rs).unwrap();
        let g = global(td.path().to_path_buf());
        let report = build_report(&g).unwrap();
        let svc = ServiceLine {
            label: "running".into(),
        };

        // Plain (no color): block present, RSS humanized to MiB, interval shown,
        // sample count shown, and the flagged timestamp present.
        let plain = crate::cli::style::Styler::new(false);
        let human = render_human(&report, false, plain, &svc);
        assert!(human.contains("Memory monitor: on"), "got:\n{human}");
        assert!(human.contains("every 60s"), "got:\n{human}");
        assert!(human.contains("64.0 MiB"), "got:\n{human}");
        assert!(human.contains("samples: 12"), "got:\n{human}");
        assert!(
            human.contains(&flagged.to_rfc3339()),
            "expected flagged ts; got:\n{human}"
        );
        // Concise mode must NOT print raw bytes; --detail must.
        assert!(
            !human.contains("bytes)"),
            "concise leaked raw bytes:\n{human}"
        );
        let detail = render_human(&report, true, plain, &svc);
        assert!(detail.contains("67108864 bytes"), "got:\n{detail}");

        // Colored: the flagged timestamp is wrapped in red.
        let styled = crate::cli::style::Styler::new(true);
        let colored = render_human(&report, false, styled, &svc);
        assert!(
            colored.contains(&format!("\x1b[31m{}\x1b[0m", flagged.to_rfc3339())),
            "flagged ts not red; got:\n{colored}"
        );
    }

    #[test]
    fn memory_monitor_present_no_flag_shows_no_growth() {
        let td = tempfile::tempdir().unwrap();
        let rs =
            live_runtime(td.path()).with_memory_monitor(spt_state::runtime::MemoryMonitorStatus {
                enabled: true,
                interval_secs: Some(30),
                last_rss_bytes: Some(10 * 1024 * 1024),
                samples: 3,
                last_flagged: None,
            });
        spt_state::write_runtime(td.path(), &rs).unwrap();
        let g = global(td.path().to_path_buf());
        let report = build_report(&g).unwrap();
        let plain = crate::cli::style::Styler::new(false);
        let svc = ServiceLine {
            label: "running".into(),
        };
        let human = render_human(&report, false, plain, &svc);
        assert!(human.contains("no growth flagged"), "got:\n{human}");
    }

    #[test]
    fn memory_monitor_absent_emits_no_block() {
        // The base `live_runtime` carries no memory monitor; the Subsystems
        // section must therefore contain no "Memory monitor" line so existing
        // no-monitor snapshots stay byte-identical.
        let td = tempfile::tempdir().unwrap();
        let rs = live_runtime(td.path());
        assert!(rs.subsystems.memory_monitor.is_none());
        spt_state::write_runtime(td.path(), &rs).unwrap();
        let g = global(td.path().to_path_buf());
        let report = build_report(&g).unwrap();
        let plain = crate::cli::style::Styler::new(false);
        let svc = ServiceLine {
            label: "running".into(),
        };
        let human = render_human(&report, true, plain, &svc);
        assert!(
            !human.contains("Memory monitor"),
            "absent monitor must not render a block; got:\n{human}"
        );
    }

    #[test]
    fn dead_pid_reports_not_running() {
        let td = tempfile::tempdir().unwrap();
        // pid 0 is never alive (pid_is_alive special-cases it false).
        let rs = spt_state::RuntimeStatus::default().with_identity(
            0,
            "1.0.0",
            chrono::Utc::now(),
            "/c.toml",
            td.path().display().to_string(),
        );
        spt_state::write_runtime(td.path(), &rs).unwrap();
        let g = global(td.path().to_path_buf());
        let report = build_report(&g).unwrap();
        assert_eq!(report.liveness, Liveness::Dead);
        assert!(!report.liveness.is_live());
    }
}
