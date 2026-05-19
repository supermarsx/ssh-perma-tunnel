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
    StatusServeArgs, StatusStatusArgs, StatusTokenRotateArgs,
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
/// [`StatusApiServer::start`], and blocks until Ctrl-C / SIGTERM.
pub async fn serve(global: &GlobalOpts, args: StatusServeArgs) -> Result<()> {
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

    let source: Arc<dyn StateSnapshotSource> =
        Arc::new(FileSnapshotSource::new(state_dir.clone()));
    // `launch` closes the deferred TLS/mTLS gate (see
    // `.orchestration/logs/f-status-tls.md`). For plain HTTP it delegates to
    // `StatusApiServer::start`, preserving the byte-identical wire behavior
    // of the t4-Bwire shipped path.
    let handle =
        crate::status_api_tls::launch(&cfg.status_api, source, &resolver).await?;
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
pub async fn status(global: &GlobalOpts, args: StatusStatusArgs) -> Result<()> {
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
pub async fn token_rotate(global: &GlobalOpts, args: StatusTokenRotateArgs) -> Result<()> {
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

    // Generate a fresh token.
    let mut raw = vec![0u8; args.bytes];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&raw);

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
                v["token"] = json!(token);
            }
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        OutputFormat::Yaml => {
            println!("rotated: true");
            println!("ref: {token_ref}");
            if args.print_token {
                println!("token: {token}");
            }
        }
        OutputFormat::Human => {
            if !global.quiet {
                println!("rotated bearer token at {token_ref}");
                if args.print_token {
                    println!("token: {token}");
                }
            }
        }
    }
    Ok(())
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
