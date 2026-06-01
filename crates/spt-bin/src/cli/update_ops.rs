//! `spt update` dispatch.
//!
//! **Scaffold.** The schema + driver crate are wired in this commit;
//! every subcommand currently returns a "scaffolded — full poll path
//! lands in a subsequent commit" notice that includes the resolved
//! source/mode so operators can verify their config parses correctly.
//!
//! Subsequent commits in the updater series fill in:
//!
//! * GitHub source backend  (commit 3 of the series)
//! * URL + static source backends (commit 3)
//! * Minisign + SHA256SUMS verification (commit 4)
//! * Atomic swap + restart (commit 5)
//! * Audit history (commit 5)
//!
//! Keeping the dispatch wired today lets the help text + completion
//! artifacts + man pages all reference the final command tree from the
//! moment the schema lands, so each subsequent fix is a pure
//! implementation patch.

use spt_cli::groups::update::{UpdateCmd, UpdateSub};
use spt_cli::GlobalOpts;
use spt_core::{Error, Result};
use spt_updater::{UpdaterConfig, UpdaterStatus};

/// Top-level dispatch.
pub async fn dispatch(global: &GlobalOpts, cmd: UpdateCmd) -> Result<()> {
    let sub = cmd.command.unwrap_or(UpdateSub::Status(Default::default()));
    match sub {
        UpdateSub::Check(_) => run_check(global).await,
        UpdateSub::Download(_) => run_pending("download").await,
        UpdateSub::Apply(_) => run_pending("apply").await,
        UpdateSub::Now(_) => run_pending("now").await,
        UpdateSub::Status(args) => run_status(global, args.json).await,
        UpdateSub::History(_) => run_pending("history").await,
    }
}

async fn run_status(global: &GlobalOpts, json: bool) -> Result<()> {
    let cfg = load_updater_config(global)?;
    let status = UpdaterStatus {
        enabled: cfg.enabled,
        mode: cfg.mode,
        last_check: None,
        latest_version: None,
        current_version: env!("CARGO_PKG_VERSION").to_string(),
        update_available: false,
        staged_artifact: None,
        next_check: None,
        last_error: None,
    };

    if json {
        let s = serde_json::to_string_pretty(&status)
            .map_err(|e| Error::RuntimeFailure(format!("status json: {e}")))?;
        println!("{s}");
    } else {
        println!("spt update — status");
        println!("  enabled:         {}", status.enabled);
        println!("  mode:            {:?}", status.mode);
        println!("  current version: {}", status.current_version);
        println!(
            "  last check:      {}",
            status.last_check.unwrap_or_else(|| "(never)".into())
        );
        println!(
            "  next check:      {}",
            status
                .next_check
                .unwrap_or_else(|| "(scheduler not running)".into())
        );
        match &cfg.source {
            spt_updater::config::SourceKind::GitHub { repo, channel } => {
                println!("  source:          github://{repo} ({channel:?})");
            }
            spt_updater::config::SourceKind::Url { url, .. } => {
                println!("  source:          url {url}");
            }
            spt_updater::config::SourceKind::Static { dir } => {
                println!("  source:          static {}", dir.display());
            }
        }
        if !cfg.enabled {
            println!();
            println!("note: [updater].enabled = false; the background polling thread is NOT");
            println!("      running. Manual `spt update check / download / apply / now` still");
            println!("      work — they do not require the thread.");
        }
    }
    Ok(())
}

async fn run_check(global: &GlobalOpts) -> Result<()> {
    let cfg = load_updater_config(global)?;
    let outcome = spt_updater::poll_once(&cfg)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("update check: {e}")))?;
    if outcome.update_available {
        println!(
            "update available: {} -> {} (current/latest)",
            outcome.current_version, outcome.latest_tag
        );
        println!("  checked at: {}", outcome.checked_at);
        println!();
        println!("Run `spt update download` to stage the artifact, then `spt update apply`.");
        println!("(Download / apply are scaffolded — verification + install land in the");
        println!(" next updater-series commit. The check + version-diff path above is live.)");
    } else {
        println!(
            "current: spt {} is the latest from {:?}",
            outcome.current_version, cfg.source
        );
        println!("  checked at: {}", outcome.checked_at);
    }
    Ok(())
}

async fn run_pending(name: &str) -> Result<()> {
    Err(Error::UnsupportedPlatform(format!(
        "spt update {name}: scaffolded — implementation lands in a follow-up commit. \
         Run `spt update status` to confirm the [updater] block parses."
    )))
}

fn load_updater_config(global: &GlobalOpts) -> Result<UpdaterConfig> {
    let cfg_path = global
        .config
        .clone()
        .ok_or_else(|| Error::InvalidArgs("provide --config or set $SPT_CONFIG".into()))?;
    let (cfg, _w) = spt_config::load(&cfg_path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", cfg_path.display())))?;
    let schema = cfg.updater.unwrap_or_default();
    UpdaterConfig::from_schema(&schema).map_err(|e| Error::InvalidConfig(format!("[updater]: {e}")))
}
