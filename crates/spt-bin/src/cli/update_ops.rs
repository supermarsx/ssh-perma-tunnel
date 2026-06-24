//! `spt update` dispatch.
//!
//! Wires the `spt update` subcommands onto the now-implemented
//! [`spt_updater`] crate API:
//!
//! * `check`    — poll the source, print version diff ([`spt_updater::poll_once`]).
//! * `download` — stage + verify the latest artifact without installing
//!   ([`spt_updater::download_and_verify`]).
//! * `apply`    — full download → verify → atomic install
//!   ([`spt_updater::apply_update`]); honours `[updater.action]`.
//! * `now`      — alias for `apply` (check + download + apply in one go).
//! * `status`   — print the resolved config / last-known state.
//! * `history`  — past install events (audit log; see note in `run_history`).

use spt_cli::groups::update::{UpdateCmd, UpdateSub};
use spt_cli::GlobalOpts;
use spt_core::{Error, Result};
use spt_updater::{UpdaterConfig, UpdaterStatus};

/// Top-level dispatch.
pub async fn dispatch(global: &GlobalOpts, cmd: UpdateCmd) -> Result<()> {
    let sub = cmd.command.unwrap_or(UpdateSub::Status(Default::default()));
    match sub {
        UpdateSub::Check(_) => run_check(global).await,
        UpdateSub::Download(_) => run_download(global).await,
        UpdateSub::Apply(args) => run_apply(global, args.no_restart).await,
        UpdateSub::Now(args) => run_apply(global, args.no_restart).await,
        UpdateSub::Status(args) => run_status(global, args.json).await,
        UpdateSub::History(_) => run_history(global).await,
    }
}

async fn run_status(global: &GlobalOpts, json: bool) -> Result<()> {
    let cfg = load_updater_config(global)?;
    let st = crate::styler(global);
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

    if !crate::cli::tunnel_ops::emit(global, json, &status)? {
        println!("{}", st.bold("spt update — status"));
        println!(
            "  enabled:         {}",
            st.state(if status.enabled {
                "enabled"
            } else {
                "disabled"
            })
        );
        println!("  mode:            {:?}", status.mode);
        println!("  current version: {}", st.cyan(&status.current_version));
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
    let st = crate::styler(global);
    let outcome = spt_updater::poll_once(&cfg)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("update check: {e}")))?;
    if outcome.update_available {
        println!(
            "{} {} -> {} (current/latest)",
            st.yellow("update available:"),
            outcome.current_version,
            st.bold(&outcome.latest_tag)
        );
        println!("  checked at: {}", outcome.checked_at);
        println!();
        println!("Run `spt update download` to stage + verify the artifact, then");
        println!("`spt update apply` to install it (or `spt update now` for both).");
    } else {
        println!(
            "{} spt {} is the latest from {:?}",
            st.green("current:"),
            outcome.current_version,
            cfg.source
        );
        println!("  checked at: {}", outcome.checked_at);
    }
    Ok(())
}

async fn run_download(global: &GlobalOpts) -> Result<()> {
    let cfg = load_updater_config(global)?;
    let st = crate::styler(global);
    let staged = spt_updater::download_and_verify(&cfg)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("update download: {e}")))?;
    println!("{}", st.green("artifact staged + verified"));
    println!("  artifact:  {}", staged.artifact.display());
    match &staged.signature {
        Some(s) => println!("  signature: {}", s.display()),
        None => println!("  signature: {}", st.dim("(none)")),
    }
    println!(
        "  checksum:  {}",
        st.dim(
            if staged.sha256sums.is_some() || staged.expected_sha256.is_some() {
                "verified (or best-effort per [updater.verify])"
            } else {
                "(none published)"
            }
        )
    );
    println!();
    println!("Run `spt update apply` to install the staged artifact.");
    Ok(())
}

async fn run_apply(global: &GlobalOpts, no_restart: bool) -> Result<()> {
    let cfg = load_updater_config(global)?;
    let st = crate::styler(global);
    let report = spt_updater::apply_update(&cfg)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("update apply: {e}")))?;
    println!(
        "{} spt {}",
        st.green("installed:"),
        st.bold(&report.version)
    );
    println!("  from:    {}", report.installed_from.display());

    let want_restart = report.restart_requested && !no_restart;
    if want_restart {
        println!(
            "  restart: {}",
            st.yellow("requested — restart the supervisor for the new binary to take effect")
        );
        println!();
        println!("note: this CLI does not hold a supervisor handle; send the running");
        println!("      daemon a reload (`spt tunnel reload` / SIGHUP) or restart the");
        println!("      service to load spt {}.", report.version);
    } else {
        println!("  restart: {}", st.dim("skipped"));
    }
    Ok(())
}

async fn run_history(global: &GlobalOpts) -> Result<()> {
    // The install audit history is emitted as structured audit events at
    // install time (see [updater.action].notify_audit). There is no
    // standalone updater history store; surface that honestly rather than
    // printing an empty fabricated table.
    let _ = load_updater_config(global)?;
    let st = crate::styler(global);
    println!("{}", st.bold("spt update — history"));
    println!(
        "  {}",
        st.dim("no separate updater history store; install events are recorded")
    );
    println!(
        "  {}",
        st.dim("as audit events when [updater.action].notify_audit = true.")
    );
    println!("  Query them via `spt event` / your audit log pipeline.");
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, GlobalOpts, LogLevel, OutputFormat};

    fn global_with_config(path: &std::path::Path) -> GlobalOpts {
        GlobalOpts {
            config: Some(path.to_path_buf()),
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            profile: None,
            output: OutputFormat::Human,
            json: false,
            log_level: LogLevel::Error,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: true,
            dry_run: false,
            portable: false,
        }
    }

    fn write_static_config(dir: &std::path::Path, dist: &std::path::Path) -> std::path::PathBuf {
        let cfg = format!(
            "version = 1\n\
             [updater]\n\
             enabled = true\n\
             mode = \"check\"\n\
             source = \"static\"\n\
             static_dir = \"{}\"\n\
             [updater.verify]\n\
             require_minisign = false\n\
             require_sha256sums = false\n",
            dist.display().to_string().replace('\\', "\\\\")
        );
        let p = dir.join("spt.toml");
        std::fs::write(&p, cfg).unwrap();
        p
    }

    fn lay_out_dist(dist: &std::path::Path, tag: &str, body: &[u8]) -> String {
        let target = spt_updater::download::TARGET;
        let art_name = format!("spt-{tag}-{target}.tar.gz");
        std::fs::write(dist.join(&art_name), body).unwrap();
        let manifest = serde_json::json!({
            "tag": tag,
            "artifacts": [ { "name": art_name } ],
            "signatures": []
        });
        std::fs::write(
            dist.join("release-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        art_name
    }

    #[test]
    fn load_config_requires_config_path() {
        let mut g = global_with_config(std::path::Path::new("/unused"));
        g.config = None;
        let err = load_updater_config(&g).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn status_smoke_renders() {
        let tmp = tempfile::tempdir().unwrap();
        let dist = tmp.path().join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        let cfg_path = write_static_config(tmp.path(), &dist);
        let g = global_with_config(&cfg_path);
        // Human + JSON paths both succeed.
        run_status(&g, false).await.unwrap();
        run_status(&g, true).await.unwrap();
    }

    #[tokio::test]
    async fn check_smoke_against_static_source() {
        let tmp = tempfile::tempdir().unwrap();
        let dist = tmp.path().join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        lay_out_dist(&dist, "99.0", b"bin");
        let cfg_path = write_static_config(tmp.path(), &dist);
        let g = global_with_config(&cfg_path);
        // 99.0 > current → update available; should print without erroring.
        run_check(&g).await.unwrap();
    }

    #[tokio::test]
    async fn download_smoke_against_static_source() {
        let tmp = tempfile::tempdir().unwrap();
        let dist = tmp.path().join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        lay_out_dist(&dist, "99.0", b"NEWBIN");
        let cfg_path = write_static_config(tmp.path(), &dist);
        let g = global_with_config(&cfg_path);
        run_download(&g).await.unwrap();
    }

    #[tokio::test]
    async fn history_smoke_renders() {
        let tmp = tempfile::tempdir().unwrap();
        let dist = tmp.path().join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        let cfg_path = write_static_config(tmp.path(), &dist);
        let g = global_with_config(&cfg_path);
        run_history(&g).await.unwrap();
    }
}
