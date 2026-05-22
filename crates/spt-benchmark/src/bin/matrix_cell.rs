//! `matrix_cell` — driver binary for one cell of the 3×3×2×3 comparative
//! benchmark matrix.
//!
//! Invoked by `scripts/perf/run_matrix.sh` once per cell. Each call:
//!
//! 1. Parses `--tool`, `--latency`, `--loss`, `--load` from argv.
//! 2. Stands up a [`ChaosProxy`] in front of a configured upstream SSH
//!    server (defaulting to `127.0.0.1:22`; overridable via `--upstream`).
//! 3. Configures the proxy with the cell's latency/loss behaviour.
//! 4. Builds the matching [`Comparator`] and hands it to [`drive_one_cell`].
//! 5. Writes the [`CellOutcome`] JSON to `--out`.
//!
//! ## Chaos-behaviour composition
//!
//! `spt-chaos-proxy` exposes one behaviour at a time. For cells where both
//! latency and loss are nonzero we prefer `LossPct` (the harsher signal)
//! and record `latency_ms` faithfully in the JSON so downstream renderers
//! can flag the limitation. This matches the C3 brief's hand-off note —
//! the resolution lives in `.orchestration/logs/t8-C3.md`.
//!
//! ## Tool selection
//!
//! `--tool` accepts `spt`, `openssh`, `autossh`. The `spt` comparator is
//! intentionally not implemented here yet; until C5 wires the in-tree
//! `spt` client into the harness, the binary records a skipped cell with
//! `skip_reason = "spt comparator not yet implemented (C5)"`.

#![allow(clippy::too_many_lines)]

use std::path::PathBuf;

use clap::Parser;
use spt_benchmark::comparators::{
    drive_one_cell, AutosshClient, CellOutcome, CellPlan, Comparator, ComparatorContext,
    OpenSshClient,
};
use spt_chaos_proxy::{ChaosBehaviour, ChaosProxy};

/// `matrix_cell` command-line interface.
#[derive(Parser, Debug)]
#[command(
    name = "matrix_cell",
    about = "Drive one cell of the comparative benchmark matrix"
)]
struct Args {
    /// Comparator to drive (`spt`, `openssh`, `autossh`).
    #[arg(long)]
    tool: String,
    /// Injected latency in milliseconds.
    #[arg(long)]
    latency: u64,
    /// Injected loss in percent (0..=100).
    #[arg(long)]
    loss: u8,
    /// Workload — `idle` or `saturated`.
    #[arg(long)]
    load: String,
    /// SSH upstream the chaos proxy forwards to.
    #[arg(long, default_value = "127.0.0.1:22")]
    upstream: String,
    /// Remote `host:port` the forward maps to. Defaults to a no-op
    /// loopback HTTP-ish target.
    #[arg(long, default_value = "127.0.0.1:80")]
    forward_remote: String,
    /// Where to write the cell-outcome JSON.
    #[arg(long)]
    out: PathBuf,
    /// SSH user.
    #[arg(long, default_value = "spt")]
    user: String,
    /// Override binary path for the chosen tool (test seam).
    #[arg(long)]
    binary: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Decide chaos behaviour. Latency-or-loss-or-both → see module docs.
    let behaviour = match (args.latency, args.loss) {
        (0, 0) => ChaosBehaviour::Pristine,
        (_, 0) => ChaosBehaviour::LatencyMs(args.latency),
        (_, l) => ChaosBehaviour::LossPct(l),
    };

    let upstream = args.upstream.parse()?;
    let forward_remote = args.forward_remote.parse()?;
    let log_dir = std::env::temp_dir().join(format!(
        "spt-matrix-{}-{}-{}-{}",
        args.tool, args.latency, args.loss, args.load
    ));
    std::fs::create_dir_all(&log_dir)?;

    let proxy = ChaosProxy::bind("127.0.0.1:0".parse().unwrap(), upstream, behaviour).await?;
    let proxy_addr = proxy.local_addr();
    tokio::spawn(proxy.run());

    let mut ctx = ComparatorContext::for_upstream(proxy_addr, forward_remote, log_dir);
    ctx.ssh_user = args.user;
    ctx.binary_override = args.binary;

    let plan = CellPlan::from_axes(&args.tool, args.latency, args.loss, &args.load);

    let outcome: CellOutcome = match args.tool.as_str() {
        "openssh" => {
            let c: Box<dyn Comparator> = Box::new(OpenSshClient::new());
            drive_one_cell(c, &ctx, &plan).await
        }
        "autossh" => {
            let c: Box<dyn Comparator> = Box::new(AutosshClient::new());
            drive_one_cell(c, &ctx, &plan).await
        }
        "spt" => {
            // Reserved — wired in by C5 once the perf CI step is ready.
            let mut o = CellOutcome::new(&args.tool, args.latency, args.loss, &args.load);
            o.skipped = true;
            o.skip_reason = Some("spt comparator not yet implemented (C5)".into());
            o
        }
        other => {
            let mut o = CellOutcome::new(other, args.latency, args.loss, &args.load);
            o.skipped = true;
            o.skip_reason = Some(format!("unknown tool: {other}"));
            o
        }
    };

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&args.out, serde_json::to_vec_pretty(&outcome.to_json())?)?;
    println!("wrote {}", args.out.display());
    Ok(())
}
