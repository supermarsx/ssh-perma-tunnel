#![allow(clippy::doc_markdown, clippy::map_unwrap_or)]
//! `spt-mangen` — auxiliary binary that regenerates the committed man pages
//! under `/packaging/man/` from the live `clap::Command` tree exposed by
//! [`spt_cli::Cli`].
//!
//! Usage:
//! ```text
//! cargo run --bin spt-mangen -- [--out <dir>]
//! ```
//!
//! Output:
//! - `spt.1`                  — root command
//! - `spt-<group>.1`          — one per top-level subcommand group (20 total)
//!
//! Leaf-subcommand pages are intentionally folded into their parent group page
//! via clap_mangen's recursive section emission, keeping the published man-page
//! count manageable while still documenting every option.
//!
//! CI invokes this binary and asserts `git diff --exit-code packaging/man/`
//! returns clean — guaranteeing the committed pages stay in lock-step with the
//! CLI tree.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use clap::CommandFactory;
use clap_mangen::Man;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let out_dir = parse_out_dir(&args).unwrap_or_else(default_out_dir);
    fs::create_dir_all(&out_dir)?;

    let cmd = spt_cli::Cli::command();
    render_recursive(&cmd, &out_dir, None)?;

    eprintln!("spt-mangen: wrote man pages to {}", out_dir.display());
    Ok(())
}

/// Walk the command tree and emit one `.1` per top-level command group plus the
/// root page. Leaf subcommands are documented as `SUBCOMMANDS` sections inside
/// their parent group page (clap_mangen's default behaviour).
fn render_recursive(
    cmd: &clap::Command,
    out_dir: &Path,
    parent: Option<&str>,
) -> std::io::Result<()> {
    let name = match parent {
        None => cmd.get_name().to_string(),
        Some(p) => format!("{p}-{}", cmd.get_name()),
    };

    let man = Man::new(cmd.clone())
        .title(name.to_uppercase())
        .section("1");
    let mut buf: Vec<u8> = Vec::new();
    man.render(&mut buf)?;
    let path = out_dir.join(format!("{name}.1"));
    fs::write(&path, &buf)?;

    // Only descend one level (root → top-level groups). Going deeper would
    // produce ~150 files; clap_mangen renders nested subcommands inside the
    // group page already.
    if parent.is_none() {
        for sub in cmd.get_subcommands() {
            // Skip the auto-generated `help` subcommand.
            if sub.get_name() == "help" {
                continue;
            }
            render_recursive(sub, out_dir, Some(cmd.get_name()))?;
        }
    }
    Ok(())
}

fn parse_out_dir(args: &[OsString]) -> Option<PathBuf> {
    let mut iter = args.iter().skip(1);
    while let Some(a) = iter.next() {
        let s = a.to_string_lossy();
        if s == "--out" || s == "-o" {
            return iter.next().map(PathBuf::from);
        }
        if let Some(rest) = s.strip_prefix("--out=") {
            return Some(PathBuf::from(rest));
        }
    }
    None
}

fn default_out_dir() -> PathBuf {
    // Resolve relative to the workspace root so `cargo run --bin spt-mangen`
    // from anywhere lands in the right place. CARGO_MANIFEST_DIR points at
    // crates/spt-bin/.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("packaging").join("man"))
        .unwrap_or_else(|| PathBuf::from("packaging/man"))
}
