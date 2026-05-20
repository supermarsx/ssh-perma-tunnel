#![allow(clippy::doc_markdown)]
//! `spt-completions` — auxiliary binary that regenerates committed shell
//! completions under `/packaging/completions/` from the live `clap::Command`
//! tree exposed by [`spt_cli::Cli`].
//!
//! Usage:
//! ```text
//! cargo run --bin spt-completions -- [--out <dir>]
//! ```

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use clap::CommandFactory;
use clap_complete::{generate, Shell};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let out_dir = parse_out_dir(&args).unwrap_or_else(default_out_dir);
    write_all(&out_dir)?;
    eprintln!(
        "spt-completions: wrote shell completions to {}",
        out_dir.display()
    );
    Ok(())
}

fn write_all(out_dir: &Path) -> std::io::Result<()> {
    let artifacts = [
        (Shell::Bash, "bash/spt"),
        (Shell::Zsh, "zsh/_spt"),
        (Shell::Fish, "fish/spt.fish"),
        (Shell::PowerShell, "powershell/spt.ps1"),
        (Shell::Elvish, "elvish/spt.elv"),
    ];

    for (shell, relative_path) in artifacts {
        write_completion(out_dir, shell, relative_path)?;
    }

    let ps1 = out_dir.join("powershell").join("spt.ps1");
    let psm1 = out_dir.join("powershell").join("spt.psm1");
    fs::copy(ps1, psm1)?;

    Ok(())
}

fn write_completion(out_dir: &Path, shell: Shell, relative_path: &str) -> std::io::Result<()> {
    let path = out_dir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut cmd = spt_cli::Cli::command();
    let bin_name = cmd.get_name().to_string();
    let mut buf = Vec::new();
    generate(shell, &mut cmd, bin_name, &mut buf);
    fs::write(path, buf)
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
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().and_then(Path::parent).map_or_else(
        || PathBuf::from("packaging/completions"),
        |root| root.join("packaging").join("completions"),
    )
}
