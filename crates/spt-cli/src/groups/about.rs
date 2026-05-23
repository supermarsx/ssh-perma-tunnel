//! `spt about` — bundled-library attribution and inventory.
//!
//! Operator use cases:
//!
//! * License-compliance audits (`spt about licenses`,
//!   `spt about list --license=GPL`).
//! * Security review / SBOM-adjacent inventory (`spt about list --format=json`).
//! * Generating distribution-friendly attribution text
//!   (`spt about export attribution.md`).
//!
//! The implementation lives in `spt-bin::cli::about_ops`; this module only
//! declares the clap-derived parser surface.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

/// `spt about` group.
#[derive(Args, Debug)]
pub struct AboutCmd {
    /// Subcommand. If omitted, `spt about` prints a quick overview.
    #[command(subcommand)]
    pub command: Option<AboutSub>,
}

/// Subcommands of `spt about`.
#[derive(Subcommand, Debug)]
pub enum AboutSub {
    /// List every bundled library, one line per entry.
    List(ListArgs),
    /// Show detailed information for a single library.
    Show(ShowArgs),
    /// Group bundled libraries by SPDX license, with counts.
    Licenses,
    /// Write attribution data to a file (format inferred from extension).
    Export(ExportArgs),
}

/// Output format for `spt about list` / `spt about export`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum AboutOutputFormat {
    /// Human-readable text (default).
    Text,
    /// Structured JSON array.
    Json,
    /// Distribution-friendly Markdown attribution block.
    Markdown,
}

impl Default for AboutOutputFormat {
    fn default() -> Self {
        Self::Text
    }
}

/// `spt about list` arguments.
#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = AboutOutputFormat::Text)]
    pub format: AboutOutputFormat,
    /// Filter by SPDX license substring (case-insensitive).
    #[arg(long)]
    pub license: Option<String>,
    /// Include dev / test dependencies (default: runtime-only).
    #[arg(long)]
    pub include_dev: bool,
}

/// `spt about show <crate>` arguments.
#[derive(Args, Debug, Clone)]
pub struct ShowArgs {
    /// Crate name to show.
    pub name: String,
}

/// `spt about export <path>` arguments.
#[derive(Args, Debug, Clone)]
pub struct ExportArgs {
    /// Destination file. Extension (`.md`, `.json`, anything else → text)
    /// selects the output format.
    pub path: PathBuf,
}
