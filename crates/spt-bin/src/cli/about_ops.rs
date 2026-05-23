//! `spt about` — bundled-library attribution and inventory.
//!
//! Data source: `build.rs` runs `cargo metadata` at compile time and emits a
//! `'static` slice of [`AboutEntry`] records to `$OUT_DIR/about_data.rs`,
//! which this module embeds via [`include!`]. The runtime has zero
//! dependency on the `cargo` binary or the `cargo_metadata` crate.
//!
//! Subcommands implemented here:
//!
//! * [`overview`]  — top-level `spt about` (version + dep summary).
//! * [`list`]      — every dependency, optionally filtered/formatted.
//! * [`show`]      — detailed view for one crate.
//! * [`licenses`]  — distribution histogram grouped by SPDX expression.
//! * [`export`]    — write attribution.{md,json,txt}.
//!
//! See the operator-facing docs in `docs/cli-reference.md`.

#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::PathBuf;

use spt_cli::groups::about::{AboutOutputFormat, ExportArgs, ListArgs, ShowArgs};
use spt_core::{Error, Result};

// ---------------------------------------------------------------------------
// Static data types — must match the shape emitted by build.rs.
// ---------------------------------------------------------------------------

/// One row of attribution data baked into the binary at build time.
#[derive(Debug, Clone, Copy)]
pub struct AboutEntry {
    /// Crate name (registry name).
    pub name: &'static str,
    /// SemVer string.
    pub version: &'static str,
    /// SPDX license expression as published in the crate's `Cargo.toml`.
    pub license: Option<&'static str>,
    /// Upstream `repository` field.
    pub repository: Option<&'static str>,
    /// Upstream `homepage` field.
    pub homepage: Option<&'static str>,
    /// Authors list.
    pub authors: &'static [&'static str],
    /// Short description from the crate's `Cargo.toml`.
    pub description: Option<&'static str>,
    /// Where the source came from (registry, local path, vendor, git).
    pub source: Source,
    /// Dependency kind by which the crate enters the build graph.
    pub dep_kind: DepKind,
    /// `true` if this entry corresponds to an `spt-*` workspace crate.
    pub is_workspace: bool,
}

/// Source of a bundled library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `https://crates.io/`.
    CratesIo,
    /// Path dep inside the workspace.
    Local(&'static str),
    /// Path dep under `vendor/` (locally patched).
    Vendor(&'static str),
    /// Git dep.
    Git {
        /// Git URL.
        url: &'static str,
        /// Resolved revision.
        rev: &'static str,
    },
    /// Anything else (alternate registry, etc.).
    Other(&'static str),
}

/// Cargo dep-kind classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepKind {
    /// Runtime dependency (the default).
    Normal,
    /// Build dependency (consumed by `build.rs` only).
    Build,
    /// Dev / test dependency.
    Development,
}

include!(concat!(env!("OUT_DIR"), "/about_data.rs"));

// ---------------------------------------------------------------------------
// Public entry points.
// ---------------------------------------------------------------------------

/// `spt about` — overview.
pub fn overview() -> Result<()> {
    let mut stdout = io::stdout().lock();
    let pkg = env!("CARGO_PKG_NAME");
    let ver = env!("CARGO_PKG_VERSION");
    let desc = env!("CARGO_PKG_DESCRIPTION");
    writeln!(stdout, "{pkg} {ver}").map_err(io_err)?;
    writeln!(stdout, "{desc}").map_err(io_err)?;
    writeln!(stdout).map_err(io_err)?;

    let bundled: Vec<_> = ABOUT_ENTRIES
        .iter()
        .filter(|e| !e.is_workspace && e.dep_kind == DepKind::Normal)
        .collect();
    writeln!(stdout, "Bundled libraries ({}):", bundled.len()).map_err(io_err)?;
    for e in bundled.iter().take(20) {
        writeln!(
            stdout,
            "  {:24} {:10} {}",
            e.name,
            e.version,
            e.license.unwrap_or("(unspecified)")
        )
        .map_err(io_err)?;
    }
    if bundled.len() > 20 {
        writeln!(
            stdout,
            "  … and {} more — run `spt about list` for the full list.",
            bundled.len() - 20
        )
        .map_err(io_err)?;
    }
    writeln!(stdout).map_err(io_err)?;
    writeln!(
        stdout,
        "Run `spt about list --format=markdown > attribution.md` for distribution-friendly attribution."
    )
    .map_err(io_err)?;
    writeln!(
        stdout,
        "Run `spt about show <crate>` for details on a specific library."
    )
    .map_err(io_err)?;
    Ok(())
}

/// `spt about list`.
pub fn list(args: ListArgs) -> Result<()> {
    let filtered = filter_entries(&args);
    let mut stdout = io::stdout().lock();
    match args.format {
        AboutOutputFormat::Text => render_text(&mut stdout, &filtered)?,
        AboutOutputFormat::Json => render_json(&mut stdout, &filtered)?,
        AboutOutputFormat::Markdown => render_markdown(&mut stdout, &filtered)?,
    }
    Ok(())
}

/// `spt about show <crate>`.
pub fn show(args: ShowArgs) -> Result<()> {
    let mut matches: Vec<&AboutEntry> = ABOUT_ENTRIES
        .iter()
        .filter(|e| e.name == args.name)
        .collect();
    if matches.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "no bundled library named `{}` (try `spt about list`)",
            args.name
        )));
    }
    matches.sort_by(|a, b| a.version.cmp(b.version));
    let mut stdout = io::stdout().lock();
    for (i, e) in matches.iter().enumerate() {
        if i > 0 {
            writeln!(stdout, "---").map_err(io_err)?;
        }
        write_show(&mut stdout, e)?;
    }
    Ok(())
}

/// `spt about licenses`.
pub fn licenses() -> Result<()> {
    let mut by_license: BTreeMap<&str, usize> = BTreeMap::new();
    let mut unspecified = 0usize;
    for e in ABOUT_ENTRIES
        .iter()
        .filter(|e| e.dep_kind == DepKind::Normal)
    {
        match e.license {
            Some(l) => *by_license.entry(l).or_default() += 1,
            None => unspecified += 1,
        }
    }
    let mut counts: Vec<(&&str, &usize)> = by_license.iter().collect();
    counts.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "License distribution:").map_err(io_err)?;
    for (lic, n) in &counts {
        let label = if **n == 1 { "crate" } else { "crates" };
        writeln!(stdout, "  {:28} {:>4} {}", lic, n, label).map_err(io_err)?;
    }
    if unspecified > 0 {
        let label = if unspecified == 1 { "crate" } else { "crates" };
        writeln!(
            stdout,
            "  {:28} {:>4} {} (COMPLIANCE RISK — review manually)",
            "(unspecified)", unspecified, label
        )
        .map_err(io_err)?;
    }
    Ok(())
}

/// `spt about export <path>`.
pub fn export(args: ExportArgs) -> Result<()> {
    let path: PathBuf = args.path;
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let entries: Vec<&AboutEntry> = ABOUT_ENTRIES.iter().collect();
    let mut buf: Vec<u8> = Vec::new();
    match ext.as_str() {
        "json" => render_json(&mut buf, &entries)?,
        "md" | "markdown" => render_markdown(&mut buf, &entries)?,
        _ => render_text(&mut buf, &entries)?,
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(io_err)?;
        }
    }
    fs::write(&path, &buf).map_err(io_err)?;
    eprintln!(
        "spt about export: wrote {} entries to {}",
        entries.len(),
        path.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Internals.
// ---------------------------------------------------------------------------

fn filter_entries(args: &ListArgs) -> Vec<&'static AboutEntry> {
    ABOUT_ENTRIES
        .iter()
        .filter(|e| match e.dep_kind {
            DepKind::Normal => true,
            DepKind::Build => false,
            DepKind::Development => args.include_dev,
        })
        .filter(|e| match &args.license {
            None => true,
            Some(needle) => e
                .license
                .map(|l| {
                    l.to_ascii_lowercase()
                        .contains(&needle.to_ascii_lowercase())
                })
                .unwrap_or(false),
        })
        .collect()
}

fn render_text<W: io::Write>(w: &mut W, entries: &[&AboutEntry]) -> Result<()> {
    writeln!(w, "Bundled libraries ({}):", entries.len()).map_err(io_err)?;
    for e in entries {
        let suffix = match &e.source {
            Source::Vendor(p) => format!("  [local patches: {p}]"),
            Source::Local(_) => "  [workspace]".to_string(),
            Source::Git { url, .. } => format!("  [git: {url}]"),
            _ => String::new(),
        };
        writeln!(
            w,
            "  {:32} {:12} {}{}",
            e.name,
            e.version,
            e.license.unwrap_or("(unspecified)"),
            suffix
        )
        .map_err(io_err)?;
    }
    Ok(())
}

fn render_json<W: io::Write>(w: &mut W, entries: &[&AboutEntry]) -> Result<()> {
    let values: Vec<serde_json::Value> = entries.iter().map(|e| entry_to_json(e)).collect();
    serde_json::to_writer_pretty(w.by_ref(), &values).map_err(|e| io_err(io::Error::other(e)))?;
    writeln!(w).map_err(io_err)?;
    Ok(())
}

fn entry_to_json(e: &AboutEntry) -> serde_json::Value {
    let source = match &e.source {
        Source::CratesIo => serde_json::json!({ "kind": "crates-io" }),
        Source::Local(p) => serde_json::json!({ "kind": "local", "path": p }),
        Source::Vendor(p) => serde_json::json!({ "kind": "vendor", "path": p }),
        Source::Git { url, rev } => serde_json::json!({ "kind": "git", "url": url, "rev": rev }),
        Source::Other(s) => serde_json::json!({ "kind": "other", "repr": s }),
    };
    let dep_kind = match e.dep_kind {
        DepKind::Normal => "normal",
        DepKind::Build => "build",
        DepKind::Development => "development",
    };
    serde_json::json!({
        "name": e.name,
        "version": e.version,
        "license": e.license,
        "repository": e.repository,
        "homepage": e.homepage,
        "authors": e.authors,
        "description": e.description,
        "source": source,
        "dep_kind": dep_kind,
        "is_workspace": e.is_workspace,
    })
}

fn render_markdown<W: io::Write>(w: &mut W, entries: &[&AboutEntry]) -> Result<()> {
    writeln!(w, "# Bundled libraries").map_err(io_err)?;
    writeln!(w).map_err(io_err)?;
    writeln!(
        w,
        "`spt` is distributed as a single binary. It embeds {} libraries; their licenses and provenance are listed below.",
        entries.len()
    )
    .map_err(io_err)?;
    writeln!(w).map_err(io_err)?;
    for e in entries {
        writeln!(w, "### {} {}", e.name, e.version).map_err(io_err)?;
        writeln!(w).map_err(io_err)?;
        if let Some(d) = e.description {
            writeln!(w, "{d}").map_err(io_err)?;
            writeln!(w).map_err(io_err)?;
        }
        writeln!(w, "* License: `{}`", e.license.unwrap_or("(unspecified)")).map_err(io_err)?;
        if let Some(url) = e.repository {
            writeln!(w, "* Repository: <{url}>").map_err(io_err)?;
        }
        if let Some(url) = e.homepage {
            writeln!(w, "* Homepage: <{url}>").map_err(io_err)?;
        }
        match &e.source {
            Source::Vendor(p) => {
                writeln!(w, "* Source: locally patched fork at `{p}`").map_err(io_err)?;
            }
            Source::Local(p) => {
                writeln!(w, "* Source: workspace crate at `{p}`").map_err(io_err)?;
            }
            Source::Git { url, rev } => {
                writeln!(w, "* Source: git `{url}` @ `{rev}`").map_err(io_err)?;
            }
            Source::CratesIo => writeln!(w, "* Source: crates.io").map_err(io_err)?,
            Source::Other(s) => writeln!(w, "* Source: `{s}`").map_err(io_err)?,
        }
        writeln!(w).map_err(io_err)?;
    }
    Ok(())
}

fn write_show<W: io::Write>(w: &mut W, e: &AboutEntry) -> Result<()> {
    writeln!(w, "name:        {}", e.name).map_err(io_err)?;
    writeln!(w, "version:     {}", e.version).map_err(io_err)?;
    writeln!(w, "license:     {}", e.license.unwrap_or("(unspecified)")).map_err(io_err)?;
    if let Some(d) = e.description {
        writeln!(w, "description: {d}").map_err(io_err)?;
    }
    if !e.authors.is_empty() {
        writeln!(w, "authors:     {}", e.authors.join(", ")).map_err(io_err)?;
    }
    if let Some(r) = e.repository {
        writeln!(w, "repository:  {r}").map_err(io_err)?;
    }
    if let Some(h) = e.homepage {
        writeln!(w, "homepage:    {h}").map_err(io_err)?;
    }
    let src = match &e.source {
        Source::CratesIo => "crates.io".to_string(),
        Source::Local(p) => format!("workspace ({p})"),
        Source::Vendor(p) => format!("vendor ({p}) — locally patched"),
        Source::Git { url, rev } => format!("git {url} @ {rev}"),
        Source::Other(s) => format!("other ({s})"),
    };
    writeln!(w, "source:      {src}").map_err(io_err)?;
    let kind = match e.dep_kind {
        DepKind::Normal => "runtime",
        DepKind::Build => "build-only",
        DepKind::Development => "dev/test",
    };
    writeln!(w, "dep-kind:    {kind}").map_err(io_err)?;
    Ok(())
}

fn io_err(e: io::Error) -> Error {
    Error::InvalidConfig(format!("about: {e}"))
}

// ---------------------------------------------------------------------------
// Unit tests (data-sanity).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn about_data_contains_at_least_100_entries() {
        assert!(
            ABOUT_ENTRIES.len() >= 100,
            "expected >=100 entries baked into about_data.rs, got {}",
            ABOUT_ENTRIES.len()
        );
    }

    #[test]
    fn workspace_includes_spt_bin() {
        assert!(ABOUT_ENTRIES.iter().any(|e| e.name == "spt-bin"));
    }

    #[test]
    fn entries_have_versions() {
        for e in ABOUT_ENTRIES {
            assert!(!e.name.is_empty());
            assert!(!e.version.is_empty(), "{} missing version", e.name);
        }
    }
}
