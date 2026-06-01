//! Build script for `spt-bin`.
//!
//! Generates `$OUT_DIR/about_data.rs` containing a `'static` slice of
//! [`AboutEntry`] records for every crate (workspace, registry, git, vendor)
//! that ends up linked into the `spt` binary.
//!
//! The generator runs `cargo metadata` against the workspace at build time so
//! the resulting binary has zero runtime dependency on `cargo` or the
//! `cargo_metadata` crate. Whenever `Cargo.lock` or this script changes the
//! file is regenerated.
//!
//! Notes:
//! * We do NOT pass `CargoOpt::AllFeatures` — that would activate features the
//!   real build does not, producing a graph that does not match what is
//!   actually linked. We let cargo resolve features as configured.
//! * Dep kinds (normal / dev / build) are recorded per entry so the runtime
//!   `spt about list --include-dev` flag can filter without rebuilding.
//! * String fields are emitted via `{:?}` (Rust's Debug formatter) so quotes,
//!   backslashes, and unicode escape correctly without hand-rolled escaping.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use cargo_metadata::{DependencyKind, MetadataCommand};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    println!("cargo:rerun-if-changed=../../Cargo.toml");

    embed_windows_resources();

    // Intentionally do NOT pass `.features(CargoOpt::AllFeatures)` — that
    // would activate features the real build does not, producing a graph
    // that does not match what is actually linked. The default behaviour
    // resolves features as cargo would for the current invocation.
    let metadata = MetadataCommand::new()
        .exec()
        .expect("`cargo metadata` failed in build.rs");

    let workspace_root = metadata.workspace_root.as_std_path().to_path_buf();
    let vendor_root = workspace_root.join("vendor");
    let workspace_members: BTreeSet<_> = metadata.workspace_members.iter().cloned().collect();

    // Walk the resolve graph from each workspace member, classifying each
    // reachable package by the strongest dep-kind path that reaches it
    // (Normal > Build > Development). The binary surfaces every reachable
    // crate; the runtime `--include-dev` flag toggles dev-only crates.
    let resolve = metadata.resolve.as_ref().expect("resolve graph missing");
    let node_by_id: BTreeMap<_, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();

    // strongest dep kind reaching pkg_id: 0=Normal, 1=Build, 2=Dev, 3=unreached
    let mut kind_of: BTreeMap<cargo_metadata::PackageId, u8> = BTreeMap::new();
    for ws in &workspace_members {
        // Workspace members themselves are treated as Normal — they ARE the binary.
        kind_of.insert(ws.clone(), 0);
    }

    // BFS from each workspace member, propagating the weakest kind along
    // each edge but keeping the strongest across all paths reaching a node.
    let mut frontier: Vec<(cargo_metadata::PackageId, u8)> = workspace_members
        .iter()
        .map(|id| (id.clone(), 0u8))
        .collect();
    while let Some((id, depth_kind)) = frontier.pop() {
        let Some(node) = node_by_id.get(&id) else {
            continue;
        };
        for dep in &node.deps {
            // Pick the strongest (= numerically smallest) kind on this edge.
            let edge_kind = dep
                .dep_kinds
                .iter()
                .map(|dk| match dk.kind {
                    DependencyKind::Normal => 0u8,
                    DependencyKind::Build => 1,
                    DependencyKind::Development | DependencyKind::Unknown => 2,
                })
                .min()
                .unwrap_or(0);
            // The kind reaching `dep.pkg` via this path is the weaker of the
            // path-to-parent kind and the edge kind (numerically larger).
            let path_kind = depth_kind.max(edge_kind);
            let entry = kind_of.entry(dep.pkg.clone()).or_insert(u8::MAX);
            if path_kind < *entry {
                *entry = path_kind;
                frontier.push((dep.pkg.clone(), path_kind));
            }
        }
    }

    let mut entries: Vec<EntryGen> = Vec::new();
    for pkg in &metadata.packages {
        let Some(kind) = kind_of.get(&pkg.id) else {
            // Unreachable from the workspace (shouldn't happen for resolved deps).
            continue;
        };
        let source_kind = classify_source(pkg, &workspace_root, &vendor_root);
        entries.push(EntryGen {
            name: pkg.name.clone(),
            version: pkg.version.to_string(),
            license: pkg.license.clone(),
            repository: pkg.repository.clone(),
            homepage: pkg.homepage.clone(),
            authors: pkg.authors.clone(),
            description: pkg.description.clone(),
            source: source_kind,
            dep_kind: *kind,
            is_workspace: workspace_members.contains(&pkg.id),
        });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));

    let out_dir: PathBuf = std::env::var_os("OUT_DIR").expect("OUT_DIR not set").into();
    let dest = out_dir.join("about_data.rs");
    let mut buf = String::new();
    buf.push_str("// AUTO-GENERATED by build.rs — do not edit.\n");
    buf.push_str("pub(crate) static ABOUT_ENTRIES: &[AboutEntry] = &[\n");
    for e in &entries {
        write_entry(&mut buf, e);
    }
    buf.push_str("];\n");
    std::fs::write(&dest, buf).expect("write about_data.rs");
}

#[derive(Debug)]
enum SourceKind {
    CratesIo,
    Local(String),
    Vendor(String),
    Git { url: String, rev: String },
    Other(String),
}

struct EntryGen {
    name: String,
    version: String,
    license: Option<String>,
    repository: Option<String>,
    homepage: Option<String>,
    authors: Vec<String>,
    description: Option<String>,
    source: SourceKind,
    /// 0 = Normal (runtime), 1 = Build, 2 = Dev.
    dep_kind: u8,
    is_workspace: bool,
}

fn classify_source(
    pkg: &cargo_metadata::Package,
    workspace_root: &Path,
    vendor_root: &Path,
) -> SourceKind {
    let manifest = pkg.manifest_path.as_std_path();
    if manifest.starts_with(vendor_root) {
        // Show the vendor subdir, relative to the workspace root.
        let rel = manifest
            .parent()
            .and_then(|p| p.strip_prefix(workspace_root).ok())
            .map_or_else(
                || manifest.display().to_string(),
                |p| p.display().to_string(),
            )
            .replace('\\', "/");
        return SourceKind::Vendor(rel);
    }
    if let Some(src) = pkg.source.as_ref() {
        let repr = src.repr.as_str();
        if src.is_crates_io() {
            return SourceKind::CratesIo;
        }
        if let Some(rest) = repr.strip_prefix("git+") {
            // form: git+<url>?<query>#<rev>
            let (url, rev) = rest.split_once('#').map_or((rest, ""), |(u, r)| (u, r));
            let url = url.split_once('?').map_or(url, |(u, _)| u);
            return SourceKind::Git {
                url: url.to_string(),
                rev: rev.to_string(),
            };
        }
        return SourceKind::Other(repr.to_string());
    }
    // No source = path dep. If it's inside the workspace, surface its rel path.
    let rel = manifest
        .parent()
        .and_then(|p| p.strip_prefix(workspace_root).ok())
        .map_or_else(
            || manifest.display().to_string(),
            |p| p.display().to_string(),
        )
        .replace('\\', "/");
    SourceKind::Local(rel)
}

fn write_entry(buf: &mut String, e: &EntryGen) {
    let _ = writeln!(buf, "    AboutEntry {{");
    let _ = writeln!(buf, "        name: {:?},", e.name);
    let _ = writeln!(buf, "        version: {:?},", e.version);
    let _ = writeln!(buf, "        license: {},", opt_str(e.license.as_ref()));
    let _ = writeln!(
        buf,
        "        repository: {},",
        opt_str(e.repository.as_ref())
    );
    let _ = writeln!(buf, "        homepage: {},", opt_str(e.homepage.as_ref()));
    let _ = writeln!(buf, "        authors: &{:?},", e.authors);
    let _ = writeln!(
        buf,
        "        description: {},",
        opt_str(e.description.as_ref())
    );
    let _ = writeln!(buf, "        source: {},", source_expr(&e.source));
    let _ = writeln!(
        buf,
        "        dep_kind: DepKind::{},",
        dep_kind_variant(e.dep_kind)
    );
    let _ = writeln!(buf, "        is_workspace: {},", e.is_workspace);
    let _ = writeln!(buf, "    }},");
}

fn opt_str(o: Option<&String>) -> String {
    match o {
        None => "None".to_string(),
        Some(s) => format!("Some({s:?})"),
    }
}

fn source_expr(s: &SourceKind) -> String {
    match s {
        SourceKind::CratesIo => "Source::CratesIo".to_string(),
        SourceKind::Local(p) => format!("Source::Local({p:?})"),
        SourceKind::Vendor(p) => format!("Source::Vendor({p:?})"),
        SourceKind::Git { url, rev } => format!("Source::Git {{ url: {url:?}, rev: {rev:?} }}"),
        SourceKind::Other(s) => format!("Source::Other({s:?})"),
    }
}

fn dep_kind_variant(k: u8) -> &'static str {
    match k {
        0 => "Normal",
        1 => "Build",
        _ => "Development",
    }
}

/// Embed the Windows PE resource (icon + VERSIONINFO) into the binary.
///
/// Gated on `CARGO_CFG_TARGET_OS == "windows"` so building on / cross-
/// compiling for non-Windows targets is a complete no-op (no extra build
/// dep activation, no .rc parse).
///
/// The resource is synthesised at build time into `$OUT_DIR/spt.rc` so the
/// VERSIONINFO block always tracks `CARGO_PKG_VERSION` (i.e. the current
/// rolling `0.YY.N`) without manual edits. The checked-in
/// `packaging/msi/spt.rc` is the read-only reference / fallback used by
/// `cargo wix` for the MSI itself; it documents the canonical field set
/// even though build.rs regenerates the live copy from it.
fn embed_windows_resources() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    // Rerun if the icon changes or the version bumps. (CARGO_PKG_VERSION
    // is propagated by cargo on every Cargo.toml edit, so the workspace
    // bump alone forces a rebuild of the resource.)
    println!("cargo:rerun-if-changed=../../assets/icon.ico");
    println!("cargo:rerun-if-changed=../../packaging/msi/spt.rc");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    // Compute the four-u16 FILEVERSION tuple from CARGO_PKG_VERSION
    // (`0.YY.N` → `(0, YY, N, 0)`). Unparseable components fall back to 0.
    let semver = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let parts: Vec<u16> = semver
        .split('.')
        .take(3)
        .map(|s| s.parse::<u16>().unwrap_or(0))
        .collect();
    let (vmajor, vminor, vpatch) = match parts.as_slice() {
        [a, b, c] => (*a, *b, *c),
        [a, b] => (*a, *b, 0),
        [a] => (*a, 0, 0),
        _ => (0, 0, 0),
    };

    // Read the icon path relative to the generated .rc location. The .rc
    // lives in OUT_DIR; reference the icon by absolute path so the
    // relative-traversal pitfalls are gone.
    let workspace_root: PathBuf = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .and_then(|p| p.parent().and_then(|p| p.parent()).map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("..").join(".."));
    let icon_path = workspace_root.join("assets").join("icon.ico");
    // .rc string literals are double-quoted; backslashes inside are
    // doubled. Build an escaped form of the icon path.
    let icon_path_rc = icon_path.display().to_string().replace('\\', "\\\\");

    let rc_body = format!(
        r#"// AUTO-GENERATED by spt-bin/build.rs — do not edit.
// Synthesised from CARGO_PKG_VERSION + assets/icon.ico on every rebuild.
// Hand-edits belong in packaging/msi/spt.rc (the documented canonical copy).

#include <winver.h>

#define IDI_ICON_APP 1

IDI_ICON_APP ICON "{icon_path_rc}"

1 VERSIONINFO
FILEVERSION     {vmajor},{vminor},{vpatch},0
PRODUCTVERSION  {vmajor},{vminor},{vpatch},0
FILEFLAGSMASK   0x3fL
FILEFLAGS       0x0L
FILEOS          VOS_NT_WINDOWS32
FILETYPE        VFT_APP
FILESUBTYPE     0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      "supermarsx"
            VALUE "FileDescription",  "Permanent SSH2/SSH3 tunnels with reconnect, observability, and service integration"
            VALUE "FileVersion",      "{semver}"
            VALUE "InternalName",     "spt"
            VALUE "LegalCopyright",   "Copyright (c) 2026 Mariana"
            VALUE "OriginalFilename", "spt.exe"
            VALUE "ProductName",      "spt"
            VALUE "ProductVersion",   "{semver}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 0x04B0
    END
END
"#,
    );

    let out_dir: PathBuf = std::env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR not set");
    let rc_out = out_dir.join("spt.rc");
    std::fs::write(&rc_out, rc_body).expect("write generated spt.rc");

    let result = embed_resource::compile(&rc_out, embed_resource::NONE);
    match result {
        embed_resource::CompilationResult::Ok => {}
        embed_resource::CompilationResult::NotWindows => {
            println!(
                "cargo:warning=spt-bin: target is Windows but embed-resource \
                 declined (no Windows linker context); .exe will not carry \
                 the icon resource"
            );
        }
        embed_resource::CompilationResult::NotAttempted(reason) => {
            println!("cargo:warning=spt-bin: embed-resource skipped: {reason}");
        }
        embed_resource::CompilationResult::Failed(err) => {
            panic!("spt-bin: failed to compile generated spt.rc: {err}");
        }
    }
}
