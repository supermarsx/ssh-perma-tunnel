//! Loading TOML configs from a file or string.
//!
//! `load_str` is the primary entry point. It deserializes through
//! [`serde_ignored`] so unknown keys are surfaced as warnings. In strict mode
//! those warnings are promoted to a hard parse error.
//!
//! [`load_dir`] supports the `--config-dir` CLI flag (spec §7.1): all
//! `*.toml` files under the directory are loaded in lexical (filename) order
//! and merged into a single [`Config`]. The first file in lex order is the
//! "base"; every other file MAY only contribute additional `[[profiles]]`
//! entries and MUST NOT redefine any of the singleton top-level tables
//! (`runtime`, `logging`, `secrets`, `dns`, `firewall`, `observability`,
//! `events`, `mcp`, `diagnostics`, `benchmark`). Conflicts are rejected.

use std::path::Path;
use std::sync::OnceLock;

use secrecy::ExposeSecret;
use spt_config_crypt::{is_sealed, unseal, KeySource};
use spt_core::{Error, Result};

use crate::diagnostic::{Diagnostic, Diagnostics};
use crate::schema::Config;

/// Process-global portable flag for the config loader. When `true`,
/// secondary discovery paths that depend on user-managed directories
/// (most importantly `~/.ssh/config`, used by the OpenSSH-config bridge
/// landing in t6-e3) are skipped. `spt-bin::main` flips this exactly
/// once after pre-scanning the CLI for `--portable`.
static PORTABLE: OnceLock<bool> = OnceLock::new();

/// Install the portable-mode flag for the config loader. Returns `true`
/// when the value was recorded, `false` when a prior call already locked
/// the slot (no-op behaviour matching `spt_state::portable::install`).
pub fn set_portable_mode(active: bool) -> bool {
    PORTABLE.set(active).is_ok()
}

/// `true` when readers may consult `~/.ssh/config` and similar
/// user-managed discovery sources. Defaults to `true`; flipping to
/// `false` is opt-in via [`set_portable_mode(true)`](set_portable_mode).
///
/// The t6-e3 OpenSSH-config bridge consults this predicate before
/// attempting `BaseDirs::home_dir().join(".ssh/config")` so portable
/// deployments never read from the operator's user account.
#[must_use]
pub fn ssh_config_reads_allowed() -> bool {
    !PORTABLE.get().copied().unwrap_or(false)
}

/// Convenience alias for the unknown-keys warnings list returned by
/// [`load`] / [`load_str`].
pub type Warnings = Vec<String>;

/// Load a config file from disk.
///
/// In strict mode, any unknown TOML key is a hard error. In non-strict mode,
/// unknown keys are returned as warning paths (e.g. `runtime.unknown_field`)
/// in the second tuple element.
///
/// Auto-detects the [`spt_config_crypt`] `SPTENC1` sealed-envelope magic. If
/// the file is sealed, a passphrase is prompted from the controlling TTY
/// via [`spt_secrets::read_passphrase`]. For non-interactive callers, use
/// [`load_with_key`].
pub fn load(path: &Path, strict: bool) -> Result<(Config, Warnings)> {
    load_with_key(path, strict, None)
}

/// Like [`load`], but accepts an explicit [`KeySource`] for sealed configs.
///
/// When `key` is `None` and the on-disk file is sealed, a passphrase is
/// prompted interactively (assuming the envelope's KDF is `argon2id`).
/// Programmatic callers (tests, scripted edit-sessions) must pass an
/// explicit `key` to avoid the prompt.
pub fn load_with_key(
    path: &Path,
    strict: bool,
    key: Option<&KeySource>,
) -> Result<(Config, Warnings)> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
    if is_sealed(&bytes) {
        let cleartext = decrypt_sealed(&bytes, key)?;
        // The plaintext is held only inside the SecretBox; we view it as
        // &str (zero-copy from the inner Zeroizing<Vec<u8>>). The Config
        // value lands on the heap as a normal struct — its secret-shaped
        // fields are protected separately by the schema's RedactedString
        // newtype (t5-e7) when materialised.
        let pt = cleartext.expose_secret();
        let raw = std::str::from_utf8(pt).map_err(|e| {
            Error::InvalidConfig(format!(
                "sealed config `{}` is not UTF-8: {e}",
                path.display()
            ))
        })?;
        return load_str(raw, strict);
    }
    let raw = std::str::from_utf8(&bytes)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
    load_str(raw, strict)
}

fn decrypt_sealed(bytes: &[u8], key: Option<&KeySource>) -> Result<spt_config_crypt::SecretSlice> {
    if let Some(k) = key {
        return unseal(bytes, k);
    }
    // Interactive prompt path — only meaningful for passphrase-KDF
    // envelopes. For vault / x25519 the caller MUST supply an explicit
    // KeySource via load_with_key.
    let meta = spt_config_crypt::peek_meta(bytes)?;
    match meta.kdf.as_str() {
        "argon2id" => {
            let pp = spt_secrets::read_passphrase("sealed config passphrase: ")?;
            let bytes_pp: spt_config_crypt::Passphrase =
                pp.expose_secret().as_bytes().to_vec().into();
            unseal(bytes, &KeySource::Passphrase(bytes_pp))
        }
        other => Err(Error::InvalidConfig(format!(
            "sealed config uses kdf `{other}` — pass an explicit key via load_with_key()"
        ))),
    }
}

/// Parse a TOML config string.
pub fn load_str(raw: &str, strict: bool) -> Result<(Config, Warnings)> {
    let mut warnings: Warnings = Vec::new();

    let de = toml::Deserializer::new(raw);
    let config: Config = serde_ignored::deserialize(de, |path| {
        warnings.push(path.to_string());
    })
    .map_err(|e| Error::InvalidConfig(format!("toml parse: {e}")))?;

    if strict && !warnings.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "unknown keys in strict mode: {}",
            warnings.join(", ")
        )));
    }

    if !warnings.is_empty() {
        for path in &warnings {
            tracing::warn!(target: "spt_config::load", path = %path, "unknown TOML key");
        }
    }

    Ok((config, warnings))
}

/// Load every `*.toml` file in `dir` (in lexical filename order) and merge
/// them into a single [`Config`].
///
/// **Merge semantics**:
///
/// - The first `.toml` file (lex order) is the "base". Its top-level tables
///   (`runtime`, `logging`, `secrets`, `dns`, `firewall`, `observability`,
///   `events`, `mcp`, `diagnostics`, `benchmark`) plus its `version` and
///   any `[[profiles]]` entries form the seed [`Config`].
/// - Every subsequent file may **only** contribute additional `[[profiles]]`
///   entries. If a non-base file sets any of the singleton top-level tables,
///   [`load_dir`] returns [`Error::InvalidConfig`].
/// - `version` must match across all files.
/// - Profile names must remain unique across the merged set (validation runs
///   downstream via [`crate::validate::validate`]; this loader emits a
///   `Error::InvalidConfig` with the conflicting name to fail fast).
///
/// Returns the merged config plus the union of unknown-key warnings from
/// every file (each warning is annotated with the originating filename for
/// human-readable diagnostics). An empty directory or one containing no
/// `*.toml` files is rejected with [`Error::InvalidConfig`].
pub fn load_dir(dir: &Path, strict: bool) -> Result<(Config, Warnings)> {
    if !dir.exists() {
        return Err(Error::InvalidConfig(format!(
            "config dir `{}` does not exist",
            dir.display()
        )));
    }
    if !dir.is_dir() {
        return Err(Error::InvalidConfig(format!(
            "config dir `{}` is not a directory",
            dir.display()
        )));
    }
    let read = std::fs::read_dir(dir)
        .map_err(|e| Error::InvalidConfig(format!("read_dir `{}`: {e}", dir.display())))?;
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for entry in read {
        let entry = entry.map_err(|e| {
            Error::InvalidConfig(format!("read_dir entry under `{}`: {e}", dir.display()))
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            files.push(path);
        }
    }
    if files.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "no `*.toml` files in config dir `{}`",
            dir.display()
        )));
    }
    files.sort();

    let mut warnings: Warnings = Vec::new();
    let mut iter = files.into_iter();
    let first = iter.next().expect("non-empty checked above");
    let first_name = display_name(&first);
    let (mut merged, w) = load(&first, strict)?;
    warnings.extend(w.into_iter().map(|p| format!("{first_name}: {p}")));

    for path in iter {
        let name = display_name(&path);
        let (overlay, w) = load(&path, strict)?;
        warnings.extend(w.into_iter().map(|p| format!("{name}: {p}")));

        if overlay.version != merged.version {
            return Err(Error::InvalidConfig(format!(
                "{name}: version `{}` does not match base `{}`",
                overlay.version, merged.version
            )));
        }
        reject_singleton_overrides(&overlay, &name)?;

        // Append profiles, rejecting duplicate names early so the operator
        // sees the offending file rather than a generic validation diagnostic.
        for p in overlay.profiles {
            if merged
                .profiles
                .iter()
                .any(|existing| existing.name == p.name)
            {
                return Err(Error::InvalidConfig(format!(
                    "{name}: duplicate profile name `{}` (already defined in an earlier file)",
                    p.name
                )));
            }
            merged.profiles.push(p);
        }
    }
    Ok((merged, warnings))
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .map_or_else(|| path.display().to_string(), ToOwned::to_owned)
}

fn reject_singleton_overrides(overlay: &Config, file: &str) -> Result<()> {
    let conflicts: &[(&str, bool)] = &[
        ("runtime", overlay.runtime.is_some()),
        ("logging", overlay.logging.is_some()),
        ("secrets", overlay.secrets.is_some()),
        ("dns", overlay.dns.is_some()),
        ("firewall", overlay.firewall.is_some()),
        ("observability", overlay.observability.is_some()),
        ("events", overlay.events.is_some()),
        ("mcp", overlay.mcp.is_some()),
        ("diagnostics", overlay.diagnostics.is_some()),
        ("benchmark", overlay.benchmark.is_some()),
    ];
    if let Some((name, _)) = conflicts.iter().find(|(_, set)| *set) {
        return Err(Error::InvalidConfig(format!(
            "{file}: only the first file in `--config-dir` may define top-level table \
             `[{name}]`; later files may only contribute `[[profiles]]`"
        )));
    }
    Ok(())
}

/// Build [`Diagnostics`] entries for warnings from [`load_str`].
///
/// Useful when callers want a single diagnostic stream covering both
/// load-time unknowns and validate-time issues.
#[must_use]
pub fn warnings_to_diagnostics(warnings: &[String]) -> Diagnostics {
    let mut out = Diagnostics::new();
    for path in warnings {
        out.push(Diagnostic::warning("unknown_key", format!("unknown TOML key `{path}`")).at(path));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{load_str, warnings_to_diagnostics};

    const MIN: &str = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
    "#;

    #[test]
    fn parses_minimum() {
        let (c, w) = load_str(MIN, false).unwrap();
        assert_eq!(c.version, 1);
        assert!(w.is_empty());
        assert_eq!(c.profiles.len(), 1);
    }

    #[test]
    fn collects_unknowns_in_lenient_mode() {
        let raw = r"
            version = 1
            [runtime]
            mystery_field = 7
        ";
        let (_c, w) = load_str(raw, false).unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("mystery_field"));
    }

    #[test]
    fn rejects_unknowns_in_strict_mode() {
        let raw = r"
            version = 1
            [runtime]
            mystery_field = 7
        ";
        let err = load_str(raw, true).unwrap_err();
        assert!(format!("{err}").contains("mystery_field"));
    }

    #[test]
    fn hop_auth_and_trust_are_known_tables() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "final"

            [[profiles.hops]]
            name = "jump"
            protocol = "ssh2"
            host = "jump"
            port = 22
            user = "alice"

            [profiles.hops.auth]
            method = "public_key"
            identity_file = "~/.ssh/id_ed25519"

            [profiles.hops.trust]
            mode = "known_hosts"
            strict = false
        "#;
        let (c, warnings) = load_str(raw, true).unwrap();
        assert!(warnings.is_empty());
        let hop = &c.profiles[0].hops[0];
        assert_eq!(hop.auth.as_ref().unwrap().method, "public_key");
        assert_eq!(
            hop.trust.as_ref().unwrap().mode.as_deref(),
            Some("known_hosts")
        );
    }

    #[test]
    fn rejects_malformed_toml() {
        let err = load_str("not [valid", false).unwrap_err();
        assert!(format!("{err}").contains("toml parse"));
    }

    #[test]
    fn warnings_to_diagnostics_works() {
        let d = warnings_to_diagnostics(&["a.b".to_owned()]);
        assert_eq!(d.warnings.len(), 1);
    }

    #[test]
    fn ssh_config_reads_allowed_matches_portable_slot() {
        use super::{ssh_config_reads_allowed, PORTABLE};
        // OnceLock contents are shared across the test binary, so we
        // verify the function matches its derivation rather than
        // attempting to mutate the global. Default (slot empty) is
        // "allowed".
        let stored = PORTABLE.get().copied();
        let expected = !stored.unwrap_or(false);
        assert_eq!(ssh_config_reads_allowed(), expected);
    }

    // ---------------- load_dir tests --------------------------------------

    use super::load_dir;
    use std::fs;

    fn write_toml(dir: &std::path::Path, name: &str, body: &str) {
        fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn load_dir_merges_profiles_in_lex_order() {
        let tmp = tempfile::tempdir().unwrap();
        write_toml(
            tmp.path(),
            "01-base.toml",
            r#"
                version = 1
                [runtime]
                state_dir = "/var/lib/spt"
                [[profiles]]
                name = "p1"
                protocol = "ssh2"
                host = "h1.example.com"
            "#,
        );
        write_toml(
            tmp.path(),
            "02-overlay.toml",
            r#"
                version = 1
                [[profiles]]
                name = "p2"
                protocol = "ssh2"
                host = "h2.example.com"
                [[profiles]]
                name = "p3"
                protocol = "ssh2"
                host = "h3.example.com"
            "#,
        );
        write_toml(
            tmp.path(),
            "99-z.toml",
            r#"
                version = 1
                [[profiles]]
                name = "z"
                protocol = "ssh2"
                host = "z.example.com"
            "#,
        );
        // A non-toml file should be ignored.
        fs::write(tmp.path().join("README.md"), "ignore me").unwrap();

        let (cfg, w) = load_dir(tmp.path(), false).unwrap();
        assert!(w.is_empty(), "no warnings expected, got: {w:?}");
        assert_eq!(cfg.version, 1);
        // p1 from base, p2+p3 from overlay, z from 99-z, in lex order.
        let names: Vec<_> = cfg.profiles.iter().map(|p| p.name.clone()).collect();
        assert_eq!(names, vec!["p1", "p2", "p3", "z"]);
        // Runtime came from the first file.
        assert_eq!(
            cfg.runtime.as_ref().and_then(|r| r.state_dir.as_deref()),
            Some("/var/lib/spt")
        );
    }

    #[test]
    fn load_dir_rejects_singleton_override_in_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        write_toml(
            tmp.path(),
            "01-base.toml",
            r#"
                version = 1
                [runtime]
                state_dir = "/var/lib/spt"
                [[profiles]]
                name = "p1"
                protocol = "ssh2"
                host = "h1.example.com"
            "#,
        );
        write_toml(
            tmp.path(),
            "02-bad.toml",
            r#"
                version = 1
                [runtime]
                state_dir = "/tmp/other"
            "#,
        );
        let err = load_dir(tmp.path(), false).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("02-bad.toml"), "got: {msg}");
        assert!(msg.contains("[runtime]"), "got: {msg}");
    }

    #[test]
    fn load_dir_empty_directory_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = load_dir(tmp.path(), false).unwrap_err();
        assert!(format!("{err}").contains("no `*.toml`"));
    }

    #[test]
    fn load_dir_missing_directory_errors() {
        let path = std::path::Path::new("/definitely/does/not/exist/spt-cfg-xyz");
        let err = load_dir(path, false).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("does not exist") || msg.contains("not a directory"));
    }

    #[test]
    fn load_dir_rejects_duplicate_profile_names_across_files() {
        let tmp = tempfile::tempdir().unwrap();
        write_toml(
            tmp.path(),
            "01-base.toml",
            r#"
                version = 1
                [[profiles]]
                name = "shared"
                protocol = "ssh2"
                host = "h1.example.com"
            "#,
        );
        write_toml(
            tmp.path(),
            "02-overlay.toml",
            r#"
                version = 1
                [[profiles]]
                name = "shared"
                protocol = "ssh2"
                host = "h2.example.com"
            "#,
        );
        let err = load_dir(tmp.path(), false).unwrap_err();
        assert!(format!("{err}").contains("duplicate profile name"));
    }

    #[test]
    fn load_dir_rejects_version_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        write_toml(
            tmp.path(),
            "01-base.toml",
            r#"
                version = 1
                [[profiles]]
                name = "p1"
                protocol = "ssh2"
                host = "h1"
            "#,
        );
        // Use literal raw string for the second body so escaped quotes parse.
        fs::write(tmp.path().join("02-mismatch.toml"), "version = 2\n").unwrap();
        let err = load_dir(tmp.path(), false).unwrap_err();
        assert!(format!("{err}").contains("does not match base"));
    }
}
