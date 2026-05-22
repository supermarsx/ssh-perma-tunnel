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
    let bytes = std::fs::read(path).map_err(|e| {
        // t8-A1: operator-facing read failure → structured diagnostic.
        Error::invalid_config(
            spt_core::Diagnostic::what(format!("Failed to read config file `{}`", path.display()))
                .why(format!("{e}"))
                .how_to_fix(
                    "Verify the path exists, is readable by this user, and the parent \
                     directory has the expected permissions (e.g. `chmod 600` on Unix).",
                )
                .file_path(path)
                .build(),
        )
    })?;
    if is_sealed(&bytes) {
        let cleartext = decrypt_sealed(&bytes, key)?;
        // The plaintext is held only inside the SecretBox; we view it as
        // &str (zero-copy from the inner Zeroizing<Vec<u8>>). The Config
        // value lands on the heap as a normal struct — its secret-shaped
        // fields are protected separately by the schema's RedactedString
        // newtype (t5-e7) when materialised.
        let pt = cleartext.expose_secret();
        let raw = std::str::from_utf8(pt).map_err(|e| {
            Error::invalid_config(
                spt_core::Diagnostic::what(format!(
                    "Sealed config `{}` decrypted to non-UTF-8 bytes",
                    path.display()
                ))
                .why(format!("{e}"))
                .how_to_fix(
                    "Re-seal the config from a UTF-8 source. If you encrypted a binary file \
                     by mistake, restore the original TOML and run `spt config seal` again.",
                )
                .file_path(path)
                .build(),
            )
        })?;
        return load_str(raw, strict);
    }
    let raw = std::str::from_utf8(&bytes).map_err(|e| {
        Error::invalid_config(
            spt_core::Diagnostic::what(format!(
                "Config file `{}` is not valid UTF-8",
                path.display()
            ))
            .why(format!("{e}"))
            .how_to_fix("Re-save the file using a UTF-8 encoding (e.g. `iconv -f <enc> -t utf-8`).")
            .file_path(path)
            .build(),
        )
    })?;
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
        other => Err(Error::invalid_config(
            spt_core::Diagnostic::what(format!("Sealed config uses an unsupported KDF `{other}`",))
                .why("the interactive-passphrase path only handles `argon2id`-sealed envelopes")
                .how_to_fix(
                    "Either re-seal with `spt config seal --kdf argon2id`, or call \
                 `load_with_key()` programmatically with the explicit KeySource for \
                 this KDF (vault, x25519, …).",
                )
                .build(),
        )),
    }
}

/// Parse a TOML config string.
pub fn load_str(raw: &str, strict: bool) -> Result<(Config, Warnings)> {
    let mut warnings: Warnings = Vec::new();

    let de = toml::Deserializer::new(raw);
    let config: Config = serde_ignored::deserialize(de, |path| {
        warnings.push(path.to_string());
    })
    .map_err(|e| {
        // t8-A1: TOML parse failures are by far the most common operator-facing
        // config error. Surface what / why / how_to_fix so they don't have to
        // squint at a raw serde error message.
        let line_no = extract_toml_line(&e);
        let mut b = spt_core::Diagnostic::what("Failed to parse config as TOML")
            .why(format!("{e}"))
            .how_to_fix(
                "Run the config through a TOML validator (e.g. `taplo lint`) or revert \
                 the most recent change. Common causes: missing quotes around string values, \
                 mismatched table headers, or a trailing comma in an inline array.",
            );
        if let Some(l) = line_no {
            b = b.line_no(l);
        }
        Error::invalid_config(b.build())
    })?;

    if strict && !warnings.is_empty() {
        return Err(Error::invalid_config(
            spt_core::Diagnostic::what("Unknown keys present in strict-mode config")
                .why(format!("unrecognised keys: {}", warnings.join(", ")))
                .how_to_fix(
                    "Delete the keys, fix any typos against the spec §5 schema, or drop \
                     the `--strict` flag if the keys are intentional vendor extensions.",
                )
                .build(),
        ));
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
        return Err(Error::invalid_config(
            spt_core::Diagnostic::what(format!(
                "Config directory `{}` does not exist",
                dir.display()
            ))
            .how_to_fix(
                "Create the directory (`mkdir -p <path>`) and populate it with at least \
                 one `*.toml` config file, or pass `--config <file>` to use a single file.",
            )
            .file_path(dir)
            .build(),
        ));
    }
    if !dir.is_dir() {
        return Err(Error::invalid_config(
            spt_core::Diagnostic::what(format!(
                "Config dir path `{}` exists but is not a directory",
                dir.display()
            ))
            .how_to_fix(
                "Pass a directory path to `--config-dir`, or use `--config <file>` for \
                 single-file configs.",
            )
            .file_path(dir)
            .build(),
        ));
    }
    let read = std::fs::read_dir(dir).map_err(|e| {
        Error::invalid_config(
            spt_core::Diagnostic::what(format!(
                "Failed to enumerate config dir `{}`",
                dir.display()
            ))
            .why(format!("{e}"))
            .how_to_fix(
                "Verify the calling user has read+execute permission on the directory \
                 (`chmod +rx`).",
            )
            .file_path(dir)
            .build(),
        )
    })?;
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
        return Err(Error::invalid_config(
            spt_core::Diagnostic::what(format!(
                "Config dir `{}` contains no `*.toml` files",
                dir.display()
            ))
            .how_to_fix(
                "Place at least one `<name>.toml` file in the directory. The first file \
                 (lex order) is the base; later files may only add `[[profiles]]`.",
            )
            .file_path(dir)
            .build(),
        ));
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
            return Err(Error::invalid_config(
                spt_core::Diagnostic::what(format!(
                    "Config dir merge: file `{name}` declares a different schema version"
                ))
                .why(format!(
                    "overlay `version = {}` does not match base `version = {}`",
                    overlay.version, merged.version
                ))
                .how_to_fix(
                    "Update every `*.toml` file in the config directory to declare the \
                     same `version = <int>`. Run `spt config migrate` to bump older files.",
                )
                .build(),
            ));
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
                return Err(Error::invalid_config(
                    spt_core::Diagnostic::what(format!("Duplicate profile name `{}`", p.name))
                        .why(format!(
                            "file `{name}` re-defines a profile already present in an earlier \
                         file (lex order); the merge would be ambiguous",
                        ))
                        .how_to_fix(
                            "Rename one of the conflicting profiles, or delete the duplicate \
                         from the later file.",
                        )
                        .build(),
                ));
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
        return Err(Error::invalid_config(
            spt_core::Diagnostic::what(format!(
                "Singleton table `[{name}]` redefined in non-base config file `{file}`"
            ))
            .why(
                "only the first file (lex order) in a `--config-dir` may set singleton \
                 top-level tables; later files may only contribute `[[profiles]]`",
            )
            .how_to_fix(format!(
                "Move the `[{name}]` block into the lex-first `*.toml` file, or delete \
                 it from `{file}`.",
            ))
            .build(),
        ));
    }
    Ok(())
}

/// Heuristic: scrape a `(line N, column M)` or `at line N` span out of a
/// [`toml::de::Error`]'s Display so we can populate `Diagnostic::line_no`.
/// We deliberately don't depend on `toml::de::Error::span()` which returns
/// byte offsets — the regex-free scan is cheap and robust to minor message
/// format changes between toml versions.
fn extract_toml_line(e: &toml::de::Error) -> Option<u32> {
    let msg = e.to_string();
    // Common toml-rs phrasings: "TOML parse error at line 5, column 3" or
    // "at line 5". We look for the first "line " + integer that follows.
    for (i, _) in msg.char_indices() {
        if msg.get(i..).is_some_and(|s| s.starts_with("line ")) {
            let rest = &msg[i + 5..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(n) = digits.parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
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
    use super::{extract_toml_line, load_str, warnings_to_diagnostics};

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
        // t8-A1: error text was upgraded to a structured diagnostic;
        // assert against the new operator-facing phrasing.
        let s = format!("{err}");
        assert!(
            s.contains("Failed to parse config as TOML") || s.contains("toml parse"),
            "got: {s}"
        );
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
        fs::write(tmp.path().join("readme.md"), "ignore me").unwrap();

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
        // t8-A1: phrasing upgraded to structured diagnostic.
        let s = format!("{err}");
        assert!(
            s.contains("Duplicate profile name") || s.contains("duplicate profile name"),
            "got: {s}"
        );
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

    // ──────── t8-A1: diagnostic regression tests ────────────────────
    // Each `Error::*Diagnostic` site converted in this file gets a
    // companion test asserting the rendered Display contains the
    // operator-facing what / why / how_to_fix substrings.

    #[test]
    fn toml_parse_failure_emits_structured_diagnostic() {
        let err = load_str("version = bad-bareword", false).unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "Failed to parse config as TOML",
            how_to_fix: "taplo lint",
        );
    }

    #[test]
    fn strict_unknown_keys_diagnostic_lists_offending_paths() {
        let raw = r"
            version = 1
            mystery_top_level = true
        ";
        let err = load_str(raw, true).unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "Unknown keys present in strict-mode config",
            why: "mystery_top_level",
            how_to_fix: "--strict",
        );
    }

    #[test]
    fn load_dir_missing_diagnostic_shows_fix_step() {
        use std::path::Path;
        let err = load_dir(Path::new("/definitely/does/not/exist/spt-cfg"), false).unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "does not exist",
            how_to_fix: "mkdir -p",
        );
    }

    #[test]
    fn load_dir_not_a_directory_diagnostic_suggests_single_file_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("not-a-dir.toml");
        fs::write(&file_path, "version = 1\n").unwrap();
        let err = load_dir(&file_path, false).unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "is not a directory",
            how_to_fix: "--config <file>",
        );
    }

    #[test]
    fn load_dir_empty_diagnostic_explains_base_file() {
        let tmp = tempfile::tempdir().unwrap();
        let err = load_dir(tmp.path(), false).unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "contains no `*.toml`",
            how_to_fix: "lex order",
        );
    }

    #[test]
    fn load_dir_version_mismatch_diagnostic_suggests_migrate() {
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
        fs::write(tmp.path().join("02-mismatch.toml"), "version = 2\n").unwrap();
        let err = load_dir(tmp.path(), false).unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "different schema version",
            how_to_fix: "spt config migrate",
        );
    }

    #[test]
    fn load_dir_duplicate_profile_diagnostic_names_offender() {
        let tmp = tempfile::tempdir().unwrap();
        let base = r#"
            version = 1
            [[profiles]]
            name = "dup"
            protocol = "ssh2"
            host = "h"
        "#;
        write_toml(tmp.path(), "01-base.toml", base);
        write_toml(
            tmp.path(),
            "02-second.toml",
            r#"
                version = 1
                [[profiles]]
                name = "dup"
                protocol = "ssh2"
                host = "h"
            "#,
        );
        let err = load_dir(tmp.path(), false).unwrap_err();
        spt_core::assert_diagnostic_contains!(err,
            what: "Duplicate profile name",
            why: "already present",
            how_to_fix: "Rename",
        );
    }

    #[test]
    fn extract_toml_line_pulls_line_number() {
        // Smoke-test the line-extraction helper used by the load_str diagnostic.
        let err = "version = ".parse::<toml::Value>().unwrap_err();
        let line = extract_toml_line(&err);
        // Either the toml message carries a line number or it doesn't —
        // both shapes are acceptable depending on toml version, but the
        // helper must not panic.
        if let Some(n) = line {
            assert!(n >= 1);
        }
    }

    #[test]
    fn diagnostic_variants_keep_invalid_config_exit_code() {
        // Regression: the new InvalidConfigDiagnostic variant must share
        // ExitCode::InvalidConfig with the legacy String-payload sibling
        // so downstream tooling (CI, systemd) treats them identically.
        let err = load_str("not valid toml = = =", false).unwrap_err();
        assert_eq!(err.exit_code(), spt_core::ExitCode::InvalidConfig);
    }

    #[test]
    fn diagnostic_what_is_present_for_every_converted_load_site() {
        // The Diagnostic accessor must surface a non-empty `what` field
        // for converted sites — this is the contract callers depend on.
        let err = load_str("not valid toml = = =", false).unwrap_err();
        let d = err.diagnostic().expect("converted site has Diagnostic");
        assert!(!d.what.is_empty());
        assert!(d.how_to_fix.is_some());
    }
}
