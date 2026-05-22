//! Schema migration framework.
//!
//! The active schema is `version = 1`. [`migrate`] is the identity for that
//! version and the rejection-on-unknown gate for everything else.
//!
//! t7-Phase0 introduces a forward migration to **schema v2** that strips the
//! deprecated `capabilities.ssh2_backend` and `capabilities.allow_libssh2`
//! keys (libssh2 was removed; russh is the only SSH2 backend). The v2
//! migration is the body of [`migrate_to_2`] and is invoked by
//! `spt config migrate --to 2` in the CLI surface.

use spt_core::{Error, Result};

/// Migrate a raw TOML string to the current schema version.
///
/// Returns the (possibly transformed) TOML text. The current implementation
/// reads the `version = N` line, accepts `1`, and rejects anything else with
/// [`Error::VersionOrMigrationFailed`].
pub fn migrate(raw: &str) -> Result<String> {
    let version = parse_version(raw)?;
    match version {
        1 => Ok(raw.to_owned()),
        other => Err(Error::VersionOrMigrationFailed(format!(
            "no migration path for config version `{other}` (only `1` is currently supported)"
        ))),
    }
}

/// Migrate a v1 config to v2 by stripping deprecated t7-Phase0 keys.
///
/// Drops:
/// * `capabilities.ssh2_backend`
/// * `capabilities.allow_libssh2`
///
/// Bumps `version = 1` to `version = 2`. If the input is already v2 the
/// function is the identity (an empty capabilities table is left alone).
pub fn migrate_to_2(raw: &str) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        Error::invalid_config(
            spt_core::Diagnostic::what("Failed to parse config for migration")
                .why(format!("toml_edit could not parse the document: {e}"))
                .how_to_fix(
                    "Fix any TOML syntax errors before running `spt config migrate`. \
                     Use `taplo lint` or revert to a known-good config and re-apply changes.",
                )
                .build(),
        )
    })?;

    let current = doc
        .get("version")
        .and_then(toml_edit::Item::as_integer)
        .ok_or_else(|| {
            Error::invalid_config(
                spt_core::Diagnostic::what("Config has no `version` field")
                    .why("migration requires a top-level `version = <int>` declaration")
                    .how_to_fix(
                        "Add `version = 1` (or your target schema version) at the top \
                         of the config file before running `spt config migrate`.",
                    )
                    .build(),
            )
        })?;
    if current == 2 {
        return Ok(doc.to_string());
    }
    if current != 1 {
        return Err(Error::VersionOrMigrationFailed(format!(
            "cannot migrate from version `{current}` to `2` (only `1 -> 2` is supported)"
        )));
    }

    if let Some(cap_item) = doc.get_mut("capabilities") {
        if let Some(table) = cap_item.as_table_like_mut() {
            table.remove("ssh2_backend");
            table.remove("allow_libssh2");
        }
    }

    doc["version"] = toml_edit::value(2);
    Ok(doc.to_string())
}

fn parse_version(raw: &str) -> Result<u64> {
    let table: toml::Value = raw.parse().map_err(|e| {
        Error::invalid_config(
            spt_core::Diagnostic::what("Failed to parse config when reading schema version")
                .why(format!("toml parse error: {e}"))
                .how_to_fix(
                    "Fix the TOML syntax (mismatched quotes, brackets, indentation), then \
                     re-run the command.",
                )
                .build(),
        )
    })?;
    match table.get("version").and_then(toml::Value::as_integer) {
        Some(v) if v >= 0 => Ok(v as u64),
        _ => Err(Error::invalid_config(
            spt_core::Diagnostic::what("Config has no `version` field")
                .why("the schema-version detector could not find a top-level non-negative integer")
                .how_to_fix(
                    "Add `version = 1` (or a higher integer matching your schema) at the \
                     top of the config file.",
                )
                .build(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_for_v1() {
        let raw = "version = 1\n[[profiles]]\nname = \"p\"\nprotocol = \"ssh2\"\nhost = \"h\"\n";
        assert_eq!(migrate(raw).unwrap(), raw);
    }

    #[test]
    fn rejects_unknown_version() {
        let raw = "version = 99\n";
        assert!(migrate(raw).is_err());
    }

    #[test]
    fn rejects_missing_version() {
        let raw = "[[profiles]]\nname = \"p\"\nprotocol = \"ssh2\"\n";
        assert!(migrate(raw).is_err());
    }

    #[test]
    fn migrate_to_2_strips_deprecated_ssh2_backend_and_allow_libssh2() {
        // t7-Phase0: v1 -> v2 migration drops the deprecated keys, bumps
        // version, and leaves the rest of the config untouched.
        let raw = r#"version = 1

[capabilities]
ssh2_backend = "libssh2"
allow_libssh2 = false
require_post_quantum_kex = false

[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
"#;
        let migrated = migrate_to_2(raw).unwrap();
        assert!(migrated.contains("version = 2"));
        assert!(!migrated.contains("ssh2_backend"));
        assert!(!migrated.contains("allow_libssh2"));
        assert!(migrated.contains("require_post_quantum_kex"));
        assert!(migrated.contains("name = \"p\""));
    }

    #[test]
    fn migrate_to_2_is_identity_when_keys_absent() {
        let raw = r#"version = 1

[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
"#;
        let migrated = migrate_to_2(raw).unwrap();
        assert!(migrated.contains("version = 2"));
        assert!(migrated.contains("name = \"p\""));
    }

    #[test]
    fn migrate_to_2_idempotent_on_v2_input() {
        let raw = "version = 2\n[[profiles]]\nname = \"p\"\nprotocol = \"ssh2\"\nhost = \"h\"\n";
        let out = migrate_to_2(raw).unwrap();
        assert!(out.contains("version = 2"));
    }
}
