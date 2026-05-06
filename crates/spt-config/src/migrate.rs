//! Schema migration framework.
//!
//! The current schema is `version = 1`; [`migrate`] is therefore an identity
//! function that confirms the version is supported. The framework is in place
//! so future schema bumps can be added without changing the public surface.

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

fn parse_version(raw: &str) -> Result<u64> {
    let table: toml::Value = raw
        .parse()
        .map_err(|e| Error::InvalidConfig(format!("toml parse: {e}")))?;
    match table.get("version").and_then(toml::Value::as_integer) {
        Some(v) if v >= 0 => Ok(v as u64),
        _ => Err(Error::InvalidConfig(
            "config is missing a `version = <int>` field".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::migrate;

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
}
