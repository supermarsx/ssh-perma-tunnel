//! Loading TOML configs from a file or string.
//!
//! `load_str` is the primary entry point. It deserializes through
//! [`serde_ignored`] so unknown keys are surfaced as warnings. In strict mode
//! those warnings are promoted to a hard parse error.

use std::path::Path;

use spt_core::{Error, Result};

use crate::diagnostic::{Diagnostic, Diagnostics};
use crate::schema::Config;

/// Convenience alias for the unknown-keys warnings list returned by
/// [`load`] / [`load_str`].
pub type Warnings = Vec<String>;

/// Load a config file from disk.
///
/// In strict mode, any unknown TOML key is a hard error. In non-strict mode,
/// unknown keys are returned as warning paths (e.g. `runtime.unknown_field`)
/// in the second tuple element.
pub fn load(path: &Path, strict: bool) -> Result<(Config, Warnings)> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
    load_str(&raw, strict)
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

/// Build [`Diagnostics`] entries for warnings from [`load_str`].
///
/// Useful when callers want a single diagnostic stream covering both
/// load-time unknowns and validate-time issues.
#[must_use]
pub fn warnings_to_diagnostics(warnings: &[String]) -> Diagnostics {
    let mut out = Diagnostics::new();
    for path in warnings {
        out.push(
            Diagnostic::warning("unknown_key", format!("unknown TOML key `{path}`")).at(path),
        );
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
    fn rejects_malformed_toml() {
        let err = load_str("not [valid", false).unwrap_err();
        assert!(format!("{err}").contains("toml parse"));
    }

    #[test]
    fn warnings_to_diagnostics_works() {
        let d = warnings_to_diagnostics(&["a.b".to_owned()]);
        assert_eq!(d.warnings.len(), 1);
    }
}
