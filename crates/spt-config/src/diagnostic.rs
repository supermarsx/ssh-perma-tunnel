//! Diagnostic types used by [`crate::validate()`] and [`crate::load()`].
//!
//! We deliberately avoid the `miette::Diagnostic` derive on every variant in
//! the schema (it would require cargo features in dev contexts) and instead
//! ship a small typed [`Diagnostic`] that can be promoted to `miette::Report`
//! at the binary boundary.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Severity of a [`Diagnostic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Hard validation error.
    Error,
    /// Non-fatal warning (deprecation, soft conflict, …).
    Warning,
    /// Informational note.
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error => f.write_str("error"),
            Self::Warning => f.write_str("warning"),
            Self::Info => f.write_str("info"),
        }
    }
}

/// A single diagnostic produced by validation or loading.
///
/// `path` is a TOML-pointer-like dotted path (e.g.
/// `profiles[0].forwards[1].bind`) to the offending field, when known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Severity bucket.
    pub severity: Severity,
    /// Stable code (e.g. `version_unsupported`, `duplicate_profile_id`).
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Dotted path to the field, when the diagnostic is field-scoped.
    pub path: Option<String>,
    /// Optional remediation hint.
    pub help: Option<String>,
}

impl Diagnostic {
    /// Build an error-severity diagnostic.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: code.into(),
            message: message.into(),
            path: None,
            help: None,
        }
    }

    /// Build a warning-severity diagnostic.
    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: code.into(),
            message: message.into(),
            path: None,
            help: None,
        }
    }

    /// Attach a field path.
    #[must_use]
    pub fn at(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Attach a remediation hint.
    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]: {}", self.severity, self.code, self.message)?;
        if let Some(p) = &self.path {
            write!(f, " (at `{p}`)")?;
        }
        if let Some(h) = &self.help {
            write!(f, "\n  help: {h}")?;
        }
        Ok(())
    }
}

/// Diagnostics bundle returned by validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostics {
    /// Hard errors. A non-empty list means validation failed.
    pub errors: Vec<Diagnostic>,
    /// Soft warnings.
    pub warnings: Vec<Diagnostic>,
}

impl Diagnostics {
    /// Construct an empty bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when no errors are present.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// Push a single diagnostic, dispatching to errors/warnings by severity.
    pub fn push(&mut self, d: Diagnostic) {
        match d.severity {
            Severity::Error => self.errors.push(d),
            Severity::Warning | Severity::Info => self.warnings.push(d),
        }
    }

    /// Convenience: number of issues across both buckets.
    #[must_use]
    pub fn total(&self) -> usize {
        self.errors.len() + self.warnings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, Diagnostics, Severity};

    #[test]
    fn push_dispatches() {
        let mut d = Diagnostics::new();
        d.push(Diagnostic::error("e", "boom"));
        d.push(Diagnostic::warning("w", "hmm"));
        assert_eq!(d.errors.len(), 1);
        assert_eq!(d.warnings.len(), 1);
        assert!(!d.is_ok());
    }

    #[test]
    fn display_includes_path() {
        let d = Diagnostic::error("c", "m").at("profiles[0].name");
        assert!(format!("{d}").contains("profiles[0].name"));
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Error.to_string(), "error");
    }
}
