//! Data model for a single diagnostic check.
//!
//! Spec §13.12: "Every check MUST have an ID, severity, status, explanation,
//! evidence, and remediation hint."

use serde::{Deserialize, Serialize};

/// Severity attached to a check. Maps roughly to the syslog severity scale —
/// this is the *importance* of the underlying issue when it fires, not the
/// runtime status of the check itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational note. No action required.
    Info,
    /// Low — recommended cleanup but not urgent.
    Low,
    /// Medium — could affect uptime or trust under load.
    Medium,
    /// High — currently impairs functionality.
    High,
    /// Critical — blocks operation entirely.
    Critical,
}

/// Outcome of running a check on a particular environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Check ran and the property under test holds.
    Pass,
    /// Check ran and a non-blocking concern was detected.
    Warn,
    /// Check ran and the property does not hold.
    Fail,
    /// Check was not applicable on this environment (e.g. Windows-only check
    /// on Linux). Skipped checks count toward neither Pass nor Fail.
    Skipped,
}

/// A single diagnostic result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// Stable identifier. Use dotted, lowercase, ASCII (e.g. `dns.resolves`).
    pub id: String,
    /// Severity of the underlying issue. Independent from `status`.
    pub severity: Severity,
    /// Outcome.
    pub status: Status,
    /// Human-readable explanation lines. Already redacted by the producer.
    pub evidence: Vec<String>,
    /// Optional remediation hint shown when status is `Warn` or `Fail`.
    pub remediation: Option<String>,
}

impl Check {
    /// Build a new check with the minimum viable fields.
    pub fn new(id: impl Into<String>, severity: Severity, status: Status) -> Self {
        Self {
            id: id.into(),
            severity,
            status,
            evidence: Vec::new(),
            remediation: None,
        }
    }

    /// Append an evidence line (chainable).
    #[must_use]
    pub fn with_evidence(mut self, line: impl Into<String>) -> Self {
        self.evidence.push(line.into());
        self
    }

    /// Set the remediation hint (chainable).
    #[must_use]
    pub fn with_remediation(mut self, remedy: impl Into<String>) -> Self {
        self.remediation = Some(remedy.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_builder() {
        let c = Check::new("dns.resolves", Severity::High, Status::Fail)
            .with_evidence("could not resolve example.com")
            .with_remediation("check `runtime.dns.upstream`");
        assert_eq!(c.id, "dns.resolves");
        assert_eq!(c.severity, Severity::High);
        assert_eq!(c.status, Status::Fail);
        assert_eq!(c.evidence, vec!["could not resolve example.com"]);
        assert_eq!(
            c.remediation.as_deref(),
            Some("check `runtime.dns.upstream`")
        );
    }

    #[test]
    fn serde_roundtrip() {
        let c = Check::new("os.kernel", Severity::Info, Status::Pass).with_evidence("Linux 6.1.0");
        let s = serde_json::to_string(&c).unwrap();
        let back: Check = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }
}
