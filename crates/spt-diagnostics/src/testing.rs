//! Public test facilities for `spt-diagnostics` (gated behind `feature = "testing"`).
//!
//! These helpers let downstream crates assemble a [`DiagnosticContext`] and
//! pre-populated [`Check`] / [`DiagnosticReport`] values without re-deriving
//! every field.
//!
//! Notable wiring: [`FakeDiagnosticContext::with_default`] populates
//! [`DiagnosticContext`] with the **already-public** sibling testing fakes
//! that were available at the time this module landed:
//!
//! - `spt_firewall::testing::RecordingPlanner` for [`DiagnosticContext::firewall_planner`]
//! - `spt_service::testing::MockServiceManager` for [`DiagnosticContext::service_manager`]
//!
//! The `resolver` slot is left `None` (an empty default backend chain would
//! emit `Skipped` from the secrets check, which is the spec-mandated fallback).
//! When `spt_secrets::testing` lands, extend [`FakeDiagnosticContext`] to wire
//! a `MemoryBackend`.

use std::path::PathBuf;
use std::sync::Arc;

use spt_firewall::testing::RecordingPlanner;
use spt_service::testing::MockServiceManager;

use crate::check::{Check, Severity, Status};
use crate::framework::{DiagnosticContext, DiagnosticReport};

// --------------------------------------------------------------------------
// Synthetic Check builders
// --------------------------------------------------------------------------

/// Build a fully populated [`Check`] with sample evidence and remediation.
///
/// The `id` is taken verbatim. Evidence is two lines so tests that assert
/// "evidence is non-empty and has more than one line" pass.
///
/// ```
/// use spt_diagnostics::testing::synthetic_check;
/// use spt_diagnostics::{Severity, Status};
///
/// let c = synthetic_check("dns.resolves", Severity::High, Status::Fail);
/// assert_eq!(c.id, "dns.resolves");
/// assert_eq!(c.severity, Severity::High);
/// assert_eq!(c.status, Status::Fail);
/// assert!(!c.evidence.is_empty());
/// assert!(c.remediation.is_some());
/// ```
#[must_use]
pub fn synthetic_check(id: &str, severity: Severity, status: Status) -> Check {
    Check::new(id, severity, status)
        .with_evidence(format!("synthetic evidence for {id} (line 1)"))
        .with_evidence("synthetic evidence (line 2)")
        .with_remediation("see docs/troubleshooting.md")
}

/// Synthetic passing check: `Severity::Info` + `Status::Pass`.
///
/// ```
/// let c = spt_diagnostics::testing::synthetic_pass("os.kernel");
/// assert_eq!(c.status, spt_diagnostics::Status::Pass);
/// ```
#[must_use]
pub fn synthetic_pass(id: &str) -> Check {
    synthetic_check(id, Severity::Info, Status::Pass)
}

/// Synthetic warning check: `Severity::Medium` + `Status::Warn`.
///
/// ```
/// let c = spt_diagnostics::testing::synthetic_warn("disk.usage");
/// assert_eq!(c.status, spt_diagnostics::Status::Warn);
/// assert_eq!(c.severity, spt_diagnostics::Severity::Medium);
/// ```
#[must_use]
pub fn synthetic_warn(id: &str) -> Check {
    synthetic_check(id, Severity::Medium, Status::Warn)
}

/// Synthetic failing check: `Severity::High` + `Status::Fail`.
///
/// ```
/// let c = spt_diagnostics::testing::synthetic_fail("net.connect");
/// assert_eq!(c.status, spt_diagnostics::Status::Fail);
/// assert_eq!(c.severity, spt_diagnostics::Severity::High);
/// ```
#[must_use]
pub fn synthetic_fail(id: &str) -> Check {
    synthetic_check(id, Severity::High, Status::Fail)
}

/// Synthetic skipped check: `Severity::Info` + `Status::Skipped`.
///
/// ```
/// let c = spt_diagnostics::testing::synthetic_skipped("mcp.serve");
/// assert_eq!(c.status, spt_diagnostics::Status::Skipped);
/// ```
#[must_use]
pub fn synthetic_skipped(id: &str) -> Check {
    synthetic_check(id, Severity::Info, Status::Skipped)
}

/// Build a populated [`DiagnosticReport`] containing one of each status, in
/// the order: pass, warn, fail, skipped. Useful for renderers and exit-code
/// translators.
///
/// ```
/// use spt_diagnostics::testing::synthetic_report;
///
/// let r = synthetic_report();
/// let c = r.counts();
/// assert_eq!(c.pass, 1);
/// assert_eq!(c.warn, 1);
/// assert_eq!(c.fail, 1);
/// assert_eq!(c.skipped, 1);
/// assert!(r.has_failures());
/// ```
#[must_use]
pub fn synthetic_report() -> DiagnosticReport {
    DiagnosticReport {
        checks: vec![
            synthetic_pass("os.kernel"),
            synthetic_warn("disk.usage"),
            synthetic_fail("net.connect"),
            synthetic_skipped("mcp.serve"),
        ],
    }
}

// --------------------------------------------------------------------------
// FakeDiagnosticContext
// --------------------------------------------------------------------------

/// Builder over a [`DiagnosticContext`] pre-populated with sibling crates'
/// testing fakes.
///
/// The wired components are kept as fields on the builder so tests can
/// **inspect** them after the runner consumes the context — e.g. to assert
/// that a firewall plan was actually requested.
///
/// ```
/// use spt_diagnostics::testing::FakeDiagnosticContext;
///
/// let fake = FakeDiagnosticContext::new().with_default();
/// let ctx = fake.context();
/// assert!(ctx.firewall_planner.is_some());
/// assert!(ctx.service_manager.is_some());
/// ```
#[derive(Default)]
pub struct FakeDiagnosticContext {
    /// The recording firewall planner, when wired by [`Self::with_firewall`].
    pub firewall_planner: Option<Arc<RecordingPlanner>>,
    /// The mock service manager, when wired by [`Self::with_service`].
    pub service_manager: Option<Arc<MockServiceManager>>,
    /// State directory tag, when set.
    pub state_dir: Option<PathBuf>,
    /// Service name to query, when set.
    pub service_name: Option<String>,
    /// Free-form tags appended into the resulting [`DiagnosticContext`].
    pub tags: Vec<(String, String)>,
}

impl FakeDiagnosticContext {
    /// Empty builder; equivalent to `DiagnosticContext::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wire **all** locally-available fakes: a [`RecordingPlanner`] and a
    /// [`MockServiceManager`]. The resolver slot is left `None`; the secrets
    /// diagnostic emits `Status::Skipped` per spec when no resolver is wired.
    #[must_use]
    pub fn with_default(self) -> Self {
        self.with_firewall(Arc::new(RecordingPlanner::new()))
            .with_service(Arc::new(MockServiceManager::new()), "spt-test")
            .with_state_dir(std::env::temp_dir())
    }

    /// Wire a recording firewall planner.
    #[must_use]
    pub fn with_firewall(mut self, p: Arc<RecordingPlanner>) -> Self {
        self.firewall_planner = Some(p);
        self
    }

    /// Wire a mock service manager and a service name to query.
    #[must_use]
    pub fn with_service(mut self, s: Arc<MockServiceManager>, name: &str) -> Self {
        self.service_manager = Some(s);
        self.service_name = Some(name.to_string());
        self
    }

    /// Set the `state_dir` field.
    #[must_use]
    pub fn with_state_dir(mut self, d: PathBuf) -> Self {
        self.state_dir = Some(d);
        self
    }

    /// Append a free-form tag.
    #[must_use]
    pub fn with_tag(mut self, k: &str, v: &str) -> Self {
        self.tags.push((k.to_string(), v.to_string()));
        self
    }

    /// Materialise the [`DiagnosticContext`] consumed by a `DiagnosticRunner`.
    /// Calling this multiple times yields fresh contexts that share the
    /// underlying `Arc`-wrapped fakes — observers can still inspect them via
    /// the builder fields.
    #[must_use]
    pub fn context(&self) -> DiagnosticContext {
        let mut c = DiagnosticContext {
            state_dir: self.state_dir.clone(),
            tags: self.tags.clone(),
            service_name: self.service_name.clone(),
            ..DiagnosticContext::default()
        };
        if let Some(p) = &self.firewall_planner {
            c.firewall_planner = Some(p.clone() as Arc<dyn spt_firewall::FirewallPlanner>);
        }
        if let Some(s) = &self.service_manager {
            c.service_manager = Some(s.clone() as Arc<dyn spt_service::ServiceManager>);
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::DiagnosticRunner;

    #[test]
    fn synthetic_report_counts_match() {
        let r = synthetic_report();
        let c = r.counts();
        assert_eq!(c.pass, 1);
        assert_eq!(c.warn, 1);
        assert_eq!(c.fail, 1);
        assert_eq!(c.skipped, 1);
    }

    #[test]
    fn synthetic_check_has_evidence_and_remediation() {
        let c = synthetic_check("x.y", Severity::Critical, Status::Fail);
        assert_eq!(c.evidence.len(), 2);
        assert!(c.remediation.is_some());
    }

    #[test]
    fn synthetic_round_trips_json() {
        let r = synthetic_report();
        let s = serde_json::to_string(&r).unwrap();
        let back: DiagnosticReport = serde_json::from_str(&s).unwrap();
        assert_eq!(back.checks.len(), r.checks.len());
    }

    #[tokio::test]
    async fn fake_context_runs_empty_runner_without_panic() {
        let fake = FakeDiagnosticContext::new().with_default();
        let ctx = fake.context();
        let runner = DiagnosticRunner::new();
        let report = runner.run(&ctx).await;
        assert!(report.checks.is_empty());
        assert!(!report.has_failures());
    }

    #[test]
    fn fake_context_default_wires_firewall_and_service() {
        let fake = FakeDiagnosticContext::new().with_default();
        let ctx = fake.context();
        assert!(ctx.firewall_planner.is_some());
        assert!(ctx.service_manager.is_some());
        assert_eq!(ctx.service_name.as_deref(), Some("spt-test"));
        assert!(ctx.state_dir.is_some());
        // Resolver intentionally not wired (no spt-secrets::testing yet).
        assert!(ctx.resolver.is_none());
    }

    #[test]
    fn fake_context_tags_propagate() {
        let fake = FakeDiagnosticContext::new()
            .with_tag("os", "linux")
            .with_tag("arch", "x86_64");
        let ctx = fake.context();
        assert_eq!(ctx.tags.len(), 2);
    }
}
