//! `Diagnostic` trait + a runner that aggregates a `DiagnosticReport`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

use crate::check::{Check, Status};

/// Read-only context passed to every diagnostic.
///
/// Concrete diagnostics typically need a state directory, an effective
/// config path, and optionally OS info. This is intentionally minimal — add
/// fields here as new diagnostics need them, rather than per-check.
///
/// All injected handles are `Option<Arc<...>>`. A diagnostic whose handle is
/// `None` MUST emit `Status::Skipped` rather than fail. This keeps
/// `DiagnosticContext::default()` usable from the runner's unit tests and
/// from CI environments where some subsystems are absent.
#[derive(Clone, Default)]
pub struct DiagnosticContext {
    /// Where the running daemon's state lives, or where it would.
    pub state_dir: Option<PathBuf>,
    /// Effective config TOML, already-redacted, for checks that look at
    /// shape (e.g. did the user set a remote-config pin).
    pub effective_config: Option<String>,
    /// Free-form key/value tags (e.g. `os=linux`, `arch=x86_64`).
    pub tags: Vec<(String, String)>,

    // -- Injected handles (deeper checks) ----------------------------------
    /// Resolver for the secrets check. None → `Skipped`.
    pub resolver: Option<Arc<spt_secrets::Resolver>>,
    /// Whether write probes (round-trip set/get/delete) are permitted.
    /// Defaults to false: diagnostics are read-only by default per spec.
    pub allow_write_probes: bool,
    /// Firewall planner for the firewall check. None → `Skipped`.
    pub firewall_planner: Option<Arc<dyn spt_firewall::FirewallPlanner>>,
    /// Firewall rules to plan and verify. Empty → `Skipped`.
    pub firewall_rules: Vec<spt_firewall::Rule>,
    /// Service manager for the service check. None → `Skipped`.
    pub service_manager: Option<Arc<dyn spt_service::ServiceManager>>,
    /// Service name to query. None → `Skipped`.
    pub service_name: Option<String>,
    /// Whether the MCP server is enabled in config.
    pub mcp_enabled: bool,
    /// Path to the spt binary used to spawn `spt mcp serve --stdio`.
    /// None → `Skipped`.
    pub mcp_binary: Option<PathBuf>,
    /// SSH2 crypto policy (allow-lists) to vet against libssh2's support.
    /// None → only the libssh2 version + supported-algs probe runs.
    pub crypto_policy: Option<spt_ssh2::CryptoPolicy>,
}

impl std::fmt::Debug for DiagnosticContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiagnosticContext")
            .field("state_dir", &self.state_dir)
            .field("effective_config_present", &self.effective_config.is_some())
            .field("tags", &self.tags)
            .field("resolver", &self.resolver.is_some())
            .field("allow_write_probes", &self.allow_write_probes)
            .field("firewall_planner", &self.firewall_planner.is_some())
            .field("firewall_rules", &self.firewall_rules.len())
            .field("service_manager", &self.service_manager.is_some())
            .field("service_name", &self.service_name)
            .field("mcp_enabled", &self.mcp_enabled)
            .field("mcp_binary", &self.mcp_binary)
            .field("crypto_policy", &self.crypto_policy.is_some())
            .finish()
    }
}

/// A single diagnostic. Async because most checks do IO (DNS lookup, file
/// open, listener probe). Implementors MUST be cheap on a `Skipped` path
/// and MUST NOT panic.
#[async_trait]
pub trait Diagnostic: Send + Sync {
    /// Stable group id (e.g. `network`, `os`). Logged at INFO.
    fn group(&self) -> &str;
    /// Run the diagnostic and return zero or more checks.
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check>;
}

/// Aggregated report.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiagnosticReport {
    /// All checks, in run order.
    pub checks: Vec<Check>,
}

impl DiagnosticReport {
    /// True iff at least one `Fail` is present.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Fail)
    }

    /// Counts by status, for summary printing.
    #[must_use]
    pub fn counts(&self) -> ReportCounts {
        let mut c = ReportCounts::default();
        for ch in &self.checks {
            match ch.status {
                Status::Pass => c.pass += 1,
                Status::Warn => c.warn += 1,
                Status::Fail => c.fail += 1,
                Status::Skipped => c.skipped += 1,
            }
        }
        c
    }
}

/// Per-status counts.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportCounts {
    /// Pass count.
    pub pass: usize,
    /// Warn count.
    pub warn: usize,
    /// Fail count.
    pub fail: usize,
    /// Skipped count.
    pub skipped: usize,
}

/// Runs a set of diagnostics, in order, and produces a [`DiagnosticReport`].
///
/// Diagnostics are stored as `Arc<dyn Diagnostic>` so the runner is `Clone`
/// and re-runnable.
#[derive(Default, Clone)]
pub struct DiagnosticRunner {
    diagnostics: Vec<Arc<dyn Diagnostic>>,
}

impl DiagnosticRunner {
    /// Empty runner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a diagnostic. Order is preserved.
    #[must_use]
    pub fn register<D: Diagnostic + 'static>(mut self, d: D) -> Self {
        self.diagnostics.push(Arc::new(d));
        self
    }

    /// Register a pre-boxed diagnostic.
    #[must_use]
    pub fn register_arc(mut self, d: Arc<dyn Diagnostic>) -> Self {
        self.diagnostics.push(d);
        self
    }

    /// Run every registered diagnostic and aggregate the results.
    pub async fn run(&self, ctx: &DiagnosticContext) -> DiagnosticReport {
        let mut checks = Vec::new();
        for d in &self.diagnostics {
            tracing::info!(group = %d.group(), "diagnostic group running");
            checks.extend(d.run(ctx).await);
        }
        DiagnosticReport { checks }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::Severity;

    struct Always {
        status: Status,
    }
    #[async_trait]
    impl Diagnostic for Always {
        fn group(&self) -> &str {
            "always"
        }
        async fn run(&self, _ctx: &DiagnosticContext) -> Vec<Check> {
            vec![Check::new("always.run", Severity::Info, self.status)]
        }
    }

    #[tokio::test]
    async fn runner_aggregates_in_order() {
        let r = DiagnosticRunner::new()
            .register(Always {
                status: Status::Pass,
            })
            .register(Always {
                status: Status::Fail,
            });
        let rep = r.run(&DiagnosticContext::default()).await;
        assert_eq!(rep.checks.len(), 2);
        assert_eq!(rep.checks[0].status, Status::Pass);
        assert_eq!(rep.checks[1].status, Status::Fail);
        assert!(rep.has_failures());
        let c = rep.counts();
        assert_eq!(c.pass, 1);
        assert_eq!(c.fail, 1);
    }

    #[tokio::test]
    async fn empty_runner_no_failures() {
        let r = DiagnosticRunner::new();
        let rep = r.run(&DiagnosticContext::default()).await;
        assert!(!rep.has_failures());
        assert_eq!(rep.counts(), ReportCounts::default());
    }
}
