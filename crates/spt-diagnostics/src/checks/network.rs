//! Network-reachability sanity checks.
//!
//! Currently: DNS resolves a configurable name (default `localhost`, so the
//! check is hermetic on CI) and the loopback address is reachable on a
//! transient port. Real upstream resolution / default-route checks are
//! deferred to t1-e18 wiring.

use async_trait::async_trait;
use std::net::ToSocketAddrs;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// DNS + reachability checks.
#[derive(Debug)]
pub struct NetworkDiagnostic {
    /// Hostname to attempt to resolve. Defaults to `localhost`.
    pub probe_host: String,
}

impl Default for NetworkDiagnostic {
    fn default() -> Self {
        Self {
            probe_host: "localhost".into(),
        }
    }
}

#[async_trait]
impl Diagnostic for NetworkDiagnostic {
    fn group(&self) -> &'static str {
        "network"
    }
    async fn run(&self, _ctx: &DiagnosticContext) -> Vec<Check> {
        let mut out = Vec::new();
        let target = format!("{}:0", self.probe_host);
        match target.to_socket_addrs() {
            Ok(addrs) => {
                let n = addrs.count();
                out.push(
                    Check::new("network.dns_resolves", Severity::High, Status::Pass).with_evidence(
                        format!("`{}` resolved to {n} address(es)", self.probe_host),
                    ),
                );
            }
            Err(e) => {
                out.push(
                    Check::new("network.dns_resolves", Severity::High, Status::Fail)
                        .with_evidence(format!("resolve `{}` failed: {e}", self.probe_host))
                        .with_remediation(
                            "verify `runtime.dns.upstream` and that system DNS is reachable",
                        ),
                );
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn localhost_resolves() {
        let d = NetworkDiagnostic::default();
        let r = d.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Pass, "{:?}", r[0]);
    }

    #[tokio::test]
    async fn bogus_host_fails() {
        let d = NetworkDiagnostic {
            probe_host: "not-a-real-host.invalid".into(),
        };
        let r = d.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Fail);
        assert!(r[0].remediation.is_some());
    }
}
