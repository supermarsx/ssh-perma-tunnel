//! System time check (`NTP`-drift detection deferred — we just record `now()`).

use async_trait::async_trait;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Records system time. NTP synchronisation status is platform-specific and
/// deferred to t1-e18; this check always passes and emits the current UTC
/// timestamp as evidence so the bundle can be cross-referenced with logs.
#[derive(Default, Debug)]
pub struct TimeDiagnostic;

#[async_trait]
impl Diagnostic for TimeDiagnostic {
    fn group(&self) -> &'static str {
        "time"
    }
    async fn run(&self, _ctx: &DiagnosticContext) -> Vec<Check> {
        let now = chrono::Utc::now().to_rfc3339();
        vec![
            Check::new("time.utc_now", Severity::Info, Status::Pass)
                .with_evidence(format!("utc = {now}")),
            Check::new("time.ntp_drift", Severity::Low, Status::Skipped)
                .with_evidence("ntp drift probe not implemented yet")
                .with_remediation("run `chronyc tracking` / `w32tm /query /status` manually"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn time_check_emits_two() {
        let r = TimeDiagnostic.run(&DiagnosticContext::default()).await;
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].status, Status::Pass);
        assert_eq!(r[1].status, Status::Skipped);
    }
}
