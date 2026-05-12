//! Runtime-process introspection from the on-disk `status.json` snapshot.
//!
//! Reads `<state_dir>/status.json` (written by the running daemon's
//! `StatusWriter`) and emits checks for uptime, profile state distribution,
//! and recent error counts. When the snapshot is absent we report
//! `Skipped` — the daemon may simply not be running.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::BTreeMap;

use spt_state::{paths, StatusSnapshot};

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Runtime diagnostic.
#[derive(Default, Debug)]
pub struct RuntimeDiagnostic;

#[async_trait]
impl Diagnostic for RuntimeDiagnostic {
    fn group(&self) -> &str {
        "runtime"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let Some(dir) = ctx.state_dir.as_ref() else {
            return vec![
                Check::new("runtime.snapshot", Severity::Info, Status::Skipped)
                    .with_evidence("no state_dir supplied via DiagnosticContext"),
            ];
        };
        let path = paths::status_path(dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return vec![
                    Check::new("runtime.snapshot", Severity::Info, Status::Skipped)
                        .with_evidence(format!("no status snapshot at {}", path.display()))
                        .with_remediation(
                            "start the daemon (`spt service start`) to populate runtime state",
                        ),
                ];
            }
            Err(e) => {
                return vec![
                    Check::new("runtime.snapshot", Severity::Medium, Status::Fail)
                        .with_evidence(format!("read {}: {e}", path.display())),
                ];
            }
        };
        let snap: StatusSnapshot = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(e) => {
                return vec![Check::new("runtime.snapshot", Severity::High, Status::Fail)
                    .with_evidence(format!("parse status.json: {e}"))
                    .with_remediation(
                        "the daemon may be writing an incompatible schema; restart it",
                    )];
            }
        };

        let mut out = Vec::new();
        out.push(
            Check::new("runtime.snapshot", Severity::Info, Status::Pass)
                .with_evidence(format!("loaded snapshot from {}", path.display()))
                .with_evidence(format!("pid = {}", snap.pid))
                .with_evidence(format!("version = {}", snap.version)),
        );

        // Uptime.
        if let Some(started) = snap.started_at {
            let secs = (Utc::now() - started).num_seconds().max(0);
            out.push(
                Check::new("runtime.uptime", Severity::Info, Status::Pass)
                    .with_evidence(format!("uptime = {secs}s"))
                    .with_evidence(format!("started_at = {started}")),
            );
        } else {
            out.push(
                Check::new("runtime.uptime", Severity::Low, Status::Skipped)
                    .with_evidence("started_at not set in snapshot"),
            );
        }

        // Profile state distribution.
        let mut by_state: BTreeMap<String, usize> = BTreeMap::new();
        for p in &snap.profiles {
            *by_state.entry(p.state.clone()).or_default() += 1;
        }
        let any_failed = by_state
            .iter()
            .any(|(s, _)| s == "failed" || s == "fatal" || s == "errored");
        let chk_status = if snap.profiles.is_empty() {
            Status::Skipped
        } else if any_failed {
            Status::Warn
        } else {
            Status::Pass
        };
        let evidence = if snap.profiles.is_empty() {
            "no profiles in snapshot".to_string()
        } else {
            by_state
                .iter()
                .map(|(s, n)| format!("{s}={n}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        out.push(
            Check::new("runtime.profiles", Severity::Medium, chk_status).with_evidence(format!(
                "profiles: {} total; states: {evidence}",
                snap.profiles.len()
            )),
        );

        // Recent error counts.
        let n = snap.last_errors.len();
        let err_status = if n == 0 {
            Status::Pass
        } else if n < 5 {
            Status::Warn
        } else {
            Status::Fail
        };
        let mut chk = Check::new("runtime.recent_errors", Severity::Medium, err_status)
            .with_evidence(format!("last_errors count = {n}"));
        if let Some(first) = snap.last_errors.first() {
            chk = chk.with_evidence(format!(
                "most-recent: scope={} category={}",
                first.scope, first.category,
            ));
        }
        if n >= 5 {
            chk = chk.with_remediation("inspect recent errors via `spt status --json`");
        }
        out.push(chk);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use spt_state::status::{LastError, ProfileStatus};
    use tempfile::tempdir;

    fn mkctx(dir: &std::path::Path) -> DiagnosticContext {
        DiagnosticContext {
            state_dir: Some(dir.to_path_buf()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn skipped_without_state_dir() {
        let r = RuntimeDiagnostic.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn skipped_when_snapshot_absent() {
        let d = tempdir().unwrap();
        let r = RuntimeDiagnostic.run(&mkctx(d.path())).await;
        assert_eq!(r[0].status, Status::Skipped);
        assert!(r[0]
            .evidence
            .iter()
            .any(|e| e.contains("no status snapshot")));
    }

    fn write_snapshot(dir: &std::path::Path, snap: &StatusSnapshot) {
        std::fs::write(paths::status_path(dir), serde_json::to_vec(snap).unwrap()).unwrap();
    }

    #[tokio::test]
    async fn happy_path_passes() {
        let d = tempdir().unwrap();
        let mut snap = StatusSnapshot {
            pid: 42,
            version: "0.1.0".into(),
            started_at: Some(Utc::now() - ChronoDuration::seconds(60)),
            ..Default::default()
        };
        snap.profiles.push(ProfileStatus {
            id: "p1".into(),
            state: "running".into(),
            ..Default::default()
        });
        write_snapshot(d.path(), &snap);

        let r = RuntimeDiagnostic.run(&mkctx(d.path())).await;
        assert!(r
            .iter()
            .any(|c| c.id == "runtime.snapshot" && c.status == Status::Pass));
        assert!(r
            .iter()
            .any(|c| c.id == "runtime.uptime" && c.status == Status::Pass));
        assert!(r
            .iter()
            .any(|c| c.id == "runtime.profiles" && c.status == Status::Pass));
        assert!(r
            .iter()
            .any(|c| c.id == "runtime.recent_errors" && c.status == Status::Pass));
    }

    #[tokio::test]
    async fn failed_profile_warns() {
        let d = tempdir().unwrap();
        let mut snap = StatusSnapshot::default();
        snap.profiles.push(ProfileStatus {
            id: "p1".into(),
            state: "failed".into(),
            ..Default::default()
        });
        write_snapshot(d.path(), &snap);
        let r = RuntimeDiagnostic.run(&mkctx(d.path())).await;
        let p = r.iter().find(|c| c.id == "runtime.profiles").unwrap();
        assert_eq!(p.status, Status::Warn);
    }

    #[tokio::test]
    async fn many_errors_fail() {
        let d = tempdir().unwrap();
        let mut snap = StatusSnapshot::default();
        for _ in 0..6 {
            snap.last_errors.push(LastError {
                scope: "network".into(),
                category: "Transient".into(),
                ..Default::default()
            });
        }
        write_snapshot(d.path(), &snap);
        let r = RuntimeDiagnostic.run(&mkctx(d.path())).await;
        let e = r.iter().find(|c| c.id == "runtime.recent_errors").unwrap();
        assert_eq!(e.status, Status::Fail);
        assert!(e.remediation.is_some());
    }

    #[tokio::test]
    async fn malformed_snapshot_fails() {
        let d = tempdir().unwrap();
        std::fs::write(paths::status_path(d.path()), b"not json").unwrap();
        let r = RuntimeDiagnostic.run(&mkctx(d.path())).await;
        assert_eq!(r[0].status, Status::Fail);
    }
}
