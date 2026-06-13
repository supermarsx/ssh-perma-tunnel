//! Secrets-subsystem readiness, driven by an injected `Resolver`.
//!
//! Per-backend health is sourced from `SecretBackend::doctor()` (read-only).
//! When `DiagnosticContext::allow_write_probes` is true the diagnostic also
//! attempts a round-trip set/get/delete on the *first* writable backend with
//! a probe namespace (`secret://spt.diagnostics/probe-<rand>`); the probe is
//! always removed in the same call. Per spec §13.12 diagnostics are
//! read-only by default, so the round-trip is opt-in.

use async_trait::async_trait;
use secrecy::ExposeSecret;
use std::sync::Arc;

use spt_secrets::{BackendKind, BackendStatus, Resolver, SecretRef};

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Real secrets diagnostic.
#[derive(Default, Debug)]
pub struct SecretsDiagnostic;

#[async_trait]
impl Diagnostic for SecretsDiagnostic {
    fn group(&self) -> &'static str {
        "secrets"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let Some(resolver) = ctx.resolver.clone() else {
            return vec![
                Check::new("secrets.resolver", Severity::High, Status::Skipped)
                    .with_evidence("no Resolver supplied via DiagnosticContext"),
            ];
        };

        let mut out = Vec::new();
        for d in resolver.backends().map(spt_secrets::SecretBackend::doctor) {
            let status = match d.status {
                BackendStatus::Ok => Status::Pass,
                BackendStatus::Degraded => Status::Warn,
                BackendStatus::Unavailable => Status::Skipped,
            };
            let sev = match d.kind {
                BackendKind::Keychain | BackendKind::Vault => Severity::High,
                BackendKind::Env | BackendKind::File => Severity::Medium,
            };
            let id = format!("secrets.backend.{}", kind_label(d.kind));
            let mut chk = Check::new(id, sev, status).with_evidence(d.message);
            if let Some(rem) = d.remediation {
                chk = chk.with_remediation(rem);
            }
            out.push(chk);
        }

        if ctx.allow_write_probes {
            out.extend(round_trip_probe(&resolver));
        } else {
            out.push(
                Check::new("secrets.round_trip", Severity::Info, Status::Skipped)
                    .with_evidence(
                        "round-trip probe disabled (set DiagnosticContext::allow_write_probes = true to enable)",
                    ),
            );
        }
        out
    }
}

fn kind_label(k: BackendKind) -> &'static str {
    match k {
        BackendKind::Keychain => "keychain",
        BackendKind::Vault => "vault",
        BackendKind::Env => "env",
        BackendKind::File => "file",
    }
}

fn round_trip_probe(resolver: &Arc<Resolver>) -> Vec<Check> {
    // Build a probe reference that survives strict validation:
    // namespace `spt.diagnostics`, name `probe-<lo64-of-now>`.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let r = match SecretRef::new("spt.diagnostics", format!("probe-{nonce}")) {
        Ok(r) => r,
        Err(e) => {
            return vec![
                Check::new("secrets.round_trip", Severity::Low, Status::Skipped)
                    .with_evidence(format!("could not build probe ref: {e}")),
            ];
        }
    };
    let payload: &[u8] = b"spt-diagnostics-probe";

    // Try each backend in chain order; first one that accepts `set` wins.
    for backend in resolver.backends() {
        // Err: backend rejected `set` — try the next one. (1.88 lint: redundant_continue)
        if backend.set(&r, payload).is_ok() {
            {
                // Round-trip read.
                let read = matches!(backend.get(&r), Ok(Some(b)) if b.expose_secret().as_slice() == payload);
                let removed = backend.remove(&r).unwrap_or(false);
                // Best-effort cleanup if `remove` lied.
                let _ = backend.remove(&r);
                let label = kind_label(backend.kind());
                let status = if read && removed {
                    Status::Pass
                } else {
                    Status::Fail
                };
                let mut chk = Check::new(
                    format!("secrets.round_trip.{label}"),
                    Severity::High,
                    status,
                )
                .with_evidence(format!(
                    "round-trip on `{label}`: get_match={read} removed={removed}"
                ));
                if status == Status::Fail {
                    chk = chk.with_remediation("inspect backend permissions / quotas");
                }
                return vec![chk];
            }
        }
    }

    vec![
        Check::new("secrets.round_trip", Severity::Low, Status::Skipped).with_evidence(
            "no backend accepted a write probe (all backends are read-only or unavailable)",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_core::Result;
    use spt_secrets::backend::secret_bytes;
    use spt_secrets::{
        BackendDoctor, BackendKind, BackendStatus, SecretBackend, SecretBytes, SecretRef,
    };
    use std::sync::Mutex;

    struct Mem {
        kind: BackendKind,
        store: Mutex<std::collections::HashMap<String, Vec<u8>>>,
        writable: bool,
        status: BackendStatus,
    }
    impl SecretBackend for Mem {
        fn kind(&self) -> BackendKind {
            self.kind
        }
        fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .get(&r.to_string())
                .cloned()
                .map(secret_bytes))
        }
        fn set(&self, r: &SecretRef, v: &[u8]) -> Result<()> {
            if !self.writable {
                return Err(spt_core::Error::UnsupportedPlatform("read-only".into()));
            }
            self.store.lock().unwrap().insert(r.to_string(), v.to_vec());
            Ok(())
        }
        fn list(&self) -> Result<Vec<SecretRef>> {
            Ok(Vec::new())
        }
        fn remove(&self, r: &SecretRef) -> Result<bool> {
            Ok(self.store.lock().unwrap().remove(&r.to_string()).is_some())
        }
        fn doctor(&self) -> BackendDoctor {
            match self.status {
                BackendStatus::Ok => BackendDoctor::ok(self.kind, "test backend ok"),
                BackendStatus::Degraded => BackendDoctor::degraded(self.kind, "x", "y"),
                BackendStatus::Unavailable => BackendDoctor::unavailable(self.kind, "x", "y"),
            }
        }
    }

    fn mk(kind: BackendKind, writable: bool, status: BackendStatus) -> Arc<dyn SecretBackend> {
        Arc::new(Mem {
            kind,
            store: Mutex::new(std::collections::HashMap::new()),
            writable,
            status,
        })
    }

    fn ctx_with(resolver: Resolver, allow_write: bool) -> DiagnosticContext {
        DiagnosticContext {
            resolver: Some(Arc::new(resolver)),
            allow_write_probes: allow_write,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn skipped_without_resolver() {
        let r = SecretsDiagnostic.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Skipped);
        assert_eq!(r[0].id, "secrets.resolver");
    }

    #[tokio::test]
    async fn maps_doctor_status_to_check_status() {
        let res = Resolver::new(vec![
            mk(BackendKind::Keychain, true, BackendStatus::Ok),
            mk(BackendKind::Vault, true, BackendStatus::Degraded),
            mk(BackendKind::Env, false, BackendStatus::Unavailable),
        ]);
        let ctx = ctx_with(res, false);
        let r = SecretsDiagnostic.run(&ctx).await;
        // Verify per-backend mapping.
        assert!(r
            .iter()
            .any(|c| c.id == "secrets.backend.keychain" && c.status == Status::Pass));
        assert!(r
            .iter()
            .any(|c| c.id == "secrets.backend.vault" && c.status == Status::Warn));
        assert!(r
            .iter()
            .any(|c| c.id == "secrets.backend.env" && c.status == Status::Skipped));
        // Round-trip skipped by default.
        assert!(r
            .iter()
            .any(|c| c.id == "secrets.round_trip" && c.status == Status::Skipped));
    }

    #[tokio::test]
    async fn round_trip_passes_on_writable_backend() {
        let res = Resolver::new(vec![mk(BackendKind::Keychain, true, BackendStatus::Ok)]);
        let ctx = ctx_with(res, true);
        let r = SecretsDiagnostic.run(&ctx).await;
        let rt = r
            .iter()
            .find(|c| c.id.starts_with("secrets.round_trip"))
            .expect("round-trip check");
        assert_eq!(rt.status, Status::Pass, "{rt:?}");
    }

    #[tokio::test]
    async fn round_trip_skipped_when_all_read_only() {
        let res = Resolver::new(vec![mk(BackendKind::Env, false, BackendStatus::Ok)]);
        let ctx = ctx_with(res, true);
        let r = SecretsDiagnostic.run(&ctx).await;
        assert!(r
            .iter()
            .any(|c| c.id == "secrets.round_trip" && c.status == Status::Skipped));
    }
}
