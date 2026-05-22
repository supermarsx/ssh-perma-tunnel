//! Unix GSSAPI backend (`libgssapi 0.9` — vendored fork).
//!
//! Drives `gss_init_sec_context` directly via `libgssapi::context::ClientCtx`.
//! Uses the caller's krb5 ticket cache (`/tmp/krb5cc_$UID` or whatever
//! `KRB5CCNAME` points at) by default; an explicit `principal` string may
//! be supplied to pick a non-default identity.
//!
//! NTLM is *not* supported on Unix even when libgssapi is present —
//! callers requesting NTLM via [`crate::sspi_provider_for`] receive
//! [`spt_core::Error::AuthFailed`] with the `UnsupportedOnUnix` marker.
//!
//! # MIC implementation
//!
//! [`GssProvider::get_mic`] and [`GssProvider::verify_mic`] call real
//! `gss_get_mic` / `gss_verify_mic` via the vendored
//! `libgssapi`-fork extension at `vendor/libgssapi-fork/`. The fork adds
//! these two methods to the `SecurityContext` trait — upstream
//! `libgssapi 0.9.1` only exposes `gss_wrap` / `gss_unwrap`. Routed
//! through the workspace `[patch.crates-io]` table.
//!
//! This produces an RFC 2743 `MIC` token (wire-distinct from a
//! non-encrypting `Wrap` token), wire-compatible with strict RFC 4462
//! §3.5 OpenSSH peers. See `.orchestration/logs/t7-P3.md`.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use libgssapi::context::{ClientCtx as GssClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred as GssCred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, GSS_NT_KRB5_PRINCIPAL};

use spt_core::{Diagnostic, Error, Result};

use crate::audit::AuditEvent;
use crate::{AuditHook, GssApiConfig, GssOutput, GssProvider};

fn map_gss_err<E: std::fmt::Display>(label: &str, err: E) -> Error {
    Error::AuthFailed(format!("libgssapi {label}: {err}"))
}

/// t8-A2: render a `catch_unwind` payload as a human-readable string.
///
/// The `Box<dyn Any + Send>` returned by [`std::panic::catch_unwind`] is the
/// raw panic payload — almost always a `String` (from `panic!("{}", …)`)
/// or a `&'static str` (string-literal panic). Anything else falls
/// through to a stable marker so the operator-facing diagnostic isn't
/// truncated. Kept private to this FFI module.
fn panic_string(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = p.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    "(non-string panic payload)".to_string()
}

/// t8-A2: run `f` and convert a panic crossing the libgssapi FFI boundary
/// into a structured [`Error::AuthFailedDiagnostic`].
///
/// `libgssapi` calls into the system MIT/Heimdal C library through `bindgen`
/// stubs. The C code is generally robust, but the vendored fork (see
/// `vendor/libgssapi-fork/`) extends `SecurityContext` with `get_mic` /
/// `verify_mic` shims that allocate `OM_uint32` minor-status slots and
/// dispatch through generic dispatch tables. Any `unwrap` along that path
/// (or a panic raised inside a `Drop` impl during error unwinding) would
/// otherwise abort the supervisor process. We catch here.
fn catch_gss_ffi<T>(label: &str, f: impl FnOnce() -> T) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|panic| {
        let msg = panic_string(&panic);
        Error::auth_failed(
            Diagnostic::what(format!(
                "libgssapi {label} panicked across the FFI boundary"
            ))
            .why(msg)
            .how_to_fix(
                "A libgssapi C call panicked. Verify the krb5 ticket cache is \
                 valid (`klist`), the target SPN is canonicalisable, and the \
                 vendored libgssapi fork is built against the matching MIT/Heimdal \
                 ABI. If reproducible, capture the offending exchange with \
                 SPT_LOG=spt_auth_sspi=trace and report at the spt-perma-tunnel repo.",
            )
            .build(),
        )
    })
}

fn make_target_name(spn: &str) -> Result<Name> {
    // Hostbased name form for `service@host` or `service/host@REALM` —
    // both are accepted by gss_import_name with GSS_C_NT_HOSTBASED_SERVICE.
    Name::new(spn.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .and_then(|n| n.canonicalize(Some(&GSS_MECH_KRB5)))
        .map_err(|e| map_gss_err("import target name", e))
}

fn make_client_cred(principal: Option<&str>) -> Result<GssCred> {
    let mut mechs = OidSet::new().map_err(|e| map_gss_err("oid set", e))?;
    mechs
        .add(&GSS_MECH_KRB5)
        .map_err(|e| map_gss_err("oid add", e))?;
    let name = match principal {
        Some(p) => {
            let n = Name::new(p.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))
                .map_err(|e| map_gss_err("import principal", e))?;
            Some(
                n.canonicalize(Some(&GSS_MECH_KRB5))
                    .map_err(|e| map_gss_err("canonicalize principal", e))?,
            )
        }
        None => None,
    };
    GssCred::acquire(name.as_ref(), None, CredUsage::Initiate, Some(&mechs))
        .map_err(|e| map_gss_err("acquire", e))
}

/// libgssapi-backed [`GssProvider`].
pub struct KerberosProvider {
    ctx: Mutex<GssClientCtx>,
    package: &'static str,
    rounds: Mutex<u32>,
    audit_hook: Option<Arc<dyn AuditHook>>,
}

impl std::fmt::Debug for KerberosProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KerberosProvider")
            .field("package", &self.package)
            .finish_non_exhaustive()
    }
}

impl KerberosProvider {
    fn new(cfg: &GssApiConfig, target: Name) -> Result<Self> {
        let cred = make_client_cred(cfg.principal.as_deref())?;
        let mut flags =
            CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_REPLAY_FLAG | CtxFlags::GSS_C_INTEG_FLAG;
        if cfg.delegate {
            flags |= CtxFlags::GSS_C_DELEG_FLAG;
        }
        if cfg.confidentiality {
            flags |= CtxFlags::GSS_C_CONF_FLAG;
        }
        let ctx = GssClientCtx::new(Some(cred), target, flags, Some(&GSS_MECH_KRB5));
        Ok(Self {
            ctx: Mutex::new(ctx),
            package: "kerberos",
            rounds: Mutex::new(0),
            audit_hook: cfg.audit_hook.clone(),
        })
    }

    fn emit(&self, event: &AuditEvent) {
        if let Some(h) = &self.audit_hook {
            h.on_event(event);
        }
    }
}

impl GssProvider for KerberosProvider {
    fn initialize(&mut self, _target: &str, input_token: Option<&[u8]>) -> Result<GssOutput> {
        let (token, complete) = {
            let mut ctx = self
                .ctx
                .lock()
                .map_err(|_| Error::AuthFailed("libgssapi: ctx mutex poisoned".into()))?;
            // t8-A2: wrap the `gss_init_sec_context` call (driven by
            // `ClientCtx::step`) in `catch_unwind`. A panic in the C-side
            // dispatch or in libgssapi's `OM_uint32` minor-status decoding
            // must surface as a clean `Error::AuthFailedDiagnostic` rather
            // than aborting the supervisor.
            let out = catch_gss_ffi("gss_init_sec_context", || ctx.step(input_token, None))?
                .map_err(|e| map_gss_err("step", e))?;
            let token = out.map(|buf| buf.to_vec());
            let complete = ctx.is_complete();
            (token, complete)
        };

        let round = {
            let mut r = self
                .rounds
                .lock()
                .map_err(|_| Error::AuthFailed("libgssapi: rounds mutex poisoned".into()))?;
            *r = r.saturating_add(1);
            *r
        };
        self.emit(&AuditEvent::TokenExchange {
            package: self.package,
            round,
            complete,
        });

        Ok(GssOutput { token, complete })
    }

    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>> {
        // Real `gss_get_mic` via the vendored libgssapi-fork (t7-P3).
        // Produces an RFC 2743 `MIC` token wire-compatible with strict
        // RFC 4462 §3.5 OpenSSH peers.
        let bytes = {
            let mut ctx = self
                .ctx
                .lock()
                .map_err(|_| Error::AuthFailed("libgssapi: ctx mutex poisoned".into()))?;
            // t8-A2: wrap `gss_get_mic` in `catch_unwind`. A panic here is
            // an integrity-token issuance bug — surface a clean diagnostic
            // instead of an abort that the supervisor would interpret as
            // a crash.
            let buf = catch_gss_ffi("gss_get_mic", || ctx.get_mic(message))?
                .map_err(|e| map_gss_err("get_mic", e))?;
            buf.to_vec()
        };
        self.emit(&AuditEvent::MicIssued {
            package: self.package,
            mic_len: bytes.len(),
        });
        Ok(bytes)
    }

    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<()> {
        // Real `gss_verify_mic` via the vendored libgssapi-fork (t7-P3).
        // The underlying `gss_verify_mic` performs the constant-time
        // integrity check internally; we no longer compare in Rust.
        let result = {
            let mut ctx = self
                .ctx
                .lock()
                .map_err(|_| Error::AuthFailed("libgssapi: ctx mutex poisoned".into()))?;
            // t8-A2: wrap `gss_verify_mic` in `catch_unwind`. A panic
            // inside the constant-time HMAC verify is a hard integrity
            // failure — surface as `auth_failed`, never abort.
            match catch_gss_ffi("gss_verify_mic", || ctx.verify_mic(message, mic)) {
                Ok(inner) => inner.map_err(|e| map_gss_err("verify_mic", e)),
                Err(e) => Err(e),
            }
        };
        match &result {
            Ok(()) => self.emit(&AuditEvent::MicVerified {
                package: self.package,
                ok: true,
            }),
            Err(_) => self.emit(&AuditEvent::MicVerified {
                package: self.package,
                ok: false,
            }),
        }
        result
    }
}

/// Real-backend entry point for [`crate::provider_for`].
///
/// Constructs a libgssapi `ClientCtx` against `cfg.service` (the target
/// SPN). Errors propagate from `gss_import_name` / `gss_acquire_cred` /
/// `gss_init_sec_context` if the local ticket cache is empty, the SPN
/// cannot be canonicalised, etc.
pub fn build_kerberos(cfg: &GssApiConfig) -> Result<Box<dyn GssProvider>> {
    let spn = cfg.service.as_deref().ok_or_else(|| {
        Error::AuthFailed(
            "libgssapi: `service` (target SPN, e.g. `host@server.example.com`) is required".into(),
        )
    })?;
    let target = make_target_name(spn)?;
    Ok(Box::new(KerberosProvider::new(cfg, target)?))
}

// ============================================================================
// t8-A2: panic-recovery boundary tests.
//
// The libgssapi FFI panic-recovery helper is exercised directly here so we
// don't need a live krb5 ticket cache to test the boundary contract. The
// real `KerberosProvider::initialize` / `get_mic` / `verify_mic` paths
// call `catch_gss_ffi` around the C-side step, so a panic crossing the
// boundary surfaces as `Error::AuthFailedDiagnostic` (not a process abort).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use spt_core::ExitCode;

    /// `panic_string` extracts both `String` and `&'static str` panic
    /// payloads. Anything else falls through to a stable marker.
    #[test]
    fn panic_string_handles_common_payloads() {
        let s_payload: Box<dyn std::any::Any + Send> = Box::new(String::from("ka-boom"));
        assert_eq!(panic_string(&s_payload), "ka-boom");
        let static_payload: Box<dyn std::any::Any + Send> = Box::new("literal");
        assert_eq!(panic_string(&static_payload), "literal");
        let other: Box<dyn std::any::Any + Send> = Box::new(7_u64);
        assert_eq!(panic_string(&other), "(non-string panic payload)");
    }

    /// `catch_gss_ffi` returns `Ok` when the inner closure runs to
    /// completion — no false-positive auth failures.
    #[test]
    fn catch_gss_ffi_passes_through_normal_returns() {
        let v = catch_gss_ffi("step", || 42_u32).expect("no panic, no error");
        assert_eq!(v, 42);
    }

    /// A panic inside the wrapped closure surfaces as
    /// `Error::AuthFailedDiagnostic` carrying the panic message — the
    /// supervisor sees a structured error, never a SIGABRT.
    #[test]
    fn kerberos_get_mic_panic_surfaces_as_runtime_failure() {
        let err = catch_gss_ffi("gss_get_mic", || -> u32 {
            panic!("C-side null pointer in gss_get_mic")
        })
        .expect_err("panic must surface as Error");
        // Auth-failed diagnostics map to the auth-failure exit class.
        assert_eq!(err.exit_code(), ExitCode::AuthFailed);
        let d = err.diagnostic().expect("structured diagnostic");
        assert!(
            d.what.contains("gss_get_mic") && d.what.contains("panicked across the FFI boundary"),
            "boundary marker missing from `what`: {}",
            d.what,
        );
        assert!(
            d.why.as_deref().unwrap().contains("C-side null pointer"),
            "panic payload not carried in `why`: {:?}",
            d.why,
        );
        assert!(
            d.how_to_fix.as_deref().unwrap().contains("libgssapi"),
            "fix-it text should mention libgssapi: {:?}",
            d.how_to_fix,
        );
    }

    /// `catch_gss_ffi` is reusable across labels — the label is woven
    /// into the diagnostic so the operator knows which call site exploded.
    #[test]
    fn catch_gss_ffi_label_appears_in_diagnostic() {
        let err = catch_gss_ffi("gss_verify_mic", || -> u8 { panic!("hmac decode") })
            .expect_err("expected panic");
        let d = err.diagnostic().expect("structured");
        assert!(d.what.contains("gss_verify_mic"));
    }

    /// `catch_gss_ffi` carries a literal-string panic payload through to
    /// the diagnostic's `why` field unchanged.
    #[test]
    fn catch_gss_ffi_preserves_static_str_payload() {
        let err = catch_gss_ffi("gss_init_sec_context", || -> u8 { panic!("literal panic") })
            .expect_err("expected panic");
        let d = err.diagnostic().expect("structured");
        assert_eq!(d.why.as_deref(), Some("literal panic"));
    }
}
