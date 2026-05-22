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

use std::sync::{Arc, Mutex};

use libgssapi::context::{ClientCtx as GssClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred as GssCred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, GSS_NT_KRB5_PRINCIPAL};

use spt_core::{Error, Result};

use crate::audit::AuditEvent;
use crate::{AuditHook, GssApiConfig, GssOutput, GssProvider};

fn map_gss_err<E: std::fmt::Display>(label: &str, err: E) -> Error {
    Error::AuthFailed(format!("libgssapi {label}: {err}"))
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
        let mut flags = CtxFlags::GSS_C_MUTUAL_FLAG
            | CtxFlags::GSS_C_REPLAY_FLAG
            | CtxFlags::GSS_C_INTEG_FLAG;
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
            let out = ctx
                .step(input_token, None)
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
            let buf = ctx
                .get_mic(message)
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
            ctx.verify_mic(message, mic)
                .map_err(|e| map_gss_err("verify_mic", e))
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
