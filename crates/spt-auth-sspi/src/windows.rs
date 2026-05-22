//! Windows SSPI backend (`sspi 0.15`).
//!
//! Drives the SSPI Negotiate / Kerberos / NTLM packages from
//! `devolutions/sspi-rs`. The pure-Rust implementation does not call into the
//! Win32 SSPI subsystem (so it does not pick up the currently-logged-on user's
//! ambient credentials for "free"); the caller is expected to thread its own
//! `username@DOMAIN` + password through the supplied [`SspiCredentials`].
//!
//! For Windows-with-AD environments where SSO is the goal, fold the user's
//! credentials in at the supervisor layer (or use the OS-native
//! `windows-rs` SSPI bindings from a separate executor — out of scope for
//! t7-A3). This backend exposes the explicit-credential path which is the
//! one common to every real RFC 4462 implementation.

use std::env;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use sspi::ntlm::NtlmConfig;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Kerberos,
    KerberosConfig, Negotiate, NegotiateConfig, Ntlm, SecurityBuffer, SecurityBufferRef,
    SecurityStatus, Sspi, SspiImpl, Username,
};

use spt_core::{Diagnostic, Error, Result};

use crate::audit::AuditEvent;
use crate::{AuditHook, GssOutput, GssProvider, SspiConfig};

/// t8-A2: render a `catch_unwind` payload as a human-readable string.
///
/// The `Box<dyn Any + Send>` returned by [`std::panic::catch_unwind`] is the
/// raw panic payload — usually a `String` (from `panic!("{}", …)`) or a
/// `&'static str` (from `panic!("literal")`). Custom panic types fall
/// through to a stable marker. Kept private so each FFI module owns its
/// own helper.
fn panic_string(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = p.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    "(non-string panic payload)".to_string()
}

/// t8-A2: run `f` and convert a panic crossing the SSPI FFI boundary into a
/// structured [`Error::AuthFailedDiagnostic`].
///
/// The pure-Rust `sspi` crate is *mostly* memory-safe, but it parses
/// untrusted-but-server-blessed token bytes from the wire and contains
/// `unwrap` paths in deeper helpers (`SecurityStatus` conversion, ASN.1
/// decoders, …). A panic from one of those would otherwise unwind through
/// the calling task and — depending on the workspace's `panic = "abort"`
/// setting — kill the supervisor. We catch here.
fn catch_sspi_ffi<T>(label: &str, f: impl FnOnce() -> T) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|panic| {
        let msg = panic_string(&panic);
        Error::auth_failed(
            Diagnostic::what(format!(
                "SSPI {label} panicked across the FFI boundary"
            ))
            .why(msg)
            .how_to_fix(
                "An sspi-rs call into pure-Rust SSPI panicked. Verify the SSPI \
                 package handle is valid and the credential/token buffers are not \
                 concurrently aliased. If reproducible, capture the offending \
                 token via SPT_LOG=spt_auth_sspi=trace and report at the \
                 spt-perma-tunnel repo.",
            )
            .build(),
        )
    })
}

/// Explicit credentials threaded into the SSPI initiator.
///
/// Recovered from the runtime environment (`SPT_SSPI_USER`, `SPT_SSPI_PASS`,
/// `SPT_SSPI_KDC_URL`) when the caller doesn't supply them out-of-band. The
/// pure-Rust sspi crate cannot resolve current-user SSO — these must be set
/// for the initiator to do anything useful.
#[derive(Debug, Clone)]
pub struct SspiCredentials {
    /// `user@DOMAIN` form.
    pub username: String,
    /// Plaintext password.
    pub password: String,
    /// KDC URL (`tcp://kdc:88`, `udp://kdc:88`, `https://…` for KKDCP).
    pub kdc_url: String,
}

impl SspiCredentials {
    /// Try to recover credentials from `SPT_SSPI_USER`, `SPT_SSPI_PASS`,
    /// `SPT_SSPI_KDC_URL`. Returns `None` if any are absent or empty.
    pub fn from_env() -> Option<Self> {
        let username = env::var("SPT_SSPI_USER").ok().filter(|s| !s.is_empty())?;
        let password = env::var("SPT_SSPI_PASS").ok().filter(|s| !s.is_empty())?;
        let kdc_url = env::var("SPT_SSPI_KDC_URL").ok().filter(|s| !s.is_empty())?;
        Some(Self {
            username,
            password,
            kdc_url,
        })
    }
}

// `Kerberos` is ~1KB, the others much smaller; box the large variants so
// the enum stays compact (`clippy::large_enum_variant`).
enum SspiContext {
    Kerberos(Box<(Kerberos, <Kerberos as SspiImpl>::CredentialsHandle)>),
    Negotiate(Box<(Negotiate, <Negotiate as SspiImpl>::CredentialsHandle)>),
    Ntlm(Box<(Ntlm, <Ntlm as SspiImpl>::CredentialsHandle)>),
}

impl std::fmt::Debug for SspiContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kerberos(_) => f.write_str("SspiContext::Kerberos"),
            Self::Negotiate(_) => f.write_str("SspiContext::Negotiate"),
            Self::Ntlm(_) => f.write_str("SspiContext::Ntlm"),
        }
    }
}

/// SSPI-backed [`GssProvider`].
pub struct SspiProvider {
    ctx: Mutex<SspiContext>,
    flags: ClientRequestFlags,
    package: &'static str,
    rounds: Mutex<u32>,
    audit_hook: Option<Arc<dyn AuditHook>>,
}

impl std::fmt::Debug for SspiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SspiProvider")
            .field("package", &self.package)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

fn map_sspi_err(err: &sspi::Error) -> Error {
    Error::AuthFailed(format!("sspi: {err}"))
}

fn build_flags(cfg: &SspiConfig) -> ClientRequestFlags {
    let mut flags =
        ClientRequestFlags::MUTUAL_AUTH | ClientRequestFlags::ALLOCATE_MEMORY;
    if cfg.delegate {
        flags |= ClientRequestFlags::DELEGATE;
    }
    if cfg.confidentiality {
        flags |= ClientRequestFlags::CONFIDENTIALITY;
    }
    flags
}

fn parse_identity(user: &str, password: &str) -> Result<AuthIdentity> {
    let username = Username::parse(user)
        .map_err(|e| Error::AuthFailed(format!("invalid SSPI username `{user}`: {e}")))?;
    Ok(AuthIdentity {
        username,
        password: password.to_owned().into(),
    })
}

impl SspiProvider {
    fn new_kerberos(cfg: &SspiConfig, creds: &SspiCredentials) -> Result<Self> {
        let kerb_cfg = KerberosConfig::new(&creds.kdc_url, hostname_or_localhost());
        let mut kerberos = Kerberos::new_client_from_config(kerb_cfg).map_err(|e| map_sspi_err(&e))?;
        let identity = parse_identity(&creds.username, &creds.password)?;
        let acq = kerberos
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity.into())
            .execute(&mut kerberos)
            .map_err(|e| map_sspi_err(&e))?;
        Ok(Self {
            ctx: Mutex::new(SspiContext::Kerberos(Box::new((
                kerberos,
                acq.credentials_handle,
            )))),
            flags: build_flags(cfg),
            package: "kerberos",
            rounds: Mutex::new(0),
            audit_hook: cfg.audit_hook.clone(),
        })
    }

    fn new_ntlm(cfg: &SspiConfig, creds: &SspiCredentials) -> Result<Self> {
        let mut ntlm = Ntlm::with_config(NtlmConfig::new(hostname_or_localhost()));
        let identity = parse_identity(&creds.username, &creds.password)?;
        let acq = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)
            .map_err(|e| map_sspi_err(&e))?;
        Ok(Self {
            ctx: Mutex::new(SspiContext::Ntlm(Box::new((ntlm, acq.credentials_handle)))),
            flags: build_flags(cfg),
            package: "ntlm",
            rounds: Mutex::new(0),
            audit_hook: cfg.audit_hook.clone(),
        })
    }

    fn new_negotiate(cfg: &SspiConfig, creds: &SspiCredentials) -> Result<Self> {
        let kerb_cfg = KerberosConfig::new(&creds.kdc_url, hostname_or_localhost());
        let pkg_list = if cfg.allow_ntlm_fallback {
            Some("kerberos,ntlm".to_owned())
        } else {
            Some("kerberos".to_owned())
        };
        let neg_cfg =
            NegotiateConfig::new(Box::new(kerb_cfg), pkg_list, hostname_or_localhost());
        let mut negotiate = Negotiate::new(neg_cfg).map_err(|e| map_sspi_err(&e))?;
        let identity = parse_identity(&creds.username, &creds.password)?;
        let acq = negotiate
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity.into())
            .execute(&mut negotiate)
            .map_err(|e| map_sspi_err(&e))?;
        Ok(Self {
            ctx: Mutex::new(SspiContext::Negotiate(Box::new((
                negotiate,
                acq.credentials_handle,
            )))),
            flags: build_flags(cfg),
            package: "negotiate",
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

fn hostname_or_localhost() -> String {
    env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".to_owned())
}

impl GssProvider for SspiProvider {
    fn initialize(&mut self, target: &str, input_token: Option<&[u8]>) -> Result<GssOutput> {
        let mut input = input_token
            .map(|t| vec![SecurityBuffer::new(t.to_vec(), BufferType::Token)])
            .unwrap_or_default();
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let status = {
            let mut ctx = self
                .ctx
                .lock()
                .map_err(|_| Error::AuthFailed("sspi: context mutex poisoned".into()))?;
            let target_owned = target.to_owned();
            // t8-A2: wrap the SSPI `initialize_security_context` call(s) in
            // `catch_unwind` so a panic inside `sspi-rs` (e.g. malformed
            // KRB5 token blob from a hostile peer) returns a clean
            // `Error::AuthFailedDiagnostic` instead of aborting the process.
            // The `??` unwraps both layers: outer `Result` is the panic
            // catcher, inner is the sspi-rs result.
            catch_sspi_ffi("initialize_security_context", || -> Result<SecurityStatus> {
            Ok(match &mut *ctx {
                SspiContext::Kerberos(boxed) => {
                    let (k, creds) = (&mut boxed.0, &mut boxed.1);
                    let mut builder = k
                        .initialize_security_context()
                        .with_credentials_handle(creds)
                        .with_context_requirements(self.flags)
                        .with_target_data_representation(DataRepresentation::Native)
                        .with_target_name(&target_owned)
                        .with_input(&mut input)
                        .with_output(&mut output);
                    let result = k
                        .initialize_security_context_impl(&mut builder)
                        .map_err(|e| map_sspi_err(&e))?
                        .resolve_to_result()
                        .map_err(|e| map_sspi_err(&e))?;
                    result.status
                }
                SspiContext::Negotiate(boxed) => {
                    let (n, creds) = (&mut boxed.0, &mut boxed.1);
                    let mut builder = n
                        .initialize_security_context()
                        .with_credentials_handle(creds)
                        .with_context_requirements(self.flags)
                        .with_target_data_representation(DataRepresentation::Native)
                        .with_target_name(&target_owned)
                        .with_input(&mut input)
                        .with_output(&mut output);
                    let result = n
                        .initialize_security_context_impl(&mut builder)
                        .map_err(|e| map_sspi_err(&e))?
                        .resolve_to_result()
                        .map_err(|e| map_sspi_err(&e))?;
                    result.status
                }
                SspiContext::Ntlm(boxed) => {
                    let (n, creds) = (&mut boxed.0, &mut boxed.1);
                    let mut builder = n
                        .initialize_security_context()
                        .with_credentials_handle(creds)
                        .with_context_requirements(self.flags)
                        .with_target_data_representation(DataRepresentation::Native)
                        .with_target_name(&target_owned)
                        .with_input(&mut input)
                        .with_output(&mut output);
                    let result = n
                        .initialize_security_context_impl(&mut builder)
                        .map_err(|e| map_sspi_err(&e))?
                        .resolve_to_result()
                        .map_err(|e| map_sspi_err(&e))?;
                    result.status
                }
            })
            })??
        };

        let complete = matches!(
            status,
            SecurityStatus::Ok | SecurityStatus::CompleteNeeded | SecurityStatus::CompleteAndContinue
        );

        let token = {
            let buf = output.into_iter().next().map(|b| b.buffer).unwrap_or_default();
            if buf.is_empty() { None } else { Some(buf) }
        };

        let round = {
            let mut r = self
                .rounds
                .lock()
                .map_err(|_| Error::AuthFailed("sspi: rounds mutex poisoned".into()))?;
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

    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<()> {
        let mut msg = message.to_vec();
        let mut tok = mic.to_vec();
        let result = {
            let mut ctx = self
                .ctx
                .lock()
                .map_err(|_| Error::AuthFailed("sspi: context mutex poisoned".into()))?;
            let mut bufs = [
                SecurityBufferRef::data_buf(&mut msg),
                SecurityBufferRef::token_buf(&mut tok),
            ];
            // t8-A2: wrap `verify_signature` in `catch_unwind`. A panic in
            // the sspi-rs HMAC verify path is otherwise an integrity-check
            // bypass risk — we want a hard `auth_failed` diagnostic, not a
            // process abort that the supervisor may interpret as a crash.
            catch_sspi_ffi("verify_signature", || {
                match &mut *ctx {
                    SspiContext::Kerberos(boxed) => boxed.0.verify_signature(&mut bufs, 0),
                    SspiContext::Negotiate(boxed) => boxed.0.verify_signature(&mut bufs, 0),
                    SspiContext::Ntlm(boxed) => boxed.0.verify_signature(&mut bufs, 0),
                }
            })?
        };
        match result {
            Ok(_) => {
                self.emit(&AuditEvent::MicVerified {
                    package: self.package,
                    ok: true,
                });
                Ok(())
            }
            Err(e) => {
                self.emit(&AuditEvent::MicVerified {
                    package: self.package,
                    ok: false,
                });
                Err(map_sspi_err(&e))
            }
        }
    }

    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut msg = message.to_vec();
        // The MIC token will be written into this buffer by `make_signature`.
        // SSPI implementations vary in the buffer size they want — 256 bytes
        // is more than enough for any RFC 4121 MIC token.
        let mut tok = vec![0u8; 256];
        let result = {
            let mut ctx = self
                .ctx
                .lock()
                .map_err(|_| Error::AuthFailed("sspi: context mutex poisoned".into()))?;
            let mut bufs = [
                SecurityBufferRef::data_buf(&mut msg),
                SecurityBufferRef::token_buf(&mut tok),
            ];
            // t8-A2: catch_unwind across `make_signature`. Same rationale
            // as `verify_signature` — a panic here must not abort the
            // process; surface a clean auth-failed diagnostic instead.
            catch_sspi_ffi("make_signature", || {
                match &mut *ctx {
                    SspiContext::Kerberos(boxed) => boxed.0.make_signature(0, &mut bufs, 0),
                    SspiContext::Negotiate(boxed) => boxed.0.make_signature(0, &mut bufs, 0),
                    SspiContext::Ntlm(boxed) => boxed.0.make_signature(0, &mut bufs, 0),
                }
            })?
        };
        result.map_err(|e| map_sspi_err(&e))?;
        // `tok` may be over-allocated; trim any all-zero trailing padding
        // back to the meaningful prefix as reported by the buffer.
        let trimmed = trim_trailing_zeros(&tok);
        self.emit(&AuditEvent::MicIssued {
            package: self.package,
            mic_len: trimmed.len(),
        });
        Ok(trimmed)
    }
}

fn trim_trailing_zeros(buf: &[u8]) -> Vec<u8> {
    let mut end = buf.len();
    while end > 0 && buf[end - 1] == 0 {
        end -= 1;
    }
    buf[..end].to_vec()
}

/// Real-backend entry point for [`crate::sspi_provider_for`].
///
/// Selects the SSPI package based on `cfg.allow_ntlm_fallback`:
/// * `false` ⇒ pure Kerberos;
/// * `true`  ⇒ Negotiate (Kerberos first, NTLM fallback).
///
/// When the caller hasn't threaded credentials in another way, falls back
/// to [`SspiCredentials::from_env`] reading `SPT_SSPI_USER`, `SPT_SSPI_PASS`,
/// `SPT_SSPI_KDC_URL`. Without credentials we return a clear
/// [`Error::AuthFailed`] rather than panic — the caller has the option to
/// rerun under a wider auth chain.
pub fn build(cfg: &SspiConfig) -> Result<Box<dyn GssProvider>> {
    let Some(creds) = SspiCredentials::from_env() else {
        return Err(Error::AuthFailed(
            "sspi: no credentials supplied. Set SPT_SSPI_USER / SPT_SSPI_PASS / \
             SPT_SSPI_KDC_URL or wire credentials via the supervisor."
                .to_owned(),
        ));
    };
    let provider = if cfg.allow_ntlm_fallback {
        SspiProvider::new_negotiate(cfg, &creds)?
    } else {
        SspiProvider::new_kerberos(cfg, &creds)?
    };
    Ok(Box::new(provider))
}

/// Build a pure-NTLM [`SspiProvider`] (no Kerberos at all). Exposed so
/// callers that explicitly want NTLM (e.g. a legacy workgroup deployment
/// without a KDC) can opt in. Returns [`Error::AuthFailed`] when env-vars
/// are missing.
pub fn build_ntlm(cfg: &SspiConfig) -> Result<Box<dyn GssProvider>> {
    let creds = SspiCredentials::from_env().ok_or_else(|| {
        Error::AuthFailed(
            "sspi-ntlm: no credentials supplied. Set SPT_SSPI_USER / SPT_SSPI_PASS".to_owned(),
        )
    })?;
    Ok(Box::new(SspiProvider::new_ntlm(cfg, &creds)?))
}

// ============================================================================
// t8-A2: panic-recovery boundary tests for the SSPI FFI helper.
//
// Exercises the boundary contract directly — a panic crossing the
// `catch_sspi_ffi` wrapper surfaces as `Error::AuthFailedDiagnostic`,
// never as a process abort. Doesn't require a live SSPI handle.
// ============================================================================

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use spt_core::ExitCode;

    /// `panic_string` extracts both `String` and `&'static str` panic
    /// payloads; anything else falls through to a stable marker.
    #[test]
    fn panic_string_handles_common_payloads() {
        let s_payload: Box<dyn std::any::Any + Send> =
            Box::new(String::from("sspi exploded"));
        assert_eq!(panic_string(&s_payload), "sspi exploded");
        let static_payload: Box<dyn std::any::Any + Send> = Box::new("literal");
        assert_eq!(panic_string(&static_payload), "literal");
        let weird: Box<dyn std::any::Any + Send> = Box::new(123_i32);
        assert_eq!(panic_string(&weird), "(non-string panic payload)");
    }

    /// Normal returns pass through unchanged — no false-positive auth
    /// failures.
    #[test]
    fn catch_sspi_ffi_passes_through_normal_returns() {
        let v = catch_sspi_ffi("initialize_security_context", || "ok").expect("no panic");
        assert_eq!(v, "ok");
    }

    /// A panic inside the wrapped closure surfaces as
    /// `Error::AuthFailedDiagnostic` carrying the panic payload — never an
    /// abort.
    #[test]
    fn sspi_initialize_panic_surfaces_as_auth_failed_diagnostic() {
        let err = catch_sspi_ffi("initialize_security_context", || -> u32 {
            panic!("malformed KRB5 AP_REP token")
        })
        .expect_err("panic must surface as Error");
        assert_eq!(err.exit_code(), ExitCode::AuthFailed);
        let d = err.diagnostic().expect("structured diagnostic");
        assert!(
            d.what.contains("initialize_security_context")
                && d.what.contains("panicked across the FFI boundary"),
            "boundary marker missing: {}",
            d.what,
        );
        assert!(
            d.why.as_deref().unwrap().contains("malformed KRB5"),
            "panic payload not carried: {:?}",
            d.why,
        );
        assert!(
            d.how_to_fix.as_deref().unwrap().contains("sspi"),
            "fix-it should mention sspi: {:?}",
            d.how_to_fix,
        );
    }

    /// The label is interpolated into the `what` field so the operator
    /// knows which sspi call site exploded.
    #[test]
    fn catch_sspi_ffi_label_appears_in_diagnostic() {
        let err = catch_sspi_ffi("verify_signature", || -> u8 { panic!("hmac") })
            .expect_err("panic");
        let d = err.diagnostic().expect("structured");
        assert!(d.what.contains("verify_signature"));
    }
}
