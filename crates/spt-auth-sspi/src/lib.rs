//! GSSAPI / Kerberos / SSPI / NTLM provider backends.
//!
//! This crate sits behind the [`spt_auth::AuthMethod::Gssapi`] and
//! [`spt_auth::AuthMethod::Sspi`] variants. It defines the [`GssProvider`]
//! trait — a thin abstraction over `gss_init_sec_context` / `InitializeSecurityContext`
//! sufficient to drive the SSH `gssapi-with-mic` userauth method (RFC 4462)
//! through one or more token round-trips and to compute / verify the per-userauth
//! MIC that proves possession of the established security context.
//!
//! # Backends
//!
//! | Target  | Library             | Mechanisms                 |
//! |---------|---------------------|----------------------------|
//! | Windows | `sspi = 0.15`       | Kerberos, NTLM, Negotiate  |
//! | Unix    | `libgssapi = 0.9`   | Kerberos-5 only            |
//!
//! The Unix dependency choice deviates from the t7-A3 plan's
//! `cross-krb5 0.4` call: `cross-krb5` exposes only `wrap`/`unwrap`, not
//! `gss_get_mic` / `gss_verify_mic`. SSH `gssapi-with-mic` (RFC 4462 §3.5)
//! mandates the MIC token form (RFC 2743), which is wire-distinct from a
//! non-encrypting Wrap token. We use `libgssapi` directly — `cross-krb5`
//! was going to pull it transitively in any case, so the dependency-graph
//! delta is zero. See `.orchestration/logs/t7-A3.md` for the decision
//! record (including the `picky 7.0.0-rc.12` transitive pin needed to make
//! `sspi 0.15.12` build on stable 1.85).
//!
//! ## Test infrastructure
//!
//! Real GSS / SSPI round-trips require an external KDC or Active Directory
//! domain. The crate ships:
//!
//! * `mock::MockGssProvider` — an in-process, deterministic-token
//!   `GssProvider` for unit-level testing (`testing` feature).
//! * `KERBEROS_LIVE=1` / `SSPI_KDC_URL=…` -gated integration tests that
//!   exercise the real `libgssapi` / `sspi` code paths against a live
//!   Heimdal / MIT-KRB5 / AD fixture (`#[ignore]` by default so CI is opt-in).
//!
//! Every token exchange and MIC operation also fires an [`AuditHook`]
//! event so the supervisor's audit subscriber (wired by Phase B1) can
//! record per-step provenance.
//!
//! # SSH `gssapi-with-mic` shape
//!
//! The `gssapi-with-mic` userauth method (RFC 4462 §3.4) is structured as:
//!
//! 1. Client sends `SSH_MSG_USERAUTH_REQUEST` selecting `gssapi-with-mic`
//!    plus the OID list it can attempt.
//! 2. Server picks one OID with `SSH_MSG_USERAUTH_GSSAPI_RESPONSE`.
//! 3. Client + server exchange opaque tokens
//!    (`SSH_MSG_USERAUTH_GSSAPI_TOKEN`) until the local GSS implementation
//!    reports `complete = true`.
//! 4. Client computes a MIC over the session-id-bound transcript and sends
//!    `SSH_MSG_USERAUTH_GSSAPI_MIC`; server verifies. Auth succeeds when
//!    the MIC verifies.
//!
//! [`GssProvider`] models exactly steps (3) and (4): [`initialize`] feeds
//! one inbound token (or `None` for the first call) and returns the next
//! outbound token plus a `complete` flag; [`get_mic`] / [`verify_mic`]
//! handle the MIC at the end.
//!
//! [`initialize`]: GssProvider::initialize
//! [`get_mic`]: GssProvider::get_mic
//! [`verify_mic`]: GssProvider::verify_mic

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use std::sync::Arc;

use spt_core::{Error, Result};
use thiserror::Error as ThisError;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(unix)]
pub mod unix;

#[cfg(any(feature = "testing", test))]
pub mod mock;

pub mod audit;

pub use audit::{AuditEvent, AuditHook, MockAuditHook, NoopAuditHook};

/// One step of a GSS / SSPI security-context token exchange.
///
/// `token` is the bytes to send to the peer (may be empty/`None` on the
/// terminal step). `complete` is `true` once the local provider considers
/// the security context fully established — the next operation should be
/// [`GssProvider::get_mic`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GssOutput {
    /// Outbound token, if any. RFC 4462 §3.4 allows empty terminal tokens.
    pub token: Option<Vec<u8>>,
    /// Whether the security context is fully established.
    pub complete: bool,
}

/// Stateful GSS / SSPI initiator handle.
///
/// One instance corresponds to one outbound auth attempt. The trait carries
/// `&mut self` because the underlying SSPI / GSSAPI contexts mutate on every
/// token exchange.
pub trait GssProvider: Send + Sync + std::fmt::Debug {
    /// Feed the inbound token (or `None` on the very first call) and produce
    /// the next outbound token plus the `complete` flag.
    fn initialize(&mut self, target: &str, input_token: Option<&[u8]>) -> Result<GssOutput>;

    /// Verify a peer-supplied MIC against `message`. Returns `Ok(())` iff
    /// the MIC verifies under the established context.
    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<()>;

    /// Compute a MIC over `message` under the established context.
    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// Mechanism selector for [`GssApiConfig`] / [`SspiConfig`].
///
/// `Negotiate` corresponds to Microsoft's SSPI "Negotiate" package, which
/// negotiates between Kerberos and NTLM at runtime. On Unix this collapses
/// to `Kerberos`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// RFC 4121 Kerberos v5.
    Kerberos,
    /// SSPI `NTLMv2` (Windows-only).
    Ntlm,
    /// SSPI Negotiate (Kerberos preferred, NTLM fallback when permitted).
    Negotiate,
}

/// Configuration for the GSSAPI (Unix) initiator.
#[derive(Debug, Clone, Default)]
pub struct GssApiConfig {
    /// Service principal hint, e.g. `host/edge.example.com@REALM`.
    pub service: Option<String>,
    /// Optional explicit client principal.
    pub principal: Option<String>,
    /// Permit credential delegation (`GSS_C_DELEG_FLAG`).
    pub delegate: bool,
    /// Request confidentiality (`GSS_C_CONF_FLAG`).
    ///
    /// Off by default; SSH `gssapi-with-mic` (RFC 4462) does not require it.
    pub confidentiality: bool,
    /// Optional [`AuditHook`] subscriber. `None` disables audit emission.
    pub audit_hook: Option<Arc<dyn AuditHook>>,
}

impl PartialEq for GssApiConfig {
    fn eq(&self, other: &Self) -> bool {
        self.service == other.service
            && self.principal == other.principal
            && self.delegate == other.delegate
            && self.confidentiality == other.confidentiality
            // `Arc<dyn AuditHook>` is not Eq; we compare by pointer identity.
            && match (&self.audit_hook, &other.audit_hook) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}
impl Eq for GssApiConfig {}

/// Configuration for the SSPI (Windows) initiator.
#[derive(Debug, Clone, Default)]
pub struct SspiConfig {
    /// Service principal hint, e.g. `host/edge.example.com`.
    pub service: Option<String>,
    /// Optional explicit client principal hint.
    pub principal: Option<String>,
    /// Permit credential delegation (`ISC_REQ_DELEGATE`).
    pub delegate: bool,
    /// Permit NTLM fallback when Kerberos cannot be negotiated.
    pub allow_ntlm_fallback: bool,
    /// Request confidentiality (`ISC_REQ_CONFIDENTIALITY`).
    pub confidentiality: bool,
    /// Optional [`AuditHook`] subscriber. `None` disables audit emission.
    pub audit_hook: Option<Arc<dyn AuditHook>>,
}

impl PartialEq for SspiConfig {
    fn eq(&self, other: &Self) -> bool {
        self.service == other.service
            && self.principal == other.principal
            && self.delegate == other.delegate
            && self.allow_ntlm_fallback == other.allow_ntlm_fallback
            && self.confidentiality == other.confidentiality
            && match (&self.audit_hook, &other.audit_hook) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}
impl Eq for SspiConfig {}

/// Resolve a Unix [`GssProvider`] from the supplied configuration.
///
/// Returns [`Error::UnsupportedPlatform`] on non-Unix targets; on Unix the
/// real `libgssapi` initiator is constructed (errors propagate from
/// `gss_init_sec_context` if the local krb5 ticket cache is empty, the SPN
/// cannot be resolved, etc.).
pub fn provider_for(cfg: &GssApiConfig) -> Result<Box<dyn GssProvider>> {
    #[cfg(unix)]
    {
        unix::build_kerberos(cfg)
    }
    #[cfg(not(unix))]
    {
        let _ = cfg;
        Err(unsupported_backend(
            "gssapi (libgssapi) is Unix-only; this target is not Unix",
        ))
    }
}

/// Resolve a Windows [`GssProvider`] from the supplied configuration.
///
/// On Windows, dispatches to the real `sspi`-backed initiator. On Unix,
/// NTLM is unsupported (libgssapi is Kerberos-only) — if
/// `allow_ntlm_fallback` is set we return [`Error::AuthFailed`] with the
/// stable `UnsupportedOnUnix` marker; otherwise we degrade to the Kerberos
/// (`provider_for`) path so the call still produces a usable initiator.
pub fn sspi_provider_for(cfg: &SspiConfig) -> Result<Box<dyn GssProvider>> {
    #[cfg(target_os = "windows")]
    {
        windows::build(cfg)
    }
    #[cfg(not(target_os = "windows"))]
    {
        if cfg.allow_ntlm_fallback {
            Err(Error::AuthFailed(unix_ntlm_message()))
        } else {
            // Pure-Kerberos SSPI requests on Unix degrade to gssapi if the
            // caller has not asked for NTLM specifically.
            provider_for(&GssApiConfig {
                service: cfg.service.clone(),
                principal: cfg.principal.clone(),
                delegate: cfg.delegate,
                confidentiality: cfg.confidentiality,
                audit_hook: cfg.audit_hook.clone(),
            })
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn unix_ntlm_message() -> String {
    "sspi NTLM is unavailable on Unix (UnsupportedOnUnix); enable Kerberos via gssapi instead"
        .to_owned()
}

/// Build the canonical `UnsupportedBackend` error. The string-encoded
/// `UnsupportedBackend:` prefix lets callers (and tests) recognise this
/// specific terminal state without a dedicated [`Error`] variant.
pub fn unsupported_backend(detail: impl Into<String>) -> Error {
    Error::UnsupportedPlatform(format!("UnsupportedBackend: {}", detail.into()))
}

/// Parsed SSH service principal (`service[/instance]@REALM`).
///
/// Used by the SSPI / GSSAPI initiators to construct the target SPN. The
/// parser accepts the three common shapes:
///
/// * `service` — host-less, no realm (rare; mostly for test vectors).
/// * `service@host` — host-form, no realm. The `host` becomes the
///   `instance` component.
/// * `service/instance@REALM` — fully-qualified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Service component, e.g. `host`.
    pub service: String,
    /// Optional instance / host component.
    pub instance: Option<String>,
    /// Optional realm component.
    pub realm: Option<String>,
}

/// Errors raised by [`Principal::parse`].
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum PrincipalParseError {
    /// The service portion was empty.
    #[error("principal: empty service component")]
    EmptyService,
    /// The instance portion was empty (slash present but nothing after).
    #[error("principal: empty instance component after `/`")]
    EmptyInstance,
    /// The realm portion was empty (`@` present but nothing after).
    #[error("principal: empty realm component after `@`")]
    EmptyRealm,
    /// More than one `@` present.
    #[error("principal: multiple `@` separators")]
    MultipleRealms,
    /// More than one `/` present.
    #[error("principal: multiple `/` separators in service component")]
    MultipleInstances,
}

impl Principal {
    /// Parse a principal string. See [`Principal`] for accepted shapes.
    pub fn parse(s: &str) -> std::result::Result<Self, PrincipalParseError> {
        let (left, realm) = match s.rsplit_once('@') {
            Some((l, r)) => {
                if r.is_empty() {
                    return Err(PrincipalParseError::EmptyRealm);
                }
                if l.contains('@') {
                    return Err(PrincipalParseError::MultipleRealms);
                }
                (l, Some(r.to_owned()))
            }
            None => (s, None),
        };
        let (service, instance) = match left.split_once('/') {
            Some((svc, inst)) => {
                if svc.is_empty() {
                    return Err(PrincipalParseError::EmptyService);
                }
                if inst.is_empty() {
                    return Err(PrincipalParseError::EmptyInstance);
                }
                if inst.contains('/') {
                    return Err(PrincipalParseError::MultipleInstances);
                }
                (svc.to_owned(), Some(inst.to_owned()))
            }
            None => {
                if left.is_empty() {
                    return Err(PrincipalParseError::EmptyService);
                }
                (left.to_owned(), None)
            }
        };
        Ok(Self {
            service,
            instance,
            realm,
        })
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.service)?;
        if let Some(inst) = &self.instance {
            f.write_str("/")?;
            f.write_str(inst)?;
        }
        if let Some(realm) = &self.realm {
            f.write_str("@")?;
            f.write_str(realm)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn parses_service_at_host() {
        let p = Principal::parse("host@edge.example.com").unwrap();
        assert_eq!(p.service, "host");
        assert_eq!(p.instance, None);
        assert_eq!(p.realm.as_deref(), Some("edge.example.com"));
    }

    #[test]
    fn parses_service_slash_instance_at_realm() {
        let p = Principal::parse("host/edge.example.com@EXAMPLE.COM").unwrap();
        assert_eq!(p.service, "host");
        assert_eq!(p.instance.as_deref(), Some("edge.example.com"));
        assert_eq!(p.realm.as_deref(), Some("EXAMPLE.COM"));
        assert_eq!(p.to_string(), "host/edge.example.com@EXAMPLE.COM");
    }

    #[test]
    fn rejects_empty_realm() {
        assert_eq!(
            Principal::parse("host@"),
            Err(PrincipalParseError::EmptyRealm)
        );
    }

    #[test]
    fn rejects_empty_instance() {
        assert_eq!(
            Principal::parse("host/"),
            Err(PrincipalParseError::EmptyInstance)
        );
    }

    #[test]
    fn rejects_double_at() {
        assert_eq!(
            Principal::parse("a@b@c"),
            Err(PrincipalParseError::MultipleRealms)
        );
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    /// Verify that `delegate = true` plumbs through the public config types.
    /// The flag is honoured by the real SSPI / GSSAPI backends via
    /// `ISC_REQ_DELEGATE` / `GSS_C_DELEG_FLAG`; this test guards the
    /// in-process plumbing so a future field rename surfaces immediately.
    #[test]
    fn delegate_flag_round_trips_through_both_configs() {
        let g = GssApiConfig {
            service: Some("host@h".into()),
            principal: None,
            delegate: true,
            ..Default::default()
        };
        assert!(g.delegate);

        let s = SspiConfig {
            service: Some("host/h".into()),
            principal: Some("user@R".into()),
            delegate: true,
            allow_ntlm_fallback: false,
            ..Default::default()
        };
        assert!(s.delegate);
        assert!(!s.allow_ntlm_fallback);
    }

    /// `AuthMethod::Gssapi`/`AuthMethod::Sspi` serde stability gate.
    /// This crate is the home of the backends — if a field rename ever lands
    /// in `spt-auth::method`, the explicit field-by-field construction below
    /// fails to compile, catching the drift at this layer.
    #[test]
    fn auth_method_serde_unchanged() {
        use spt_auth::AuthMethod;

        let gssapi = AuthMethod::Gssapi {
            service: Some("host@h".into()),
            principal: None,
            delegate: false,
        };
        let json = serde_json::to_string(&gssapi).unwrap();
        let back: AuthMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(gssapi, back);
        assert!(json.contains(r#""method":"gssapi""#), "{json}");

        let sspi = AuthMethod::Sspi {
            service: None,
            principal: None,
            delegate: false,
            allow_ntlm_fallback: true,
        };
        let json = serde_json::to_string(&sspi).unwrap();
        let back: AuthMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(sspi, back);
        assert!(json.contains(r#""method":"sspi""#), "{json}");
        assert!(json.contains(r#""allow_ntlm_fallback":true"#), "{json}");
    }
}
