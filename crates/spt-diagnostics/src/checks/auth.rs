//! Authentication diagnostics.
//!
//! For each profile in the loaded config, translate its `[profiles.auth]`
//! table into one or more [`spt_auth::AuthMethod`] values and run the
//! shape-only validator from `spt-auth`. Results are reported per profile per
//! method.
//!
//! This check does **not** open a real connection — `--probe` (live connect)
//! lives in `cli::diag_ops::auth` since it requires a tokio runtime and
//! profile factory wiring beyond the `DiagnosticContext` surface. Here we
//! cover the structural-validation portion of `spt diagnose auth`.

#![allow(clippy::manual_let_else)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::if_not_else)]

use async_trait::async_trait;
use std::path::PathBuf;

use spt_auth::{validate, AuthMethod, SecretRef};
use spt_config::schema::{Auth as AuthCfg, Config, Profile};

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// `auth.<profile>.<method>` checks.
#[derive(Debug, Default)]
pub struct AuthDiagnostic {
    /// Restrict to a single profile (None = all).
    pub profile_filter: Option<String>,
    /// Pre-loaded config. If unset the diagnostic re-parses
    /// `ctx.effective_config` on each run.
    pub config: Option<Config>,
}

impl AuthDiagnostic {
    /// Build a diagnostic restricted to one profile.
    #[must_use]
    pub fn for_profile(name: impl Into<String>) -> Self {
        Self {
            profile_filter: Some(name.into()),
            config: None,
        }
    }

    /// Provide the loaded config directly. Avoids re-parsing on every run.
    #[must_use]
    pub fn with_config(mut self, cfg: Config) -> Self {
        self.config = Some(cfg);
        self
    }
}

#[async_trait]
impl Diagnostic for AuthDiagnostic {
    fn group(&self) -> &'static str {
        "auth"
    }

    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let mut out = Vec::new();
        let cfg = match resolve_config(self, ctx) {
            Some(c) => c,
            None => {
                out.push(
                    Check::new("auth.config", Severity::Medium, Status::Skipped)
                        .with_evidence("no config loaded"),
                );
                return out;
            }
        };

        let mut any = false;
        for profile in &cfg.profiles {
            if let Some(filter) = &self.profile_filter {
                if profile.name != *filter {
                    continue;
                }
            }
            any = true;
            check_profile(profile, &mut out);
        }

        if !any {
            out.push(
                Check::new("auth.profiles", Severity::Low, Status::Skipped)
                    .with_evidence("no matching profiles in config"),
            );
        }
        out
    }
}

fn resolve_config(d: &AuthDiagnostic, ctx: &DiagnosticContext) -> Option<Config> {
    if let Some(c) = &d.config {
        return Some(c.clone());
    }
    let body = ctx.effective_config.as_ref()?;
    spt_config::load::load_str(body, false).ok().map(|(c, _)| c)
}

fn check_profile(profile: &Profile, out: &mut Vec<Check>) {
    let id_prefix = format!("auth.{}", profile.name);

    let Some(auth) = profile.auth.as_ref() else {
        out.push(
            Check::new(
                format!("{id_prefix}.declared"),
                Severity::Low,
                Status::Skipped,
            )
            .with_evidence(format!(
                "profile `{}` declares no [profiles.auth]",
                profile.name
            )),
        );
        return;
    };

    let methods = match translate_methods(profile, auth) {
        Ok(v) => v,
        Err(msg) => {
            out.push(
                Check::new(
                    format!("{id_prefix}.translate"),
                    Severity::High,
                    Status::Fail,
                )
                .with_evidence(msg)
                .with_remediation(
                    "fix `[profiles.auth]` references; see spec §9.12 for the full enumeration",
                ),
            );
            return;
        }
    };

    if methods.is_empty() {
        out.push(
            Check::new(
                format!("{id_prefix}.declared"),
                Severity::Medium,
                Status::Warn,
            )
            .with_evidence(format!(
                "profile `{}` has [profiles.auth] but no method fields set",
                profile.name
            ))
            .with_remediation("set one of: identity_file, password, agent, token, …"),
        );
        return;
    }

    for (i, method) in methods.iter().enumerate() {
        let method_name = method_label(method);
        let id = format!("{id_prefix}.{method_name}");
        match validate(method) {
            Ok(()) => {
                out.push(
                    Check::new(id, Severity::High, Status::Pass)
                        .with_evidence(format!("method[{i}] `{method_name}` validated")),
                );
            }
            Err(e) => {
                out.push(
                    Check::new(id, Severity::High, Status::Fail)
                        .with_evidence(format!("method[{i}] `{method_name}`: {e}"))
                        .with_remediation("see spec §9.12 for required fields per method"),
                );
            }
        }
    }

    // SSH3 bearer-only / SSH2 vs SSH3 method-fit guard.
    if profile.protocol == "ssh3" {
        for m in &methods {
            if matches!(
                m,
                AuthMethod::Agent { .. }
                    | AuthMethod::PublicKey { .. }
                    | AuthMethod::KeyboardInteractive { .. }
                    | AuthMethod::Gssapi { .. }
                    | AuthMethod::Sspi { .. }
            ) {
                out.push(
                    Check::new(
                        format!("{id_prefix}.protocol_fit"),
                        Severity::High,
                        Status::Fail,
                    )
                    .with_evidence(format!(
                        "profile `{}` uses ssh3 but configured a method only valid for ssh2",
                        profile.name
                    ))
                    .with_remediation(
                        "ssh3 supports bearer / oidc / basic / certificate; remove ssh2-only methods",
                    ),
                );
                break;
            }
        }
    }
    if profile.protocol == "ssh2" {
        for m in &methods {
            if matches!(
                m,
                AuthMethod::Bearer { .. }
                    | AuthMethod::OidcDeviceFlow { .. }
                    | AuthMethod::Basic { .. }
            ) {
                out.push(
                    Check::new(
                        format!("{id_prefix}.protocol_fit"),
                        Severity::High,
                        Status::Fail,
                    )
                    .with_evidence(format!(
                        "profile `{}` uses ssh2 but configured an HTTP-only method",
                        profile.name
                    ))
                    .with_remediation("bearer/oidc/basic require ssh3"),
                );
                break;
            }
        }
    }
}

/// Translate the loose `[profiles.auth]` accumulator into the strict
/// [`AuthMethod`] enum so [`spt_auth::validate`] can vet shape.
fn translate_methods(profile: &Profile, a: &AuthCfg) -> Result<Vec<AuthMethod>, String> {
    let mut out = Vec::new();
    let method = normalize_auth_method(&a.method);
    if let Some(p) = &a.password {
        let secret = SecretRef::parse(p).map_err(|e| format!("auth.password: {e}"))?;
        if method == "basic" {
            out.push(AuthMethod::Basic {
                username: profile.user.clone().unwrap_or_default(),
                password: secret,
            });
        } else {
            out.push(AuthMethod::Password { secret });
        }
    }
    if let Some(t) = &a.token {
        let secret = SecretRef::parse(t).map_err(|e| format!("auth.token: {e}"))?;
        out.push(AuthMethod::Bearer { token: secret });
    }
    if let Some(key) = &a.identity_file {
        let passphrase = a
            .passphrase
            .as_ref()
            .map(|p| SecretRef::parse(p))
            .transpose()
            .map_err(|e| format!("auth.passphrase: {e}"))?;
        out.push(AuthMethod::PublicKey {
            identity_file: PathBuf::from(key),
            passphrase,
            allow_ssh_rsa_sha1: false,
        });
    }
    if a.agent.unwrap_or(false) {
        out.push(AuthMethod::Agent {
            socket: None,
            identity_hint: None,
        });
    }
    if let (Some(issuer), Some(client_id)) = (&a.oidc_issuer, &a.oidc_client_id) {
        let url = url::Url::parse(issuer).map_err(|e| format!("auth.oidc_issuer: {e}"))?;
        out.push(AuthMethod::OidcDeviceFlow {
            issuer: url,
            client_id: client_id.clone(),
            audience: None,
        });
    }
    if method == "gssapi" {
        out.push(AuthMethod::Gssapi {
            service: a.gssapi_service.clone(),
            principal: a.gssapi_principal.clone(),
            delegate: a.gssapi_delegate.unwrap_or(false),
        });
    }
    if method == "sspi" {
        out.push(AuthMethod::Sspi {
            service: a.sspi_service.clone(),
            principal: a.sspi_principal.clone(),
            delegate: a.sspi_delegate.unwrap_or(false),
            allow_ntlm_fallback: a.sspi_allow_ntlm_fallback.unwrap_or(false),
        });
    }
    if let Some(cert) = &a.certificate_file {
        // certificate requires a paired key — use identity_file.
        if let Some(key) = &a.identity_file {
            let passphrase = a
                .passphrase
                .as_ref()
                .map(|p| SecretRef::parse(p))
                .transpose()
                .map_err(|e| format!("auth.passphrase: {e}"))?;
            out.push(AuthMethod::Certificate {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
                passphrase,
            });
        }
    }
    Ok(out)
}

fn normalize_auth_method(method: &str) -> String {
    match method.trim().to_ascii_lowercase().as_str() {
        "publickey" | "public-key" | "ssh3_public_key" => "public_key".into(),
        "bearer_token" => "bearer".into(),
        "http_basic" => "basic".into(),
        "oidc" => "oidc_device_flow".into(),
        "kerberos" | "gssapi-with-mic" | "gssapi_with_mic" => "gssapi".into(),
        "negotiate" => "sspi".into(),
        other => other.into(),
    }
}

fn method_label(m: &AuthMethod) -> &'static str {
    match m {
        AuthMethod::PublicKey { .. } => "public_key",
        AuthMethod::Agent { .. } => "agent",
        AuthMethod::Password { .. } => "password",
        AuthMethod::Bearer { .. } => "bearer",
        AuthMethod::KeyboardInteractive { .. } => "keyboard_interactive",
        AuthMethod::Certificate { .. } => "certificate",
        AuthMethod::Gssapi { .. } => "gssapi",
        AuthMethod::Sspi { .. } => "sspi",
        AuthMethod::Basic { .. } => "http_basic",
        AuthMethod::OidcDeviceFlow { .. } => "oidc_device_flow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_str(body: &str) -> Config {
        spt_config::load::load_str(body, false).unwrap().0
    }

    #[tokio::test]
    async fn skipped_when_no_config() {
        let d = AuthDiagnostic::default();
        let r = d.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn passes_for_agent_method() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "agent"
agent = true
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        let agent = r.iter().find(|c| c.id.ends_with(".agent")).unwrap();
        assert_eq!(agent.status, Status::Pass);
    }

    #[tokio::test]
    async fn fails_when_identity_file_missing() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "publickey"
identity_file = "/no/such/file/xyz"
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        let pk = r.iter().find(|c| c.id.ends_with(".public_key")).unwrap();
        assert_eq!(pk.status, Status::Fail);
    }

    #[tokio::test]
    async fn warns_when_no_method_set() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "publickey"
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(r.iter().any(|c| c.status == Status::Warn));
    }

    #[tokio::test]
    async fn protocol_fit_flags_bearer_on_ssh2() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "bearer"
token = "env:T"
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(
            r.iter()
                .any(|c| c.id.ends_with(".protocol_fit") && c.status == Status::Fail),
            "{r:#?}"
        );
    }

    #[tokio::test]
    async fn protocol_fit_flags_pubkey_on_ssh3() {
        let cfg = cfg_str(
            r#"
version = 1
acknowledge_experimental = "ssh3"
[[profiles]]
name = "p"
protocol = "ssh3"
host = "h"
[profiles.auth]
method = "publickey"
agent = true
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(
            r.iter()
                .any(|c| c.id.ends_with(".protocol_fit") && c.status == Status::Fail),
            "{r:#?}"
        );
    }

    #[tokio::test]
    async fn skipped_when_profile_has_no_auth_block() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        let dec = r.iter().find(|c| c.id.ends_with(".declared")).unwrap();
        assert_eq!(dec.status, Status::Skipped);
    }

    #[tokio::test]
    async fn no_matching_profiles_emits_dedicated_skip() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "a"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "agent"
agent = true
"#,
        );
        let d = AuthDiagnostic::for_profile("does-not-exist").with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(r
            .iter()
            .any(|c| c.id == "auth.profiles" && c.status == Status::Skipped));
    }

    #[tokio::test]
    async fn translate_failure_surfaces_as_translate_check() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "password"
password = "raw-text-not-a-ref"
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(
            r.iter()
                .any(|c| c.id.ends_with(".translate") && c.status == Status::Fail),
            "{r:#?}"
        );
    }

    #[tokio::test]
    async fn oidc_method_passes_validation_on_ssh3() {
        let cfg = cfg_str(
            r#"
version = 1
acknowledge_experimental = "ssh3"
[[profiles]]
name = "p"
protocol = "ssh3"
host = "h"
[profiles.auth]
method = "oidc_device_flow"
oidc_issuer = "https://login.example.com"
oidc_client_id = "id"
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(
            r.iter()
                .any(|c| c.id.ends_with(".oidc_device_flow") && c.status == Status::Pass),
            "{r:#?}"
        );
    }

    #[tokio::test]
    async fn gssapi_method_passes_structural_validation_on_ssh2() {
        let cfg = cfg_str(
            r#"
version = 1
[capabilities]
allow_gssapi = true
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "kerberos"
gssapi_service = "host/edge.example.com"
"#,
        );
        let d = AuthDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(
            r.iter()
                .any(|c| c.id.ends_with(".gssapi") && c.status == Status::Pass),
            "{r:#?}"
        );
    }

    #[test]
    fn group_label_is_auth() {
        assert_eq!(AuthDiagnostic::default().group(), "auth");
    }

    #[tokio::test]
    async fn reads_config_from_diagnostic_context_when_no_inline_config() {
        let body = r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "agent"
agent = true
"#;
        let ctx = DiagnosticContext {
            effective_config: Some(body.into()),
            ..Default::default()
        };
        let d = AuthDiagnostic::default();
        let r = d.run(&ctx).await;
        // Should not be the "no config loaded" skip.
        assert!(!r.iter().any(|c| c.id == "auth.config"));
        assert!(r.iter().any(|c| c.id.starts_with("auth.p.")));
    }

    #[tokio::test]
    async fn filter_restricts_to_single_profile() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "a"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "agent"
agent = true
[[profiles]]
name = "b"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "agent"
agent = true
"#,
        );
        let d = AuthDiagnostic::for_profile("b").with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(r.iter().all(|c| !c.id.starts_with("auth.a")));
        assert!(r.iter().any(|c| c.id.starts_with("auth.b")));
    }
}
