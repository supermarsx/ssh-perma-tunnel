//! Trust diagnostics — known_hosts parseability + pin-format validation.
//!
//! For each profile in the loaded config:
//!
//! * Parse `[profiles.trust].known_hosts_file` (if any) and surface
//!   unparseable lines.
//! * Validate every entry in `[profiles.trust].pin_sha256` is a well-formed
//!   `SHA256:<base64>` host pin.
//! * Validate every entry in `[profiles.tls].pin_sha256` is a well-formed
//!   SHA-256 SPKI pin (32 bytes, base64-encoded).
//!
//! Live host-key fetch + comparison ("connect with verification disabled,
//! compare to pin") is intentionally **not** done here — it requires the
//! protocol stack and a tokio runtime, plus deliberately disabling trust,
//! both of which the diagnostic context is not meant to carry. The
//! companion CLI op (`cli::diag_ops::trust`) can perform a live probe via
//! the running supervisor's MCP surface; this check covers offline
//! correctness.

#![allow(clippy::manual_let_else)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::if_not_else)]

use async_trait::async_trait;

use spt_config::schema::{Config, Profile};

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// `trust.<profile>.*` checks.
#[derive(Debug, Default)]
pub struct TrustDiagnostic {
    /// Restrict to a single profile (None = all).
    pub profile_filter: Option<String>,
    /// Pre-loaded config. If unset the diagnostic re-parses
    /// `ctx.effective_config` on each run.
    pub config: Option<Config>,
}

impl TrustDiagnostic {
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
impl Diagnostic for TrustDiagnostic {
    fn group(&self) -> &str {
        "trust"
    }

    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let mut out = Vec::new();
        let cfg = match resolve_config(self, ctx) {
            Some(c) => c,
            None => {
                out.push(
                    Check::new("trust.config", Severity::Medium, Status::Skipped)
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
                Check::new("trust.profiles", Severity::Low, Status::Skipped)
                    .with_evidence("no matching profiles in config"),
            );
        }
        out
    }
}

fn resolve_config(d: &TrustDiagnostic, ctx: &DiagnosticContext) -> Option<Config> {
    if let Some(c) = &d.config {
        return Some(c.clone());
    }
    let body = ctx.effective_config.as_ref()?;
    spt_config::load::load_str(body, false).ok().map(|(c, _)| c)
}

fn check_profile(profile: &Profile, out: &mut Vec<Check>) {
    let id_prefix = format!("trust.{}", profile.name);

    // known_hosts file: parse and report unparseable lines.
    if let Some(trust) = profile.trust.as_ref() {
        if let Some(path) = &trust.known_hosts_file {
            let p = std::path::PathBuf::from(path);
            let id = format!("{id_prefix}.known_hosts");
            if !p.exists() {
                out.push(
                    Check::new(id, Severity::Medium, Status::Warn)
                        .with_evidence(format!("known_hosts `{path}` does not exist (yet)"))
                        .with_remediation("created on first verified connect"),
                );
            } else {
                match spt_trust::KnownHosts::load(&p) {
                    Ok(k) => {
                        out.push(Check::new(id, Severity::High, Status::Pass).with_evidence(
                            format!("{} entries parsed from `{path}`", k.entries.len()),
                        ));
                    }
                    Err(e) => {
                        out.push(
                            Check::new(id, Severity::High, Status::Fail)
                                .with_evidence(format!("parse `{path}`: {e}"))
                                .with_remediation("inspect file for malformed lines"),
                        );
                    }
                }
            }
        }

        // SHA-256 host pins.
        if let Some(pins) = &trust.pin_sha256 {
            for (i, pin) in pins.iter().enumerate() {
                let id = format!("{id_prefix}.pin_sha256[{i}]");
                match validate_host_pin(pin) {
                    Ok(()) => {
                        out.push(
                            Check::new(id, Severity::High, Status::Pass)
                                .with_evidence(format!("pin `{pin}` parsed")),
                        );
                    }
                    Err(e) => {
                        out.push(
                            Check::new(id, Severity::High, Status::Fail)
                                .with_evidence(format!("invalid pin `{pin}`: {e}"))
                                .with_remediation(
                                    "format must be `SHA256:<base64-no-padding>` per spec §9.13",
                                ),
                        );
                    }
                }
            }
        }
    }

    // TLS SPKI pins (SSH3).
    if let Some(tls) = profile.tls.as_ref() {
        if let Some(pins) = &tls.pin_sha256 {
            for (i, pin) in pins.iter().enumerate() {
                let id = format!("{id_prefix}.tls_pin[{i}]");
                match validate_tls_pin(pin) {
                    Ok(()) => {
                        out.push(
                            Check::new(id, Severity::High, Status::Pass)
                                .with_evidence(format!("tls pin `{pin}` parsed")),
                        );
                    }
                    Err(e) => {
                        out.push(
                            Check::new(id, Severity::High, Status::Fail)
                                .with_evidence(format!("invalid tls pin `{pin}`: {e}"))
                                .with_remediation(
                                    "format must be `sha256/<base64-of-32-byte-spki-hash>`",
                                ),
                        );
                    }
                }
            }
        }
    }
}

/// Lightweight validator for the spec §9.13 host pin shape:
/// `SHA256:<base64-no-padding-of-32-byte-fingerprint>`.
fn validate_host_pin(pin: &str) -> Result<(), String> {
    use base64::Engine;
    let body = pin
        .strip_prefix("SHA256:")
        .ok_or_else(|| "missing `SHA256:` prefix".to_owned())?;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(body)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(body))
        .map_err(|e| format!("base64: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    Ok(())
}

/// Lightweight validator for the spec §9.13 TLS SPKI pin shape.
fn validate_tls_pin(pin: &str) -> Result<(), String> {
    use base64::Engine;
    let body = pin
        .strip_prefix("sha256/")
        .or_else(|| pin.strip_prefix("SHA256/"))
        .ok_or_else(|| "missing `sha256/` prefix".to_owned())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(body))
        .map_err(|e| format!("base64: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn cfg_str(body: &str) -> Config {
        spt_config::load::load_str(body, false).unwrap().0
    }

    #[tokio::test]
    async fn skipped_when_no_config() {
        let d = TrustDiagnostic::default();
        let r = d.run(&DiagnosticContext::default()).await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn parses_known_hosts() {
        let mut f = NamedTempFile::new().unwrap();
        // A real ed25519 host key with the OpenSSH format.
        f.write_all(b"example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0wmN/Cr3JXqmLW7u+g9pTh+wyqDHpSQEIQczXkVx9q\n").unwrap();
        let path = f.path().to_string_lossy().to_string();
        let cfg = cfg_str(&format!(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.trust]
known_hosts_file = "{}"
"#,
            path.replace('\\', "\\\\")
        ));
        let d = TrustDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        let kh = r.iter().find(|c| c.id.ends_with(".known_hosts")).unwrap();
        assert_eq!(kh.status, Status::Pass, "{kh:?}");
    }

    #[tokio::test]
    async fn fails_on_malformed_pin() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.trust]
pin_sha256 = ["not-a-pin"]
"#,
        );
        let d = TrustDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(r
            .iter()
            .any(|c| c.id.contains(".pin_sha256[0]") && c.status == Status::Fail));
    }

    #[tokio::test]
    async fn passes_well_formed_tls_pin() {
        // 32 zero bytes base64 = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh3"
endpoint = "https://h.example.com"
acknowledge_experimental = true
[profiles.tls]
pin_sha256 = ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
"#,
        );
        let d = TrustDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        assert!(r
            .iter()
            .any(|c| c.id.contains(".tls_pin[0]") && c.status == Status::Pass));
    }

    #[tokio::test]
    async fn warns_when_known_hosts_missing() {
        let cfg = cfg_str(
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.trust]
known_hosts_file = "/no/such/file/spt-test-known-hosts"
"#,
        );
        let d = TrustDiagnostic::default().with_config(cfg);
        let r = d.run(&DiagnosticContext::default()).await;
        let kh = r.iter().find(|c| c.id.ends_with(".known_hosts")).unwrap();
        assert_eq!(kh.status, Status::Warn);
    }
}
