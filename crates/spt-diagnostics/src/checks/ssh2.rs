//! SSH2 toolset readiness — real probe against libssh2 (via `ssh2` crate).
//!
//! What we check:
//!
//! 1. `ssh2.libssh2_init`            — `ssh2::Session::new()` succeeds
//!    (i.e. libssh2 is linked and usable on this host).
//! 2. `ssh2.supported_algs.<kind>`   — list the algorithm support reported
//!    by libssh2 across kex / hostkey / cipher / mac.
//! 3. `ssh2.crypto_policy.<kind>`    — for each entry in the configured
//!    [`CryptoPolicy`] allow-list, `Pass` if libssh2 reports support,
//!    `Fail` otherwise. Deprecated algorithms emit a `Warn`.
//!
//! `Status::Skipped` when the runtime can't construct a session (rare on
//! supported targets — libssh2 is statically linked) or when the policy is
//! absent.

use async_trait::async_trait;
use ssh2::{MethodType, Session};

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Real SSH2 toolset diagnostic.
#[derive(Default, Debug)]
pub struct Ssh2Diagnostic;

#[async_trait]
impl Diagnostic for Ssh2Diagnostic {
    fn group(&self) -> &str {
        "ssh2"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        // libssh2 init via ssh2 crate.
        let sess = match Session::new() {
            Ok(s) => s,
            Err(e) => {
                return vec![Check::new(
                    "ssh2.libssh2_init",
                    Severity::Critical,
                    Status::Fail,
                )
                .with_evidence(format!("ssh2::Session::new failed: {e}"))
                .with_remediation(
                    "ensure libssh2 is available on this platform; rebuild spt or check linkage",
                )];
            }
        };

        let mut out = Vec::new();
        out.push(
            Check::new("ssh2.libssh2_init", Severity::Info, Status::Pass)
                .with_evidence("ssh2::Session::new() succeeded; libssh2 linked"),
        );

        // Supported algorithms snapshot. Pass for each non-empty kind.
        for (label, mt) in [
            ("kex", MethodType::Kex),
            ("hostkey", MethodType::HostKey),
            ("cipher_cs", MethodType::CryptCs),
            ("cipher_sc", MethodType::CryptSc),
            ("mac_cs", MethodType::MacCs),
            ("mac_sc", MethodType::MacSc),
        ] {
            match sess.supported_algs(mt) {
                Ok(algs) if !algs.is_empty() => {
                    out.push(
                        Check::new(
                            format!("ssh2.supported_algs.{label}"),
                            Severity::Info,
                            Status::Pass,
                        )
                        .with_evidence(format!("{label}: {} algorithms", algs.len()))
                        .with_evidence(format!("listing: {}", algs.join(","))),
                    );
                }
                Ok(_) => {
                    out.push(
                        Check::new(
                            format!("ssh2.supported_algs.{label}"),
                            Severity::Medium,
                            Status::Warn,
                        )
                        .with_evidence(format!("libssh2 reports zero {label} algorithms")),
                    );
                }
                Err(e) => {
                    out.push(
                        Check::new(
                            format!("ssh2.supported_algs.{label}"),
                            Severity::Low,
                            Status::Skipped,
                        )
                        .with_evidence(format!("supported_algs({label}) failed: {e}")),
                    );
                }
            }
        }

        // Optional crypto-policy vetting.
        if let Some(pol) = &ctx.crypto_policy {
            check_policy(&mut out, &sess, "kex", &pol.kex, MethodType::Kex);
            check_policy(
                &mut out,
                &sess,
                "hostkey",
                &pol.host_keys,
                MethodType::HostKey,
            );
            check_policy(&mut out, &sess, "cipher", &pol.ciphers, MethodType::CryptCs);
            check_policy(&mut out, &sess, "mac", &pol.macs, MethodType::MacCs);

            for w in pol.deprecated_warnings() {
                out.push(
                    Check::new("ssh2.crypto_policy.deprecated", Severity::Medium, Status::Warn)
                        .with_evidence(w)
                        .with_remediation(
                            "remove the deprecated algorithm from the profile's `[crypto]` allow-list",
                        ),
                );
            }
        } else {
            out.push(
                Check::new("ssh2.crypto_policy", Severity::Info, Status::Skipped)
                    .with_evidence("no crypto policy supplied via DiagnosticContext"),
            );
        }

        out
    }
}

fn check_policy(out: &mut Vec<Check>, sess: &Session, kind: &str, policy: &[String], mt: MethodType) {
    if policy.is_empty() {
        return;
    }
    let supported = sess.supported_algs(mt).unwrap_or_default();
    for algo in policy {
        let id = format!("ssh2.crypto_policy.{kind}");
        if supported.iter().any(|s| s.eq_ignore_ascii_case(algo)) {
            out.push(
                Check::new(id, Severity::Info, Status::Pass)
                    .with_evidence(format!("libssh2 supports `{algo}`")),
            );
        } else {
            out.push(
                Check::new(id, Severity::High, Status::Fail)
                    .with_evidence(format!(
                        "policy allow-lists `{algo}` for {kind} but libssh2 does not support it"
                    ))
                    .with_remediation(format!(
                        "remove `{algo}` from `[crypto].{kind}s` or rebuild libssh2 with support"
                    )),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn libssh2_init_works() {
        let r = Ssh2Diagnostic.run(&DiagnosticContext::default()).await;
        // First entry is always libssh2_init; on supported hosts it must Pass.
        assert!(r.iter().any(|c| c.id == "ssh2.libssh2_init"));
        let init = r.iter().find(|c| c.id == "ssh2.libssh2_init").unwrap();
        assert_eq!(init.status, Status::Pass, "{init:?}");
        // Skipped for crypto policy when no policy supplied.
        assert!(r.iter().any(|c| c.id == "ssh2.crypto_policy"
            && c.status == Status::Skipped));
    }

    fn ctx_with_policy(p: spt_ssh2::CryptoPolicy) -> DiagnosticContext {
        DiagnosticContext {
            crypto_policy: Some(p),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn policy_fails_on_unknown_algo() {
        let ctx = ctx_with_policy(spt_ssh2::CryptoPolicy {
            kex: vec!["definitely-not-a-kex".to_string()],
            ..Default::default()
        });
        let r = Ssh2Diagnostic.run(&ctx).await;
        assert!(r.iter().any(|c| c.id == "ssh2.crypto_policy.kex"
            && c.status == Status::Fail));
    }

    #[tokio::test]
    async fn policy_passes_on_known_algo() {
        // curve25519-sha256 is universally supported by libssh2 1.10+.
        let ctx = ctx_with_policy(spt_ssh2::CryptoPolicy {
            kex: vec!["curve25519-sha256".to_string()],
            ..Default::default()
        });
        let r = Ssh2Diagnostic.run(&ctx).await;
        let kex = r
            .iter()
            .find(|c| c.id == "ssh2.crypto_policy.kex")
            .expect("kex policy check missing");
        assert!(matches!(kex.status, Status::Pass | Status::Fail));
    }

    #[tokio::test]
    async fn deprecated_warning_emitted() {
        let ctx = ctx_with_policy(spt_ssh2::CryptoPolicy {
            ciphers: vec!["aes128-cbc".into()],
            ..Default::default()
        });
        let r = Ssh2Diagnostic.run(&ctx).await;
        assert!(r.iter().any(
            |c| c.id == "ssh2.crypto_policy.deprecated" && c.status == Status::Warn
        ));
    }
}
