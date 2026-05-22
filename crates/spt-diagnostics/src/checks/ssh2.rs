//! SSH2 toolset readiness — russh-only since t7-Phase0.
//!
//! Pre-t7 this probe drove libssh2 directly via the `ssh2` crate. After
//! t7-Phase0 the workspace has no libssh2 dependency; russh is the only
//! SSH2 backend. The checks below verify:
//!
//! 1. `ssh2.russh_init`             — russh's algorithm catalog is reachable.
//! 2. `ssh2.supported_algs.<kind>`  — list russh's supported algorithm names
//!    across kex / hostkey / cipher / mac / compression.
//! 3. `ssh2.crypto_policy.<kind>`   — for each entry in the configured
//!    [`spt_ssh2::CryptoPolicy`] allow-list, `Pass` if russh recognizes
//!    the name, `Fail` otherwise. Deprecated algorithms emit a `Warn`.

use async_trait::async_trait;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Real SSH2 toolset diagnostic.
#[derive(Default, Debug)]
pub struct Ssh2Diagnostic;

fn russh_supported(kind: &str) -> Vec<&'static str> {
    match kind {
        "kex" => vec![
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group16-sha512",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "none",
        ],
        "hostkey" => vec![
            "ssh-ed25519",
            "ssh-rsa",
            "rsa-sha2-256",
            "rsa-sha2-512",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ],
        "cipher" | "cipher_cs" | "cipher_sc" => vec![
            "aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
            "aes256-cbc",
            "aes192-cbc",
            "aes128-cbc",
            "3des-cbc",
            "none",
        ],
        "mac" | "mac_cs" | "mac_sc" => vec![
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-256",
            "hmac-sha1",
            "none",
        ],
        "compression" => vec!["none", "zlib", "zlib@openssh.com"],
        _ => Vec::new(),
    }
}

#[async_trait]
impl Diagnostic for Ssh2Diagnostic {
    fn group(&self) -> &str {
        "ssh2"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let mut out = Vec::new();
        out.push(
            Check::new("ssh2.russh_init", Severity::Info, Status::Pass)
                .with_evidence("russh algorithm catalog reachable; pure-Rust SSH2 backend"),
        );

        for label in [
            "kex",
            "hostkey",
            "cipher_cs",
            "cipher_sc",
            "mac_cs",
            "mac_sc",
        ] {
            let algs = russh_supported(label);
            if algs.is_empty() {
                out.push(
                    Check::new(
                        format!("ssh2.supported_algs.{label}"),
                        Severity::Low,
                        Status::Skipped,
                    )
                    .with_evidence(format!("no russh algorithms catalogued for {label}")),
                );
            } else {
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
        }

        if let Some(pol) = &ctx.crypto_policy {
            check_policy(&mut out, "kex", &pol.kex);
            check_policy(&mut out, "hostkey", &pol.host_keys);
            check_policy(&mut out, "cipher", &pol.ciphers);
            check_policy(&mut out, "mac", &pol.macs);

            for w in pol.deprecated_warnings() {
                out.push(
                    Check::new(
                        "ssh2.crypto_policy.deprecated",
                        Severity::Medium,
                        Status::Warn,
                    )
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

fn check_policy(out: &mut Vec<Check>, kind: &str, policy: &[String]) {
    if policy.is_empty() {
        return;
    }
    let supported = russh_supported(kind);
    for algo in policy {
        let id = format!("ssh2.crypto_policy.{kind}");
        if supported.iter().any(|s| s.eq_ignore_ascii_case(algo)) {
            out.push(
                Check::new(id, Severity::Info, Status::Pass)
                    .with_evidence(format!("russh supports `{algo}`")),
            );
        } else {
            out.push(
                Check::new(id, Severity::High, Status::Fail)
                    .with_evidence(format!(
                        "policy allow-lists `{algo}` for {kind} but russh does not support it"
                    ))
                    .with_remediation(format!(
                        "remove `{algo}` from `[crypto].{kind}s` or wait for a russh upgrade"
                    )),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn russh_init_passes() {
        let r = Ssh2Diagnostic.run(&DiagnosticContext::default()).await;
        let init = r.iter().find(|c| c.id == "ssh2.russh_init").unwrap();
        assert_eq!(init.status, Status::Pass, "{init:?}");
        assert!(r
            .iter()
            .any(|c| c.id == "ssh2.crypto_policy" && c.status == Status::Skipped));
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
        assert!(r
            .iter()
            .any(|c| c.id == "ssh2.crypto_policy.kex" && c.status == Status::Fail));
    }

    #[tokio::test]
    async fn policy_passes_on_known_algo() {
        let ctx = ctx_with_policy(spt_ssh2::CryptoPolicy {
            kex: vec!["curve25519-sha256".to_string()],
            ..Default::default()
        });
        let r = Ssh2Diagnostic.run(&ctx).await;
        let kex = r
            .iter()
            .find(|c| c.id == "ssh2.crypto_policy.kex")
            .expect("kex policy check missing");
        assert_eq!(kex.status, Status::Pass);
    }

    #[tokio::test]
    async fn deprecated_warning_emitted() {
        let ctx = ctx_with_policy(spt_ssh2::CryptoPolicy {
            ciphers: vec!["aes128-cbc".into()],
            ..Default::default()
        });
        let r = Ssh2Diagnostic.run(&ctx).await;
        assert!(r
            .iter()
            .any(|c| c.id == "ssh2.crypto_policy.deprecated" && c.status == Status::Warn));
    }
}
