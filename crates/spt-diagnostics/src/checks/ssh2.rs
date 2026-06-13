//! SSH2 toolset readiness — russh-only since t7-Phase0.
//!
//! Pre-t7 this probe drove libssh2 directly via the `ssh2` crate. After
//! t7-Phase0 the workspace has no libssh2 dependency; russh is the only
//! SSH2 backend. The checks below verify:
//!
//! 1. `ssh2.russh_init`             — russh's algorithm catalog is reachable.
//!    Built by reading [`russh::Preferred::DEFAULT`] at runtime rather than
//!    a hardcoded `Pass`, so the check fails loudly if russh ever ships an
//!    empty default negotiation set (E8-F8).
//! 2. `ssh2.supported_algs.<kind>`  — list russh's *actually-negotiated*
//!    default algorithm names across kex / hostkey / cipher / mac /
//!    compression, queried live from [`russh::Preferred::DEFAULT`] so the
//!    listing can never silently drift from the linked russh version
//!    (previously a hand-maintained string table — E8-F8).
//! 3. `ssh2.crypto_policy.<kind>`   — for each entry in the configured
//!    [`spt_ssh2::CryptoPolicy`] allow-list, `Pass` if russh recognizes
//!    the name (via the real `TryFrom<&str>` parser russh uses on connect),
//!    `Fail` otherwise. Deprecated algorithms emit a `Warn`.

use async_trait::async_trait;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Real SSH2 toolset diagnostic.
#[derive(Default, Debug)]
pub struct Ssh2Diagnostic;

/// The russh default-negotiated algorithm names for `kind`, queried live from
/// [`russh::Preferred::DEFAULT`]. Returns owned `String`s because russh's
/// `Name` newtypes only expose `&str` borrows tied to the (static) default.
///
/// `kind` accepts both bare (`cipher`, `mac`) and direction-suffixed
/// (`cipher_cs`, `cipher_sc`, `mac_cs`, `mac_sc`) labels; russh negotiates a
/// single set per direction-pair, so both suffixes map to the same list.
fn russh_supported(kind: &str) -> Vec<String> {
    let p = russh::Preferred::DEFAULT;
    match kind {
        "kex" => p.kex.iter().map(|n| n.as_ref().to_string()).collect(),
        "hostkey" | "host_key" | "key" => {
            p.key.iter().map(|n| n.as_ref().to_string()).collect()
        }
        "cipher" | "cipher_cs" | "cipher_sc" => {
            p.cipher.iter().map(|n| n.as_ref().to_string()).collect()
        }
        "mac" | "mac_cs" | "mac_sc" => p.mac.iter().map(|n| n.as_ref().to_string()).collect(),
        "compression" => p
            .compression
            .iter()
            .map(|n| n.as_ref().to_string())
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether russh recognizes `algo` for `kind`, using the *same* `TryFrom<&str>`
/// parsers russh applies when building a connection's `Preferred` set. This is
/// the real acceptance test — a name passes here iff russh would accept it on
/// the wire, not iff it appears in a hand-maintained list.
fn russh_recognizes(kind: &str, algo: &str) -> bool {
    match kind {
        "kex" => russh::kex::Name::try_from(algo).is_ok(),
        // russh 0.61: host-key algorithms are `ssh_key::Algorithm` (parsed via
        // `Algorithm::new`), not a dedicated `key::Name` newtype.
        "hostkey" | "host_key" | "key" => russh::keys::ssh_key::Algorithm::new(algo).is_ok(),
        "cipher" => russh::cipher::Name::try_from(algo).is_ok(),
        "mac" => russh::mac::Name::try_from(algo).is_ok(),
        "compression" => russh::compression::Name::try_from(algo).is_ok(),
        _ => false,
    }
}

#[async_trait]
impl Diagnostic for Ssh2Diagnostic {
    fn group(&self) -> &'static str {
        "ssh2"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let mut out = Vec::new();

        // E8-F8: actually probe russh rather than hardcoding `Pass`. Reading
        // `Preferred::DEFAULT` exercises the algorithm-catalog statics; a
        // healthy backend negotiates at least one kex / key / cipher / mac by
        // default. An empty default set means russh shipped a broken build.
        let p = russh::Preferred::DEFAULT;
        let catalogue_total =
            p.kex.len() + p.key.len() + p.cipher.len() + p.mac.len() + p.compression.len();
        if p.kex.is_empty() || p.key.is_empty() || p.cipher.is_empty() || p.mac.is_empty() {
            out.push(
                Check::new("ssh2.russh_init", Severity::High, Status::Fail)
                    .with_evidence(format!(
                        "russh default negotiation set is incomplete: \
                         kex={} key={} cipher={} mac={}",
                        p.kex.len(),
                        p.key.len(),
                        p.cipher.len(),
                        p.mac.len(),
                    ))
                    .with_remediation("the linked russh build is broken; reinstall / rebuild spt"),
            );
        } else {
            out.push(
                Check::new("ssh2.russh_init", Severity::Info, Status::Pass).with_evidence(format!(
                    "russh algorithm catalog reachable ({catalogue_total} default algorithms); \
                     pure-Rust SSH2 backend"
                )),
            );
        }

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
    for algo in policy {
        let id = format!("ssh2.crypto_policy.{kind}");
        // Validate against russh's real `TryFrom<&str>` parser, not just the
        // default-negotiated subset: a policy may legitimately request a
        // non-default-but-supported algorithm (e.g. an extra cipher).
        if russh_recognizes(kind, algo) {
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

    // E8-F8: the supported-algs listing must be *derived* from russh, not a
    // frozen string table. Tie the diagnostic's reported counts back to
    // `russh::Preferred::DEFAULT` so a russh upgrade that changes the default
    // set is reflected automatically (and this test fails if the wiring is
    // ever reverted to a hardcoded list).
    #[test]
    fn supported_algs_are_queried_live_from_russh() {
        let p = russh::Preferred::DEFAULT;
        assert_eq!(russh_supported("kex").len(), p.kex.len());
        assert_eq!(russh_supported("cipher").len(), p.cipher.len());
        assert_eq!(russh_supported("mac").len(), p.mac.len());
        assert_eq!(russh_supported("hostkey").len(), p.key.len());
        // curve25519 is russh's default kex; if russh drops it this fails loud.
        assert!(
            russh_supported("kex")
                .iter()
                .any(|a| a.starts_with("curve25519-sha256")),
            "russh default kex set: {:?}",
            russh_supported("kex"),
        );
        // Direction suffixes resolve to the same set as the bare label.
        assert_eq!(russh_supported("cipher"), russh_supported("cipher_cs"));
        assert_eq!(russh_supported("mac_sc"), russh_supported("mac"));
        assert!(russh_supported("bogus-kind").is_empty());
    }

    // The policy acceptance test now uses russh's real parser: a supported
    // cipher that is *not* in the default negotiation set must still Pass.
    #[tokio::test]
    async fn policy_passes_on_supported_non_default_algo() {
        // aes256-cbc is recognized by russh's `TryFrom` parser but is not a
        // default cipher; the old default-list test would have failed it.
        if russh_recognizes("cipher", "aes256-cbc") {
            let ctx = ctx_with_policy(spt_ssh2::CryptoPolicy {
                ciphers: vec!["aes256-cbc".to_string()],
                ..Default::default()
            });
            let r = Ssh2Diagnostic.run(&ctx).await;
            assert!(
                r.iter()
                    .any(|c| c.id == "ssh2.crypto_policy.cipher" && c.status == Status::Pass),
                "checks: {r:?}"
            );
        }
    }

    #[test]
    fn russh_recognizes_known_and_rejects_unknown() {
        assert!(russh_recognizes("kex", "curve25519-sha256"));
        assert!(russh_recognizes("mac", "hmac-sha2-256"));
        assert!(!russh_recognizes("kex", "definitely-not-a-kex"));
        assert!(!russh_recognizes("unknown-kind", "anything"));
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
