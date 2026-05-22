//! Host-key verification wiring (russh-only since t7-Phase0).
//!
//! russh hands the host key directly as a `russh_keys::key::PublicKey` —
//! the russh-backend converts it to `ssh_key::PublicKey` via
//! [`russh_keys::PublicKeyBase64`] before calling [`TrustVerifier::verify`].
//! The libssh2 `HostKeyType`-tagged blob path was removed alongside the
//! `async-ssh2-lite` dispatch.

use spt_core::{Error, Result};
use spt_trust::known_hosts::KnownHostsResult;
use spt_trust::{KnownHosts, Sha256HostPin};
use ssh_key::PublicKey;

/// Trust verification policy carried by a profile.
#[derive(Debug, Clone, Default)]
pub struct TrustVerifier {
    /// Optional `known_hosts` file contents.
    pub known_hosts: Option<KnownHosts>,
    /// Optional SHA-256 pin map.
    pub sha256_pins: Option<Sha256HostPin>,
    /// If `true`, verification fails when no entry exists for the host
    /// (TOFU disabled). If `false` and `known_hosts` is configured but lacks
    /// an entry, the key is accepted *only when* `Sha256HostPin` also has no
    /// entry — pure TOFU adoption is left to the supervisor's prompt-loop.
    pub strict: bool,
}

/// Outcome of a host-key check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyOutcome {
    /// Host is known and the key matches.
    Match,
    /// No entry was found in any configured trust source.
    NotFound,
}

impl TrustVerifier {
    /// Verify the presented key against every configured source. Errors out
    /// on the first source that returns `Mismatch` or `Revoked`.
    pub fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<HostKeyOutcome> {
        let mut any_found = false;
        if let Some(kh) = &self.known_hosts {
            match kh.verify(host, port, key) {
                KnownHostsResult::Match => return Ok(HostKeyOutcome::Match),
                KnownHostsResult::Mismatch { .. } => {
                    return Err(Error::TrustFailed(format!(
                        "known_hosts mismatch for {host}:{port}"
                    )));
                }
                KnownHostsResult::Revoked => {
                    return Err(Error::TrustFailed(format!(
                        "host key for {host}:{port} is @revoked in known_hosts"
                    )));
                }
                KnownHostsResult::NotFound => {}
            }
        }
        if let Some(pin) = &self.sha256_pins {
            match pin.verify(host, port, key) {
                KnownHostsResult::Match => return Ok(HostKeyOutcome::Match),
                KnownHostsResult::Mismatch { .. } => {
                    return Err(Error::TrustFailed(format!(
                        "SHA-256 pin mismatch for {host}:{port}"
                    )));
                }
                KnownHostsResult::Revoked => {
                    // Pin map does not encode revocation; treat as mismatch.
                    return Err(Error::TrustFailed(format!(
                        "SHA-256 pin: revoked key for {host}:{port}"
                    )));
                }
                KnownHostsResult::NotFound => any_found |= false,
            }
        }
        if self.strict {
            return Err(Error::TrustFailed(format!(
                "host {host}:{port} not found in any trust source (strict mode)"
            )));
        }
        let _ = any_found;
        Ok(HostKeyOutcome::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm as SkAlgorithm, PrivateKey};

    fn fresh_pub() -> PublicKey {
        let mut rng = ssh_key::rand_core::OsRng;
        PrivateKey::random(&mut rng, SkAlgorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    #[test]
    fn known_hosts_match_returns_match() {
        let key = fresh_pub();
        let mut kh = KnownHosts::default();
        kh.add("h.example", 22, key.clone(), false);
        let v = TrustVerifier {
            known_hosts: Some(kh),
            sha256_pins: None,
            strict: true,
        };
        assert_eq!(
            v.verify("h.example", 22, &key).unwrap(),
            HostKeyOutcome::Match
        );
    }

    #[test]
    fn known_hosts_mismatch_errors() {
        let stored = fresh_pub();
        let presented = fresh_pub();
        let mut kh = KnownHosts::default();
        kh.add("h.example", 22, stored, false);
        let v = TrustVerifier {
            known_hosts: Some(kh),
            ..Default::default()
        };
        let err = v.verify("h.example", 22, &presented).unwrap_err();
        assert!(matches!(err, Error::TrustFailed(_)));
    }

    #[test]
    fn strict_no_entry_errors() {
        let key = fresh_pub();
        let v = TrustVerifier {
            strict: true,
            ..Default::default()
        };
        let err = v.verify("nope.example", 22, &key).unwrap_err();
        assert!(matches!(err, Error::TrustFailed(_)));
    }

    #[test]
    fn non_strict_no_entry_returns_notfound() {
        let key = fresh_pub();
        let v = TrustVerifier::default();
        assert_eq!(
            v.verify("nope.example", 22, &key).unwrap(),
            HostKeyOutcome::NotFound
        );
    }

    #[test]
    fn pin_match_via_sha256() {
        use ssh_key::HashAlg;
        let key = fresh_pub();
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let mut pin = Sha256HostPin::default();
        pin.insert("h.example", 22, fp);
        let v = TrustVerifier {
            sha256_pins: Some(pin),
            strict: true,
            ..Default::default()
        };
        assert_eq!(
            v.verify("h.example", 22, &key).unwrap(),
            HostKeyOutcome::Match
        );
    }
}
