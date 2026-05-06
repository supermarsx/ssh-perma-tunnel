//! Host-key verification wiring.
//!
//! libssh2 surfaces the peer's host key as raw bytes plus a "key type" hint
//! (`HostKeyType`). We rebuild an `ssh_key::PublicKey` from those bytes and
//! delegate to the verifier configured by the profile (`KnownHosts` and/or
//! `Sha256HostPin`).

use spt_core::{Error, Result};
use spt_trust::known_hosts::KnownHostsResult;
use spt_trust::{KnownHosts, Sha256HostPin};
use ssh2::HostKeyType;
use ssh_key::public::{Ed25519PublicKey, KeyData, RsaPublicKey};
use ssh_key::{Algorithm, EcdsaCurve, Mpint, PublicKey};

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
    pub fn verify(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<HostKeyOutcome> {
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

/// Convert libssh2's `(blob, host_key_type)` tuple into an `ssh_key::PublicKey`.
///
/// libssh2 returns the key's wire-format `mpint` blob (RSA/DSA/ECDSA) or the
/// raw 32-byte ed25519 public key. We reconstruct the typed key.
pub fn rebuild_public_key(blob: &[u8], ty: HostKeyType) -> Result<PublicKey> {
    let key_data = match ty {
        HostKeyType::Rsa => {
            // libssh2 RSA host key blob: ssh string `e` || ssh string `n`.
            let (e, rest) = read_ssh_string(blob)?;
            let (n, _) = read_ssh_string(rest)?;
            KeyData::Rsa(RsaPublicKey {
                e: Mpint::from_bytes(e).map_err(map_err)?,
                n: Mpint::from_bytes(n).map_err(map_err)?,
            })
        }
        HostKeyType::Ed25519 => {
            if blob.len() != 32 {
                return Err(Error::TrustFailed(format!(
                    "ed25519 host key blob length {} != 32",
                    blob.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(blob);
            KeyData::Ed25519(Ed25519PublicKey(arr))
        }
        HostKeyType::Ecdsa256 | HostKeyType::Ecdsa384 | HostKeyType::Ecdsa521 => {
            let _curve = match ty {
                HostKeyType::Ecdsa256 => EcdsaCurve::NistP256,
                HostKeyType::Ecdsa384 => EcdsaCurve::NistP384,
                _ => EcdsaCurve::NistP521,
            };
            // libssh2 returns the raw uncompressed EC point (leading 0x04).
            let pk = ssh_key::public::EcdsaPublicKey::from_sec1_bytes(blob)
                .map_err(map_err)?;
            KeyData::Ecdsa(pk)
        }
        HostKeyType::Dss => {
            return Err(Error::TrustFailed(
                "DSS host keys are not supported (deprecated)".into(),
            ));
        }
        HostKeyType::Unknown => {
            return Err(Error::TrustFailed(
                "peer presented an unknown host-key type".into(),
            ));
        }
    };
    let alg = match &key_data {
        KeyData::Rsa(_) => Algorithm::Rsa { hash: None },
        KeyData::Ed25519(_) => Algorithm::Ed25519,
        KeyData::Ecdsa(k) => Algorithm::Ecdsa { curve: k.curve() },
        _ => unreachable!(),
    };
    let _ = alg;
    Ok(PublicKey::new(key_data, ""))
}

fn read_ssh_string(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    if buf.len() < 4 {
        return Err(Error::TrustFailed("truncated host-key blob".into()));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Err(Error::TrustFailed("host-key field overruns blob".into()));
    }
    Ok((&buf[4..4 + len], &buf[4 + len..]))
}

#[allow(clippy::needless_pass_by_value)]
fn map_err(e: ssh_key::Error) -> Error {
    Error::TrustFailed(format!("ssh-key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use ssh_key::{Algorithm as SkAlgorithm, PrivateKey};

    fn fresh_pub() -> PublicKey {
        PrivateKey::random(&mut OsRng, SkAlgorithm::Ed25519)
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

    #[test]
    fn rebuild_ed25519_roundtrip() {
        use ssh_key::HashAlg;
        let key = fresh_pub();
        // Extract raw 32-byte ed25519 pub bytes
        let bytes = match key.key_data() {
            KeyData::Ed25519(b) => b.0,
            _ => unreachable!(),
        };
        let rebuilt = rebuild_public_key(&bytes, HostKeyType::Ed25519).unwrap();
        // Compare via fingerprint
        assert_eq!(
            rebuilt.fingerprint(HashAlg::Sha256).to_string(),
            key.fingerprint(HashAlg::Sha256).to_string()
        );
    }
}
