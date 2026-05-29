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
use ssh_key::{HashAlg, PublicKey};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Trust verification policy carried by a profile.
#[derive(Debug, Clone, Default)]
pub struct TrustVerifier {
    /// Optional `known_hosts` file contents.
    pub known_hosts: Option<KnownHosts>,
    /// Optional SHA-256 pin map.
    pub sha256_pins: Option<Sha256HostPin>,
    /// On-disk `known_hosts` path. Required when [`Self::accept_new`] is true
    /// so a TOFU-accepted key can be persisted.
    pub known_hosts_path: Option<PathBuf>,
    /// If `true`, verification fails when no entry exists for the host (no
    /// TOFU). If `false` and no source records the host, the result is
    /// `NotFound`. The russh handler treats `NotFound` as a connection
    /// refusal; see [`HostKeyOutcome`].
    pub strict: bool,
    /// Trust-on-first-use. When `true` and `verify()` would otherwise return
    /// `NotFound`, the presented key is appended to [`Self::known_hosts_path`]
    /// and the outcome becomes [`HostKeyOutcome::TofuAdded`] (the handler
    /// accepts the connection). A *mismatch* against an existing entry is
    /// **never** TOFU-accepted — it still errors with `TrustFailed`.
    pub accept_new: bool,
}

/// Outcome of a host-key check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyOutcome {
    /// Host is known and the key matches.
    Match,
    /// No entry was found in any configured trust source. The russh handler
    /// must treat this as a refusal — otherwise any server key would be
    /// accepted on first connect.
    NotFound,
    /// No entry existed and the policy has `accept_new = true` (TOFU). The
    /// key was appended to the configured `known_hosts` file and the handler
    /// must accept the connection.
    TofuAdded,
}

impl TrustVerifier {
    /// Verify the presented key against every configured source. Errors out
    /// on the first source that returns `Mismatch` or `Revoked`. When no
    /// source records the host and [`Self::accept_new`] is true, the key is
    /// persisted to [`Self::known_hosts_path`] and the outcome is
    /// `TofuAdded`.
    pub fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<HostKeyOutcome> {
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
                KnownHostsResult::NotFound => {}
            }
        }
        // TOFU branch: configured + permitted + writable target. Only fires
        // when every source returned `NotFound` (mismatches above already
        // returned `Err`).
        if self.accept_new {
            if let Some(path) = &self.known_hosts_path {
                append_known_hosts(path, host, port, key)?;
                let fp = key.fingerprint(HashAlg::Sha256);
                warn!(
                    target: "spt_ssh2::trust",
                    host = host,
                    port = port,
                    fingerprint = %fp,
                    path = %path.display(),
                    "TOFU: accepted new host key and persisted to known_hosts"
                );
                return Ok(HostKeyOutcome::TofuAdded);
            }
        }
        if self.strict {
            return Err(Error::TrustFailed(format!(
                "host {host}:{port} not found in any trust source (strict mode)"
            )));
        }
        Ok(HostKeyOutcome::NotFound)
    }
}

/// Append a single OpenSSH `known_hosts` line. `O_APPEND` makes the write
/// atomic for line-length writes on POSIX, and `FILE_APPEND_DATA` likewise
/// on Windows, so a concurrent reconnect appending another TOFU line cannot
/// interleave with this one.
fn append_known_hosts(path: &Path, host: &str, port: u16, key: &PublicKey) -> Result<()> {
    let host_prefix = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    let encoded = key
        .to_openssh()
        .map_err(|e| Error::TrustFailed(format!("encode host key for TOFU append: {e}")))?;
    let line = format!("{host_prefix} {encoded}\n");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| {
            Error::TrustFailed(format!(
                "open known_hosts {} for TOFU append: {e}",
                path.display()
            ))
        })?;
    f.write_all(line.as_bytes()).map_err(|e| {
        Error::TrustFailed(format!(
            "write known_hosts {} for TOFU append: {e}",
            path.display()
        ))
    })?;
    Ok(())
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
            ..Default::default()
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
    fn tofu_appends_and_returns_added() {
        let key = fresh_pub();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let v = TrustVerifier {
            accept_new: true,
            known_hosts_path: Some(path.clone()),
            ..Default::default()
        };
        assert_eq!(
            v.verify("new.example", 2222, &key).unwrap(),
            HostKeyOutcome::TofuAdded
        );
        let body = std::fs::read_to_string(&path).unwrap();
        // Non-default port is bracket-quoted per OpenSSH known_hosts grammar.
        assert!(body.starts_with("[new.example]:2222 "));
        assert!(body.ends_with('\n'));
        // A second TOFU append for a different host extends the file.
        let key2 = fresh_pub();
        v.verify("other.example", 22, &key2).unwrap();
        let body2 = std::fs::read_to_string(&path).unwrap();
        assert!(body2.lines().count() == 2);
    }

    #[test]
    fn tofu_without_path_falls_through() {
        // accept_new + no path + non-strict → NotFound (not error, not added).
        let key = fresh_pub();
        let v = TrustVerifier {
            accept_new: true,
            known_hosts_path: None,
            ..Default::default()
        };
        assert_eq!(
            v.verify("h.example", 22, &key).unwrap(),
            HostKeyOutcome::NotFound
        );
    }

    #[test]
    fn tofu_does_not_override_mismatch() {
        // Existing entry + presented key differs → TrustFailed regardless of
        // accept_new. This is the critical invariant: TOFU only ever applies
        // when *no* entry exists.
        let stored = fresh_pub();
        let presented = fresh_pub();
        let mut kh = KnownHosts::default();
        kh.add("h.example", 22, stored, false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let v = TrustVerifier {
            known_hosts: Some(kh),
            accept_new: true,
            known_hosts_path: Some(path.clone()),
            ..Default::default()
        };
        let err = v.verify("h.example", 22, &presented).unwrap_err();
        assert!(matches!(err, Error::TrustFailed(_)));
        // File must not have been touched.
        assert!(!path.exists());
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
