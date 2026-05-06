//! SHA-256 host pin map: explicit pinning of host keys by their OpenSSH
//! `SHA256:<base64nopadding>` fingerprint, independent of `known_hosts`.
//!
//! This is the second leg of the SSH2 trust model in spec §9.13: a profile
//! may carry a `pin_sha256 = ["SHA256:abc…"]` array that is consulted in
//! addition to (or instead of) `known_hosts`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};
use subtle::ConstantTimeEq;

use crate::known_hosts::KnownHostsResult;

/// One or more accepted SHA-256 fingerprints per `(host, port)` pair.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Sha256HostPin {
    /// Map from `host:port` → list of accepted `SHA256:base64nopad` strings.
    pub pins: HashMap<String, Vec<String>>,
}

impl Sha256HostPin {
    /// Construct an empty pin map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single pin entry.
    pub fn insert(&mut self, host: &str, port: u16, fingerprint: impl Into<String>) {
        let key = format_host_key(host, port);
        self.pins.entry(key).or_default().push(fingerprint.into());
    }

    /// Verify that `key`'s SHA-256 fingerprint matches one of the configured
    /// pins for `(host, port)`.
    #[must_use]
    pub fn verify(&self, host: &str, port: u16, key: &PublicKey) -> KnownHostsResult {
        let want = key.fingerprint(HashAlg::Sha256).to_string();
        let key_host = format_host_key(host, port);
        let Some(list) = self.pins.get(&key_host) else {
            return KnownHostsResult::NotFound;
        };
        for entry in list {
            if entry.as_bytes().ct_eq(want.as_bytes()).into() {
                return KnownHostsResult::Match;
            }
        }
        KnownHostsResult::Mismatch {
            stored: vec![key.clone()],
        }
    }
}

fn format_host_key(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    use super::*;

    #[test]
    fn match_and_mismatch() {
        let pk = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let key = pk.public_key().clone();
        let fp = key.fingerprint(HashAlg::Sha256).to_string();

        let mut p = Sha256HostPin::new();
        p.insert("h.example", 22, fp);

        assert_eq!(p.verify("h.example", 22, &key), KnownHostsResult::Match);

        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();
        assert!(matches!(
            p.verify("h.example", 22, &other),
            KnownHostsResult::Mismatch { .. }
        ));
        assert_eq!(
            p.verify("missing.example", 22, &key),
            KnownHostsResult::NotFound
        );
    }
}
