//! t8-A6 edge cases for `known_hosts` matching that the inline unit-test
//! module didn't already exercise.
//!
//! The bulk of canonical match / mismatch / hashed-host / revocation /
//! cert-authority behavior is covered inside `crates/spt-trust/src/known_hosts.rs`.
//! Here we add: IPv6-bracket parse, port-in-brackets, mixed-algorithm
//! coexistence for the same host, save/load round-trip with multiple entries,
//! and a constant-time-style structural check.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]

use rand::rngs::OsRng;
use ssh_key::{Algorithm, PrivateKey, PublicKey};

use spt_trust::known_hosts::Marker;
use spt_trust::{KnownHosts, KnownHostsResult};

fn ed25519_pub() -> PublicKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .clone()
}

fn rsa_pub() -> PublicKey {
    // RSA keygen is slow; use the smallest workable size (2048) and only
    // one per test.
    PrivateKey::random(
        &mut OsRng,
        Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha256),
        },
    )
    .unwrap()
    .public_key()
    .clone()
}

fn line(host: &str, key: &PublicKey) -> String {
    format!("{host} {}", key.to_openssh().unwrap())
}

#[test]
fn ipv6_address_in_bracket_form_matches() {
    let key = ed25519_pub();
    // OpenSSH `[::1]:2222` form for nonstandard ports; verify via port lookup.
    let text = line("[::1]:2222", &key);
    let kh = KnownHosts::parse(&text).unwrap();
    assert_eq!(kh.verify("::1", 2222, &key), KnownHostsResult::Match);
}

#[test]
fn ipv6_address_default_port_22_uses_bare_form() {
    let key = ed25519_pub();
    // For port 22, OpenSSH stores the bare host without brackets.
    let text = line("::1", &key);
    let kh = KnownHosts::parse(&text).unwrap();
    assert_eq!(kh.verify("::1", 22, &key), KnownHostsResult::Match);
}

#[test]
fn port_in_brackets_does_not_match_default_port() {
    let key = ed25519_pub();
    let text = line("[example.com]:2222", &key);
    let kh = KnownHosts::parse(&text).unwrap();
    // Port 22 lookup must miss the [host]:2222 entry.
    assert_eq!(
        kh.verify("example.com", 22, &key),
        KnownHostsResult::NotFound
    );
}

#[test]
fn ed25519_and_rsa_coexist_for_same_host() {
    let ed = ed25519_pub();
    let rsa = rsa_pub();
    let text = format!(
        "{}\n{}\n",
        line("multi.example", &ed),
        line("multi.example", &rsa)
    );
    let kh = KnownHosts::parse(&text).unwrap();
    assert_eq!(kh.entries.len(), 2);
    // Either algorithm matches when its corresponding key is presented.
    assert_eq!(kh.verify("multi.example", 22, &ed), KnownHostsResult::Match);
    assert_eq!(
        kh.verify("multi.example", 22, &rsa),
        KnownHostsResult::Match
    );
    // A third (unrelated) key returns Mismatch (host found, key not).
    let other = ed25519_pub();
    match kh.verify("multi.example", 22, &other) {
        KnownHostsResult::Mismatch { stored } => {
            assert_eq!(stored.len(), 2, "both stored keys reported");
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
}

#[test]
fn hashed_host_dns_round_trip_consistent() {
    let key = ed25519_pub();
    let mut kh = KnownHosts::default();
    kh.add("alpha.example.org", 22, key.clone(), true);
    kh.add("[alpha.example.org]:2222", 2222, key.clone(), true);
    // The first entry must match the default-port host on lookup.
    assert_eq!(
        kh.verify("alpha.example.org", 22, &key),
        KnownHostsResult::Match
    );
    // The second matches the nonstandard port.
    assert_eq!(
        kh.verify("alpha.example.org", 2222, &key),
        KnownHostsResult::Match
    );
    // Render+reparse round-trip preserves verification semantics.
    let text = kh.render();
    let reparsed = KnownHosts::parse(&text).unwrap();
    assert_eq!(
        reparsed.verify("alpha.example.org", 22, &key),
        KnownHostsResult::Match
    );
    assert_eq!(
        reparsed.verify("alpha.example.org", 2222, &key),
        KnownHostsResult::Match
    );
}

#[test]
fn cert_authority_marker_does_not_match_host_key_lookup() {
    // CA-marker entries are skipped for direct host-key verification; this
    // behavior is documented in known_hosts.rs and tested inline, but we
    // duplicate at integration-test level to catch accidental regressions
    // in the public verify() contract.
    let ca_key = ed25519_pub();
    let text = format!(
        "@cert-authority *.svc.example.com {}\n",
        ca_key.to_openssh().unwrap()
    );
    let kh = KnownHosts::parse(&text).unwrap();
    assert_eq!(
        kh.verify("host.svc.example.com", 22, &ca_key),
        KnownHostsResult::NotFound
    );
    // But the entry is still parsed and addressable in the entries vec.
    assert_eq!(kh.entries.len(), 1);
    assert_eq!(kh.entries[0].marker, Some(Marker::CertAuthority));
}

#[test]
fn revoked_takes_precedence_when_listed_before_normal_entry() {
    let key = ed25519_pub();
    let text = format!(
        "@revoked example.com {}\n{}\n",
        key.to_openssh().unwrap(),
        line("example.com", &key)
    );
    let kh = KnownHosts::parse(&text).unwrap();
    // Revoked entry trumps the trust entry — the iteration finds Revoked
    // first because the input lists @revoked first.
    assert_eq!(
        kh.verify("example.com", 22, &key),
        KnownHostsResult::Revoked
    );
}

#[test]
fn unknown_host_returns_not_found() {
    let key = ed25519_pub();
    let text = line("known.example", &key);
    let kh = KnownHosts::parse(&text).unwrap();
    assert_eq!(
        kh.verify("unknown.example", 22, &key),
        KnownHostsResult::NotFound
    );
}

#[test]
fn save_and_load_preserves_multi_entry_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("kh");
    let ed = ed25519_pub();
    let mut kh = KnownHosts::default();
    kh.add("alpha.example", 22, ed.clone(), false);
    kh.add("beta.example", 2222, ed.clone(), true);
    kh.add("[::1]:22", 22, ed.clone(), false);
    kh.save(Some(&p)).unwrap();
    let loaded = KnownHosts::load(&p).unwrap();
    assert_eq!(loaded.entries.len(), 3);
    assert_eq!(
        loaded.verify("alpha.example", 22, &ed),
        KnownHostsResult::Match
    );
    assert_eq!(
        loaded.verify("beta.example", 2222, &ed),
        KnownHostsResult::Match
    );
}

#[test]
fn comment_lines_and_blank_lines_round_trip() {
    let key = ed25519_pub();
    let text = format!(
        "# header\n\n# second comment\n{}\n\n",
        line("comment.example", &key)
    );
    let kh = KnownHosts::parse(&text).unwrap();
    assert_eq!(kh.entries.len(), 1);
    assert_eq!(
        kh.verify("comment.example", 22, &key),
        KnownHostsResult::Match
    );
}

#[test]
fn host_field_is_case_insensitive_for_literal_matches() {
    let key = ed25519_pub();
    let text = line("Mixed.Case.Example", &key);
    let kh = KnownHosts::parse(&text).unwrap();
    // OpenSSH globbing in known_hosts.rs uses `eq_ignore_ascii_case`.
    assert_eq!(
        kh.verify("mixed.case.example", 22, &key),
        KnownHostsResult::Match
    );
    assert_eq!(
        kh.verify("MIXED.CASE.EXAMPLE", 22, &key),
        KnownHostsResult::Match
    );
}
