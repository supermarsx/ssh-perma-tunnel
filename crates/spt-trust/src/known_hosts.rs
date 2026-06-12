//! OpenSSH `known_hosts` parser, writer, and verifier.
//!
//! Supports plain hostname, comma-separated host lists, hashed hosts
//! (`|1|<salt>|<hash>`), wildcard patterns (`*`/`?`), and `[host]:port` form.
//! Markers (`@cert-authority`, `@revoked`) are recognised; revoked entries
//! reject any matching key.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use atomicwrites::{AtomicFile, OverwriteBehavior};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use ssh_key::PublicKey;
use subtle::ConstantTimeEq;

use spt_core::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

/// Result of [`KnownHosts::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownHostsResult {
    /// Host known and key matches.
    Match,
    /// Host known but presented key differs from stored key(s).
    Mismatch {
        /// All stored keys for the matched host.
        stored: Vec<PublicKey>,
    },
    /// Host has no entry.
    NotFound,
    /// Host has a `@revoked` entry that matches the key. Always an error.
    Revoked,
}

/// One parsed `known_hosts` entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Optional marker line prefix (`@cert-authority` / `@revoked`).
    pub marker: Option<Marker>,
    /// Host pattern as it appeared in the source file.
    pub host_field: String,
    /// Parsed public key.
    pub key: PublicKey,
}

/// Recognised OpenSSH markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Marker {
    /// `@cert-authority` — entry is a CA, not a host key.
    CertAuthority,
    /// `@revoked` — entry forbids the listed key.
    Revoked,
}

/// In-memory representation of a `known_hosts` file.
#[derive(Debug, Default, Clone)]
pub struct KnownHosts {
    /// Source path, when read from disk.
    pub path: Option<PathBuf>,
    /// Parsed entries, in original order.
    pub entries: Vec<Entry>,
    /// Lookup acceleration for exact (plaintext, non-wildcard, non-hashed)
    /// host fields: normalized lookup string → indices into `entries`.
    ///
    /// Built by [`KnownHosts::parse`]/[`KnownHosts::load`]/[`KnownHosts::add`].
    /// `verify` consults it as a fast path for the common case (a large file of
    /// plaintext hosts) and falls back to a linear scan for hashed and wildcard
    /// entries. When `None` (e.g. the `entries` field was populated directly),
    /// `verify` performs a full linear scan, so the index is purely an
    /// optimization and never affects correctness.
    index: Option<HostIndex>,
}

/// Exact-match index over plaintext entries.
#[derive(Debug, Default, Clone)]
struct HostIndex {
    /// Normalized lookup key (`host` or `[host]:port`, lowercased) → entry
    /// indices that contain an exact (non-wildcard) literal for that key.
    exact: HashMap<String, Vec<usize>>,
    /// Indices of entries that need a linear scan regardless: hashed hosts,
    /// any comma-list containing a wildcard (`*`/`?`) or a negation (`!`).
    needs_scan: Vec<usize>,
}

impl KnownHosts {
    /// Parse a `known_hosts`-formatted string.
    pub fn parse(text: &str) -> Result<Self> {
        let mut entries = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            entries.push(parse_line(line, lineno + 1)?);
        }
        let index = Some(build_index(&entries));
        Ok(Self {
            path: None,
            entries,
            index,
        })
    }

    /// Read and parse a `known_hosts` file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).map_err(|e| {
            Error::RuntimeFailure(format!("read known_hosts `{}`: {e}", path.display()))
        })?;
        let mut k = Self::parse(&text)?;
        k.path = Some(path.to_path_buf());
        Ok(k)
    }

    /// Verify whether `key` is known for `(host, port)`.
    pub fn verify(&self, host: &str, port: u16, key: &PublicKey) -> KnownHostsResult {
        let mut found_host = false;
        let mut stored = Vec::new();

        // Process one candidate entry. Returns `Some(result)` to short-circuit
        // (Revoked/Match), or `None` to continue scanning.
        let mut consider = |e: &Entry| -> Option<KnownHostsResult> {
            // Revoked entries take precedence: reject if the *key* matches.
            if matches!(e.marker, Some(Marker::Revoked)) {
                if keys_equal(&e.key, key) {
                    return Some(KnownHostsResult::Revoked);
                }
                return None;
            }
            // Skip CA-marker entries for direct host-key verification —
            // certificate validation is handled in spt-key.
            if matches!(e.marker, Some(Marker::CertAuthority)) {
                return None;
            }
            found_host = true;
            stored.push(e.key.clone());
            if keys_equal(&e.key, key) {
                return Some(KnownHostsResult::Match);
            }
            None
        };

        match &self.index {
            // Fast path: exact-match index for plaintext entries plus a linear
            // pass over hashed/wildcard/negated entries only. The two candidate
            // sets are disjoint by construction (an entry is either an exact
            // plaintext literal or it requires a scan), so no entry is
            // double-processed and the visited set is identical to the naive
            // full scan — only the iteration order differs, which does not
            // change the outcome (Revoked dominates; any key match is a Match;
            // Mismatch is order-independent over the stored-key set).
            Some(idx) => {
                for keyform in [host.to_owned(), format!("[{host}]:{port}")] {
                    if let Some(hits) = idx.exact.get(&keyform.to_ascii_lowercase()) {
                        for &ei in hits {
                            if let Some(r) = consider(&self.entries[ei]) {
                                return r;
                            }
                        }
                    }
                }
                for &ei in &idx.needs_scan {
                    let e = &self.entries[ei];
                    if !host_matches(&e.host_field, host, port) {
                        continue;
                    }
                    if let Some(r) = consider(e) {
                        return r;
                    }
                }
            }
            // Fallback: no index (entries populated directly). Full linear scan
            // preserves exact original semantics.
            None => {
                for e in &self.entries {
                    if !host_matches(&e.host_field, host, port) {
                        continue;
                    }
                    if let Some(r) = consider(e) {
                        return r;
                    }
                }
            }
        }

        if found_host {
            KnownHostsResult::Mismatch { stored }
        } else {
            KnownHostsResult::NotFound
        }
    }

    /// Append a new entry (host + key) to this file. Hashed-host form is used
    /// when `hashed = true`.
    pub fn add(&mut self, host: &str, port: u16, key: PublicKey, hashed: bool) {
        let host_field = if hashed {
            hash_host_random(&format_host(host, port))
        } else {
            format_host(host, port)
        };
        let new_idx = self.entries.len();
        let entry = Entry {
            marker: None,
            host_field,
            key,
        };
        // Keep the index coherent if it exists; otherwise rebuild on next
        // verify via the None fast-path fallback.
        if let Some(idx) = self.index.as_mut() {
            index_one(idx, new_idx, &entry.host_field);
        }
        self.entries.push(entry);
    }

    /// Render to `known_hosts` text form.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            if let Some(m) = e.marker {
                out.push_str(match m {
                    Marker::CertAuthority => "@cert-authority ",
                    Marker::Revoked => "@revoked ",
                });
            }
            out.push_str(&e.host_field);
            out.push(' ');
            // ssh-key public keys render as `algo base64 [comment]`.
            if let Ok(s) = e.key.to_openssh() {
                out.push_str(&s);
            }
            out.push('\n');
        }
        out
    }

    /// Atomically save to `path` (or the recorded source path).
    pub fn save(&self, path: Option<&Path>) -> Result<()> {
        let path = path
            .map(Path::to_path_buf)
            .or_else(|| self.path.clone())
            .ok_or_else(|| Error::InvalidArgs("KnownHosts::save: no destination path".into()))?;
        let text = self.render();
        let af = AtomicFile::new(&path, OverwriteBehavior::AllowOverwrite);
        af.write(|f| {
            use std::io::Write;
            f.write_all(text.as_bytes())
        })
        .map_err(|e| {
            Error::RuntimeFailure(format!("save known_hosts `{}`: {e}", path.display()))
        })?;
        Ok(())
    }
}

fn parse_line(line: &str, lineno: usize) -> Result<Entry> {
    let mut rest = line;
    let mut marker = None;
    if let Some(after) = line.strip_prefix("@cert-authority") {
        marker = Some(Marker::CertAuthority);
        rest = after.trim_start();
    } else if let Some(after) = line.strip_prefix("@revoked") {
        marker = Some(Marker::Revoked);
        rest = after.trim_start();
    }

    let mut parts = rest.splitn(2, char::is_whitespace);
    let host_field = parts
        .next()
        .ok_or_else(|| {
            Error::InvalidConfig(format!("known_hosts line {lineno}: missing host field"))
        })?
        .to_owned();
    let key_blob = parts
        .next()
        .ok_or_else(|| Error::InvalidConfig(format!("known_hosts line {lineno}: missing key")))?;
    let key = PublicKey::from_openssh(key_blob.trim())
        .map_err(|e| Error::InvalidConfig(format!("known_hosts line {lineno}: parse key: {e}")))?;
    Ok(Entry {
        marker,
        host_field,
        key,
    })
}

fn format_host(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Build the exact-match acceleration index over a slice of entries.
fn build_index(entries: &[Entry]) -> HostIndex {
    let mut idx = HostIndex::default();
    for (i, e) in entries.iter().enumerate() {
        index_one(&mut idx, i, &e.host_field);
    }
    idx
}

/// Classify a single entry's host field and register it in `idx` at position
/// `i`. Exact plaintext literals go into the lowercased `exact` map; hashed,
/// wildcard, or negated fields go into `needs_scan`.
fn index_one(idx: &mut HostIndex, i: usize, host_field: &str) {
    // Hashed hosts always require the linear HMAC pass.
    if host_field.starts_with("|1|") {
        idx.needs_scan.push(i);
        return;
    }
    // A field with any wildcard or negation cannot be resolved by exact lookup.
    if host_field.contains('*') || host_field.contains('?') || host_field.contains('!') {
        idx.needs_scan.push(i);
        return;
    }
    // Pure plaintext comma-list: index every literal under its normalized,
    // lowercased form so `verify` can look it up directly.
    for raw in host_field.split(',') {
        let pat = raw.trim().trim_matches('"');
        if pat.is_empty() {
            continue;
        }
        idx.exact
            .entry(pat.to_ascii_lowercase())
            .or_default()
            .push(i);
    }
}

fn host_matches(field: &str, host: &str, port: u16) -> bool {
    // Hashed host: `|1|salt-b64|hash-b64`
    if let Some(rest) = field.strip_prefix("|1|") {
        return match rest.split_once('|') {
            Some((salt_b64, hash_b64)) => verify_hashed(salt_b64, hash_b64, host, port),
            None => false,
        };
    }
    // Comma-separated host list, OpenSSH two-pass semantics: a negated pattern
    // (`!pat`) that matches the host vetoes the *entire* field regardless of
    // any positive matches; otherwise the field matches iff at least one
    // positive (non-negated) pattern matches.
    let candidates = [host.to_owned(), format!("[{host}]:{port}")];
    let mut positive_hit = false;
    for raw in field.split(',') {
        let pat = raw.trim();
        if pat.is_empty() {
            continue;
        }
        let (neg, pat) = match pat.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, pat),
        };
        let pat_norm = pat.trim_matches('"');
        let m = candidates.iter().any(|c| glob_match(pat_norm, c));
        if m {
            if neg {
                // Negated match vetoes the whole field.
                return false;
            }
            positive_hit = true;
        }
    }
    positive_hit
}

fn glob_match(pattern: &str, text: &str) -> bool {
    // Tiny ssh-style glob: '*' = any run, '?' = any single char.
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                if rec(&p[1..], t) {
                    return true;
                }
                if t.is_empty() {
                    return false;
                }
                rec(p, &t[1..])
            }
            (Some(b'?'), Some(_)) => rec(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

fn verify_hashed(salt_b64: &str, hash_b64: &str, host: &str, port: u16) -> bool {
    let Ok(salt) = B64.decode(salt_b64) else {
        return false;
    };
    let Ok(want) = B64.decode(hash_b64) else {
        return false;
    };
    for candidate in [host.to_owned(), format!("[{host}]:{port}")] {
        if let Ok(mut mac) = HmacSha1::new_from_slice(&salt) {
            mac.update(candidate.as_bytes());
            let got = mac.finalize().into_bytes();
            if got.ct_eq(&want).into() {
                return true;
            }
        }
    }
    false
}

fn hash_host_random(host_text: &str) -> String {
    let mut salt = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut mac = HmacSha1::new_from_slice(&salt).expect("HMAC accepts any key length");
    mac.update(host_text.as_bytes());
    let hash = mac.finalize().into_bytes();
    format!("|1|{}|{}", B64.encode(salt), B64.encode(hash))
}

fn keys_equal(a: &PublicKey, b: &PublicKey) -> bool {
    match (a.to_bytes(), b.to_bytes()) {
        (Ok(x), Ok(y)) => x.ct_eq(&y).into(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    fn one_key() -> PublicKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    fn entry_text(host: &str, key: &PublicKey) -> String {
        format!("{host} {}", key.to_openssh().unwrap())
    }

    #[test]
    fn parse_round_trip() {
        let key = one_key();
        let text = entry_text("example.com", &key);
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(kh.entries.len(), 1);
        let r = kh.verify("example.com", 22, &key);
        assert_eq!(r, KnownHostsResult::Match);
    }

    #[test]
    fn mismatch() {
        let stored = one_key();
        let presented = one_key();
        let text = entry_text("example.com", &stored);
        let kh = KnownHosts::parse(&text).unwrap();
        let r = kh.verify("example.com", 22, &presented);
        assert!(matches!(r, KnownHostsResult::Mismatch { .. }));
    }

    #[test]
    fn not_found() {
        let kh = KnownHosts::default();
        let r = kh.verify("nope.example", 22, &one_key());
        assert_eq!(r, KnownHostsResult::NotFound);
    }

    #[test]
    fn hashed_host_match() {
        let key = one_key();
        let mut kh = KnownHosts::default();
        kh.add("example.com", 22, key.clone(), true);
        let line = kh.entries[0].host_field.clone();
        assert!(line.starts_with("|1|"));
        let r = kh.verify("example.com", 22, &key);
        assert_eq!(r, KnownHostsResult::Match);
    }

    #[test]
    fn nonstandard_port() {
        let key = one_key();
        let text = entry_text("[example.com]:2222", &key);
        let kh = KnownHosts::parse(&text).unwrap();
        let r = kh.verify("example.com", 2222, &key);
        assert_eq!(r, KnownHostsResult::Match);
    }

    #[test]
    fn revoked_blocks_match() {
        let key = one_key();
        let text = format!("@revoked example.com {}", key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        let r = kh.verify("example.com", 22, &key);
        assert_eq!(r, KnownHostsResult::Revoked);
    }

    #[test]
    fn comments_and_blank_lines_ok() {
        let key = one_key();
        let text = format!("# leading comment\n\n{}\n", entry_text("h", &key));
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(kh.entries.len(), 1);
    }

    #[test]
    fn comma_list() {
        let key = one_key();
        let text = format!("alias,example.com {}", key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(kh.verify("example.com", 22, &key), KnownHostsResult::Match);
        assert_eq!(kh.verify("alias", 22, &key), KnownHostsResult::Match);
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kh");
        let key = one_key();
        let mut kh = KnownHosts::default();
        kh.add("h.example", 22, key.clone(), false);
        kh.save(Some(&p)).unwrap();
        let loaded = KnownHosts::load(&p).unwrap();
        assert_eq!(
            loaded.verify("h.example", 22, &key),
            KnownHostsResult::Match
        );
    }

    #[test]
    fn cert_authority_marker_skipped_for_host_key_verification() {
        let key = one_key();
        let text = format!("@cert-authority example.com {}", key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        // Direct host-key verification skips CA markers — NotFound is expected.
        let r = kh.verify("example.com", 22, &key);
        assert_eq!(r, KnownHostsResult::NotFound);
    }

    #[test]
    fn revoked_marker_only_blocks_matching_key() {
        let revoked_key = one_key();
        let other_key = one_key();
        let text = format!("@revoked example.com {}", revoked_key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        // A different key isn't blocked by the @revoked entry, so NotFound.
        assert_eq!(
            kh.verify("example.com", 22, &other_key),
            KnownHostsResult::NotFound
        );
    }

    #[test]
    fn glob_wildcard_star_matches_any_run() {
        let key = one_key();
        let text = entry_text("*.example.com", &key);
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(
            kh.verify("a.example.com", 22, &key),
            KnownHostsResult::Match
        );
        assert_eq!(
            kh.verify("deep.sub.example.com", 22, &key),
            KnownHostsResult::Match
        );
        // Doesn't match the apex (no leading dot in the glob).
        assert_eq!(
            kh.verify("example.com", 22, &key),
            KnownHostsResult::NotFound
        );
    }

    #[test]
    fn glob_question_mark_matches_single_char() {
        let key = one_key();
        let text = entry_text("h?st", &key);
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(kh.verify("host", 22, &key), KnownHostsResult::Match);
        assert_eq!(kh.verify("hist", 22, &key), KnownHostsResult::Match);
        assert_eq!(kh.verify("hooost", 22, &key), KnownHostsResult::NotFound);
    }

    #[test]
    fn negated_pattern_alone_never_matches() {
        // OpenSSH semantics: a field consisting solely of a negation has no
        // positive pattern, so it matches *nothing* — neither the excluded
        // host nor any other host. (Previously this implementation incorrectly
        // treated `!h` as "everything except h".)
        let key = one_key();
        let text = format!("!secret.example.com {}", key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(
            kh.verify("secret.example.com", 22, &key),
            KnownHostsResult::NotFound
        );
        assert_eq!(
            kh.verify("other.example.com", 22, &key),
            KnownHostsResult::NotFound
        );
    }

    #[test]
    fn negation_vetoes_wildcard_in_same_field() {
        // E2-F3 regression: `*,!bad.example.com` must NOT trust `bad` even
        // though `*` matches it — the negation vetoes the whole field. Any
        // other host is still trusted via the `*` positive.
        let key = one_key();
        let text = format!("*,!bad.example.com {}", key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        // Negated host is vetoed -> not trusted.
        assert_eq!(
            kh.verify("bad.example.com", 22, &key),
            KnownHostsResult::NotFound
        );
        // A different host still matches via the `*` positive pattern.
        assert_eq!(
            kh.verify("good.example.com", 22, &key),
            KnownHostsResult::Match
        );
    }

    #[test]
    fn negation_order_independent_veto() {
        // The veto must hold regardless of pattern order in the field
        // (`!bad` listed before the wildcard).
        let key = one_key();
        let text = format!("!bad.example.com,*.example.com {}", key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(
            kh.verify("bad.example.com", 22, &key),
            KnownHostsResult::NotFound
        );
        assert_eq!(
            kh.verify("ok.example.com", 22, &key),
            KnownHostsResult::Match
        );
    }

    #[test]
    fn indexed_lookup_matches_linear_scan() {
        // E2-F4 regression: the exact-match index must produce byte-identical
        // verify() outcomes to a forced full linear scan over the same entries,
        // across plaintext, wildcard, hashed, and [host]:port forms.
        let ka = one_key();
        let kb = one_key();
        let kc = one_key();
        let kd = one_key();
        let mut text = String::new();
        text.push_str(&entry_text("alpha.example", &ka));
        text.push('\n');
        text.push_str(&entry_text("beta.example,gamma.example", &kb));
        text.push('\n');
        text.push_str(&entry_text("*.wild.example", &kc));
        text.push('\n');
        text.push_str(&entry_text("[svc.example]:2222", &kd));
        text.push('\n');

        let indexed = KnownHosts::parse(&text).unwrap();
        // Force the linear fallback by clearing the index.
        let mut linear = indexed.clone();
        linear.index = None;

        let cases: &[(&str, u16, &PublicKey)] = &[
            ("alpha.example", 22, &ka),
            ("alpha.example", 22, &kb), // mismatch
            ("beta.example", 22, &kb),
            ("gamma.example", 22, &kb),
            ("host.wild.example", 22, &kc),
            ("svc.example", 2222, &kd),
            ("svc.example", 22, &kd), // wrong port -> not found
            ("absent.example", 22, &ka),
        ];
        for (host, port, key) in cases {
            assert_eq!(
                indexed.verify(host, *port, key),
                linear.verify(host, *port, key),
                "indexed vs linear mismatch for {host}:{port}"
            );
        }
        // And the exact entries are actually in the index (not all scanned).
        let idx = indexed.index.as_ref().unwrap();
        assert!(idx.exact.contains_key("alpha.example"));
        assert!(idx.exact.contains_key("beta.example"));
        assert!(idx.exact.contains_key("gamma.example"));
        assert!(idx.exact.contains_key("[svc.example]:2222"));
        // The wildcard entry is in needs_scan, not exact.
        assert!(!idx.exact.contains_key("*.wild.example"));
        assert!(!idx.needs_scan.is_empty());
    }

    #[test]
    fn add_keeps_index_coherent() {
        // Entries added via add() after parse() must be findable through the
        // index fast path.
        let k1 = one_key();
        let k2 = one_key();
        let text = entry_text("first.example", &k1);
        let mut kh = KnownHosts::parse(&text).unwrap();
        kh.add("second.example", 22, k2.clone(), false);
        assert_eq!(kh.verify("first.example", 22, &k1), KnownHostsResult::Match);
        assert_eq!(kh.verify("second.example", 22, &k2), KnownHostsResult::Match);
        let idx = kh.index.as_ref().unwrap();
        assert!(idx.exact.contains_key("second.example"));
    }

    #[test]
    fn hashed_host_nonstandard_port_match() {
        let key = one_key();
        let mut kh = KnownHosts::default();
        kh.add("h.example", 2222, key.clone(), true);
        assert!(kh.entries[0].host_field.starts_with("|1|"));
        assert_eq!(kh.verify("h.example", 2222, &key), KnownHostsResult::Match);
        // Different port doesn't match.
        assert_eq!(kh.verify("h.example", 22, &key), KnownHostsResult::NotFound);
    }

    #[test]
    fn parse_line_missing_key_errors() {
        let r = KnownHosts::parse("example.com\n");
        let err = r.unwrap_err();
        match err {
            spt_core::Error::InvalidConfig(msg) => {
                assert!(msg.contains("missing key"), "got: {msg}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn parse_line_bad_key_errors() {
        let r = KnownHosts::parse("example.com ssh-ed25519 NOT-BASE64-AT-ALL\n");
        let err = r.unwrap_err();
        match err {
            spt_core::Error::InvalidConfig(msg) => {
                assert!(msg.contains("parse key") || msg.contains("known_hosts line"));
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn save_without_path_errors() {
        let kh = KnownHosts::default();
        let r = kh.save(None);
        match r {
            Err(spt_core::Error::InvalidArgs(msg)) => assert!(msg.contains("no destination")),
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn save_uses_recorded_path_if_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kh");
        let key = one_key();
        std::fs::write(&p, entry_text("example.com", &key) + "\n").unwrap();
        let kh = KnownHosts::load(&p).unwrap();
        assert!(kh.path.is_some());
        // Save without explicit dest must use the loaded path.
        kh.save(None).unwrap();
    }

    #[test]
    fn render_includes_marker_and_round_trips_via_save() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kh");
        let key = one_key();
        let entry = Entry {
            marker: Some(Marker::CertAuthority),
            host_field: "ca.example.com".into(),
            key: key.clone(),
        };
        let kh = KnownHosts {
            path: None,
            entries: vec![entry],
            index: None,
        };
        let rendered = kh.render();
        assert!(rendered.starts_with("@cert-authority "));
        // Save + reload preserves the marker.
        kh.save(Some(&p)).unwrap();
        let loaded = KnownHosts::load(&p).unwrap();
        assert_eq!(loaded.entries[0].marker, Some(Marker::CertAuthority));
    }

    #[test]
    fn render_revoked_marker() {
        let key = one_key();
        let kh = KnownHosts {
            path: None,
            entries: vec![Entry {
                marker: Some(Marker::Revoked),
                host_field: "bad.example".into(),
                key,
            }],
            index: None,
        };
        let rendered = kh.render();
        assert!(rendered.starts_with("@revoked "));
    }

    #[test]
    fn add_unhashed_uses_bracket_form_for_nonstandard_port() {
        let key = one_key();
        let mut kh = KnownHosts::default();
        kh.add("h.example", 2222, key, false);
        assert_eq!(kh.entries[0].host_field, "[h.example]:2222");
    }

    #[test]
    fn load_returns_runtime_failure_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("does-not-exist");
        let err = KnownHosts::load(&p).unwrap_err();
        match err {
            spt_core::Error::RuntimeFailure(msg) => {
                assert!(msg.contains("read known_hosts"));
            }
            other => panic!("expected RuntimeFailure, got {other:?}"),
        }
    }

    #[test]
    fn hashed_host_with_corrupt_salt_or_hash_does_not_match() {
        let key = one_key();
        // Manually craft a malformed hashed-host entry.
        let text = format!("|1|not-base64!|alsonotb64! {}", key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(
            kh.verify("example.com", 22, &key),
            KnownHostsResult::NotFound
        );
    }

    #[test]
    fn hashed_host_missing_separator_does_not_match() {
        let key = one_key();
        let text = format!("|1|onlysalt {}", key.to_openssh().unwrap());
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(
            kh.verify("example.com", 22, &key),
            KnownHostsResult::NotFound
        );
    }
}
