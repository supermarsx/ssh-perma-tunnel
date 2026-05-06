//! OpenSSH `known_hosts` parser, writer, and verifier.
//!
//! Supports plain hostname, comma-separated host lists, hashed hosts
//! (`|1|<salt>|<hash>`), wildcard patterns (`*`/`?`), and `[host]:port` form.
//! Markers (`@cert-authority`, `@revoked`) are recognised; revoked entries
//! reject any matching key.

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
        Ok(Self {
            path: None,
            entries,
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
        for e in &self.entries {
            if !host_matches(&e.host_field, host, port) {
                continue;
            }
            // Revoked entries take precedence: reject if the *key* matches.
            if matches!(e.marker, Some(Marker::Revoked)) {
                if keys_equal(&e.key, key) {
                    return KnownHostsResult::Revoked;
                }
                continue;
            }
            // Skip CA-marker entries for direct host-key verification —
            // certificate validation is handled in spt-key.
            if matches!(e.marker, Some(Marker::CertAuthority)) {
                continue;
            }
            found_host = true;
            stored.push(e.key.clone());
            if keys_equal(&e.key, key) {
                return KnownHostsResult::Match;
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
        self.entries.push(Entry {
            marker: None,
            host_field,
            key,
        });
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
            .ok_or_else(|| {
                Error::InvalidArgs("KnownHosts::save: no destination path".into())
            })?;
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
    let key_blob = parts.next().ok_or_else(|| {
        Error::InvalidConfig(format!("known_hosts line {lineno}: missing key"))
    })?;
    let key = PublicKey::from_openssh(key_blob.trim()).map_err(|e| {
        Error::InvalidConfig(format!("known_hosts line {lineno}: parse key: {e}"))
    })?;
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

fn host_matches(field: &str, host: &str, port: u16) -> bool {
    // Hashed host: `|1|salt-b64|hash-b64`
    if let Some(rest) = field.strip_prefix("|1|") {
        return match rest.split_once('|') {
            Some((salt_b64, hash_b64)) => verify_hashed(salt_b64, hash_b64, host, port),
            None => false,
        };
    }
    // Comma-separated host list.
    field.split(',').any(|h| literal_match(h, host, port))
}

fn literal_match(pat: &str, host: &str, port: u16) -> bool {
    let pat = pat.trim();
    if pat.is_empty() {
        return false;
    }
    let mut neg = false;
    let pat = pat.strip_prefix('!').map_or(pat, |r| {
        neg = true;
        r
    });
    let pat_norm = pat.trim_matches(|c| c == '"');
    let candidates = [host.to_owned(), format!("[{host}]:{port}")];
    let m = candidates.iter().any(|c| glob_match(pat_norm, c));
    if neg {
        !m
    } else {
        m
    }
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
    fn save_and_load(
    ) {
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
}
