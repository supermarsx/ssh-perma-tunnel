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
                KnownHostsResult::Mismatch { stored } => {
                    // Log the MISMATCH at the detection site with the expected vs
                    // received SHA-256 fingerprints (public identifiers, never key
                    // material) so a MITM is not invisible in-crate. The decision
                    // is unchanged — a mismatch still REJECTS.
                    let (received, expected) = fingerprint_diff(key, &stored);
                    warn!(
                        target: "spt_ssh2::trust",
                        host = host,
                        port = port,
                        received_fingerprint = %received,
                        expected_fingerprints = %expected,
                        "host key MISMATCH against known_hosts — possible MITM; rejecting"
                    );
                    return Err(Error::TrustFailed(format!(
                        "known_hosts mismatch for {host}:{port}"
                    )));
                }
                KnownHostsResult::Revoked => {
                    let received = key.fingerprint(HashAlg::Sha256);
                    warn!(
                        target: "spt_ssh2::trust",
                        host = host,
                        port = port,
                        received_fingerprint = %received,
                        "host key is @revoked in known_hosts; rejecting"
                    );
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
                    let received = key.fingerprint(HashAlg::Sha256);
                    let expected = pin
                        .pins_for(host, port)
                        .map(|v| v.join(", "))
                        .unwrap_or_default();
                    warn!(
                        target: "spt_ssh2::trust",
                        host = host,
                        port = port,
                        received_fingerprint = %received,
                        expected_pins = %expected,
                        "SHA-256 host-key pin MISMATCH — possible MITM; rejecting"
                    );
                    return Err(Error::TrustFailed(format!(
                        "SHA-256 pin mismatch for {host}:{port}"
                    )));
                }
                KnownHostsResult::Revoked => {
                    // Pin map does not encode revocation; treat as mismatch.
                    let received = key.fingerprint(HashAlg::Sha256);
                    warn!(
                        target: "spt_ssh2::trust",
                        host = host,
                        port = port,
                        received_fingerprint = %received,
                        "SHA-256 pin: revoked key; rejecting"
                    );
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
                let fp = key.fingerprint(HashAlg::Sha256);
                // M-7: the trust DECISION (key accepted on first use) is separate
                // from PERSISTING it. A transient known_hosts write failure
                // (read-only fs, ENOSPC, EACCES, momentarily-absent dir — more
                // likely under a hardened read-only Docker rootfs) must NOT be a
                // terminal `TrustFailed`: the connection is genuinely trusted, we
                // just couldn't cache it. Log a warning and proceed so the next
                // connect retries the append rather than killing the profile
                // forever. A real key MISMATCH/revocation is still terminal — it
                // is handled above and never reaches this branch.
                match append_known_hosts(path, host, port, key) {
                    Ok(()) => {
                        warn!(
                            target: "spt_ssh2::trust",
                            host = host,
                            port = port,
                            fingerprint = %fp,
                            path = %path.display(),
                            "TOFU: accepted new host key and persisted to known_hosts"
                        );
                    }
                    Err(e) => {
                        warn!(
                            target: "spt_ssh2::trust",
                            host = host,
                            port = port,
                            fingerprint = %fp,
                            path = %path.display(),
                            error = %e,
                            "TOFU: accepted new host key but failed to persist it to \
                             known_hosts; proceeding without caching (will retry on \
                             next connect)"
                        );
                    }
                }
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

/// Format the `(received, expected)` SHA-256 fingerprint pair logged when a
/// presented host key does not match `known_hosts`. Split out so the
/// expected≠received diff is unit-testable without a tracing subscriber. Both
/// sides are public `SHA256:<base64>` fingerprints (the expected side joins
/// every stored key); never key material.
#[must_use]
fn fingerprint_diff(presented: &PublicKey, stored: &[PublicKey]) -> (String, String) {
    let received = presented.fingerprint(HashAlg::Sha256).to_string();
    let expected = stored
        .iter()
        .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    (received, expected)
}

/// Persist a single OpenSSH `known_hosts` line for a newly-accepted TOFU key.
///
/// Crash-safety: a raw `O_APPEND` + `write_all` is **not** crash-atomic — a
/// crash or partial fs flush mid-append can leave a truncated final line and
/// poison the file. Instead this reads the current file, appends the new
/// entry, and rewrites the whole file via a temp-file + fsync + atomic rename
/// (plus a directory fsync on unix). Readers therefore only ever observe the
/// old complete file or the new complete file; a torn intermediate state is
/// impossible. If the existing file's final line lacks a trailing newline
/// (e.g. a pre-existing torn write), a separator is inserted first so the new
/// entry always lands on its own parseable line — and the defensive parser in
/// `spt-trust` skips the stale partial line rather than rejecting the file.
///
/// The temp file is created with 0600 (born-restricted on unix) and that mode
/// carries over to the target on rename, preserving the private permissions.
///
/// Only genuinely-new keys reach here (a mismatch is terminal and handled by
/// the caller before this function is called).
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

    // Read the current contents, tolerating a missing file (first TOFU write
    // creates it).
    let mut content = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(Error::TrustFailed(format!(
                "read known_hosts {} for TOFU append: {e}",
                path.display()
            )));
        }
    };
    // Guard against a prior torn write: ensure the new entry begins on its own
    // line even if the file's final line was truncated without a newline.
    if !content.is_empty() && !content.ends_with(b"\n") {
        content.push(b'\n');
    }
    content.extend_from_slice(line.as_bytes());

    write_atomic_known_hosts(path, &content)
}

/// Rewrite `path` with `content` crash-atomically and durably: write to a
/// sibling temp file (0600, born-restricted on unix), fsync it, atomically
/// rename it over the target, then fsync the directory (unix). No new deps —
/// uses the `tempfile` crate already in this crate's dependency graph.
fn write_atomic_known_hosts(path: &Path, content: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let mut tmp = tempfile::Builder::new()
        .prefix(".known_hosts.spt-tofu.")
        .tempfile_in(&dir)
        .map_err(|e| {
            Error::TrustFailed(format!(
                "create temp for known_hosts {}: {e}",
                path.display()
            ))
        })?;

    // Born-restricted 0600 on unix (tempfile already creates 0600, but be
    // explicit so the target keeps private perms after the rename).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600)).map_err(
            |e| {
                Error::TrustFailed(format!(
                    "set 0600 on temp for known_hosts {}: {e}",
                    path.display()
                ))
            },
        )?;
    }

    tmp.write_all(content).map_err(|e| {
        Error::TrustFailed(format!(
            "write temp for known_hosts {}: {e}",
            path.display()
        ))
    })?;
    // fsync the file data+metadata before the rename so the bytes are durable.
    tmp.as_file().sync_all().map_err(|e| {
        Error::TrustFailed(format!(
            "fsync temp for known_hosts {}: {e}",
            path.display()
        ))
    })?;

    // Atomic replace of the target (overwrites any existing file).
    tmp.persist(path).map_err(|e| {
        Error::TrustFailed(format!(
            "atomically replace known_hosts {}: {}",
            path.display(),
            e.error
        ))
    })?;

    // fsync the directory so the rename itself is durable across a crash.
    #[cfg(unix)]
    {
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
    }
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
    fn changed_host_key_logs_expected_ne_received_fingerprints() {
        // A changed host key must be logged AT THE DETECTION SITE with the
        // expected (stored) and received (presented) SHA-256 fingerprints so a
        // MITM is not invisible in-crate — while the decision stays a REJECT.
        // We assert the code path feeding the `warn!`: `fingerprint_diff` yields
        // distinct `SHA256:` strings for the stored vs presented key. Fails
        // against pre-fix (the helper/log did not exist and `stored` was
        // discarded via `Mismatch { .. }`).
        let stored = fresh_pub();
        let presented = fresh_pub();
        let mut kh = KnownHosts::default();
        kh.add("h.example", 22, stored.clone(), false);
        let v = TrustVerifier {
            known_hosts: Some(kh),
            ..Default::default()
        };
        // Rejection preserved.
        assert!(v.verify("h.example", 22, &presented).is_err());

        let (received, expected) = fingerprint_diff(&presented, std::slice::from_ref(&stored));
        assert!(received.starts_with("SHA256:"), "received={received}");
        assert!(expected.starts_with("SHA256:"), "expected={expected}");
        assert_ne!(
            received, expected,
            "a changed key must produce different expected/received fingerprints"
        );
        // Expected reflects the stored key; received reflects the presented one.
        assert_eq!(expected, stored.fingerprint(HashAlg::Sha256).to_string());
        assert_eq!(received, presented.fingerprint(HashAlg::Sha256).to_string());
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
    fn tofu_persist_failure_is_not_terminal() {
        // M-7 regression: a transient known_hosts WRITE failure (here: the
        // parent directory does not exist, so the append/create `open` fails)
        // must NOT yield a terminal `TrustFailed`. The trust DECISION (accept
        // on first use) is separate from PERSISTING it — the connection is
        // trusted, we just couldn't cache it, so `verify` returns Ok(TofuAdded)
        // and the profile keeps running. Fails against the pre-fix code (which
        // propagated the write error as `TrustFailed`); passes after the fix.
        let key = fresh_pub();
        let dir = tempfile::tempdir().unwrap();
        // A path whose parent directory does not exist → `open(append|create)`
        // fails (NotFound) without creating intermediate dirs.
        let bad = dir.path().join("missing_subdir").join("known_hosts");
        let v = TrustVerifier {
            accept_new: true,
            known_hosts_path: Some(bad.clone()),
            ..Default::default()
        };
        let outcome = v
            .verify("new.example", 22, &key)
            .expect("a known_hosts persist failure must be non-terminal");
        assert_eq!(outcome, HostKeyOutcome::TofuAdded);
        // The write genuinely failed: nothing was persisted.
        assert!(!bad.exists());
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
    fn unknown_and_changed_keys_never_yield_an_accept_outcome() {
        // Pins the contract the production russh handler
        // (`ClientHandler::check_server_key`) relies on: an unknown host in
        // strict, non-TOFU mode and a key that differs from a stored entry must
        // BOTH be rejected — they may never resolve to an "accept" outcome
        // (`Match`/`TofuAdded`). If `verify` ever regressed to returning an
        // accept variant for these inputs, the handler would auto-trust an
        // unknown/changed server key. `NotFound` is the only non-error outcome
        // an unknown host may produce (non-strict), and the handler refuses it.
        let presented = fresh_pub();

        // 1. Unknown host, strict, no TOFU → reject (Err), not any Ok variant.
        let strict = TrustVerifier {
            strict: true,
            accept_new: false,
            ..Default::default()
        };
        let r = strict.verify("unknown.example", 22, &presented);
        assert!(
            r.is_err(),
            "strict unknown host must be rejected, got {r:?}"
        );

        // 2. Unknown host, non-strict → NotFound (the handler treats this as a
        //    refusal). Crucially NOT Match/TofuAdded.
        let lax = TrustVerifier::default();
        let outcome = lax.verify("unknown.example", 22, &presented).unwrap();
        assert_eq!(outcome, HostKeyOutcome::NotFound);
        assert_ne!(outcome, HostKeyOutcome::Match);
        assert_ne!(outcome, HostKeyOutcome::TofuAdded);

        // 3. Changed key against a stored entry → reject, even with TOFU on and
        //    a writable path (TOFU must never override a mismatch).
        let stored = fresh_pub();
        let mut kh = KnownHosts::default();
        kh.add("host.example", 22, stored, false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let with_tofu = TrustVerifier {
            known_hosts: Some(kh),
            accept_new: true,
            known_hosts_path: Some(path.clone()),
            ..Default::default()
        };
        let r = with_tofu.verify("host.example", 22, &presented);
        assert!(
            matches!(r, Err(Error::TrustFailed(_))),
            "changed key must be rejected as TrustFailed, got {r:?}"
        );
        // A rejected mismatch must not have been persisted to known_hosts.
        assert!(
            !path.exists(),
            "rejected key must not be written to known_hosts"
        );
    }

    #[test]
    fn tofu_append_onto_torn_file_heals_and_stays_parseable() {
        // (e) Atomic/durable append integrity + torn-line healing. A file whose
        // final line was truncated by a prior crash (no trailing newline) must
        // NOT have the new TOFU entry glued onto it. The read-modify-write path
        // inserts a separator so the new entry lands on its own parseable line,
        // and the file reloads cleanly with the new host verifying Match. Fails
        // against pre-fix code (raw O_APPEND glued the bytes → the merged line
        // was unparseable → `KnownHosts::load` Err-ed on the whole file).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        // Pre-existing torn final line (partial base64, no newline).
        std::fs::write(&path, "torn.example ssh-ed25519 AAAAC3Nz").unwrap();

        let key = fresh_pub();
        let v = TrustVerifier {
            accept_new: true,
            known_hosts_path: Some(path.clone()),
            ..Default::default()
        };
        assert_eq!(
            v.verify("fresh.example", 22, &key).unwrap(),
            HostKeyOutcome::TofuAdded
        );

        // The new entry is on its own line, separated from the torn one.
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\nfresh.example ssh-ed25519 "));

        // Reloads cleanly (torn line skipped) and the new host verifies.
        let loaded = KnownHosts::load(&path).expect("healed file must load");
        assert_eq!(
            loaded.verify("fresh.example", 22, &key),
            KnownHostsResult::Match
        );

        // Atomic temp+rename leaves no litter behind in the directory.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".known_hosts.spt-tofu.")
            })
            .collect();
        assert!(leftover.is_empty(), "atomic append left a temp file behind");
    }

    #[cfg(unix)]
    #[test]
    fn tofu_append_creates_file_with_0600() {
        // The born-restricted 0600 mode must survive the temp+rename.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let key = fresh_pub();
        let v = TrustVerifier {
            accept_new: true,
            known_hosts_path: Some(path.clone()),
            ..Default::default()
        };
        v.verify("new.example", 22, &key).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "known_hosts must be 0600, got {mode:o}"
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

    /// Minimal hand-rolled tracing capture harness that is safe under the
    /// multi-threaded lib-test binary.
    ///
    /// Design: a PROCESS-GLOBAL subscriber is installed exactly once via
    /// [`std::sync::Once`] + `set_global_default` (the `Err` is ignored if a
    /// default is already installed). Installing a single, permanent global
    /// default makes tracing's per-callsite interest cache resolve to
    /// "enabled" once and never flip again. Each emitted event is routed into
    /// a THREAD-LOCAL slot: only the thread that armed its slot records
    /// anything, so parallel sibling tests that hit the same `warn!` callsite
    /// (with an empty slot) record nothing and cannot interfere. This is why a
    /// thread-local `with_default` approach is flaky under the parallel runner
    /// and this one is not.
    mod warn_capture {
        use std::cell::RefCell;
        use std::sync::{Arc, Mutex, Once};
        use tracing::field::{Field, Visit};
        use tracing::{span, Event, Level, Metadata, Subscriber};

        /// One captured event: level, target and its `(field, value)` pairs.
        #[derive(Clone)]
        pub struct Captured {
            pub level: Level,
            pub target: String,
            pub fields: Vec<(String, String)>,
        }

        impl Captured {
            /// Value of the first field named `name`, if present.
            pub fn field(&self, name: &str) -> Option<&str> {
                self.fields
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.as_str())
            }
        }

        type Buffer = Arc<Mutex<Vec<Captured>>>;

        thread_local! {
            static SLOT: RefCell<Option<Buffer>> = const { RefCell::new(None) };
        }

        struct FieldVisitor(Vec<(String, String)>);

        impl Visit for FieldVisitor {
            fn record_str(&mut self, field: &Field, value: &str) {
                self.0.push((field.name().to_string(), value.to_string()));
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                // `%value` (Display) records via `record_debug` with a
                // `format_args!`, whose Debug rendering is the Display string.
                self.0
                    .push((field.name().to_string(), format!("{value:?}")));
            }
        }

        struct CaptureSubscriber;

        impl Subscriber for CaptureSubscriber {
            fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}
            fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}
            fn event(&self, event: &Event<'_>) {
                SLOT.with(|slot| {
                    if let Some(buf) = slot.borrow().as_ref() {
                        let meta = event.metadata();
                        let mut v = FieldVisitor(Vec::new());
                        event.record(&mut v);
                        buf.lock().unwrap().push(Captured {
                            level: *meta.level(),
                            target: meta.target().to_string(),
                            fields: v.0,
                        });
                    }
                });
            }
            fn enter(&self, _span: &span::Id) {}
            fn exit(&self, _span: &span::Id) {}
        }

        /// Install the global subscriber exactly once. Idempotent and
        /// parallel-safe.
        fn install() {
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                let _ = tracing::subscriber::set_global_default(CaptureSubscriber);
            });
        }

        /// Arm this thread's capture slot, run `f`, disarm, and return the
        /// events emitted on this thread during `f`.
        pub fn capture<R>(f: impl FnOnce() -> R) -> (R, Vec<Captured>) {
            install();
            let buf: Buffer = Arc::new(Mutex::new(Vec::new()));
            SLOT.with(|s| *s.borrow_mut() = Some(buf.clone()));
            let out = f();
            SLOT.with(|s| *s.borrow_mut() = None);
            let events = buf.lock().unwrap().clone();
            (out, events)
        }
    }

    #[test]
    fn mismatch_emits_warn_with_expected_ne_received_fingerprints() {
        // Unlike `changed_host_key_logs_expected_ne_received_fingerprints`
        // (which only exercises the `fingerprint_diff` helper), this test
        // captures the REAL `tracing::warn!` emitted by `verify` at the
        // detection site — so deleting the `warn!` makes this test fail. It
        // proves a host-key MITM is not invisible in-crate: the warning carries
        // distinct received≠expected SHA-256 fingerprints, and the rejection
        // decision is preserved (logging never relaxes it).
        let stored = fresh_pub();
        let presented = fresh_pub();
        let mut kh = KnownHosts::default();
        kh.add("h.example", 22, stored, false);
        let v = TrustVerifier {
            known_hosts: Some(kh),
            ..Default::default()
        };

        let (result, events) = warn_capture::capture(|| v.verify("h.example", 22, &presented));

        // Decision preserved: still a hard rejection.
        assert!(
            matches!(result, Err(Error::TrustFailed(_))),
            "host-key mismatch must still reject, got {result:?}"
        );

        // Exactly the expected WARN event was captured at this callsite.
        let warn = events
            .iter()
            .find(|e| {
                e.level == tracing::Level::WARN
                    && e.target == "spt_ssh2::trust"
                    && e.field("received_fingerprint").is_some()
                    && e.field("expected_fingerprints").is_some()
            })
            .expect("expected a WARN event on target spt_ssh2::trust with both fingerprint fields");

        let received = warn
            .field("received_fingerprint")
            .expect("warn must carry received_fingerprint");
        let expected = warn
            .field("expected_fingerprints")
            .expect("warn must carry expected_fingerprints");

        assert!(
            !received.is_empty(),
            "received fingerprint must be non-empty"
        );
        assert!(
            !expected.is_empty(),
            "expected fingerprint must be non-empty"
        );
        assert!(
            received.contains("SHA256:"),
            "received must look like a SHA256 fingerprint, got {received}"
        );
        assert!(
            expected.contains("SHA256:"),
            "expected must look like a SHA256 fingerprint, got {expected}"
        );
        assert_ne!(
            received, expected,
            "the mismatch diff must be real: received must differ from expected"
        );
    }
}
