//! On-disk cache for remote-config bodies.
//!
//! Spec §14.3: "Remote config content MUST be size-limited, schema-validated,
//! and written to a local cache atomically. Remote config fetch failures MUST
//! never replace a known-good local config with partial or invalid content."
//!
//! We write the body and a sidecar `<file>.sha256` (containing the lowercase
//! hex digest of the body, plus an `ETag` value if the server returned one)
//! through `spt_state::write_atomic`, which uses tempfile + rename for
//! atomicity.

use sha2::{Digest, Sha256};
use spt_core::Result;
use spt_state::write_atomic;
use std::path::{Path, PathBuf};

/// Default cache file name under `<state_dir>/`.
pub const CACHE_FILE_NAME: &str = "remote-config-cache.toml";
/// Default sidecar metadata file name.
pub const SIDECAR_FILE_NAME: &str = "remote-config-cache.sha256";

/// Where the cached body is written. Combine with the configured
/// `cache_file` from `RemoteConfigSpec.etag_cache` if provided, else use the
/// default name under `state_dir`.
#[must_use]
pub fn cache_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CACHE_FILE_NAME)
}

/// Where the sidecar metadata file lives.
#[must_use]
pub fn fingerprint_sidecar_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SIDECAR_FILE_NAME)
}

/// Compute the lowercase hex SHA-256 of a byte slice.
#[must_use]
pub fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Atomically save a fetched body and its associated `ETag` to disk.
///
/// On success, both the body and the `<>.sha256` sidecar are persisted.
/// The sidecar format is one line, JSON-encoded, with fields `sha256` and
/// optional `etag`, so that future readers can verify integrity and resume
/// conditional GETs without re-parsing the body.
pub fn save_atomic(state_dir: &Path, body: &[u8], etag: Option<&str>) -> Result<()> {
    let body_path = cache_path(state_dir);
    let sidecar_path = fingerprint_sidecar_path(state_dir);
    write_atomic(&body_path, body)?;
    let sha = hex_sha256(body);
    let json = serde_json::json!({
        "sha256": sha,
        "etag": etag,
    });
    write_atomic(&sidecar_path, json.to_string().as_bytes())?;
    Ok(())
}

/// Cached entry loaded from disk. Returned by [`load_cached`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedEntry {
    /// Cached body bytes.
    pub body: Vec<u8>,
    /// Server-provided `ETag` from the last successful fetch, if any.
    pub etag: Option<String>,
    /// SHA-256 digest of `body` recorded in the sidecar at write time. Tests
    /// MAY check this against a freshly-computed digest of `body` to detect
    /// on-disk tampering.
    pub recorded_sha256: Option<String>,
}

/// Load the cached body and metadata, or return `None` if either file is
/// missing. Returns an error only if a file exists but is unreadable.
///
/// Callers SHOULD verify `recorded_sha256` against `hex_sha256(&body)` if
/// integrity-on-read is desired.
pub fn load_cached(state_dir: &Path) -> Result<Option<CachedEntry>> {
    let body_path = cache_path(state_dir);
    if !body_path.exists() {
        return Ok(None);
    }
    let body = std::fs::read(&body_path).map_err(|e| {
        spt_core::Error::StateLockFailed {
            path: body_path.clone(),
            reason: format!("read cache: {e}"),
        }
    })?;
    let sidecar_path = fingerprint_sidecar_path(state_dir);
    let (etag, recorded_sha256) = if sidecar_path.exists() {
        let raw = std::fs::read_to_string(&sidecar_path).map_err(|e| {
            spt_core::Error::StateLockFailed {
                path: sidecar_path.clone(),
                reason: format!("read sidecar: {e}"),
            }
        })?;
        match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => (
                v.get("etag")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                v.get("sha256")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            ),
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };
    Ok(Some(CachedEntry {
        body,
        etag,
        recorded_sha256,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip() {
        let d = tempdir().unwrap();
        save_atomic(d.path(), b"hello", Some("\"abc\"")).unwrap();
        let e = load_cached(d.path()).unwrap().unwrap();
        assert_eq!(e.body, b"hello");
        assert_eq!(e.etag.as_deref(), Some("\"abc\""));
        assert_eq!(e.recorded_sha256.as_deref(), Some(&*hex_sha256(b"hello")));
    }

    #[test]
    fn missing_returns_none() {
        let d = tempdir().unwrap();
        assert!(load_cached(d.path()).unwrap().is_none());
    }

    #[test]
    fn sidecar_corrupt_recovers() {
        let d = tempdir().unwrap();
        save_atomic(d.path(), b"x", None).unwrap();
        std::fs::write(fingerprint_sidecar_path(d.path()), "not json").unwrap();
        let e = load_cached(d.path()).unwrap().unwrap();
        assert_eq!(e.body, b"x");
        assert!(e.etag.is_none());
        assert!(e.recorded_sha256.is_none());
    }
}
