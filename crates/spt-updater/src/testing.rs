//! Test fixtures for `spt-updater`, behind the `testing` feature.
//!
//! The headline fixture is [`MockReleaseSource`] — an in-memory
//! [`ReleaseSource`](crate::source::ReleaseSource) that returns a
//! caller-supplied [`ReleaseInfo`](crate::source::ReleaseInfo) from
//! [`latest`](crate::source::ReleaseSource::latest) with **no network**. It
//! mirrors the shape of the real `GitHubSource`/`UrlSource` backends (a single
//! async `latest()` method) so an integration test can drive the whole
//! `check → download → verify → install` flow off a fake "available release".
//!
//! Because the artifact bytes are staged on disk and referenced via `file://`
//! URLs, the *download* step exercises the real
//! [`download_release`](crate::download::download_release) path (its `file://`
//! branch), the *verify* step exercises the real
//! [`verify_artifact`](crate::verify::verify_artifact), and the *install* step
//! exercises the real [`install_over`](crate::install::install_over) — all
//! hermetically. See the workspace e2e crate's `update_eventsink.rs` for the
//! driving tests.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::error::{UpdaterError, UpdaterResult};
use crate::source::{ReleaseArtifact, ReleaseInfo, ReleaseSource};
use crate::verify::sha256_bytes;

/// In-memory [`ReleaseSource`] returning a pre-built [`ReleaseInfo`].
///
/// Construct one directly from a [`ReleaseInfo`] via [`MockReleaseSource::new`],
/// or use [`MockReleaseSource::staged`] to write artifact bytes (and optional
/// checksum / signature sidecars) into a directory and get back a source whose
/// artifact URL is a `file://` reference to those bytes.
///
/// `latest()` can be made to fail (to model a source/network error) via
/// [`MockReleaseSource::failing`]; the call count is recorded so a test can
/// assert the flow polled exactly once.
pub struct MockReleaseSource {
    release: ReleaseInfo,
    fail_with: Option<String>,
    calls: Arc<Mutex<usize>>,
}

impl MockReleaseSource {
    /// A source that returns `release` from every `latest()` call.
    #[must_use]
    pub fn new(release: ReleaseInfo) -> Self {
        Self {
            release,
            fail_with: None,
            calls: Arc::new(Mutex::new(0)),
        }
    }

    /// A source whose `latest()` always fails with `msg` (models a
    /// source/network error). The supplied `release` is otherwise ignored.
    #[must_use]
    pub fn failing(msg: impl Into<String>) -> Self {
        Self {
            release: ReleaseInfo {
                tag: "0.0".into(),
                cargo_version: String::new(),
                published_at: String::new(),
                artifacts: Vec::new(),
                signatures: Vec::new(),
                extra: serde_json::Value::Null,
            },
            fail_with: Some(msg.into()),
            calls: Arc::new(Mutex::new(0)),
        }
    }

    /// Stage `artifact_bytes` on disk under `dir` and return a source whose
    /// single artifact is a `file://` URL to the staged bytes.
    ///
    /// * `tag` is the release tag (`YY.N`); the artifact filename embeds
    ///   [`crate::download::TARGET`] so `select_artifact` matches this build.
    /// * `checksum` controls the `SHA256SUMS`/inline-digest material:
    ///   - [`MockChecksum::None`] publishes no digest;
    ///   - [`MockChecksum::Correct`] publishes the true SHA-256;
    ///   - [`MockChecksum::Wrong`] publishes a deliberately-incorrect digest
    ///     (drives the fail-closed verify path).
    ///
    /// # Errors
    /// Returns an [`UpdaterError`] if the artifact bytes cannot be written.
    pub fn staged(
        dir: &Path,
        tag: &str,
        artifact_bytes: &[u8],
        checksum: MockChecksum,
    ) -> UpdaterResult<Self> {
        std::fs::create_dir_all(dir).map_err(|e| {
            UpdaterError::Install(format!("create staging src dir {}: {e}", dir.display()))
        })?;
        let target = crate::download::TARGET;
        let art_name = format!("spt-{tag}-{target}.tar.gz");
        let art_path = dir.join(&art_name);
        std::fs::write(&art_path, artifact_bytes)
            .map_err(|e| UpdaterError::Install(format!("write {}: {e}", art_path.display())))?;
        let art_url = url::Url::from_file_path(&art_path)
            .map_err(|()| {
                UpdaterError::Source(format!("bad artifact path {}", art_path.display()))
            })?
            .to_string();

        // Inline per-asset digest mirrors how GitHub exposes the asset
        // `digest`; the verify step consumes either this or a SHA256SUMS body.
        let sha256 = match checksum {
            MockChecksum::None => None,
            MockChecksum::Correct => Some(sha256_bytes(artifact_bytes)),
            MockChecksum::Wrong => Some("00".repeat(32)),
        };

        let release = ReleaseInfo {
            tag: tag.to_string(),
            cargo_version: if tag.split('.').count() == 2 {
                format!("0.{tag}")
            } else {
                tag.to_string()
            },
            published_at: "2099-01-01T00:00:00Z".into(),
            artifacts: vec![ReleaseArtifact {
                name: art_name,
                url: art_url,
                size: Some(artifact_bytes.len() as u64),
                sha256,
            }],
            signatures: Vec::new(),
            extra: serde_json::Value::Null,
        };
        Ok(Self::new(release))
    }

    /// Borrow the release this source will return.
    #[must_use]
    pub fn release(&self) -> &ReleaseInfo {
        &self.release
    }

    /// Number of `latest()` calls observed so far.
    #[must_use]
    pub fn call_count(&self) -> usize {
        *self.calls.lock()
    }
}

/// Checksum-publication mode for [`MockReleaseSource::staged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockChecksum {
    /// Publish no digest at all (best-effort verify proceeds; strict fails).
    None,
    /// Publish the artifact's true SHA-256 (verify passes).
    Correct,
    /// Publish a deliberately-wrong SHA-256 (verify fails closed).
    Wrong,
}

#[async_trait]
impl ReleaseSource for MockReleaseSource {
    async fn latest(&self) -> UpdaterResult<ReleaseInfo> {
        *self.calls.lock() += 1;
        if let Some(msg) = &self.fail_with {
            return Err(UpdaterError::Source(msg.clone()));
        }
        Ok(self.release.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn staged_source_returns_release_with_file_url() {
        let dir = std::env::temp_dir().join(format!("spt-mock-src-{}", std::process::id()));
        let src =
            MockReleaseSource::staged(&dir, "99.0", b"NEWBIN", MockChecksum::Correct).unwrap();
        let rel = src.latest().await.unwrap();
        assert_eq!(rel.tag, "99.0");
        assert_eq!(rel.artifacts.len(), 1);
        assert!(rel.artifacts[0].url.starts_with("file://"));
        assert_eq!(
            rel.artifacts[0].sha256.as_deref(),
            Some(sha256_bytes(b"NEWBIN").as_str())
        );
        assert_eq!(src.call_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn failing_source_errors() {
        let src = MockReleaseSource::failing("boom");
        assert!(src.latest().await.is_err());
    }

    #[test]
    fn wrong_checksum_differs_from_true() {
        let dir = std::env::temp_dir().join(format!("spt-mock-src-w-{}", std::process::id()));
        let src = MockReleaseSource::staged(&dir, "99.0", b"abc", MockChecksum::Wrong).unwrap();
        assert_ne!(
            src.release().artifacts[0].sha256.as_deref(),
            Some(sha256_bytes(b"abc").as_str())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
