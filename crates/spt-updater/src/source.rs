//! Release-source backends. `GitHubSource` + `UrlSource` + `StaticSource`
//! all implement the [`ReleaseSource`] trait so the rest of the updater
//! is source-agnostic.
//!
//! **This module is a scaffold.** The real backends land in a subsequent
//! commit. The trait + types live here so downstream code can take a
//! dependency without recompiling once each backend ships.

use async_trait::async_trait;

use crate::error::UpdaterResult;

/// Information about a single release. Source backends produce these
/// when polling the upstream catalog.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    /// User-facing tag (bare `YY.N`, no `v` prefix).
    pub tag: String,
    /// Semver-compatible `0.YY.N` form.
    pub cargo_version: String,
    /// Date the release was published, ISO-8601 UTC.
    pub published_at: String,
    /// Map of artifact filename → download URL.
    pub artifacts: Vec<ReleaseArtifact>,
    /// Optional minisign signature URL for the artifact set
    /// (`<artifact>.minisig`), keyed by artifact name.
    pub signatures: Vec<ReleaseArtifact>,
    /// Source-specific extra metadata (e.g. the GitHub HTML release URL).
    pub extra: serde_json::Value,
}

/// One downloadable artifact within a release.
#[derive(Debug, Clone)]
pub struct ReleaseArtifact {
    /// Filename (e.g. `spt-0.26.4-x86_64-unknown-linux-gnu.tar.gz`).
    pub name: String,
    /// HTTPS URL.
    pub url: String,
    /// Size in bytes, if the source exposes it.
    pub size: Option<u64>,
    /// SHA-256, if the source exposes it.
    pub sha256: Option<String>,
}

/// Polling backend.
#[async_trait]
pub trait ReleaseSource: Send + Sync {
    /// Return the latest release matching the configured channel.
    async fn latest(&self) -> UpdaterResult<ReleaseInfo>;
}
