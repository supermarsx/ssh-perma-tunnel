//! Release-source backends.
//!
//! [`ReleaseSource`] is the polymorphism boundary — the polling loop in
//! [`crate::Updater`] only knows about this trait, never the concrete
//! GitHub / URL / static implementations. Adding a new source (S3 bucket,
//! GitLab Releases, custom registry, …) is a matter of writing one more
//! `impl ReleaseSource for FooSource` and a one-line dispatch in
//! [`build_source`].

use async_trait::async_trait;
use reqwest::header::{ACCEPT, USER_AGENT};
use reqwest::Client;
use serde::Deserialize;
use tracing::debug;

use crate::config::{ReleaseChannel, SourceKind, UpdaterConfig};
use crate::error::{UpdaterError, UpdaterResult};

/// Information about a single release. Source backends produce these
/// when polling the upstream catalog.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    /// User-facing tag (bare `YY.N`, no `v` prefix).
    pub tag: String,
    /// Semver-compatible `0.YY.N` form. Populated when derivable from
    /// the source (cargo-bumped releases) and empty otherwise.
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

/// Build the concrete source backend from a resolved [`UpdaterConfig`].
/// Returns a boxed trait object so the polling loop is source-agnostic.
pub fn build_source(cfg: &UpdaterConfig) -> UpdaterResult<Box<dyn ReleaseSource>> {
    match &cfg.source {
        SourceKind::GitHub { repo, channel } => {
            Ok(Box::new(GitHubSource::new(repo.clone(), *channel)?))
        }
        SourceKind::Url { .. } | SourceKind::Static { .. } => {
            // URL + static backends land in a follow-up commit. The
            // scaffolded error keeps the dispatcher consistent.
            Err(UpdaterError::Source(
                "url and static sources are scaffolded; only `source = \"github\"` \
                 polls today"
                    .into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// GitHub source
// ---------------------------------------------------------------------------

/// GitHub Releases API polling backend. Reads the `latest` release for
/// `<owner>/<repo>` (or the first stable / first prerelease entry from
/// `releases?per_page=10` when `channel = Prerelease`).
pub struct GitHubSource {
    repo: String,
    channel: ReleaseChannel,
    client: Client,
}

impl GitHubSource {
    /// Build a new client. Picks up `GITHUB_TOKEN` from the environment
    /// for private repos / rate-limit relief; falls back to anonymous.
    pub fn new(repo: String, channel: ReleaseChannel) -> UpdaterResult<Self> {
        let mut builder =
            Client::builder().user_agent(concat!("spt-updater/", env!("CARGO_PKG_VERSION")));
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            let mut headers = reqwest::header::HeaderMap::new();
            let value = format!("Bearer {token}");
            if let Ok(hv) = reqwest::header::HeaderValue::from_str(&value) {
                headers.insert(reqwest::header::AUTHORIZATION, hv);
                builder = builder.default_headers(headers);
            }
        }
        let client = builder
            .build()
            .map_err(|e| UpdaterError::Source(format!("reqwest build: {e}")))?;
        Ok(Self {
            repo,
            channel,
            client,
        })
    }

    fn url(&self) -> String {
        match self.channel {
            // `releases/latest` is GitHub's official "latest stable" pointer
            // — skips drafts and prereleases server-side.
            ReleaseChannel::Stable => {
                format!("https://api.github.com/repos/{}/releases/latest", self.repo)
            }
            ReleaseChannel::Prerelease => {
                format!(
                    "https://api.github.com/repos/{}/releases?per_page=10",
                    self.repo
                )
            }
        }
    }
}

#[async_trait]
impl ReleaseSource for GitHubSource {
    async fn latest(&self) -> UpdaterResult<ReleaseInfo> {
        let url = self.url();
        debug!(target: "spt_updater::source", url = %url, "polling GitHub Releases");
        let resp = self
            .client
            .get(&url)
            .header(ACCEPT, "application/vnd.github+json")
            .header(
                USER_AGENT,
                concat!("spt-updater/", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .await
            .map_err(|e| UpdaterError::Source(format!("GET {url}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(UpdaterError::Source(format!(
                "GET {url} returned HTTP {}",
                status.as_u16()
            )));
        }

        let release: GhRelease = match self.channel {
            ReleaseChannel::Stable => resp
                .json()
                .await
                .map_err(|e| UpdaterError::Source(format!("parse latest: {e}")))?,
            ReleaseChannel::Prerelease => {
                let list: Vec<GhRelease> = resp
                    .json()
                    .await
                    .map_err(|e| UpdaterError::Source(format!("parse list: {e}")))?;
                list.into_iter()
                    .next()
                    .ok_or_else(|| UpdaterError::Source("no releases listed".into()))?
            }
        };

        Ok(into_release_info(release))
    }
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    digest: Option<String>,
}

fn into_release_info(rel: GhRelease) -> ReleaseInfo {
    // Strip optional `v` prefix to surface the bare YY.N tag.
    let tag = rel.tag_name.trim_start_matches('v').to_string();
    let cargo_version = if tag.split('.').count() == 2 {
        format!("0.{tag}")
    } else {
        tag.clone()
    };

    let mut artifacts = Vec::with_capacity(rel.assets.len());
    let mut signatures = Vec::new();
    for a in rel.assets {
        let sha = a.digest.as_ref().and_then(|d| {
            d.strip_prefix("sha256:")
                .map(str::to_lowercase)
                .or_else(|| Some(d.to_lowercase()))
        });
        let artifact = ReleaseArtifact {
            name: a.name.clone(),
            url: a.browser_download_url,
            size: a.size,
            sha256: sha,
        };
        if a.name.ends_with(".minisig") {
            signatures.push(artifact);
        } else {
            artifacts.push(artifact);
        }
    }

    ReleaseInfo {
        tag,
        cargo_version,
        published_at: rel.published_at.unwrap_or_default(),
        artifacts,
        signatures,
        extra: serde_json::json!({
            "html_url": rel.html_url,
            "prerelease": rel.prerelease,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_v_prefix_stripped() {
        let rel = GhRelease {
            tag_name: "v26.4".into(),
            published_at: None,
            html_url: None,
            prerelease: false,
            assets: vec![],
        };
        let info = into_release_info(rel);
        assert_eq!(info.tag, "26.4");
        assert_eq!(info.cargo_version, "0.26.4");
    }

    #[test]
    fn full_semver_passes_through_cargo_field() {
        let rel = GhRelease {
            tag_name: "0.26.4".into(),
            published_at: None,
            html_url: None,
            prerelease: false,
            assets: vec![],
        };
        let info = into_release_info(rel);
        assert_eq!(info.tag, "0.26.4");
        assert_eq!(info.cargo_version, "0.26.4");
    }

    #[test]
    fn minisig_assets_partition_into_signatures() {
        let rel = GhRelease {
            tag_name: "26.4".into(),
            published_at: None,
            html_url: None,
            prerelease: false,
            assets: vec![
                GhAsset {
                    name: "spt-26.4.tar.gz".into(),
                    browser_download_url: "https://example/a".into(),
                    size: Some(1024),
                    digest: Some("sha256:abc".into()),
                },
                GhAsset {
                    name: "spt-26.4.tar.gz.minisig".into(),
                    browser_download_url: "https://example/a.minisig".into(),
                    size: None,
                    digest: None,
                },
            ],
        };
        let info = into_release_info(rel);
        assert_eq!(info.artifacts.len(), 1);
        assert_eq!(info.signatures.len(), 1);
        assert_eq!(info.artifacts[0].sha256.as_deref(), Some("abc"));
    }
}
