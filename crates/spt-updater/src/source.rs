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
        SourceKind::Url {
            url,
            index,
            fingerprint,
        } => Ok(Box::new(UrlSource::new(
            url.clone(),
            index.clone(),
            fingerprint,
        )?)),
        SourceKind::Static { dir } => Ok(Box::new(StaticSource::new(dir.clone()))),
    }
}

/// Shared user-agent for every HTTP backend.
const UA: &str = concat!("spt-updater/", env!("CARGO_PKG_VERSION"));

/// Build the same reqwest client the GitHub backend uses (anonymous, with
/// the spt-updater user-agent). Centralised so the `url` backend reuses the
/// identical HTTP stack — no second client configuration to drift.
fn http_client() -> UpdaterResult<Client> {
    Client::builder()
        .user_agent(UA)
        .build()
        .map_err(|e| UpdaterError::Source(format!("reqwest build: {e}")))
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

// ---------------------------------------------------------------------------
// URL source
// ---------------------------------------------------------------------------

/// HTTPS release-manifest backend. Fetches an operator-hosted
/// `release-manifest.json` (the `index` URL), pins its body to a configured
/// SHA-256 (`fingerprint`), and synthesises per-artifact download URLs from
/// the `url` template by substituting `{version}` / `{target}`.
///
/// Manifest schema (kept deliberately small; superset of GitHub's fields):
///
/// ```json
/// {
///   "tag": "26.4",
///   "published_at": "2026-01-02T03:04:05Z",
///   "artifacts": [
///     { "name": "spt-26.4-x86_64-unknown-linux-gnu.tar.gz",
///       "url": "https://mirror.example/dist/26.4/spt-...tar.gz",
///       "size": 1048576,
///       "sha256": "abc..." }
///   ],
///   "signatures": [
///     { "name": "spt-26.4-...tar.gz.minisig",
///       "url": "https://mirror.example/dist/26.4/spt-...tar.gz.minisig" }
///   ]
/// }
/// ```
///
/// `artifacts[].url` is optional — when omitted, the backend renders the
/// `url` template (`{version}`/`{target}` filled from the manifest tag and
/// each artifact name's embedded target, falling back to the bare name).
pub struct UrlSource {
    /// Artifact URL template with `{version}` / `{target}` placeholders.
    url_template: String,
    /// Manifest URL.
    index: String,
    /// Required lowercase hex SHA-256 of the manifest body.
    fingerprint: String,
    client: Client,
}

impl std::fmt::Debug for UrlSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlSource")
            .field("url_template", &self.url_template)
            .field("index", &self.index)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl UrlSource {
    /// Build a URL-source backend. Validates the manifest URL parses.
    pub fn new(url_template: String, index: String, fingerprint: &str) -> UpdaterResult<Self> {
        // Validate the manifest URL up-front so a typo surfaces at build
        // time rather than as an opaque GET failure.
        url::Url::parse(&index)
            .map_err(|e| UpdaterError::Source(format!("updater.url_index `{index}`: {e}")))?;
        Ok(Self {
            url_template,
            index,
            fingerprint: fingerprint.to_lowercase(),
            client: http_client()?,
        })
    }

    /// Render the `url` template for a given version + target.
    fn render_template(&self, version: &str, target: &str) -> String {
        self.url_template
            .replace("{version}", version)
            .replace("{target}", target)
    }
}

#[derive(Debug, Deserialize)]
struct UrlManifest {
    tag: String,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    artifacts: Vec<UrlManifestArtifact>,
    #[serde(default)]
    signatures: Vec<UrlManifestArtifact>,
}

#[derive(Debug, Deserialize)]
struct UrlManifestArtifact {
    name: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    sha256: Option<String>,
}

#[async_trait]
impl ReleaseSource for UrlSource {
    async fn latest(&self) -> UpdaterResult<ReleaseInfo> {
        debug!(target: "spt_updater::source", url = %self.index, "polling URL manifest");
        let resp = self
            .client
            .get(&self.index)
            .header(USER_AGENT, UA)
            .send()
            .await
            .map_err(|e| UpdaterError::Source(format!("GET {}: {e}", self.index)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(UpdaterError::Source(format!(
                "GET {} returned HTTP {}",
                self.index,
                status.as_u16()
            )));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| UpdaterError::Source(format!("read {}: {e}", self.index)))?;

        // Pin the manifest body to the configured fingerprint before we
        // trust a single byte of it.
        let got = sha256_hex(&body);
        if got != self.fingerprint {
            return Err(UpdaterError::Source(format!(
                "manifest fingerprint mismatch: expected {}, got {got}",
                self.fingerprint
            )));
        }

        let manifest: UrlManifest = serde_json::from_slice(&body)
            .map_err(|e| UpdaterError::Source(format!("parse manifest: {e}")))?;

        let tag = manifest.tag.trim_start_matches('v').to_string();
        let cargo_version = if tag.split('.').count() == 2 {
            format!("0.{tag}")
        } else {
            tag.clone()
        };

        let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
        for a in manifest.artifacts {
            let url = a
                .url
                .unwrap_or_else(|| self.render_template(&tag, &target_from_name(&a.name)));
            artifacts.push(ReleaseArtifact {
                name: a.name,
                url,
                size: a.size,
                sha256: a.sha256.map(|s| s.to_lowercase()),
            });
        }
        let signatures = manifest
            .signatures
            .into_iter()
            .map(|s| ReleaseArtifact {
                name: s.name.clone(),
                url: s
                    .url
                    .unwrap_or_else(|| self.render_template(&tag, &target_from_name(&s.name))),
                size: s.size,
                sha256: s.sha256.map(|h| h.to_lowercase()),
            })
            .collect();

        Ok(ReleaseInfo {
            tag,
            cargo_version,
            published_at: manifest.published_at.unwrap_or_default(),
            artifacts,
            signatures,
            extra: serde_json::json!({ "index": self.index }),
        })
    }
}

/// Best-effort extraction of a target triple from an artifact filename.
/// Returns the longest `*-*-*-*` token that looks like a Rust target, else
/// the whole name (so the template still renders something deterministic).
fn target_from_name(name: &str) -> String {
    const ARCHES: &[&str] = &["x86_64", "aarch64", "armv7", "i686", "arm", "riscv64gc"];
    // Strip common archive suffixes first.
    let base = name
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".tar.xz")
        .trim_end_matches(".zip")
        .trim_end_matches(".exe")
        .trim_end_matches(".minisig");
    // A Rust target triple has >=3 dash-separated components and contains a
    // known arch token. Scan suffixes of the dash-split for the first run
    // that starts with a recognised arch.
    let parts: Vec<&str> = base.split('-').collect();
    for (i, p) in parts.iter().enumerate() {
        if ARCHES.contains(p) {
            return parts[i..].join("-");
        }
    }
    base.to_string()
}

// ---------------------------------------------------------------------------
// Static source
// ---------------------------------------------------------------------------

/// Offline / `file://` release directory backend. Reads a
/// `release-manifest.json` from a local directory laid out like
/// `dist/<version>/`. Artifact URLs are emitted as absolute `file://` paths
/// so the rest of the pipeline (download, verify) treats them uniformly.
///
/// The static backend performs **no** network I/O, so it is the backend the
/// integration tests exercise without mocking HTTP.
#[derive(Debug)]
pub struct StaticSource {
    dir: std::path::PathBuf,
}

impl StaticSource {
    /// Build a static backend rooted at `dir`.
    #[must_use]
    pub fn new(dir: std::path::PathBuf) -> Self {
        Self { dir }
    }

    /// Resolve a name (which may be a bare filename or an absolute path)
    /// into a `file://` URL anchored at the source directory.
    fn file_url(&self, name: &str) -> String {
        let candidate = std::path::Path::new(name);
        let abs = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            self.dir.join(name)
        };
        url::Url::from_file_path(&abs).map_or_else(
            // `from_file_path` only fails for relative paths; we joined onto
            // an absolute dir, so this fallback is defensive.
            |()| format!("file://{}", abs.display()),
            |u| u.to_string(),
        )
    }
}

#[async_trait]
impl ReleaseSource for StaticSource {
    async fn latest(&self) -> UpdaterResult<ReleaseInfo> {
        let manifest_path = self.dir.join("release-manifest.json");
        debug!(
            target: "spt_updater::source",
            path = %manifest_path.display(),
            "reading static release manifest"
        );
        let body = std::fs::read(&manifest_path)
            .map_err(|e| UpdaterError::Source(format!("read {}: {e}", manifest_path.display())))?;
        let manifest: UrlManifest = serde_json::from_slice(&body)
            .map_err(|e| UpdaterError::Source(format!("parse static manifest: {e}")))?;

        let tag = manifest.tag.trim_start_matches('v').to_string();
        let cargo_version = if tag.split('.').count() == 2 {
            format!("0.{tag}")
        } else {
            tag.clone()
        };

        let artifacts = manifest
            .artifacts
            .into_iter()
            .map(|a| ReleaseArtifact {
                url: a.url.unwrap_or_else(|| self.file_url(&a.name)),
                name: a.name,
                size: a.size,
                sha256: a.sha256.map(|h| h.to_lowercase()),
            })
            .collect();
        let signatures = manifest
            .signatures
            .into_iter()
            .map(|s| ReleaseArtifact {
                url: s.url.unwrap_or_else(|| self.file_url(&s.name)),
                name: s.name,
                size: s.size,
                sha256: s.sha256.map(|h| h.to_lowercase()),
            })
            .collect();

        Ok(ReleaseInfo {
            tag,
            cargo_version,
            published_at: manifest.published_at.unwrap_or_default(),
            artifacts,
            signatures,
            extra: serde_json::json!({ "dir": self.dir.display().to_string() }),
        })
    }
}

/// Lowercase hex SHA-256 of `bytes`. Shared with [`crate::verify`] via its
/// own copy; kept module-local here to avoid a cross-module dependency for
/// the manifest pin.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
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

    // ---- target extraction --------------------------------------------

    #[test]
    fn target_extracted_from_artifact_name() {
        assert_eq!(
            target_from_name("spt-26.4-x86_64-unknown-linux-gnu.tar.gz"),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            target_from_name("spt-26.4-aarch64-apple-darwin.tar.gz"),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            target_from_name("spt-26.4-x86_64-pc-windows-msvc.zip"),
            "x86_64-pc-windows-msvc"
        );
        // No recognisable arch → returns the de-suffixed base.
        assert_eq!(target_from_name("plain.tar.gz"), "plain");
    }

    #[test]
    fn url_source_rejects_unparseable_index() {
        let err = UrlSource::new(
            "https://x/{version}/{target}".into(),
            "not a url".into(),
            "deadbeef",
        )
        .unwrap_err();
        assert_eq!(err.code(), "updater_source");
    }

    #[test]
    fn url_template_render_substitutes_placeholders() {
        let s = UrlSource::new(
            "https://mirror/dist/{version}/spt-{version}-{target}.tar.gz".into(),
            "https://mirror/dist/release-manifest.json".into(),
            "00",
        )
        .unwrap();
        assert_eq!(
            s.render_template("26.4", "x86_64-unknown-linux-gnu"),
            "https://mirror/dist/26.4/spt-26.4-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    // ---- static backend (no network, file-based) ----------------------

    fn write_manifest(dir: &std::path::Path, body: &str) {
        std::fs::write(dir.join("release-manifest.json"), body).unwrap();
    }

    #[tokio::test]
    async fn static_source_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("spt-26.5.tar.gz"), b"artifact").unwrap();
        write_manifest(
            tmp.path(),
            r#"{
                "tag": "26.5",
                "published_at": "2026-02-02T00:00:00Z",
                "artifacts": [
                    { "name": "spt-26.5.tar.gz", "size": 8, "sha256": "ABCDEF" }
                ],
                "signatures": [
                    { "name": "spt-26.5.tar.gz.minisig" }
                ]
            }"#,
        );
        let src = StaticSource::new(tmp.path().to_path_buf());
        let info = src.latest().await.unwrap();
        assert_eq!(info.tag, "26.5");
        assert_eq!(info.cargo_version, "0.26.5");
        assert_eq!(info.artifacts.len(), 1);
        // file:// URL synthesised from the bare name.
        assert!(info.artifacts[0].url.starts_with("file://"));
        assert!(info.artifacts[0].url.ends_with("spt-26.5.tar.gz"));
        // sha256 lowercased.
        assert_eq!(info.artifacts[0].sha256.as_deref(), Some("abcdef"));
        assert_eq!(info.signatures.len(), 1);
    }

    #[tokio::test]
    async fn static_source_missing_manifest_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let src = StaticSource::new(tmp.path().to_path_buf());
        let err = src.latest().await.unwrap_err();
        assert_eq!(err.code(), "updater_source");
    }

    #[tokio::test]
    async fn static_source_bad_json_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write_manifest(tmp.path(), "{ not json");
        let src = StaticSource::new(tmp.path().to_path_buf());
        let err = src.latest().await.unwrap_err();
        assert_eq!(err.code(), "updater_source");
    }

    #[test]
    fn build_source_dispatches_static() {
        use crate::config::{
            ActionConfig, ScheduleKind, SourceKind, StagingConfig, UpdateMode, UpdaterConfig,
            VerifyConfig,
        };
        let cfg = UpdaterConfig {
            enabled: true,
            mode: UpdateMode::Check,
            schedule: ScheduleKind::Interval(std::time::Duration::from_secs(60)),
            source: SourceKind::Static {
                dir: std::path::PathBuf::from("/tmp/dist"),
            },
            verify: VerifyConfig {
                require_minisign: false,
                minisign_pubkey: None,
                require_sha256sums: false,
                gpg_pubkey: None,
            },
            action: ActionConfig {
                restart_supervisor: false,
                notify_audit: false,
                post_install_hook: None,
            },
            staging: StagingConfig {
                dir: None,
                keep_last: 1,
            },
            window: None,
        };
        // Should construct without error (no I/O until `.latest()`).
        assert!(build_source(&cfg).is_ok());
    }
}
