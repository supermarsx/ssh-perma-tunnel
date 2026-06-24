//! Artifact download + target selection.
//!
//! Bridges a [`ReleaseInfo`](crate::source::ReleaseInfo) to on-disk staged
//! files. Supports both HTTP(S) URLs (via the same `reqwest` stack the
//! source backends use) and `file://` URLs (the `static` source), so the
//! download path is uniform regardless of backend.

use std::path::{Path, PathBuf};

use reqwest::header::USER_AGENT;
use tracing::debug;

use crate::error::{UpdaterError, UpdaterResult};
use crate::source::{ReleaseArtifact, ReleaseInfo};

const UA: &str = concat!("spt-updater/", env!("CARGO_PKG_VERSION"));

/// The build's target triple, baked in at compile time. Used to pick the
/// matching artifact from a multi-platform release.
pub const TARGET: &str = env!("SPT_TARGET");

/// A staged download: the artifact plus any sidecar signature / checksum
/// material, ready for [`crate::verify::verify_artifact`].
#[derive(Debug, Clone)]
pub struct Staged {
    /// Path to the downloaded artifact on disk.
    pub artifact: PathBuf,
    /// Path to the downloaded `<artifact>.minisig`, if the release had one.
    pub signature: Option<PathBuf>,
    /// Body of a downloaded `SHA256SUMS` file, if the release had one.
    pub sha256sums: Option<String>,
    /// The artifact's filename (for SHA256SUMS lookup).
    pub name: String,
    /// The per-artifact digest the source surfaced, if any.
    pub expected_sha256: Option<String>,
}

/// Pick the artifact matching `target` (default: this build's [`TARGET`]).
/// Falls back to the sole artifact when the release ships exactly one.
#[must_use]
pub fn select_artifact<'a>(rel: &'a ReleaseInfo, target: &str) -> Option<&'a ReleaseArtifact> {
    if let Some(a) = rel.artifacts.iter().find(|a| a.name.contains(target)) {
        return Some(a);
    }
    if rel.artifacts.len() == 1 {
        return rel.artifacts.first();
    }
    None
}

/// Find the `.minisig` signature for `artifact_name` in the release set.
#[must_use]
pub fn select_signature<'a>(
    rel: &'a ReleaseInfo,
    artifact_name: &str,
) -> Option<&'a ReleaseArtifact> {
    let want = format!("{artifact_name}.minisig");
    rel.signatures
        .iter()
        .find(|s| s.name == want || s.name.contains(artifact_name))
}

/// Find a `SHA256SUMS` artifact in the release set, if published.
#[must_use]
pub fn select_sha256sums(rel: &ReleaseInfo) -> Option<&ReleaseArtifact> {
    rel.artifacts
        .iter()
        .chain(rel.signatures.iter())
        .find(|a| a.name.eq_ignore_ascii_case("SHA256SUMS") || a.name.ends_with("SHA256SUMS"))
}

/// Download the target artifact (and its signature / SHA256SUMS, if present)
/// for `rel` into `staging_dir`, returning the staged file set.
pub async fn download_release(
    rel: &ReleaseInfo,
    target: &str,
    staging_dir: &Path,
) -> UpdaterResult<Staged> {
    let artifact = select_artifact(rel, target).ok_or_else(|| {
        UpdaterError::Source(format!(
            "no artifact in release {} matches target `{target}` ({} artifacts available)",
            rel.tag,
            rel.artifacts.len()
        ))
    })?;

    std::fs::create_dir_all(staging_dir).map_err(|e| {
        UpdaterError::Install(format!("create staging dir {}: {e}", staging_dir.display()))
    })?;

    let client = reqwest::Client::builder()
        .user_agent(UA)
        .build()
        .map_err(|e| UpdaterError::Source(format!("reqwest build: {e}")))?;

    let artifact_path = staging_dir.join(&artifact.name);
    fetch_to(&client, &artifact.url, &artifact_path).await?;

    let signature = if let Some(sig) = select_signature(rel, &artifact.name) {
        let sig_path = staging_dir.join(&sig.name);
        fetch_to(&client, &sig.url, &sig_path).await?;
        Some(sig_path)
    } else {
        None
    };

    let sha256sums = if let Some(sums) = select_sha256sums(rel) {
        let bytes = fetch_bytes(&client, &sums.url).await?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        None
    };

    Ok(Staged {
        artifact: artifact_path,
        signature,
        sha256sums,
        name: artifact.name.clone(),
        expected_sha256: artifact.sha256.clone(),
    })
}

/// Fetch a URL (HTTP(S) or `file://`) to `dest`.
async fn fetch_to(client: &reqwest::Client, url: &str, dest: &Path) -> UpdaterResult<()> {
    let bytes = fetch_bytes(client, url).await?;
    std::fs::write(dest, &bytes)
        .map_err(|e| UpdaterError::Install(format!("write {}: {e}", dest.display())))?;
    debug!(
        target: "spt_updater::download",
        url = %url,
        dest = %dest.display(),
        bytes = bytes.len(),
        "staged"
    );
    Ok(())
}

/// Fetch a URL's bytes. Handles `file://` locally (the `static` backend)
/// and everything else over HTTP(S).
async fn fetch_bytes(client: &reqwest::Client, url: &str) -> UpdaterResult<Vec<u8>> {
    if let Some(path) = file_url_to_path(url) {
        return std::fs::read(&path)
            .map_err(|e| UpdaterError::Source(format!("read {}: {e}", path.display())));
    }
    let resp = client
        .get(url)
        .header(USER_AGENT, UA)
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
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| UpdaterError::Source(format!("read body {url}: {e}")))
}

/// Convert a `file://` URL to a local path; returns `None` for other schemes.
fn file_url_to_path(url: &str) -> Option<PathBuf> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "file" {
        return None;
    }
    parsed.to_file_path().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ReleaseArtifact;

    fn art(name: &str) -> ReleaseArtifact {
        ReleaseArtifact {
            name: name.into(),
            url: format!("https://example/{name}"),
            size: None,
            sha256: None,
        }
    }

    fn rel(artifacts: Vec<ReleaseArtifact>, signatures: Vec<ReleaseArtifact>) -> ReleaseInfo {
        ReleaseInfo {
            tag: "26.4".into(),
            cargo_version: "0.26.4".into(),
            published_at: String::new(),
            artifacts,
            signatures,
            extra: serde_json::Value::Null,
        }
    }

    #[test]
    fn selects_artifact_by_target_substring() {
        let r = rel(
            vec![
                art("spt-26.4-x86_64-unknown-linux-gnu.tar.gz"),
                art("spt-26.4-aarch64-apple-darwin.tar.gz"),
            ],
            vec![],
        );
        let chosen = select_artifact(&r, "aarch64-apple-darwin").unwrap();
        assert!(chosen.name.contains("aarch64-apple-darwin"));
    }

    #[test]
    fn selects_sole_artifact_as_fallback() {
        let r = rel(vec![art("spt.tar.gz")], vec![]);
        assert!(select_artifact(&r, "no-match-triple").is_some());
    }

    #[test]
    fn no_match_when_multiple_and_none_match() {
        let r = rel(vec![art("a-linux.tar.gz"), art("b-darwin.tar.gz")], vec![]);
        assert!(select_artifact(&r, "windows").is_none());
    }

    #[test]
    fn selects_matching_signature() {
        let r = rel(
            vec![art("spt-linux.tar.gz")],
            vec![art("spt-linux.tar.gz.minisig")],
        );
        let sig = select_signature(&r, "spt-linux.tar.gz").unwrap();
        assert_eq!(sig.name, "spt-linux.tar.gz.minisig");
    }

    #[test]
    fn selects_sha256sums() {
        let r = rel(vec![art("spt-linux.tar.gz"), art("SHA256SUMS")], vec![]);
        assert!(select_sha256sums(&r).is_some());
    }

    #[test]
    fn file_url_roundtrips_to_path() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("art.bin");
        std::fs::write(&p, b"x").unwrap();
        let u = url::Url::from_file_path(&p).unwrap();
        let back = file_url_to_path(u.as_str()).unwrap();
        assert_eq!(back, p);
        assert!(file_url_to_path("https://example/x").is_none());
    }

    #[tokio::test]
    async fn download_from_file_urls_stages_everything() {
        // Build a release whose artifact + signature + SHA256SUMS are all
        // file:// URLs — exercises the whole download path with no network.
        let src = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();

        let art_path = src.path().join("spt-26.4-thistarget.tar.gz");
        std::fs::write(&art_path, b"ARTIFACT").unwrap();
        let sig_path = src.path().join("spt-26.4-thistarget.tar.gz.minisig");
        std::fs::write(&sig_path, b"SIGNATURE").unwrap();
        let sums_path = src.path().join("SHA256SUMS");
        std::fs::write(&sums_path, b"abc  spt-26.4-thistarget.tar.gz\n").unwrap();

        let to_url = |p: &Path| url::Url::from_file_path(p).unwrap().to_string();
        let r = rel(
            vec![
                ReleaseArtifact {
                    name: "spt-26.4-thistarget.tar.gz".into(),
                    url: to_url(&art_path),
                    size: None,
                    sha256: Some("abc".into()),
                },
                ReleaseArtifact {
                    name: "SHA256SUMS".into(),
                    url: to_url(&sums_path),
                    size: None,
                    sha256: None,
                },
            ],
            vec![ReleaseArtifact {
                name: "spt-26.4-thistarget.tar.gz.minisig".into(),
                url: to_url(&sig_path),
                size: None,
                sha256: None,
            }],
        );

        let staged = download_release(&r, "thistarget", stage.path())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&staged.artifact).unwrap(), b"ARTIFACT");
        assert!(staged.signature.is_some());
        assert_eq!(
            std::fs::read(staged.signature.as_ref().unwrap()).unwrap(),
            b"SIGNATURE"
        );
        assert!(staged.sha256sums.unwrap().contains("spt-26.4-thistarget"));
        assert_eq!(staged.expected_sha256.as_deref(), Some("abc"));
    }
}
