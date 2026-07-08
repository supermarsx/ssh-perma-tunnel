//! Artifact download + target selection.
//!
//! Bridges a [`ReleaseInfo`](crate::source::ReleaseInfo) to on-disk staged
//! files. Supports both HTTP(S) URLs (via the same `reqwest` stack the
//! source backends use) and `file://` URLs (the `static` source), so the
//! download path is uniform regardless of backend.

use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::USER_AGENT;
use tracing::debug;

use crate::error::{UpdaterError, UpdaterResult};
use crate::source::{ReleaseArtifact, ReleaseInfo};

const UA: &str = concat!("spt-updater/", env!("CARGO_PKG_VERSION"));

/// The build's target triple, baked in at compile time. Used to pick the
/// matching artifact from a multi-platform release.
pub const TARGET: &str = env!("SPT_TARGET");

/// Hard ceiling on any single downloaded artifact / sidecar body. A release
/// binary plus its archive is comfortably under this; anything larger from an
/// update endpoint is treated as hostile (OOM-DoS) and aborted. This bounds
/// the streamed body even when the source advertises no `size`.
pub const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// Per-request total timeout for HTTP(S) downloads. Decoupled from any
/// background-poll cadence; long enough for a large artifact on a slow link,
/// short enough that a slowloris endpoint cannot stall the updater forever.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// TCP connect timeout — fail fast on an unreachable / black-holed host.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounded redirect budget. `https_only(true)` already rejects any
/// redirect-to-HTTP downgrade; this caps redirect-loop / hop count.
const MAX_REDIRECTS: usize = 5;

/// Derive a safe staging filename from a server-supplied artifact name.
///
/// The server (GitHub asset name, URL-manifest `name`) fully controls this
/// string, so it must never be joined onto a path verbatim — a name like
/// `../../../../etc/cron.d/x`, an absolute path, or a Windows drive/UNC prefix
/// would otherwise let a malicious release write outside the staging dir
/// *before* verification runs. We reduce the name to its final path component
/// (`Path::file_name`) and reject anything that does not survive that reduction
/// unchanged: empty, traversal (`.`/`..`), separators, absolute, or a drive/UNC
/// prefix. The returned value is a bare filename with no path separators.
fn safe_staging_name(name: &str) -> UpdaterResult<String> {
    let reject = |reason: &str| {
        Err(UpdaterError::Source(format!(
            "refusing unsafe artifact name `{name}`: {reason}"
        )))
    };

    if name.is_empty() {
        return reject("empty");
    }
    // Reject any separator (both `/` and `\`) and NUL up front — `file_name`
    // on a Windows host treats `/` as a separator but a Unix daemon does not,
    // so we screen both regardless of platform to be portable and strict.
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return reject("contains a path separator or NUL");
    }
    // Reject a drive-letter prefix (`C:...`) or any colon, which on Windows
    // can introduce alternate-data-stream / drive-relative semantics.
    if name.contains(':') {
        return reject("contains a drive or stream separator");
    }
    let p = Path::new(name);
    if p.is_absolute() {
        return reject("is an absolute path");
    }
    // After the separator screen above, a well-formed name has exactly one
    // component equal to itself. `file_name` returns None for `.`/`..`/`/`.
    match p.file_name().and_then(|s| s.to_str()) {
        Some(base) if base == name && base != "." && base != ".." => Ok(base.to_string()),
        _ => reject("does not reduce to a single safe filename component"),
    }
}

/// Build the hardened reqwest client used for all updater downloads:
/// connect + overall timeout, `https_only` (no HTTP / redirect-to-HTTP
/// downgrade), and a bounded redirect policy.
fn build_client() -> UpdaterResult<reqwest::Client> {
    // reqwest's rustls backend reads the process-global crypto provider and
    // panics if none is installed; ensure aws-lc-rs (the single workspace-wide
    // provider) is the default before the client is built.
    spt_trust::install_default_crypto_provider();
    reqwest::Client::builder()
        .user_agent(UA)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .build()
        .map_err(|e| UpdaterError::Source(format!("reqwest build: {e}")))
}

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

    let client = build_client()?;

    // Never join a server-supplied name onto the staging path. Reduce it to a
    // sanitized basename first; a traversal / absolute / drive-prefixed name
    // is rejected here, before any byte is written (H1).
    let artifact_base = safe_staging_name(&artifact.name)?;
    let artifact_path = staging_dir.join(&artifact_base);
    // If the source advertised a size, refuse anything larger than it (and the
    // absolute cap); otherwise the absolute cap alone bounds the body (H2).
    let artifact_cap = size_cap(artifact.size);
    fetch_to(&client, &artifact.url, &artifact_path, artifact_cap).await?;

    let signature = if let Some(sig) = select_signature(rel, &artifact.name) {
        let sig_base = safe_staging_name(&sig.name)?;
        let sig_path = staging_dir.join(&sig_base);
        // Signatures are tiny; cap them hard at the absolute ceiling.
        fetch_to(&client, &sig.url, &sig_path, MAX_DOWNLOAD_BYTES).await?;
        Some(sig_path)
    } else {
        None
    };

    let sha256sums = if let Some(sums) = select_sha256sums(rel) {
        let bytes = fetch_bytes(&client, &sums.url, MAX_DOWNLOAD_BYTES).await?;
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

/// Resolve the effective byte cap for an artifact: the advertised `size`
/// (when present and within the absolute ceiling) else the absolute ceiling.
/// A source claiming a size larger than the ceiling is itself capped — we
/// never trust a server-supplied size to *raise* the limit.
fn size_cap(advertised: Option<u64>) -> u64 {
    match advertised {
        Some(n) => n.min(MAX_DOWNLOAD_BYTES),
        None => MAX_DOWNLOAD_BYTES,
    }
}

/// Fetch a URL (HTTP(S) or `file://`) to `dest`, aborting if the body exceeds
/// `max_bytes`.
async fn fetch_to(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    max_bytes: u64,
) -> UpdaterResult<()> {
    let bytes = fetch_bytes(client, url, max_bytes).await?;
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

/// Fetch a URL's bytes, enforcing `max_bytes` as a hard cap. Handles
/// `file://` locally (the `static` backend) and everything else over HTTP(S).
///
/// For HTTP(S) the body is read in chunks and aborted the instant the running
/// total would exceed `max_bytes`, so a malicious endpoint streaming an
/// unbounded body cannot OOM the daemon (H2). An advertised `Content-Length`
/// larger than the cap is rejected before the first chunk. `file://` reads are
/// length-checked against the cap too.
async fn fetch_bytes(
    client: &reqwest::Client,
    url: &str,
    max_bytes: u64,
) -> UpdaterResult<Vec<u8>> {
    if let Some(path) = file_url_to_path(url) {
        let meta = std::fs::metadata(&path)
            .map_err(|e| UpdaterError::Source(format!("stat {}: {e}", path.display())))?;
        if meta.len() > max_bytes {
            return Err(UpdaterError::Source(format!(
                "{} is {} bytes, exceeds cap {max_bytes}",
                path.display(),
                meta.len()
            )));
        }
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
    // Reject up front if the server advertises a body larger than the cap.
    if let Some(len) = resp.content_length() {
        if len > max_bytes {
            return Err(UpdaterError::Source(format!(
                "{url} advertises {len} bytes, exceeds cap {max_bytes}"
            )));
        }
    }
    // Stream chunk-by-chunk and abort the moment the running total would
    // exceed the cap — do not trust the advertised Content-Length.
    let mut body: Vec<u8> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| UpdaterError::Source(format!("read body {url}: {e}")))?
    {
        if (body.len() as u64).saturating_add(chunk.len() as u64) > max_bytes {
            return Err(UpdaterError::Source(format!(
                "{url} body exceeds cap {max_bytes} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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

    // ---- H1: artifact-name sanitization -------------------------------

    #[test]
    fn safe_name_accepts_plain_basename() {
        assert_eq!(
            safe_staging_name("spt-26.4-x86_64-unknown-linux-gnu.tar.gz").unwrap(),
            "spt-26.4-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(safe_staging_name("SHA256SUMS").unwrap(), "SHA256SUMS");
        assert_eq!(
            safe_staging_name("a.tar.gz.minisig").unwrap(),
            "a.tar.gz.minisig"
        );
    }

    #[test]
    fn safe_name_rejects_unix_traversal() {
        assert!(safe_staging_name("../../../../etc/cron.d/x").is_err());
        assert!(safe_staging_name("..").is_err());
        assert!(safe_staging_name(".").is_err());
        assert!(safe_staging_name("a/b").is_err());
    }

    #[test]
    fn safe_name_rejects_absolute_and_windows_paths() {
        assert!(safe_staging_name("/etc/passwd").is_err());
        assert!(safe_staging_name("C:\\Windows\\System32\\evil.dll").is_err());
        assert!(safe_staging_name("C:relative").is_err());
        // UNC / backslash separators.
        assert!(safe_staging_name("\\\\server\\share\\x").is_err());
        assert!(safe_staging_name("dir\\file").is_err());
    }

    #[test]
    fn safe_name_rejects_empty_and_nul() {
        assert!(safe_staging_name("").is_err());
        assert!(safe_staging_name("a\0b").is_err());
    }

    #[tokio::test]
    async fn traversal_artifact_name_writes_nothing_outside_staging() {
        let src = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        let art_path = src.path().join("real.tar.gz");
        std::fs::write(&art_path, b"PAYLOAD").unwrap();
        let to_url = |p: &Path| url::Url::from_file_path(p).unwrap().to_string();

        // A release whose sole artifact (matched as the lone fallback) carries
        // a traversal name. The download must be rejected before any write.
        let r = rel(
            vec![ReleaseArtifact {
                name: "../../../../tmp/spt-evil".into(),
                url: to_url(&art_path),
                size: None,
                sha256: None,
            }],
            vec![],
        );
        let err = download_release(&r, "no-target-match", stage.path())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "updater_source");
        // Nothing landed in (or above) the staging dir.
        assert!(!stage.path().join("spt-evil").exists());
        let escaped = stage.path().parent().unwrap().join("spt-evil");
        assert!(!escaped.exists());
    }

    #[tokio::test]
    async fn traversal_signature_name_is_rejected() {
        let src = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        let art_path = src.path().join("spt-thistarget.tar.gz");
        std::fs::write(&art_path, b"A").unwrap();
        let sig_path = src.path().join("sig");
        std::fs::write(&sig_path, b"S").unwrap();
        let to_url = |p: &Path| url::Url::from_file_path(p).unwrap().to_string();

        let r = rel(
            vec![ReleaseArtifact {
                name: "spt-thistarget.tar.gz".into(),
                url: to_url(&art_path),
                size: None,
                sha256: None,
            }],
            vec![ReleaseArtifact {
                // matched by `contains(artifact_name)` → "spt-thistarget.tar.gz"
                name: "spt-thistarget.tar.gz/../../evil.minisig".into(),
                url: to_url(&sig_path),
                size: None,
                sha256: None,
            }],
        );
        let err = download_release(&r, "thistarget", stage.path())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "updater_source");
    }

    // ---- H2: size cap -------------------------------------------------

    #[test]
    fn size_cap_clamps_to_ceiling() {
        assert_eq!(size_cap(None), MAX_DOWNLOAD_BYTES);
        assert_eq!(size_cap(Some(1024)), 1024);
        // A server cannot raise the cap above the absolute ceiling.
        assert_eq!(size_cap(Some(u64::MAX)), MAX_DOWNLOAD_BYTES);
    }

    #[tokio::test]
    async fn file_body_over_cap_is_rejected() {
        let src = tempfile::tempdir().unwrap();
        let big = src.path().join("big.bin");
        std::fs::write(&big, vec![0u8; 4096]).unwrap();
        let url = url::Url::from_file_path(&big).unwrap().to_string();
        let client = build_client().unwrap();
        // cap below the file size → reject.
        let err = fetch_bytes(&client, &url, 1024).await.unwrap_err();
        assert_eq!(err.code(), "updater_source");
        // cap above the file size → ok.
        let ok = fetch_bytes(&client, &url, 8192).await.unwrap();
        assert_eq!(ok.len(), 4096);
    }

    #[tokio::test]
    async fn oversized_artifact_via_size_field_is_rejected() {
        // The artifact file is larger than the source-advertised `size`, so
        // the per-artifact cap (= advertised size) trips on the file read.
        let src = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        let art_path = src.path().join("spt-thistarget.tar.gz");
        std::fs::write(&art_path, vec![7u8; 2048]).unwrap();
        let url = url::Url::from_file_path(&art_path).unwrap().to_string();
        let r = rel(
            vec![ReleaseArtifact {
                name: "spt-thistarget.tar.gz".into(),
                url,
                size: Some(10), // claims tiny; real file is 2048 bytes
                sha256: None,
            }],
            vec![],
        );
        let err = download_release(&r, "thistarget", stage.path())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "updater_source");
    }

    #[test]
    fn build_client_is_https_only_and_rejects_http() {
        // The hardened client must refuse a plain-http GET (no network needed;
        // https_only short-circuits before connecting).
        let client = build_client().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(fetch_bytes(&client, "http://example.invalid/x", 1024))
            .unwrap_err();
        assert_eq!(err.code(), "updater_source");
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
