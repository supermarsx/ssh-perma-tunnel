//! Artifact verification — minisign signature + SHA256SUMS + optional GPG.
//!
//! **This module is a scaffold.** The real verification path lands in a
//! subsequent commit; the trait + entry point live here so the install
//! path can take the dependency without recompiling later.

use std::path::Path;

use crate::config::VerifyConfig;
use crate::error::UpdaterResult;

/// Verify a downloaded artifact against the configured policy. Returns
/// `Ok(())` only when every required check passed.
pub async fn verify_artifact(
    _cfg: &VerifyConfig,
    _artifact: &Path,
    _signature: Option<&Path>,
) -> UpdaterResult<()> {
    // Implementation lands in commit 4 of the updater series.
    Ok(())
}
