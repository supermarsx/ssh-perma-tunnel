//! Install-history audit trail (`[updater.action].notify_audit`).
//!
//! `notify_audit` defaults to `true` and `spt update history` points operators
//! at "install events recorded as an audit trail" — but before this module the
//! trail was never written, so `history` had nothing to show (wire-observ
//! finding 15). This module persists an append-only JSONL record of each
//! successful install and exposes a reader so the CLI can surface it.
//!
//! The trail lives at `<staging_dir>/.spt-update-history.jsonl`. It is a
//! dotfile so [`crate::staging::prune`] never treats it as a build artifact.
//! Writing the trail is **best-effort**: a failure to record history must never
//! fail an otherwise-successful install, so [`record_install`] logs on error
//! and returns `Ok`-shaped intent to the caller via a `warn!` rather than
//! propagating.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::warn;

/// The dotfile name of the install-history trail inside the staging dir.
pub const HISTORY_FILE: &str = ".spt-update-history.jsonl";

/// One recorded install event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    /// ISO-8601 UTC timestamp of the install.
    pub timestamp: String,
    /// The event kind (currently always `"installed"`).
    pub event: String,
    /// The version tag that was installed.
    pub version: String,
    /// The staged artifact the new binary was installed from.
    pub artifact: String,
}

/// Absolute path to the history trail inside `staging_dir`.
#[must_use]
pub fn history_path(staging_dir: &Path) -> PathBuf {
    staging_dir.join(HISTORY_FILE)
}

/// Append a successful-install record to the trail under `staging_dir`.
///
/// Best-effort: any IO error is logged at `warn!` and swallowed — recording
/// history must not turn a successful install into a failure. Called only when
/// `[updater.action].notify_audit` is set.
pub fn record_install(staging_dir: &Path, version: &str, artifact: &Path) {
    let entry = AuditEntry {
        timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        event: "installed".to_string(),
        version: version.to_string(),
        artifact: artifact.display().to_string(),
    };
    if let Err(e) = append_entry(staging_dir, &entry) {
        warn!(
            target: "spt_updater::audit",
            error = %e,
            "failed to record update-install audit trail entry"
        );
    }
}

fn append_entry(staging_dir: &Path, entry: &AuditEntry) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(staging_dir)?;
    let mut line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_path(staging_dir))?;
    f.write_all(line.as_bytes())
}

/// Read the install-history trail from `staging_dir`, newest last.
///
/// A missing trail returns an empty vec. Malformed lines are skipped (a
/// truncated final write must not poison the whole history). Public so the
/// `spt update history` CLI can render real data.
#[must_use]
pub fn read_history(staging_dir: &Path) -> Vec<AuditEntry> {
    let path = history_path(staging_dir);
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<AuditEntry>(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        record_install(dir.path(), "26.5", Path::new("/stage/spt-26.5.tar.gz"));
        record_install(dir.path(), "26.6", Path::new("/stage/spt-26.6.tar.gz"));

        let hist = read_history(dir.path());
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[0].version, "26.5");
        assert_eq!(hist[1].version, "26.6");
        assert_eq!(hist[1].event, "installed");
        assert_eq!(hist[1].artifact, "/stage/spt-26.6.tar.gz");
    }

    #[test]
    fn missing_trail_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_history(dir.path()).is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let p = history_path(dir.path());
        std::fs::write(
            &p,
            "not json\n{\"timestamp\":\"t\",\"event\":\"installed\",\"version\":\"9.9\",\"artifact\":\"a\"}\n",
        )
        .unwrap();
        let hist = read_history(dir.path());
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].version, "9.9");
    }
}
