//! Hosts-file render / apply / restore.
//!
//! `HostsManager` writes a managed block bracketed by sentinel comments:
//!
//! ```text
//! # >>> spt-managed >>>
//! 10.0.0.1   mail.tunnel.local
//! ::1        loopback6.tunnel.local
//! # <<< spt-managed <<<
//! ```
//!
//! Anything outside that block is preserved verbatim. Backup behavior:
//! before the first apply, the original hosts-file is copied to
//! `<state_dir>/hosts/backup-<unix-ts>` (callers pass the backup directory).
//! `restore` reads the most-recent backup and writes it back.
//!
//! Cross-platform default paths:
//! - Unix: `/etc/hosts`
//! - Windows: `C:\Windows\System32\drivers\etc\hosts`
//!
//! Tests must always pass a tempdir path — never write the real system file.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{DnsError, Result};
use crate::zone::{Record, RecordKind};

/// Begin marker for the spt-managed block.
pub const HOSTS_BEGIN_MARKER: &str = "# >>> spt-managed >>>";
/// End marker for the spt-managed block.
pub const HOSTS_END_MARKER: &str = "# <<< spt-managed <<<";

/// One line in the managed block: `<address>  <name1> [name2 ...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsEntry {
    /// Literal address column (`10.0.0.1`, `::1`, etc.).
    pub address: String,
    /// One or more hostnames. The first is the canonical name; the rest are
    /// aliases.
    pub names: Vec<String>,
}

impl HostsEntry {
    /// Render a single line (no trailing newline).
    #[must_use]
    pub fn render_line(&self) -> String {
        format!("{}\t{}", self.address, self.names.join(" "))
    }

    /// Build the hosts-file entries for a set of managed [`Record`]s.
    ///
    /// Only `A`/`AAAA` records map to hosts-file lines — a hosts file expresses
    /// address→name mappings, so `SRV`/`TXT` records are skipped. A single
    /// trailing dot is stripped from each owner name so the rendered line uses
    /// the conventional un-rooted hostname form.
    ///
    /// This is the bridge the `mode = "hosts_file"` run-path uses to turn a
    /// synthesized [`crate::ManagedZone`]'s records (static `[[dns.records]]`
    /// plus `auto_records`) into the managed block.
    #[must_use]
    pub fn from_records(records: &[Record]) -> Vec<Self> {
        records
            .iter()
            .filter(|r| matches!(r.kind, RecordKind::A | RecordKind::AAAA))
            .map(|r| Self {
                address: r.value.clone(),
                names: vec![r.name.trim_end_matches('.').to_string()],
            })
            .collect()
    }
}

/// How `[dns] mode = "hosts_file"` drives the system hosts file, mapped from
/// the `[dns] hosts_file_mode` config value (`render_only|apply|restore`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostsFileMode {
    /// `render_only` — compute the managed block and report the diff, but never
    /// modify the OS hosts file.
    RenderOnly,
    /// `apply` — write the managed block into the hosts file (backing up the
    /// original first). This is the default when `hosts_file_mode` is unset, so
    /// selecting `mode = "hosts_file"` actually manages the file.
    #[default]
    Apply,
    /// `restore` — roll the hosts file back to the most recent backup.
    Restore,
}

impl HostsFileMode {
    /// Parse a `[dns] hosts_file_mode` config string.
    ///
    /// An absent/empty value defaults to [`HostsFileMode::Apply`] so that
    /// selecting `mode = "hosts_file"` actually manages the hosts file rather
    /// than silently no-op'ing. Unknown values are returned as `Err(value)` so
    /// the caller can fail closed / warn.
    pub fn from_config_str(s: &str) -> std::result::Result<Self, String> {
        match s.trim() {
            "" | "apply" => Ok(Self::Apply),
            "render_only" => Ok(Self::RenderOnly),
            "restore" => Ok(Self::Restore),
            other => Err(other.to_string()),
        }
    }
}

/// Outcome of running the hosts-file mode via [`HostsManager::run_mode`].
#[derive(Debug, Clone)]
pub struct HostsModeOutcome {
    /// The mode that was run.
    pub mode: HostsFileMode,
    /// Apply/render diff report (populated for `RenderOnly`/`Apply`, `None` for
    /// `Restore`).
    pub report: Option<HostsApplyReport>,
    /// True when a `Restore` actually wrote the backup back to the target.
    pub restored: bool,
}

/// Result of an apply operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsApplyReport {
    /// Path that was (or would have been) written.
    pub path: PathBuf,
    /// True if the operation actually modified the file.
    pub changed: bool,
    /// True if a backup was written this call.
    pub backed_up: bool,
    /// Path of the backup written (if any).
    pub backup_path: Option<PathBuf>,
    /// Previous file contents (only populated on dry-run / changed=true).
    pub previous: Option<String>,
    /// New file contents that were (or would be) written.
    pub next: String,
}

/// Hosts-file manager. Holds the desired managed-block entries and a backup
/// directory.
#[derive(Debug, Clone)]
pub struct HostsManager {
    /// Desired entries inside the managed block.
    entries: Vec<HostsEntry>,
    /// Directory that backups are written into. Created if it does not
    /// exist on first apply.
    backup_dir: PathBuf,
    /// Default path used when `apply`/`restore` is called with `path = None`.
    default_path: PathBuf,
}

impl HostsManager {
    /// Build a manager. `backup_dir` typically points at
    /// `<state_dir>/hosts`.
    pub fn new(entries: Vec<HostsEntry>, backup_dir: impl Into<PathBuf>) -> Self {
        Self {
            entries,
            backup_dir: backup_dir.into(),
            default_path: default_hosts_path(),
        }
    }

    /// Override the default hosts-file path. Useful for tests.
    #[must_use]
    pub fn with_default_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.default_path = path.into();
        self
    }

    /// Render the **managed block only** (without surrounding file content).
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(HOSTS_BEGIN_MARKER);
        s.push('\n');
        for e in &self.entries {
            s.push_str(&e.render_line());
            s.push('\n');
        }
        s.push_str(HOSTS_END_MARKER);
        s.push('\n');
        s
    }

    /// Compute the next file contents given the current ones.
    fn merge(&self, current: &str) -> String {
        let block = self.render();
        let block_trimmed = block.trim_end_matches('\n');
        if let Some((before, after)) = split_managed_block(current) {
            // Replace existing managed block.
            let mut s = String::with_capacity(before.len() + block_trimmed.len() + after.len() + 1);
            s.push_str(before);
            s.push_str(block_trimmed);
            s.push('\n');
            s.push_str(after);
            s
        } else {
            // Append, with a separating newline if the file doesn't end with one.
            let mut s = current.to_string();
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(block_trimmed);
            s.push('\n');
            s
        }
    }

    /// Apply the managed block to `path` (or the default OS hosts file).
    ///
    /// On `dry_run = true`, returns the diff-shaped report without modifying
    /// any files.
    pub fn apply(&self, path: Option<&Path>, dry_run: bool) -> Result<HostsApplyReport> {
        let target = path.map_or_else(|| self.default_path.clone(), Path::to_path_buf);
        let current = match std::fs::read_to_string(&target) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(DnsError::Io(e)),
        };
        let next = self.merge(&current);

        if next == current {
            return Ok(HostsApplyReport {
                path: target,
                changed: false,
                backed_up: false,
                backup_path: None,
                previous: Some(current),
                next,
            });
        }

        if dry_run {
            return Ok(HostsApplyReport {
                path: target,
                changed: true,
                backed_up: false,
                backup_path: None,
                previous: Some(current),
                next,
            });
        }

        // Real apply: backup, then write atomically.
        let previous_entries = managed_entry_count(&current);
        std::fs::create_dir_all(&self.backup_dir)?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup_path = self.backup_dir.join(format!("backup-{ts}"));
        std::fs::write(&backup_path, &current)?;

        write_atomic(&target, &next)?;

        // A hosts-file mutation is a privileged, host-wide change; log it at
        // INFO so an operator can see when spt added/removed managed entries.
        tracing::info!(
            path = %target.display(),
            entries = self.entries.len(),
            previous_entries,
            backup = %backup_path.display(),
            "dns: hosts-file managed block updated (entries added/removed)"
        );

        Ok(HostsApplyReport {
            path: target,
            changed: true,
            backed_up: true,
            backup_path: Some(backup_path),
            previous: Some(current),
            next,
        })
    }

    /// Drive the hosts-file lifecycle for `mode = "hosts_file"`.
    ///
    /// Dispatches on the parsed [`HostsFileMode`]:
    /// * [`HostsFileMode::RenderOnly`] — computes the diff without writing.
    /// * [`HostsFileMode::Apply`] — writes the managed block (honoring
    ///   `dry_run`), logging at INFO when the file is actually modified.
    /// * [`HostsFileMode::Restore`] — restores the most recent backup (skipped
    ///   under `dry_run`).
    ///
    /// This is the entry point `spt-bin` calls at `tunnel run` when the DNS
    /// `mode` selects `hosts_file` (see crate docs), turning what used to be a
    /// silent no-op into an actual hosts-file mutation.
    pub fn run_mode(
        &self,
        mode: HostsFileMode,
        path: Option<&Path>,
        dry_run: bool,
    ) -> Result<HostsModeOutcome> {
        match mode {
            HostsFileMode::RenderOnly => {
                // Never mutate: compute the diff report as a forced dry-run.
                let report = self.apply(path, true)?;
                Ok(HostsModeOutcome {
                    mode,
                    report: Some(report),
                    restored: false,
                })
            }
            HostsFileMode::Apply => {
                let report = self.apply(path, dry_run)?;
                Ok(HostsModeOutcome {
                    mode,
                    report: Some(report),
                    restored: false,
                })
            }
            HostsFileMode::Restore => {
                if dry_run {
                    Ok(HostsModeOutcome {
                        mode,
                        report: None,
                        restored: false,
                    })
                } else {
                    self.restore(path)?;
                    Ok(HostsModeOutcome {
                        mode,
                        report: None,
                        restored: true,
                    })
                }
            }
        }
    }

    /// Restore the most recent backup into `path` (or the default OS file).
    pub fn restore(&self, path: Option<&Path>) -> Result<()> {
        let target = path.map_or_else(|| self.default_path.clone(), Path::to_path_buf);
        let backup = latest_backup(&self.backup_dir)?
            .ok_or_else(|| DnsError::BackupMissing(self.backup_dir.display().to_string()))?;
        let contents = std::fs::read_to_string(&backup)?;
        write_atomic(&target, &contents)?;
        tracing::info!(
            path = %target.display(),
            backup = %backup.display(),
            "dns: hosts-file restored from backup"
        );
        Ok(())
    }
}

/// Default hosts-file path for the current OS.
#[must_use]
pub fn default_hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        // Use SystemRoot to be robust to non-default drives.
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// If `text` contains a managed block, return `(before, after)` slices that
/// surround it (the markers themselves are excluded; the trailing newline of
/// the end-marker line is consumed into `after`'s leading position).
fn split_managed_block(text: &str) -> Option<(&str, &str)> {
    let begin = text.find(HOSTS_BEGIN_MARKER)?;
    let end_search_from = begin + HOSTS_BEGIN_MARKER.len();
    let end_rel = text[end_search_from..].find(HOSTS_END_MARKER)?;
    let end_abs = end_search_from + end_rel + HOSTS_END_MARKER.len();
    // Consume the newline after the end marker, if any.
    let after_start = if text.as_bytes().get(end_abs).copied() == Some(b'\n') {
        end_abs + 1
    } else {
        end_abs
    };
    Some((&text[..begin], &text[after_start..]))
}

/// Count the entry lines inside an existing managed block (0 if there is no
/// block). Used only for mutation logging (added/removed visibility).
fn managed_entry_count(text: &str) -> usize {
    let Some(begin) = text.find(HOSTS_BEGIN_MARKER) else {
        return 0;
    };
    let rest = &text[begin + HOSTS_BEGIN_MARKER.len()..];
    let Some(end_rel) = rest.find(HOSTS_END_MARKER) else {
        return 0;
    };
    rest[..end_rel]
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
}

fn latest_backup(dir: &Path) -> Result<Option<PathBuf>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if let Some(ts) = s.strip_prefix("backup-") {
            if let Ok(n) = ts.parse::<u64>() {
                if best.as_ref().is_none_or(|(b, _)| n > *b) {
                    best = Some((n, entry.path()));
                }
            }
        }
    }
    Ok(best.map(|(_, p)| p))
}

fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension(format!(
        "spt-tmp-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_entries() -> Vec<HostsEntry> {
        vec![
            HostsEntry {
                address: "10.0.0.1".into(),
                names: vec!["mail.tunnel.local".into()],
            },
            HostsEntry {
                address: "::1".into(),
                names: vec!["v6.tunnel.local".into(), "alias.tunnel.local".into()],
            },
        ]
    }

    #[test]
    fn render_includes_markers_and_entries() {
        let m = HostsManager::new(sample_entries(), tempdir().unwrap().path());
        let s = m.render();
        assert!(s.starts_with(HOSTS_BEGIN_MARKER));
        assert!(s.trim_end().ends_with(HOSTS_END_MARKER));
        assert!(s.contains("10.0.0.1\tmail.tunnel.local"));
        assert!(s.contains("::1\tv6.tunnel.local alias.tunnel.local"));
    }

    #[test]
    fn apply_then_idempotent_apply() {
        let dir = tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1\tlocalhost\n# user note\n").unwrap();

        let m = HostsManager::new(sample_entries(), dir.path().join("backup"));
        let r1 = m.apply(Some(&hosts), false).unwrap();
        assert!(r1.changed);
        assert!(r1.backed_up);
        assert!(r1.backup_path.unwrap().exists());

        let r2 = m.apply(Some(&hosts), false).unwrap();
        assert!(!r2.changed);
        assert!(!r2.backed_up);
    }

    #[test]
    fn user_content_outside_markers_preserved() {
        let dir = tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let user = "127.0.0.1\tlocalhost\n# user note\n192.168.1.1\trouter\n";
        std::fs::write(&hosts, user).unwrap();

        let m = HostsManager::new(sample_entries(), dir.path().join("backup"));
        m.apply(Some(&hosts), false).unwrap();
        let after = std::fs::read_to_string(&hosts).unwrap();
        assert!(after.contains("127.0.0.1\tlocalhost"));
        assert!(after.contains("# user note"));
        assert!(after.contains("192.168.1.1\trouter"));
        assert!(after.contains("mail.tunnel.local"));
    }

    #[test]
    fn restore_returns_to_backup() {
        let dir = tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let original = "127.0.0.1\tlocalhost\n";
        std::fs::write(&hosts, original).unwrap();

        let m = HostsManager::new(sample_entries(), dir.path().join("backup"));
        m.apply(Some(&hosts), false).unwrap();
        // Modify file again
        std::fs::write(&hosts, "totally other content\n").unwrap();

        m.restore(Some(&hosts)).unwrap();
        let restored = std::fs::read_to_string(&hosts).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn dry_run_produces_diff_no_write() {
        let dir = tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1\tlocalhost\n").unwrap();
        let before = std::fs::read_to_string(&hosts).unwrap();

        let m = HostsManager::new(sample_entries(), dir.path().join("backup"));
        let report = m.apply(Some(&hosts), true).unwrap();
        assert!(report.changed);
        assert!(!report.backed_up);
        assert!(report.backup_path.is_none());
        assert_ne!(report.previous.as_deref().unwrap(), report.next);

        let after = std::fs::read_to_string(&hosts).unwrap();
        assert_eq!(before, after, "dry-run must not modify the hosts file");
    }

    #[test]
    fn replaces_existing_managed_block_in_place() {
        let dir = tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let existing = format!(
            "127.0.0.1\tlocalhost\n{HOSTS_BEGIN_MARKER}\n9.9.9.9\told.entry\n{HOSTS_END_MARKER}\n# trailing user\n"
        );
        std::fs::write(&hosts, &existing).unwrap();

        let m = HostsManager::new(sample_entries(), dir.path().join("backup"));
        m.apply(Some(&hosts), false).unwrap();
        let after = std::fs::read_to_string(&hosts).unwrap();
        assert!(!after.contains("9.9.9.9"));
        assert!(after.contains("mail.tunnel.local"));
        assert!(after.contains("# trailing user"));
        assert!(after.starts_with("127.0.0.1\tlocalhost\n"));
    }

    #[test]
    fn missing_backup_returns_error() {
        let dir = tempdir().unwrap();
        let m = HostsManager::new(sample_entries(), dir.path().join("nonexistent"));
        let res = m.restore(Some(&dir.path().join("hosts")));
        assert!(matches!(res, Err(DnsError::BackupMissing(_))));
    }

    // ---- hosts_file mode wiring (finding 9 / MED no-op) --------------------

    #[test]
    fn hosts_file_mode_parses_config_strings() {
        assert_eq!(
            HostsFileMode::from_config_str("apply").unwrap(),
            HostsFileMode::Apply
        );
        // Empty defaults to Apply so `mode = "hosts_file"` is never a no-op.
        assert_eq!(
            HostsFileMode::from_config_str("").unwrap(),
            HostsFileMode::Apply
        );
        assert_eq!(
            HostsFileMode::from_config_str("render_only").unwrap(),
            HostsFileMode::RenderOnly
        );
        assert_eq!(
            HostsFileMode::from_config_str("restore").unwrap(),
            HostsFileMode::Restore
        );
        assert!(HostsFileMode::from_config_str("bogus").is_err());
    }

    #[test]
    fn hosts_entries_from_records_maps_addresses_only() {
        use std::time::Duration;
        let recs = vec![
            Record::a(
                "web.tunnel.local.",
                "10.0.0.5".parse().unwrap(),
                Duration::from_secs(60),
            ),
            Record::aaaa(
                "v6.tunnel.local.",
                "fd00::1".parse().unwrap(),
                Duration::from_secs(60),
            ),
            Record::srv(
                "_svc._tcp.tunnel.local.",
                1,
                1,
                443,
                "web.tunnel.local.",
                Duration::from_secs(60),
            ),
            Record::txt("t.tunnel.local.", "hi", Duration::from_secs(60)),
        ];
        let entries = HostsEntry::from_records(&recs);
        // SRV/TXT are not address records -> only the A and AAAA map.
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.address == "10.0.0.5" && e.names == vec!["web.tunnel.local".to_string()]));
        assert!(entries
            .iter()
            .any(|e| e.address == "fd00::1" && e.names == vec!["v6.tunnel.local".to_string()]));
    }

    #[test]
    fn hosts_file_mode_apply_writes_then_removes_entries() {
        let dir = tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1\tlocalhost\n").unwrap();

        // Apply with two entries -> both land in the managed block.
        let m = HostsManager::new(sample_entries(), dir.path().join("backup"));
        let out = m
            .run_mode(HostsFileMode::Apply, Some(&hosts), false)
            .unwrap();
        assert_eq!(out.mode, HostsFileMode::Apply);
        assert!(out.report.as_ref().unwrap().changed);
        assert!(!out.restored);
        let after = std::fs::read_to_string(&hosts).unwrap();
        assert!(after.contains("mail.tunnel.local"));
        assert!(after.contains("v6.tunnel.local"));

        // Re-apply with a smaller set -> the dropped entry is removed from the
        // managed block while user lines are preserved.
        let m2 = HostsManager::new(
            vec![HostsEntry {
                address: "10.0.0.1".into(),
                names: vec!["mail.tunnel.local".into()],
            }],
            dir.path().join("backup"),
        );
        let out2 = m2
            .run_mode(HostsFileMode::Apply, Some(&hosts), false)
            .unwrap();
        assert!(out2.report.unwrap().changed);
        let after2 = std::fs::read_to_string(&hosts).unwrap();
        assert!(after2.contains("mail.tunnel.local"));
        assert!(
            !after2.contains("v6.tunnel.local"),
            "removed entry must be gone from the managed block"
        );
        assert!(
            after2.contains("127.0.0.1\tlocalhost"),
            "user lines outside the block must be preserved"
        );
    }

    #[test]
    fn hosts_file_mode_render_only_does_not_write() {
        let dir = tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1\tlocalhost\n").unwrap();
        let before = std::fs::read_to_string(&hosts).unwrap();

        let m = HostsManager::new(sample_entries(), dir.path().join("backup"));
        let out = m
            .run_mode(HostsFileMode::RenderOnly, Some(&hosts), false)
            .unwrap();
        assert_eq!(out.mode, HostsFileMode::RenderOnly);
        // The diff is computed (changed=true) but nothing is written.
        assert!(out.report.as_ref().unwrap().changed);
        assert_eq!(
            before,
            std::fs::read_to_string(&hosts).unwrap(),
            "render_only must not modify the hosts file"
        );
    }

    #[test]
    fn apply_logs_info_on_mutation_but_not_on_dry_run() {
        let dir = tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1\tlocalhost\n").unwrap();
        let m = HostsManager::new(sample_entries(), dir.path().join("backup"));

        // A real mutation must log at INFO with the hosts-file marker.
        let (_r, events) =
            crate::test_log_capture::capture(|| m.apply(Some(&hosts), false).unwrap());
        assert!(
            events
                .iter()
                .any(|e| e.level == tracing::Level::INFO && e.fields.contains("hosts-file")),
            "expected INFO hosts-file mutation log, got {events:?}"
        );

        // A dry-run (no write) must NOT log a mutation.
        let (_r2, events2) =
            crate::test_log_capture::capture(|| m.apply(Some(&hosts), true).unwrap());
        assert!(
            !events2
                .iter()
                .any(|e| e.fields.contains("hosts-file managed block updated")),
            "dry-run must not emit a mutation log, got {events2:?}"
        );
    }
}
