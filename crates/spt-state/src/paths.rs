//! Pure-string helpers for paths inside the state directory.
//!
//! All other modules in this crate go through these helpers so there is a
//! single source of truth for the on-disk layout described in plan §3.

use std::path::{Path, PathBuf};

/// `<dir>/spt.lock` — exclusive process lock file.
#[must_use]
pub fn lock_path(dir: &Path) -> PathBuf {
    dir.join("spt.lock")
}

/// `<dir>/spt.pid` — current process PID, written after lock acquisition.
#[must_use]
pub fn pid_path(dir: &Path) -> PathBuf {
    dir.join("spt.pid")
}

/// `<dir>/status.json` — current status snapshot (atomically replaced).
#[must_use]
pub fn status_path(dir: &Path) -> PathBuf {
    dir.join("status.json")
}

/// `<dir>/status.<ts>.json` — ringed historical snapshot.
#[must_use]
pub fn status_ring_path(dir: &Path, ts: &str) -> PathBuf {
    dir.join(format!("status.{ts}.json"))
}

/// `<dir>/metrics.prom` — Prometheus text exposition file.
#[must_use]
pub fn metrics_path(dir: &Path) -> PathBuf {
    dir.join("metrics.prom")
}

/// `<dir>/events/` — JSONL event log directory.
#[must_use]
pub fn events_dir(dir: &Path) -> PathBuf {
    dir.join("events")
}

/// `<dir>/events/<YYYY-MM-DD>.jsonl` — daily rotated event log file.
#[must_use]
pub fn events_file(dir: &Path, date_yyyy_mm_dd: &str) -> PathBuf {
    events_dir(dir).join(format!("{date_yyyy_mm_dd}.jsonl"))
}

/// `<dir>/sessions/<id>.json` — per-session detail snapshot.
#[must_use]
pub fn session_path(dir: &Path, id: &str) -> PathBuf {
    dir.join("sessions").join(format!("{id}.json"))
}

/// `<dir>/remote-config-cache.toml`.
#[must_use]
pub fn remote_config_cache_path(dir: &Path) -> PathBuf {
    dir.join("remote-config-cache.toml")
}

/// `<dir>/remote-config-cache.toml.sha256`.
#[must_use]
pub fn remote_config_cache_sha_path(dir: &Path) -> PathBuf {
    dir.join("remote-config-cache.toml.sha256")
}

/// `<dir>/vault.spt`.
#[must_use]
pub fn vault_path(dir: &Path) -> PathBuf {
    dir.join("vault.spt")
}

/// `<dir>/vault.spt.meta`.
#[must_use]
pub fn vault_meta_path(dir: &Path) -> PathBuf {
    dir.join("vault.spt.meta")
}

/// `<dir>/dns/zone.snapshot.json`.
#[must_use]
pub fn dns_snapshot_path(dir: &Path) -> PathBuf {
    dir.join("dns").join("zone.snapshot.json")
}

/// `<dir>/remote-log-spool/<sink>/`.
#[must_use]
pub fn spool_dir(dir: &Path, sink_name: &str) -> PathBuf {
    dir.join("remote-log-spool").join(sink_name)
}

/// `<dir>/benchmarks/`.
#[must_use]
pub fn benchmarks_dir(dir: &Path) -> PathBuf {
    dir.join("benchmarks")
}

/// `<dir>/diagnostics/`.
#[must_use]
pub fn diagnostics_dir(dir: &Path) -> PathBuf {
    dir.join("diagnostics")
}

/// `<dir>/hosts/` — backup directory for hosts-file managed-block backups.
#[must_use]
pub fn hosts_backup_dir(dir: &Path) -> PathBuf {
    dir.join("hosts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn well_known_paths() {
        let d = Path::new("/var/state");
        assert_eq!(lock_path(d), Path::new("/var/state/spt.lock"));
        assert_eq!(pid_path(d), Path::new("/var/state/spt.pid"));
        assert_eq!(status_path(d), Path::new("/var/state/status.json"));
        assert_eq!(
            status_ring_path(d, "20260101T000000Z"),
            Path::new("/var/state/status.20260101T000000Z.json")
        );
        assert_eq!(metrics_path(d), Path::new("/var/state/metrics.prom"));
        assert_eq!(events_dir(d), Path::new("/var/state/events"));
        assert_eq!(
            events_file(d, "2026-05-05"),
            Path::new("/var/state/events/2026-05-05.jsonl")
        );
        assert_eq!(
            session_path(d, "abc"),
            Path::new("/var/state/sessions/abc.json")
        );
        assert_eq!(vault_path(d), Path::new("/var/state/vault.spt"));
        assert_eq!(vault_meta_path(d), Path::new("/var/state/vault.spt.meta"));
        assert_eq!(
            dns_snapshot_path(d),
            Path::new("/var/state/dns/zone.snapshot.json")
        );
        assert_eq!(
            spool_dir(d, "https"),
            Path::new("/var/state/remote-log-spool/https")
        );
    }

    #[test]
    fn rooted_relative_paths() {
        let d = Path::new("relative");
        assert_eq!(lock_path(d), Path::new("relative/spt.lock"));
        assert_eq!(pid_path(d), Path::new("relative/spt.pid"));
        assert_eq!(status_path(d), Path::new("relative/status.json"));
    }

    #[test]
    fn remote_config_cache_paths() {
        let d = Path::new("/x");
        assert_eq!(
            remote_config_cache_path(d),
            Path::new("/x/remote-config-cache.toml")
        );
        assert_eq!(
            remote_config_cache_sha_path(d),
            Path::new("/x/remote-config-cache.toml.sha256")
        );
    }

    #[test]
    fn aux_dir_paths() {
        let d = Path::new("/v");
        assert_eq!(benchmarks_dir(d), Path::new("/v/benchmarks"));
        assert_eq!(diagnostics_dir(d), Path::new("/v/diagnostics"));
        assert_eq!(hosts_backup_dir(d), Path::new("/v/hosts"));
    }

    #[test]
    fn spool_dir_handles_special_sink_names() {
        let d = Path::new("/var");
        assert_eq!(
            spool_dir(d, "syslog-tls"),
            Path::new("/var/remote-log-spool/syslog-tls")
        );
    }

    #[test]
    fn status_ring_path_distinct_per_timestamp() {
        let d = Path::new("/v");
        let a = status_ring_path(d, "20260101T000000Z");
        let b = status_ring_path(d, "20260101T000001Z");
        assert_ne!(a, b);
        assert_ne!(a, status_path(d));
    }

    #[test]
    fn events_paths_compose_correctly() {
        let d = Path::new("/srv/spt");
        let dir = events_dir(d);
        let file = events_file(d, "2099-12-31");
        assert!(file.starts_with(&dir));
        assert_eq!(file.file_name().unwrap(), "2099-12-31.jsonl");
    }

    #[test]
    fn session_path_in_sessions_subdir() {
        let d = Path::new("/srv");
        let p = session_path(d, "abc-123");
        assert!(p.starts_with(d.join("sessions")));
        assert_eq!(p.file_name().unwrap(), "abc-123.json");
    }
}
