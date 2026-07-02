//! Linux cgroup memory-pressure reader (pure `procfs`/`cgroupfs` reads).
//!
//! This module gives the [`crate::monitor::MemoryMonitor`] tick a genuine
//! *pre-OOM* signal that the RSS-slope heuristic cannot provide: how close the
//! process's cgroup is to its memory limit, and whether the kernel OOM-killer
//! has already fired inside the cgroup.
//!
//! * **cgroup v2** — reads `memory.current` vs `memory.max` (a literal `max`
//!   string means "unlimited"), the `oom_kill` counter from `memory.events`,
//!   and optionally the `some avg10` field from the per-cgroup `memory.pressure`
//!   PSI file.
//! * **cgroup v1** — falls back to `memory/memory.usage_in_bytes` vs
//!   `memory/memory.limit_in_bytes` (a page-aligned sentinel near `u64::MAX`
//!   means "unlimited"), and the `oom_kill` field of `memory/memory.oom_control`
//!   where the kernel exposes it.
//!
//! Every read is best-effort: a missing or unparsable file yields `None` for
//! that field rather than an error, so a partially-populated `cgroupfs`
//! (containers, restricted mounts) degrades gracefully. The parsing helpers are
//! pure and compiled on every platform so they can be unit-tested anywhere; only
//! [`CgroupReader::detect`] (which hard-codes `/sys/fs/cgroup`) is Linux-only.

use std::path::{Path, PathBuf};

/// cgroup v1 reports a page-aligned sentinel close to `u64::MAX` in
/// `limit_in_bytes` when no limit is set. Treat any value at or above this as
/// "unlimited" so we never compute a bogus ~0% usage against it.
const V1_UNLIMITED_MIN: u64 = 0x7000_0000_0000_0000;

/// Which cgroup hierarchy the reader is bound to.
///
/// The variants are only *constructed* by [`CgroupReader::detect_at`], which is
/// exercised in production solely via the Linux-only [`CgroupReader::detect`]
/// (and by the cross-platform unit tests). Off Linux, outside of tests, the
/// constructor is dead — hence the conditional `allow`.
#[cfg_attr(all(not(target_os = "linux"), not(test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CgroupVersion {
    /// Unified hierarchy (`memory.current` / `memory.max`).
    V2,
    /// Legacy hierarchy (`memory/memory.usage_in_bytes` / `limit_in_bytes`).
    V1,
}

/// Parse a cgroup v2 `memory.max` value. Returns `None` for the literal `max`
/// (unlimited) or any unparsable content; `Some(bytes)` for a numeric limit.
pub(crate) fn parse_mem_max(s: &str) -> Option<u64> {
    let t = s.trim();
    if t == "max" {
        return None;
    }
    t.parse::<u64>().ok()
}

/// Parse a cgroup `memory.current` / `usage_in_bytes` byte count.
pub(crate) fn parse_mem_current(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

/// Parse a cgroup v1 `limit_in_bytes`. The unlimited sentinel maps to `None`.
pub(crate) fn parse_v1_limit(s: &str) -> Option<u64> {
    let v = s.trim().parse::<u64>().ok()?;
    if v >= V1_UNLIMITED_MIN {
        None
    } else {
        Some(v)
    }
}

/// Extract the `oom_kill` counter from a `memory.events` (v2) or
/// `memory.oom_control` (v1) blob. Both expose a whitespace-separated
/// `oom_kill <N>` line. The distinct `oom_kill_disable` key is *not* matched
/// (exact first-token comparison).
pub(crate) fn parse_oom_kill(blob: &str) -> Option<u64> {
    for line in blob.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("oom_kill") {
            return it.next().and_then(|v| v.parse::<u64>().ok());
        }
    }
    None
}

/// Extract the `some avg10` value from a PSI `memory.pressure` /
/// `/proc/pressure/memory` blob (an early memory-stall indicator).
pub(crate) fn parse_psi_some_avg10(blob: &str) -> Option<f64> {
    for line in blob.lines() {
        if let Some(rest) = line.strip_prefix("some ") {
            for tok in rest.split_whitespace() {
                if let Some(v) = tok.strip_prefix("avg10=") {
                    return v.parse::<f64>().ok();
                }
            }
        }
    }
    None
}

/// A single point-in-time reading of the cgroup's memory accounting. Every
/// field is optional so a restricted `cgroupfs` degrades to "unknown" rather
/// than a hard error.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CgroupSnapshot {
    /// Current memory charge, in bytes.
    pub(crate) current: Option<u64>,
    /// Hard memory limit, in bytes. `None` means unlimited (`max`) or unknown.
    pub(crate) limit: Option<u64>,
    /// Cumulative cgroup OOM-kill count.
    pub(crate) oom_kill: Option<u64>,
    /// PSI `some avg10` memory-stall percentage, when available.
    pub(crate) psi_some_avg10: Option<f64>,
}

impl CgroupSnapshot {
    /// Current usage as a percentage of the limit, or `None` when the limit is
    /// unlimited/unknown or usage is unknown.
    pub(crate) fn usage_pct(&self) -> Option<f64> {
        match (self.current, self.limit) {
            (Some(c), Some(l)) if l > 0 => Some(c as f64 / l as f64 * 100.0),
            _ => None,
        }
    }
}

/// A reader bound to a detected cgroup hierarchy under a fixed root.
#[derive(Debug, Clone)]
pub(crate) struct CgroupReader {
    version: CgroupVersion,
    root: PathBuf,
}

impl CgroupReader {
    /// Detect the memory-controller hierarchy under an arbitrary `root` (used by
    /// tests with a temp dir). Returns `None` when neither v2 nor v1 memory
    /// accounting files are present.
    ///
    /// Reachable in production only through the Linux-only [`Self::detect`];
    /// off Linux (outside tests) it is dead, hence the conditional `allow`.
    #[cfg_attr(all(not(target_os = "linux"), not(test)), allow(dead_code))]
    pub(crate) fn detect_at(root: &Path) -> Option<Self> {
        if root.join("memory.current").is_file() {
            Some(Self {
                version: CgroupVersion::V2,
                root: root.to_path_buf(),
            })
        } else if root.join("memory").join("memory.usage_in_bytes").is_file() {
            Some(Self {
                version: CgroupVersion::V1,
                root: root.to_path_buf(),
            })
        } else {
            None
        }
    }

    /// Detect the memory-controller hierarchy at the canonical mount point.
    #[cfg(target_os = "linux")]
    pub(crate) fn detect() -> Option<Self> {
        Self::detect_at(Path::new("/sys/fs/cgroup"))
    }

    /// Take a best-effort snapshot of the current usage/limit/OOM counters.
    pub(crate) fn snapshot(&self) -> CgroupSnapshot {
        match self.version {
            CgroupVersion::V2 => CgroupSnapshot {
                current: read_opt(&self.root.join("memory.current"))
                    .and_then(|s| parse_mem_current(&s)),
                limit: read_opt(&self.root.join("memory.max")).and_then(|s| parse_mem_max(&s)),
                oom_kill: read_opt(&self.root.join("memory.events"))
                    .and_then(|s| parse_oom_kill(&s)),
                psi_some_avg10: read_opt(&self.root.join("memory.pressure"))
                    .and_then(|s| parse_psi_some_avg10(&s)),
            },
            CgroupVersion::V1 => {
                let base = self.root.join("memory");
                CgroupSnapshot {
                    current: read_opt(&base.join("memory.usage_in_bytes"))
                        .and_then(|s| parse_mem_current(&s)),
                    limit: read_opt(&base.join("memory.limit_in_bytes"))
                        .and_then(|s| parse_v1_limit(&s)),
                    oom_kill: read_opt(&base.join("memory.oom_control"))
                        .and_then(|s| parse_oom_kill(&s)),
                    // cgroup v1 has no per-cgroup PSI file.
                    psi_some_avg10: None,
                }
            }
        }
    }
}

/// Read a whole file to a `String`, mapping any I/O error to `None`.
fn read_opt(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // --- pure parser coverage ------------------------------------------------

    #[test]
    fn parse_mem_max_handles_numeric_and_unlimited() {
        assert_eq!(parse_mem_max("1048576\n"), Some(1_048_576));
        assert_eq!(parse_mem_max("  2048  "), Some(2048));
        assert_eq!(parse_mem_max("max\n"), None);
        assert_eq!(parse_mem_max("max"), None);
        assert_eq!(parse_mem_max("not-a-number"), None);
        assert_eq!(parse_mem_max(""), None);
    }

    #[test]
    fn parse_mem_current_trims() {
        assert_eq!(parse_mem_current("12345\n"), Some(12_345));
        assert_eq!(parse_mem_current("garbage"), None);
    }

    #[test]
    fn parse_v1_limit_treats_sentinel_as_unlimited() {
        assert_eq!(parse_v1_limit("104857600\n"), Some(104_857_600));
        // The classic v1 "unlimited" value on 64-bit kernels.
        assert_eq!(parse_v1_limit("9223372036854771712"), None);
        assert_eq!(parse_v1_limit(&u64::MAX.to_string()), None);
        assert_eq!(parse_v1_limit("nope"), None);
    }

    #[test]
    fn parse_oom_kill_finds_counter_not_disable_key() {
        let events = "low 0\nhigh 3\nmax 0\noom 1\noom_kill 7\n";
        assert_eq!(parse_oom_kill(events), Some(7));
        // v1 oom_control: `oom_kill_disable` must NOT be matched.
        let ctrl = "oom_kill_disable 0\nunder_oom 0\noom_kill 4\n";
        assert_eq!(parse_oom_kill(ctrl), Some(4));
        // Missing counter.
        assert_eq!(parse_oom_kill("low 0\nhigh 0\n"), None);
        // Present key but non-numeric value.
        assert_eq!(parse_oom_kill("oom_kill x\n"), None);
    }

    #[test]
    fn parse_psi_some_avg10_extracts_field() {
        let psi = "some avg10=1.23 avg60=0.50 avg300=0.10 total=999\n\
                   full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert_eq!(parse_psi_some_avg10(psi), Some(1.23));
        assert_eq!(parse_psi_some_avg10("full avg10=5.00 total=1"), None);
        assert_eq!(parse_psi_some_avg10(""), None);
    }

    #[test]
    fn usage_pct_guards_zero_and_unknown() {
        let s = CgroupSnapshot {
            current: Some(90),
            limit: Some(100),
            oom_kill: None,
            psi_some_avg10: None,
        };
        assert_eq!(s.usage_pct(), Some(90.0));
        let unlimited = CgroupSnapshot {
            current: Some(90),
            limit: None,
            oom_kill: None,
            psi_some_avg10: None,
        };
        assert_eq!(unlimited.usage_pct(), None);
        let zero = CgroupSnapshot {
            current: Some(1),
            limit: Some(0),
            oom_kill: None,
            psi_some_avg10: None,
        };
        assert_eq!(zero.usage_pct(), None);
    }

    // --- temp-dir reader coverage (runs on every platform) -------------------

    /// A self-cleaning unique temp dir built with std only (no `tempfile` dep).
    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn new() -> Self {
            static CTR: AtomicU64 = AtomicU64::new(0);
            let n = CTR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "spt-cgroup-test-{}-{}-{}",
                std::process::id(),
                n,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
        fn write(&self, rel: &str, contents: &str) {
            let p = self.path.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).expect("create parent");
            }
            std::fs::write(p, contents).expect("write file");
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn detect_none_when_no_memory_files() {
        let td = TempDir::new();
        assert!(CgroupReader::detect_at(&td.path).is_none());
    }

    #[test]
    fn v2_reader_snapshot_parses_all_fields() {
        let td = TempDir::new();
        td.write("memory.current", "838860800\n"); // 800 MiB
        td.write("memory.max", "1073741824\n"); // 1 GiB
        td.write("memory.events", "low 0\nhigh 2\nmax 0\noom 0\noom_kill 3\n");
        td.write(
            "memory.pressure",
            "some avg10=4.20 avg60=1.0 avg300=0.2 total=5\nfull avg10=0.0 total=0\n",
        );

        let reader = CgroupReader::detect_at(&td.path).expect("v2 detect");
        let snap = reader.snapshot();
        assert_eq!(snap.current, Some(838_860_800));
        assert_eq!(snap.limit, Some(1_073_741_824));
        assert_eq!(snap.oom_kill, Some(3));
        assert_eq!(snap.psi_some_avg10, Some(4.20));
        // 800/1024 MiB ~= 78.125%
        let pct = snap.usage_pct().expect("pct");
        assert!((pct - 78.125).abs() < 0.001, "pct was {pct}");
    }

    #[test]
    fn v2_reader_handles_unlimited_and_missing() {
        let td = TempDir::new();
        td.write("memory.current", "500\n");
        td.write("memory.max", "max\n");
        // No memory.events / memory.pressure files at all.
        let reader = CgroupReader::detect_at(&td.path).expect("v2 detect");
        let snap = reader.snapshot();
        assert_eq!(snap.current, Some(500));
        assert_eq!(snap.limit, None);
        assert_eq!(snap.oom_kill, None);
        assert_eq!(snap.psi_some_avg10, None);
        assert_eq!(snap.usage_pct(), None);
    }

    #[test]
    fn v1_reader_snapshot_parses_all_fields() {
        let td = TempDir::new();
        td.write("memory/memory.usage_in_bytes", "950000000\n");
        td.write("memory/memory.limit_in_bytes", "1000000000\n");
        td.write(
            "memory/memory.oom_control",
            "oom_kill_disable 0\nunder_oom 0\noom_kill 9\n",
        );

        let reader = CgroupReader::detect_at(&td.path).expect("v1 detect");
        let snap = reader.snapshot();
        assert_eq!(snap.current, Some(950_000_000));
        assert_eq!(snap.limit, Some(1_000_000_000));
        assert_eq!(snap.oom_kill, Some(9));
        assert_eq!(snap.psi_some_avg10, None);
        assert_eq!(snap.usage_pct(), Some(95.0));
    }

    #[test]
    fn v1_reader_unlimited_sentinel() {
        let td = TempDir::new();
        td.write("memory/memory.usage_in_bytes", "500\n");
        td.write("memory/memory.limit_in_bytes", "9223372036854771712\n");
        let reader = CgroupReader::detect_at(&td.path).expect("v1 detect");
        let snap = reader.snapshot();
        assert_eq!(snap.limit, None);
        assert_eq!(snap.usage_pct(), None);
    }
}
