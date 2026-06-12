//! Bounded on-disk spool for sinks (remote logs, event sinks).
//!
//! Layout: a single directory holds files named `00000000000000000001.bin`,
//! `…2.bin`, etc. — fixed-width 20-digit zero-padded sequence numbers so that
//! lexicographic order = insertion order.
//!
//! ## Atomicity
//!
//! `push` writes `<n>.bin.tmp` then renames to `<n>.bin`. Readers never see a
//! half-written file.
//!
//! ## Eviction
//!
//! When `push` would push the spool past `max_bytes` or `max_files`, the
//! oldest entries are deleted FIFO until both limits are satisfied.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use spt_core::{Error, Result};

/// Configuration for a [`DiskSpool`].
#[derive(Debug, Clone)]
pub struct SpoolConfig {
    /// Maximum total on-disk size in bytes. 0 = unlimited.
    pub max_bytes: u64,
    /// Maximum number of entries. 0 = unlimited.
    pub max_files: usize,
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_files: 10_000,
        }
    }
}

/// One spool entry returned by [`DiskSpool::pop`].
#[derive(Debug)]
pub struct SpoolEntry {
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Sequence number / filename stem.
    pub seq: u64,
    /// On-disk path (caller may delete; `pop` already removes it).
    pub path: PathBuf,
}

/// Bounded on-disk FIFO spool.
#[derive(Debug)]
pub struct DiskSpool {
    dir: PathBuf,
    cfg: SpoolConfig,
    /// Sequence numbers in FIFO order, parsed from existing filenames on open.
    queue: VecDeque<u64>,
    /// Cumulative size of files in the queue.
    total_bytes: u64,
    /// Next sequence number to assign.
    next_seq: u64,
}

const SEQ_WIDTH: usize = 20;
const SUFFIX: &str = ".bin";
const TMP_SUFFIX: &str = ".bin.tmp";

impl DiskSpool {
    /// Open or create a spool at `dir`. Pre-existing files are restored to the
    /// queue in seq order so the spool survives a process restart.
    pub fn open(dir: PathBuf, cfg: SpoolConfig) -> Result<Self> {
        std::fs::create_dir_all(&dir).map_err(|e| Error::StateLockFailed {
            path: dir.clone(),
            reason: format!("create spool dir: {e}"),
        })?;

        // Clean up any leftover .bin.tmp from a prior crash.
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.filter_map(std::result::Result::ok) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(TMP_SUFFIX) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }

        let mut entries: Vec<(u64, u64)> = Vec::new(); // (seq, size)
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.filter_map(std::result::Result::ok) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(stem) = name.strip_suffix(SUFFIX) {
                    if stem.len() == SEQ_WIDTH {
                        if let Ok(n) = stem.parse::<u64>() {
                            let size = entry.metadata().map(|m| m.len()).unwrap_or_default();
                            entries.push((n, size));
                        }
                    }
                }
            }
        }
        entries.sort_by_key(|(s, _)| *s);
        let total_bytes = entries.iter().map(|(_, s)| *s).sum();
        let next_seq = entries.last().map_or(1, |(s, _)| s + 1);
        let queue = entries.iter().map(|(s, _)| *s).collect();

        Ok(Self {
            dir,
            cfg,
            queue,
            total_bytes,
            next_seq,
        })
    }

    /// Push a payload. Evicts oldest entries to satisfy size/file caps.
    ///
    /// A single payload larger than [`SpoolConfig::max_bytes`] is rejected with
    /// [`Error::RuntimeFailure`] rather than being written: admitting it would
    /// leave `total_bytes > max_bytes` and violate the byte-cap guarantee even
    /// after evicting the entire queue. (`max_bytes == 0` means unlimited, so no
    /// single-payload cap applies.)
    pub fn push(&mut self, payload: &[u8]) -> Result<u64> {
        let size = payload.len() as u64;

        // Reject a single payload that can never fit under the byte cap.
        if self.cfg.max_bytes > 0 && size > self.cfg.max_bytes {
            return Err(Error::RuntimeFailure(format!(
                "spool payload {size} bytes exceeds max_bytes {} cap",
                self.cfg.max_bytes
            )));
        }

        // Evict to fit.
        self.evict_to_fit(size);

        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| Error::RuntimeFailure("spool sequence number overflow".into()))?;

        let final_path = self.path_for(seq);
        let tmp_path = self.tmp_path_for(seq);

        std::fs::write(&tmp_path, payload).map_err(|e| Error::StateLockFailed {
            path: tmp_path.clone(),
            reason: format!("spool write tmp: {e}"),
        })?;
        std::fs::rename(&tmp_path, &final_path).map_err(|e| Error::StateLockFailed {
            path: final_path.clone(),
            reason: format!("spool rename: {e}"),
        })?;

        self.queue.push_back(seq);
        self.total_bytes += size;
        Ok(seq)
    }

    /// Pop the oldest entry, removing it from disk. Returns `Ok(None)` if empty.
    pub fn pop(&mut self) -> Result<Option<SpoolEntry>> {
        let Some(seq) = self.queue.pop_front() else {
            return Ok(None);
        };
        let path = self.path_for(seq);
        let payload = std::fs::read(&path).map_err(|e| Error::StateLockFailed {
            path: path.clone(),
            reason: format!("spool read: {e}"),
        })?;
        self.total_bytes = self.total_bytes.saturating_sub(payload.len() as u64);
        let _ = std::fs::remove_file(&path);
        Ok(Some(SpoolEntry { payload, seq, path }))
    }

    /// Number of pending entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// True if the spool has no pending entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Total bytes currently spooled.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Spool root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, seq: u64) -> PathBuf {
        self.dir.join(format!("{seq:0SEQ_WIDTH$}{SUFFIX}"))
    }

    fn tmp_path_for(&self, seq: u64) -> PathBuf {
        self.dir.join(format!("{seq:0SEQ_WIDTH$}{TMP_SUFFIX}"))
    }

    fn evict_to_fit(&mut self, incoming: u64) {
        // Files cap.
        if self.cfg.max_files > 0 {
            while self.queue.len() >= self.cfg.max_files {
                if self.evict_oldest().is_none() {
                    break;
                }
            }
        }
        // Bytes cap.
        if self.cfg.max_bytes > 0 {
            while self.total_bytes + incoming > self.cfg.max_bytes && !self.queue.is_empty() {
                if self.evict_oldest().is_none() {
                    break;
                }
            }
        }
    }

    fn evict_oldest(&mut self) -> Option<u64> {
        let seq = self.queue.pop_front()?;
        let path = self.path_for(seq);
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let _ = std::fs::remove_file(&path);
        self.total_bytes = self.total_bytes.saturating_sub(size);
        Some(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_push_pop_preserves_fifo() {
        let tmp = tempdir().unwrap();
        let mut s = DiskSpool::open(
            tmp.path().to_path_buf(),
            SpoolConfig {
                max_bytes: 1024,
                max_files: 100,
            },
        )
        .unwrap();
        for i in 0..5_u8 {
            s.push(&[i, i, i]).unwrap();
        }
        assert_eq!(s.len(), 5);

        let mut got: Vec<u8> = Vec::new();
        while let Some(e) = s.pop().unwrap() {
            got.push(e.payload[0]);
        }
        assert_eq!(got, vec![0, 1, 2, 3, 4]);
        assert_eq!(s.len(), 0);
        assert_eq!(s.total_bytes(), 0);
    }

    #[test]
    fn max_files_evicts_oldest() {
        let tmp = tempdir().unwrap();
        let mut s = DiskSpool::open(
            tmp.path().to_path_buf(),
            SpoolConfig {
                max_bytes: 0,
                max_files: 3,
            },
        )
        .unwrap();
        for i in 0..5_u8 {
            s.push(&[i]).unwrap();
        }
        assert_eq!(s.len(), 3, "should be capped at 3");

        let e1 = s.pop().unwrap().unwrap();
        let e2 = s.pop().unwrap().unwrap();
        let e3 = s.pop().unwrap().unwrap();
        assert_eq!(e1.payload, vec![2]);
        assert_eq!(e2.payload, vec![3]);
        assert_eq!(e3.payload, vec![4]);
    }

    #[test]
    fn max_bytes_evicts_oldest() {
        let tmp = tempdir().unwrap();
        let mut s = DiskSpool::open(
            tmp.path().to_path_buf(),
            SpoolConfig {
                max_bytes: 6, // hold ~3 of 2-byte payloads
                max_files: 0,
            },
        )
        .unwrap();
        for _ in 0..10 {
            s.push(b"ab").unwrap();
        }
        assert!(s.total_bytes() <= 6);
        assert!(s.len() <= 3);
    }

    #[test]
    fn oversized_payload_is_rejected_and_cap_preserved() {
        let tmp = tempdir().unwrap();
        let mut s = DiskSpool::open(
            tmp.path().to_path_buf(),
            SpoolConfig {
                max_bytes: 4,
                max_files: 0,
            },
        )
        .unwrap();
        // A fitting payload is admitted.
        s.push(b"abcd").unwrap();
        assert_eq!(s.len(), 1);

        // A single oversized payload is rejected outright; existing entries and
        // the byte cap are left intact (no eviction-then-overflow).
        let err = s.push(b"abcde").unwrap_err();
        assert!(
            matches!(err, Error::RuntimeFailure(ref m) if m.contains("exceeds max_bytes")),
            "unexpected error: {err:?}"
        );
        assert_eq!(s.len(), 1, "rejected push must not evict existing entries");
        assert!(s.total_bytes() <= 4);

        // The surviving entry is still the original, intact payload.
        let e = s.pop().unwrap().unwrap();
        assert_eq!(e.payload, b"abcd");
    }

    #[test]
    fn unlimited_max_bytes_accepts_large_payload() {
        let tmp = tempdir().unwrap();
        let mut s = DiskSpool::open(
            tmp.path().to_path_buf(),
            SpoolConfig {
                max_bytes: 0, // unlimited
                max_files: 0,
            },
        )
        .unwrap();
        s.push(&vec![0u8; 4096]).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.total_bytes(), 4096);
    }

    #[test]
    fn restart_recovers_queue_in_order() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        {
            let mut s = DiskSpool::open(dir.clone(), SpoolConfig::default()).unwrap();
            for i in 0..3_u8 {
                s.push(&[i]).unwrap();
            }
        }

        let mut s = DiskSpool::open(dir, SpoolConfig::default()).unwrap();
        assert_eq!(s.len(), 3);
        let a = s.pop().unwrap().unwrap();
        let b = s.pop().unwrap().unwrap();
        let c = s.pop().unwrap().unwrap();
        assert_eq!(a.payload, vec![0]);
        assert_eq!(b.payload, vec![1]);
        assert_eq!(c.payload, vec![2]);
    }

    #[test]
    fn leftover_tmp_files_cleaned_on_open() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join(format!("{:0w$}{}", 1, TMP_SUFFIX, w = SEQ_WIDTH));
        std::fs::write(&stale, b"corrupt").unwrap();
        assert!(stale.exists());

        let _s = DiskSpool::open(dir, SpoolConfig::default()).unwrap();
        assert!(!stale.exists());
    }
}
