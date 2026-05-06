//! Atomic file replacement helpers.
//!
//! Wraps [`atomicwrites::AtomicFile`] with `AllowOverwrite` semantics. The
//! file at the target path is either fully present (with the new contents)
//! or completely unmodified — readers never observe a partial write.

use std::io::Write;
use std::path::{Path, PathBuf};

use atomicwrites::{AllowOverwrite, AtomicFile};
use spt_core::{Error, Result};

pub use atomicwrites::AtomicFile as AtomicFileHandle;

/// Atomically write `bytes` to `path`, replacing any existing file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let af = AtomicFile::new(path, AllowOverwrite);
    af.write(|f| f.write_all(bytes))
        .map_err(|e| map_err(path, &e))
}

/// Atomically write `s` to `path`, replacing any existing file.
pub fn write_atomic_string(path: &Path, s: &str) -> Result<()> {
    write_atomic(path, s.as_bytes())
}

fn map_err(path: &Path, e: &atomicwrites::Error<std::io::Error>) -> Error {
    Error::StateLockFailed {
        path: PathBuf::from(path),
        reason: format!("atomic write failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_and_replace_is_atomic_visible() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("f.json");
        write_atomic_string(&p, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "first");

        write_atomic_string(&p, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "second");

        // Bytes API
        write_atomic(&p, b"third").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"third");
    }

    #[test]
    fn many_overwrites_succeed() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("hot.json");
        for i in 0..50_u32 {
            write_atomic_string(&p, &i.to_string()).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "49");
    }
}
