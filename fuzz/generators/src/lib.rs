//! Helpers shared by the corpus generators.
//!
//! The generators are small CLIs that emit a deterministic, diverse set of
//! seed inputs into `fuzz/corpus/<target>/`. They do *not* produce random
//! mutations — that's libFuzzer's job. Instead each generator hand-picks
//! representative shapes (valid + boundary) and round-trips the valid ones
//! through the production parser to confirm they actually parse before
//! committing.

use std::fs;
use std::path::{Path, PathBuf};

/// Resolve the output directory from `argv[1]`, creating it if missing.
pub fn out_dir_from_args() -> PathBuf {
    let arg = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: {} <output-dir>", std::env::args().next().unwrap_or_default());
        std::process::exit(2);
    });
    let p = PathBuf::from(arg);
    fs::create_dir_all(&p).expect("create output dir");
    p
}

/// Write `bytes` to `<dir>/<name>` (overwriting), and report.
pub fn write_file(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("  + {} ({} bytes)", name, bytes.len());
}
