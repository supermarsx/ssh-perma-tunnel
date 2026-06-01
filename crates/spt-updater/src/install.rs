//! Platform-specific atomic-swap of the running spt binary.
//!
//! **This module is a scaffold.** Real swap logic lands in commit 5 of
//! the updater series. Unix: `fs::rename` over the live exe path (POSIX
//! permits this; the running process keeps its open file mapping until
//! it exits). Windows: write to a sibling temp path + `MoveFileEx` with
//! `MOVEFILE_DELAY_UNTIL_REBOOT`, OR spawn a tiny replacement stub.

use std::path::Path;

use crate::error::UpdaterResult;

/// Atomically replace the running binary with `new_binary`. The caller
/// is responsible for verifying `new_binary` before invoking this.
pub async fn install_atomic(_new_binary: &Path) -> UpdaterResult<()> {
    // Implementation lands in commit 5 of the updater series.
    Ok(())
}
