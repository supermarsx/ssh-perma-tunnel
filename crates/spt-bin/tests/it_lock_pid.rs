//! Two acquisitions of the state lock on the same directory must report
//! contention with `ExitCode::StateLockFailed` (16).

use spt_core::ExitCode;
use spt_state::StateLock;
use tempfile::TempDir;

#[test]
fn second_acquire_fails_with_exit_code_16() {
    let dir = TempDir::new().expect("tempdir");
    let _held = StateLock::acquire(dir.path()).expect("first acquire");
    let err = StateLock::acquire(dir.path()).expect_err("second acquire must fail");
    assert_eq!(err.exit_code(), ExitCode::StateLockFailed);
    let exit_value: i32 = err.exit_code().as_i32();
    assert_eq!(exit_value, 16);
}
