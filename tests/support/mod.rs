//! Shared helpers for `spt-e2e-tests`.
//!
//! Currently empty -- the only shipped test (`e2e/reload_diff.rs`) is
//! self-contained. Future expansion: when `RusshTestServer` (in
//! `crates/spt-ssh2/src/testing.rs`) gains `direct-tcpip` /
//! `tcpip-forward` / restart / keepalive-counter support and
//! libssh2-vs-russh interop is verified working at the baseline, this
//! module will host the russh-fixture wrapper and the `TempStateDir +
//! spawn-spt` helpers from the brief.
//!
//! See `.orchestration/state.md` Escalations -> "f-e2e-russh" for context.

#![deny(missing_docs)]
