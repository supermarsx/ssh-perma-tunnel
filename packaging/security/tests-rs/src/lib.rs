//! Smoke tests for spt packaging-security artifacts (AppArmor, SELinux, seccomp).
//!
//! See `tests/smoke.rs`. This lib target exists only so cargo accepts the
//! crate; the real assertions live in the integration tests.

#![forbid(unsafe_code)]
