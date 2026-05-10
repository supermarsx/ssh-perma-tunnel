//! Windows Group-Policy / registry-overlay surface for the `spt` binary.
//!
//! Two pieces:
//!
//! * [`registry`] — reads policy values from the `HKLM`/`HKCU`
//!   `Software\Policies\spt` tree. Real on Windows; a no-op stub elsewhere.
//! * [`overlay`] — applies the loaded [`spt_config::PolicyBundle`] over a
//!   parsed [`spt_config::Config`] using the binding rules defined in
//!   `spt-config::policy`.
//!
//! `t2-wire` will register `mod policy;` from `main.rs` and call
//! [`overlay::apply`] after `spt_config::load` returns.

pub mod overlay;
pub mod registry;
