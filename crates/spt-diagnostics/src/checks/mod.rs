//! Concrete `Diagnostic` implementations.
//!
//! Each module here covers one toolset from spec §13.12. The current
//! implementation focuses on environment-only checks that don't depend on
//! deeper crates (we ship the framework + a representative set; remaining
//! toolsets are stubbed as `Skipped` until t1-e18 wires real crate APIs).

pub mod network;
pub mod os;
pub mod permissions;
pub mod ssh2;
pub mod time;
pub mod vault;

pub use network::NetworkDiagnostic;
pub use os::OsDiagnostic;
pub use permissions::PermissionsDiagnostic;
pub use ssh2::Ssh2Diagnostic;
pub use time::TimeDiagnostic;
pub use vault::VaultDiagnostic;
