//! Concrete `Diagnostic` implementations.
//!
//! Each module here covers one toolset from spec §13.12. Deeper checks
//! (`secrets`, `firewall`, `service`, `mcp`, `runtime`, real `ssh2`) consume
//! injected handles from the [`DiagnosticContext`](crate::DiagnosticContext).
//! When a handle is absent the corresponding check emits `Skipped` so that
//! `DiagnosticContext::default()` continues to be a usable test scaffold.

pub mod firewall;
pub mod mcp;
pub mod network;
pub mod os;
pub mod permissions;
pub mod runtime;
pub mod secrets;
pub mod service;
pub mod ssh2;
pub mod time;

pub use firewall::FirewallDiagnostic;
pub use mcp::McpDiagnostic;
pub use network::NetworkDiagnostic;
pub use os::OsDiagnostic;
pub use permissions::PermissionsDiagnostic;
pub use runtime::RuntimeDiagnostic;
pub use secrets::SecretsDiagnostic;
pub use service::ServiceDiagnostic;
pub use ssh2::Ssh2Diagnostic;
pub use time::TimeDiagnostic;
