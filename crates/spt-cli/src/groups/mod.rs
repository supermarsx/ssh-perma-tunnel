//! One module per top-level command group from spec §7.

pub mod about;
pub mod auth;
pub mod benchmark;
pub mod completion;
pub mod config;
pub mod diagnose;
pub mod dns;
pub mod event;
pub mod firewall;
// t6-e6:start — FTP→SFTP translator group. Bwire wires the matching
// `Command::Ftp` variant into `crate::Command` at registration time.
pub mod ftp;
// t6-e6:end
pub mod forward;
pub mod key;
pub mod kill;
pub mod log;
pub mod mcp;
pub mod observe;
pub mod profile;
pub mod secret;
pub mod service;
pub mod session;
pub mod sftp;
pub mod stats;
pub mod status;
pub mod tunnel;
pub mod update;
