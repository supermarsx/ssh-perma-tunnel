//! Transparent DNS resolver and hosts-file manager for `spt`.
//!
//! This crate implements spec §13.8: a built-in DNS server (disabled by
//! default) with **split-horizon** semantics — managed names from the active
//! `[dns]` zone are answered locally, everything else is forwarded to the
//! configured upstreams. It also owns the hosts-file render/apply/restore
//! lifecycle, with a managed-block marker so it never clobbers user-authored
//! lines outside the markers.
//!
//! Public surface:
//! - [`server::DnsServer`] / [`server::DnsServerBuilder`] — listener + handler.
//! - [`zone::ManagedZone`] / [`zone::Record`] — managed-zone description.
//! - [`split_horizon::SplitHorizonHandler`] — the [`hickory_server::server::RequestHandler`]
//!   implementation, exposed in case callers want to host their own server.
//! - [`health::HealthSource`] — trait wired to `spt-supervisor` at runtime so
//!   `AnswerWhenListening` / `AnswerWhenHealthy` policies can consult live
//!   forward state.
//! - [`hosts::HostsManager`] / [`hosts::HostsApplyReport`] — hosts-file
//!   render/apply/restore.
//!
//! See the module docs for the individual building blocks.

#![warn(missing_docs)]

pub mod error;
pub mod health;
pub mod hosts;
pub mod server;
pub mod split_horizon;
pub mod srv;
pub mod zone;

pub use error::{DnsError, Result};
pub use health::{ForwardHealth, HealthSource, NoHealth};
pub use hosts::{HostsApplyReport, HostsEntry, HostsManager, HOSTS_BEGIN_MARKER, HOSTS_END_MARKER};
pub use server::{DnsHandle, DnsServer, DnsServerBuilder};
pub use split_horizon::SplitHorizonHandler;
pub use zone::{AnswerPolicy, ManagedZone, Record, RecordKind};
