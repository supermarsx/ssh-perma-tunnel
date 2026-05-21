//! Passive-only FTP→SFTP translator (`spt-ftp-translator`).
//!
//! Implements a hand-rolled RFC 959 / RFC 3659 control channel that
//! translates supported verbs into [`spt_sftp::SftpClient`] calls. By design:
//!
//! * Active mode (PORT / EPRT) is **refused** with `502 active mode disabled
//!   by security policy` — see [`verbs`] for the dispatch table and
//!   `docs/ftp-translator.md` for the security rationale.
//! * Anonymous login is disabled by default. Operators opt in by setting
//!   [`AuthPolicy::Anonymous`] explicitly.
//! * AUTH TLS is opt-in via [`TlsConfig`]; the control channel is upgraded
//!   in-place once the client issues `AUTH TLS` followed by `PBSZ 0` /
//!   `PROT P`. Data channels honour `PROT P` once the control channel is
//!   encrypted.
//!
//! The translator never opens active data connections — every transfer
//! uses a passive listener bound from [`TranslatorConfig::passive_port_range`].
//! IPv6 clients are served via EPSV; IPv4 clients via PASV.

#![deny(unsafe_op_in_unsafe_fn)]
// The verb dispatcher legitimately uses long match arms and repeats the
// `Reply` ctor a lot — relax the pedantic lint set here so the crate clears
// `-D warnings` under the workspace lints table.
#![allow(clippy::match_same_arms)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_test_module)]
#![allow(clippy::map_unwrap_or)]

pub mod config;
pub mod data;
pub mod error;
pub mod factory;
pub mod reply;
pub mod server;
pub mod state;
pub mod tls;
pub mod verbs;

#[cfg(any(test, feature = "testing"))]
pub mod mock;

pub use config::{AuthPolicy, TlsConfig, TranslatorConfig};
pub use error::TranslatorError;
pub use factory::{ProfileResolver, SftpFactory, Ssh2SftpFactory, Ssh2UserBinding};
pub use reply::Reply;
pub use server::{serve, Server, ServerHandle};
pub use state::{ControlState, LoginPhase, SessionState, TransferMode, TransferType};
pub use verbs::{parse_command, Verb};
