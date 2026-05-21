//! SSH2 backend for spt built on [`russh`] with a legacy libssh2 compatibility path.
//!
//! Implements [`spt_protocol::TunnelProtocol`] and [`spt_protocol::TunnelSession`]
//! for the SSH2 transport mandated by spec §17.4.
//!
//! Highlights:
//! * Pure-Rust `russh` transport for new runtime profiles.
//! * Legacy non-blocking libssh2 wrapped by `async-ssh2-lite`'s Tokio
//!   `AsyncFd` adapter for compatibility while the migration completes.
//! * Public-key (memory + file fallback), agent, password, keyboard-interactive
//!   and OpenSSH-certificate auth, tried in `AuthConfig.methods` order.
//! * Host-key verification via `spt-trust`'s [`spt_trust::KnownHosts`] and/or
//!   [`spt_trust::Sha256HostPin`] (whichever the profile selects, both
//!   supported).
//! * Local TCP forwards (`direct-tcpip`), remote TCP forwards
//!   (`tcpip-forward` + `forwarded-tcpip`), dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT
//!   proxy listeners, and multi-hop chains via per-hop `direct-tcpip`
//!   channels promoted to the next session's transport.
//! * Periodic keepalive driver (`keepalive_send`).
//! * Crypto policy enforcement via libssh2 `method_pref` calls with warning
//!   logs on deprecated algorithms.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod crypto;
pub(crate) mod dynamic;
pub mod errors;
pub mod forward;
pub mod hostkey;
pub mod kbi_bridge;
pub mod multi_hop;
pub mod protocol;
pub mod proxy_jump;
pub(crate) mod russh_backend;
pub mod session;
pub mod sftp;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use crypto::CryptoPolicy;
pub use protocol::{Ssh2BackendKind, Ssh2Protocol, Ssh2ProtocolBuilder, TrustPolicy};
pub use session::Ssh2Session;
pub use sftp::{SftpClient, SftpDirEntry, SftpMetadata};
