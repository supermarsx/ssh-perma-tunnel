//! SSH2 backend for spt built on the pure-Rust [`russh`] crate.
//!
//! Implements [`spt_protocol::TunnelProtocol`] and [`spt_protocol::TunnelSession`]
//! for the SSH2 transport mandated by spec §17.4. The legacy libssh2 path
//! was removed in t7-Phase0; russh is the only backend.
//!
//! Highlights:
//! * Public-key, agent, password, keyboard-interactive, OpenSSH-certificate,
//!   GSSAPI/SSPI auth tried in `AuthConfig.methods` order.
//! * Host-key verification via `spt-trust`'s [`spt_trust::KnownHosts`] and/or
//!   [`spt_trust::Sha256HostPin`].
//! * Local TCP forwards (`direct-tcpip`), remote TCP forwards
//!   (`tcpip-forward` + `forwarded-tcpip`), dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP
//!   CONNECT proxy listeners, and multi-hop chains via per-hop `direct-tcpip`
//!   channels promoted to the next russh session's transport (no socketpair).
//! * UDS forwarding (`direct-streamlocal@openssh.com` + `streamlocal-forward`).
//! * Crypto policy enforcement via [`russh::Preferred`] (kex / cipher / mac
//!   / hostkey / compression allow-lists) with warning logs on deprecated
//!   algorithms.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod agent;
pub mod connect;
pub mod crypto;
pub(crate) mod dynamic;
pub mod errors;
pub mod hostkey;
pub mod multi_hop;
pub mod protocol;
pub mod proxy_jump;
pub(crate) mod russh_backend;
pub(crate) mod secret;
pub mod session;
pub mod sftp;
pub mod udp_tcp_framed;
pub mod udp_uds_mode;
pub mod uds_forward;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use agent::Agent;
pub use crypto::CryptoPolicy;
pub use protocol::{Ssh2BackendKind, Ssh2Protocol, Ssh2ProtocolBuilder, TrustPolicy};
// conn-wire: re-export so `spt-bin`'s profile_factory can build the
// `[profiles.connection]` socket/channel tuning policy and pass it to
// `Ssh2ProtocolBuilder::connection`.
pub use russh_backend::ConnectionPolicy;
pub use session::Ssh2Session;
pub use sftp::{SftpClient, SftpDirEntry, SftpMetadata};

// t6-e13: re-export the obfuscation surface so callers can build connect
// streams without depending on `spt-obfs` directly.
pub use connect::{connect_to_endpoint, ConnectStream};
pub use spt_obfs::{AuditHook, NoopAuditHook, ObfsConfig, ObfsTransport};
