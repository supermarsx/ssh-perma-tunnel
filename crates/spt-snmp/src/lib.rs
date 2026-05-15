//! # `spt-snmp`
//!
//! A standalone, dependency-light SNMPv3 USM agent and trap sender written
//! from scratch against the relevant RFCs:
//!
//! - **RFC 3411** — SNMP architecture
//! - **RFC 3412** — Message processing and dispatching (the SNMPv3 envelope)
//! - **RFC 3414** — User-based Security Model (USM)
//! - **RFC 3416** — Protocol Operations (PDU semantics)
//! - **RFC 3826** — AES-128-CFB privacy
//! - **RFC 7860** — HMAC-SHA-2 authentication for USM
//! - **RFC 2578** — SMIv2 application types
//!
//! The crate has no `unsafe`, no panics outside tests, and no `spt-*`
//! dependencies — it is intended to be publishable on its own.
//!
//! ## Example: build a minimal `authPriv` agent
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use spt_snmp::{
//!     AgentBuilder, AuthProtocol, ObjectIdentifier, PrivProtocol,
//!     SecretBytes, UsmUser, Value,
//! };
//!
//! # async fn run() -> spt_snmp::Result<()> {
//! let user = UsmUser::auth_priv(
//!     "monitor",
//!     AuthProtocol::HmacSha256,
//!     SecretBytes::from("auth-pass-very-long"),
//!     PrivProtocol::Aes128,
//!     SecretBytes::from("priv-pass-very-long"),
//! );
//!
//! let agent = AgentBuilder::new()
//!     .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
//!     .enterprise_pen(12345) // Use your registered IANA PEN.
//!     .add_user(user)
//!     .add_scalar(
//!         ObjectIdentifier::new([1u32, 3, 6, 1, 4, 1, 12_345, 1, 1, 0]),
//!         spt_snmp::ConstScalar::new(Value::OctetString(b"hello".to_vec())),
//!     )
//!     .run()
//!     .await?;
//! # let _ = agent;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Pedantic lints we deliberately relax for this crate. Each is justified:
// - `doc_markdown`: SNMP terminology (GetRequest, ScopedPDU, msgFlags...) is
//   from RFCs and reads more naturally without backticks in prose.
// - `trivially_copy_pass_by_ref`: `&PrivSalt` (8 bytes) reads more naturally
//   than passing by value next to other `&[u8]` arguments.
// - `manual_debug_impl_not_all_fields`: agent/handle Debug intentionally
//   redacts the socket and the Tokio JoinHandle.
// - `struct_field_names`/`enum_variant_names`: SNMP types (`msg_*`,
//   `*Priv`) match the RFC field names; renaming would harm clarity.
// - `needless_pass_by_value`/`unused_async`/`unnecessary_wraps` /
//   `match_same_arms`/`manual_let_else`: occasional patterns where the
//   pedantic suggestion would fight the protocol shape.
#![allow(
    clippy::doc_markdown,
    clippy::trivially_copy_pass_by_ref,
    clippy::missing_fields_in_debug,
    clippy::struct_field_names,
    clippy::enum_variant_names,
    clippy::needless_pass_by_value,
    clippy::unused_async,
    clippy::unnecessary_wraps,
    clippy::match_same_arms,
    clippy::manual_let_else
)]

pub mod agent;
pub mod ber;

pub mod engine;
pub mod error;
pub mod message;
pub mod mib;
pub mod oid;
pub mod pdu;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod trap;
pub mod usm;
pub mod value;

pub use agent::{Agent, AgentBuilder, AgentHandle, DOCUMENTATION_ENTERPRISE_PEN};
pub use engine::{generate_engine_id, EngineClock, EngineId};
pub use error::{Error, Result, UsmError};
pub use mib::{ConstScalar, Handler, MibRegistry, TableHandler};
pub use oid::{
    documentation_enterprise_oid, enterprise_oid, ObjectIdentifier, DOCUMENTATION_ENTERPRISE_OID,
};
pub use pdu::{ErrorStatus, Pdu, PduKind};
pub use trap::TrapSender;
pub use usm::{AuthProtocol, PrivProtocol, SecretBytes, SecurityLevel, UsmCounters, UsmUser};
pub use value::{Value, VarBind};
