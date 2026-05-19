//! TOML configuration schema, validation, rendering, diffing, and migration
//! for `spt`.
//!
//! `spt-config` defines every TOML table from the spec (`spec.md` §8 and §9) as
//! `serde` types and exposes the I/O-light operations the rest of the workspace
//! needs:
//!
//! * [`load()`] — parse a config file from disk, collecting unknown-key warnings.
//! * [`validate()`] — semantic validation producing a [`Diagnostics`] bundle with
//!   `miette`-friendly messages.
//! * [`render()`] — render a config back to TOML with optional secret redaction.
//! * [`diff()`] — field-level diff used by the reload reconciler.
//! * [`migrate()`] — version-to-version migration framework.
//! * [`mutate`] — `toml_edit`-based mutators preserving comments/formatting.
//! * [`fingerprint()`] — SHA-256 of the canonical-rendered config for status
//!   snapshots.
//!
//! The crate is "almost pure" — the only filesystem I/O is reading and writing
//! config files via [`std::fs`] (and atomic writes via the `atomicwrites`
//! crate). Network I/O for remote config lives in `spt-remote-config`; only the
//! [`remote::RemoteConfigSpec`] descriptor lives here.

#![forbid(unsafe_code)]

pub mod diagnostic;
pub mod diff;
pub mod fingerprint;
pub mod load;
pub mod migrate;
pub mod mutate;
pub mod policy;
pub mod remote;
pub mod render;
pub mod round_robin;
pub mod schema;
pub mod status_api;
pub mod validate;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use diagnostic::{Diagnostic, Diagnostics as ValidationDiagnostics, Severity};
pub use diff::{diff, Change, ChangeKind};
pub use fingerprint::fingerprint;
pub use load::{load, load_dir, load_str, Warnings};
pub use migrate::migrate;
pub use policy::{
    find_binding, ApplyMode, Binding, BindingKind, OverlayReport, PolicyBundle, PolicyOverlay,
    PolicyValue, BINDINGS,
};
pub use render::render;
pub use round_robin::{RoundRobinConfig, SelectionPolicy};
pub use schema::*;
pub use status_api::{
    default_bind as status_api_default_bind, default_rate_limit as status_api_default_rate_limit,
    StatusApiAuthConfig, StatusApiAuthMode, StatusApiConfig, StatusApiTlsConfig,
};
pub use validate::validate;
