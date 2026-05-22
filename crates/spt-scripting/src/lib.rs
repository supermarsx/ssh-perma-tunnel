//! Scriptable tunnelling hooks for `spt` (t6-e7 + t7-A2).
//!
//! This crate exposes a sandboxed [`ScriptEngine`] driven by `rhai 1.19`+
//! (pure-Rust, MSRV 1.66) which surfaces five hook entry-points wired into
//! [`spt_ssh2::session::Ssh2Session`]:
//!
//! | Hook              | Trigger                                          | Event payload                |
//! |-------------------|--------------------------------------------------|------------------------------|
//! | `pre_connect`     | before the TCP/QUIC connect attempt              | [`event::PreConnect`]        |
//! | `post_connect`    | after successful authentication                  | [`event::PostConnect`]       |
//! | `on_forward_state`| every forward state-machine transition           | [`event::ForwardState`]      |
//! | `on_disconnect`   | after the session terminates                     | [`event::Disconnect`]        |
//! | `on_event`        | generic catch-all for any structured event       | [`event::Generic`]           |
//!
//! # Sandbox
//!
//! The engine runs with a strictly minimal Rhai package set:
//!
//! * Only [`rhai::packages::CorePackage`] is registered. No filesystem, no
//!   network, no `eval`, no `import`, no module loading.
//! * `engine.disable_symbol("eval")` and `engine.disable_symbol("import")`
//!   are applied before the AST is built so a script containing either
//!   token fails at compile time.
//! * Five `engine.set_max_*` bounds are applied from [`ScriptLimits`]
//!   before AST registration: `max_operations`, `max_call_levels`,
//!   `max_string_size`, `max_array_size`, `max_modules` (default `0`
//!   forbids `import`).
//! * Every hook invocation runs against a *fresh* [`rhai::Scope`]; the
//!   AST is the only shared state, eliminating mutable carry-over between
//!   hook invocations.
//!
//! Malformed scripts are rejected at [`ScriptEngine::load`] time — *not* at
//! first invocation — so configuration errors surface at startup.
//!
//! Event payloads ride into the script as a [`rhai::Dynamic`] built via
//! `rhai::serde::to_dynamic`; fields are accessed by name from the script
//! side (e.g. `event.host`, `event.attempt`).

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod audit;
pub mod config;
pub mod engine;
pub mod error;
pub mod event;

pub use audit::{AuditEntry, AuditSink, HookOutcome, MockAuditSink, NoopAuditSink};
pub use config::{HookName, ScriptConfig, ScriptHooks, ScriptLimits};
pub use engine::ScriptEngine;
pub use error::ScriptError;
pub use event::{
    Disconnect, ForwardState, ForwardStateTransition, Generic, PostConnect, PreConnect,
};
