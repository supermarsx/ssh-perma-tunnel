//! Scriptable tunnelling hooks for `spt` (t6-e7).
//!
//! This crate exposes a sandboxed [`ScriptEngine`] driven by `rhai 1.19`
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
//! * Every hook invocation runs against a *clone* of the engine's seed
//!   [`rhai::Scope`]; the original scope is never mutated, eliminating
//!   shared mutable state between hook invocations.
//!
//! Malformed scripts are rejected at [`ScriptEngine::load`] time — *not* at
//! first invocation — so configuration errors surface at startup.
//!
//! # Lockfile status — rhai absent
//!
//! `rhai` is not present in `Cargo.lock`. Under the workspace policy
//! (`cargo build --workspace --locked`, no `cargo update`), the dep cannot
//! be activated. This crate ships the **complete sandbox surface** (config
//! types, event payloads, engine handle, error taxonomy, hook-site
//! adapter) so:
//!
//! * Schema and runtime types are stable and unit-tested today.
//! * Downstream session code (the hook call sites in
//!   `crates/spt-ssh2/src/session.rs`) can be wired against the stable
//!   [`ScriptEngine`] API without touching the lockfile.
//! * When `rhai` is added to the lockfile in a follow-up, only the body of
//!   [`engine::ScriptEngine::load`] and the per-hook dispatcher in
//!   [`engine::ScriptEngine::invoke`] need real implementations — the
//!   public surface, defaults, and tests stay identical.
//!
//! Under the `engine` cargo feature (default `off`) the crate compiles
//! against `rhai 1.19`. Without it, [`ScriptEngine::load`] still validates
//! the path-and-syntax shape via the stub interpreter in
//! [`engine`], and every hook becomes a logged no-op that returns success.
//!
//! See `.orchestration/logs/t6-e7.md` for the full decision record (and
//! `.orchestration/logs/t6-e9.md` for the analogous SSPI / GSSAPI shape).

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod config;
pub mod engine;
pub mod error;
pub mod event;

pub use config::{ScriptConfig, ScriptHooks, ScriptLimits, HookName};
pub use engine::ScriptEngine;
pub use error::ScriptError;
pub use event::{Disconnect, ForwardState, ForwardStateTransition, Generic, PostConnect, PreConnect};
