//! Event bus, binding evaluator, and notification sinks for spt.
//!
//! # Architecture
//!
//! 1. Producers call [`EventBus::emit`] with a typed [`Event`]. The bus
//!    fans out via `tokio::sync::broadcast` to subscribers and (optionally)
//!    to `spt-state::EventRing` for persistence.
//! 2. The [`Dispatcher`] task subscribes to the bus and evaluates each
//!    [`Binding`] — events whose `match` predicates pass are dispatched to
//!    the binding's `Sink`s.
//! 3. Each [`Sink`] receives an `Arc<Event>` and decides how to deliver it.
//!    Sinks that talk to networks (email, HTTP, SMS, push) accept their
//!    transport via trait objects so unit tests can pass mocks. Failed
//!    deliveries are written to a per-sink [`spt_state::DiskSpool`] for
//!    later retry.
//!
//! # Crate layout
//!
//! * [`event`] — canonical `Event` schema (kind / severity / fields).
//! * [`bus`] — `EventBus` broadcast hub.
//! * [`binding`] — match expressions + dispatch policy.
//! * [`template`] — Mustache-like `{{field}}` substitution for sink subjects.
//! * [`sinks`] — concrete sink types and the `Sink` trait.
//! * [`dispatcher`] — task that consumes events and applies bindings.
//! * [`mcp_notifier`] — cross-crate `McpNotifier` trait.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// t8-E1: blanket allow — 39 missing-docs items across sinks/template/
// binding/dispatcher. Public surface is documented in
// `docs/events.md`. Per-item docstrings deferred to v1.1 sweep.
#![allow(missing_docs)]

pub mod binding;
pub mod bus;
pub mod dispatcher;
pub mod event;
pub mod mcp_notifier;
pub mod sinks;
pub mod template;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use binding::{Binding, BindingMatch, Dedupe, SinkRef};
pub use bus::{EventBus, EventBusConfig};
pub use dispatcher::{Dispatcher, DispatcherConfig};
pub use event::{Event, EventBuilder, EventKind, Severity};
pub use mcp_notifier::{McpNotification, McpNotifier, NoopMcpNotifier};
pub use sinks::{Sink, SinkError};
pub use template::render_template;
