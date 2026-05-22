//! [`ChaosBehaviour::DnsAnswerRotation`](crate::ChaosBehaviour::DnsAnswerRotation)
//! companion module.
//!
//! **Deferred to C2.** DNS answer rotation is not a TCP-proxy concern — it
//! lives in a `MockResolver` that publishes answers on a `hickory-resolver`
//! shim alongside the proxy. This module is intentionally a thin
//! placeholder so the public API (and the [`crate::ChaosBehaviour`] enum)
//! stays stable as C2 fills it in.

// TODO(C2): implement `MockResolver` here that:
//   * binds a UDP socket on 127.0.0.1
//   * answers A queries from `answers` round-robin
//   * advances on a `ttl`-spaced tokio::time::interval
//   * exposes a `MockResolver::handle()` for runtime mutation
