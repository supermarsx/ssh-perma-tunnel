//! [`ChaosBehaviour::HostKeyChurn`](crate::ChaosBehaviour::HostKeyChurn)
//! companion module.
//!
//! **Deferred to C2.** Host-key rotation is a server-side concern, not a
//! proxy concern. The actual mechanism lives in `tests/chaos/src/harness.rs`
//! as a `ChurningSshServer` stub that re-derives its host key after the
//! configured `new_after` elapses. This module exists only so the
//! [`crate::ChaosBehaviour`] enum has a stable home for the variant.

// TODO(C2): expose a `ChurningSshServer` helper here once the harness
// settles on a russh server-side fixture style.
