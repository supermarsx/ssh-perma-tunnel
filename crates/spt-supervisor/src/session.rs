//! Live session bookkeeping shared between the orchestrator and per-profile
//! tasks.
//!
//! Each successful `protocol.connect` allocates a fresh [`SessionId`] and
//! registers a row in [`SessionRegistry`]. The orchestrator exposes
//! [`crate::Orchestrator::session_list`] / [`crate::Orchestrator::session_close`]
//! / [`crate::Orchestrator::session_drain`] over this registry.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use spt_core::SessionId;

/// Public state name of a session — currently a 1:1 mirror of the profile
/// state machine state but exposed as an opaque string for forward compat.
pub type SessionState = String;

/// One row in the global session table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRow {
    /// Stable session id (UUID).
    pub id: SessionId,
    /// Owning profile name.
    pub profile: String,
    /// Backend protocol name (`"ssh2"`, `"ssh3"`, `"mock"`).
    pub protocol: String,
    /// Currently-bound endpoint as `"host:port"`.
    pub endpoint: String,
    /// When the session opened.
    pub since: DateTime<Utc>,
    /// State name as reported by the profile state machine.
    pub state: SessionState,
    /// Bytes received in this session.
    pub bytes_in: u64,
    /// Bytes sent in this session.
    pub bytes_out: u64,
    /// Open per-connection count across all forwards of this session.
    pub conns_open: u64,
}

/// Process-wide registry of live sessions, shared by the orchestrator and the
/// per-profile tasks.
#[derive(Debug, Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<DashMap<SessionId, SessionRow>>,
}

impl SessionRegistry {
    /// New empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert / overwrite.
    pub fn insert(&self, row: SessionRow) {
        self.inner.insert(row.id.clone(), row);
    }

    /// Remove by id.
    pub fn remove(&self, id: &SessionId) -> Option<SessionRow> {
        self.inner.remove(id).map(|(_, v)| v)
    }

    /// Look up by id.
    #[must_use]
    pub fn get(&self, id: &SessionId) -> Option<SessionRow> {
        self.inner.get(id).map(|r| r.value().clone())
    }

    /// Number of live sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Snapshot the registry.
    #[must_use]
    pub fn snapshot(&self) -> Vec<SessionRow> {
        self.inner.iter().map(|r| r.value().clone()).collect()
    }

    /// Filter by profile.
    #[must_use]
    pub fn by_profile(&self, profile: &str) -> Vec<SessionRow> {
        self.inner
            .iter()
            .filter(|r| r.value().profile == profile)
            .map(|r| r.value().clone())
            .collect()
    }

    /// Apply a mutation to one row, if present.
    pub fn update<F: FnOnce(&mut SessionRow)>(&self, id: &SessionId, f: F) {
        if let Some(mut e) = self.inner.get_mut(id) {
            f(e.value_mut());
        }
    }

    /// Add `bytes_in` / `bytes_out` to one row (handy for tests + production
    /// stat updates).
    pub fn add_bytes(&self, id: &SessionId, bytes_in: u64, bytes_out: u64) {
        self.update(id, |row| {
            row.bytes_in = row.bytes_in.saturating_add(bytes_in);
            row.bytes_out = row.bytes_out.saturating_add(bytes_out);
        });
    }
}
