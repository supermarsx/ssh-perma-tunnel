//! Concurrent session and connection tables backed by `dashmap`.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use spt_core::{ConnectionId, ForwardId, ProfileId, SessionId};

/// One row in the session table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub session_id: SessionId,
    pub profile_id: ProfileId,
    pub opened_at: DateTime<Utc>,
    pub remote_endpoint: String,
    /// Last activity timestamp (server-set).
    pub last_activity: DateTime<Utc>,
    /// Bytes received in this session.
    pub bytes_in: u64,
    /// Bytes sent in this session.
    pub bytes_out: u64,
}

/// One row in the connection table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub connection_id: ConnectionId,
    pub session_id: SessionId,
    pub forward_id: ForwardId,
    pub opened_at: DateTime<Utc>,
    pub peer: String,
    /// Local address the connection landed on.
    pub local: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Thread-safe table of active sessions, keyed by session id.
#[derive(Debug, Clone, Default)]
pub struct SessionTable {
    inner: Arc<DashMap<SessionId, SessionEntry>>,
}

impl SessionTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace.
    pub fn insert(&self, e: SessionEntry) {
        self.inner.insert(e.session_id.clone(), e);
    }

    /// Remove by id, returning the row if present.
    pub fn remove(&self, id: &SessionId) -> Option<SessionEntry> {
        self.inner.remove(id).map(|(_, v)| v)
    }

    /// Lookup by id.
    #[must_use]
    pub fn get(&self, id: &SessionId) -> Option<SessionEntry> {
        self.inner.get(id).map(|r| r.value().clone())
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Snapshot the entire table as a Vec.
    #[must_use]
    pub fn snapshot(&self) -> Vec<SessionEntry> {
        self.inner.iter().map(|r| r.value().clone()).collect()
    }

    /// Apply a mutation closure to one entry, if present.
    pub fn update<F: FnOnce(&mut SessionEntry)>(&self, id: &SessionId, f: F) {
        if let Some(mut entry) = self.inner.get_mut(id) {
            f(entry.value_mut());
        }
    }

    /// Evict entries whose `last_activity` is older than `older_than`.
    /// Returns the number evicted.
    pub fn evict_idle(&self, older_than: DateTime<Utc>) -> usize {
        let to_remove: Vec<SessionId> = self
            .inner
            .iter()
            .filter(|r| r.value().last_activity < older_than)
            .map(|r| r.key().clone())
            .collect();
        let n = to_remove.len();
        for k in to_remove {
            self.inner.remove(&k);
        }
        n
    }
}

/// Thread-safe table of active connections, keyed by connection id.
#[derive(Debug, Clone, Default)]
pub struct ConnectionTable {
    inner: Arc<DashMap<ConnectionId, ConnectionEntry>>,
}

impl ConnectionTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, e: ConnectionEntry) {
        self.inner.insert(e.connection_id.clone(), e);
    }

    pub fn remove(&self, id: &ConnectionId) -> Option<ConnectionEntry> {
        self.inner.remove(id).map(|(_, v)| v)
    }

    #[must_use]
    pub fn get(&self, id: &ConnectionId) -> Option<ConnectionEntry> {
        self.inner.get(id).map(|r| r.value().clone())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<ConnectionEntry> {
        self.inner.iter().map(|r| r.value().clone()).collect()
    }

    /// Iterate connections belonging to a forward.
    #[must_use]
    pub fn for_forward(&self, fid: &ForwardId) -> Vec<ConnectionEntry> {
        self.inner
            .iter()
            .filter(|r| &r.value().forward_id == fid)
            .map(|r| r.value().clone())
            .collect()
    }

    pub fn update<F: FnOnce(&mut ConnectionEntry)>(&self, id: &ConnectionId, f: F) {
        if let Some(mut entry) = self.inner.get_mut(id) {
            f(entry.value_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn mksess(id: &str, last: i64) -> SessionEntry {
        SessionEntry {
            session_id: SessionId::new(id).unwrap(),
            profile_id: ProfileId::new("p").unwrap(),
            opened_at: dt(0),
            remote_endpoint: "host:22".into(),
            last_activity: dt(last),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    fn mkconn(id: &str, fid: &str) -> ConnectionEntry {
        ConnectionEntry {
            connection_id: ConnectionId::new(id).unwrap(),
            session_id: SessionId::new("s1").unwrap(),
            forward_id: ForwardId::new(fid).unwrap(),
            opened_at: dt(0),
            peer: "1.2.3.4:1234".into(),
            local: "127.0.0.1:5000".into(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    #[test]
    fn session_insert_lookup_remove() {
        let t = SessionTable::new();
        t.insert(mksess("s1", 100));
        assert_eq!(t.len(), 1);
        let e = t.get(&SessionId::new("s1").unwrap()).unwrap();
        assert_eq!(e.last_activity, dt(100));
        let r = t.remove(&SessionId::new("s1").unwrap()).unwrap();
        assert_eq!(r.session_id, SessionId::new("s1").unwrap());
        assert!(t.is_empty());
    }

    #[test]
    fn session_update_mutates_entry() {
        let t = SessionTable::new();
        t.insert(mksess("s1", 100));
        t.update(&SessionId::new("s1").unwrap(), |e| e.bytes_in += 42);
        assert_eq!(t.get(&SessionId::new("s1").unwrap()).unwrap().bytes_in, 42);
    }

    #[test]
    fn session_evict_idle() {
        let t = SessionTable::new();
        t.insert(mksess("s1", 50));
        t.insert(mksess("s2", 200));
        let n = t.evict_idle(dt(100));
        assert_eq!(n, 1);
        assert!(t.get(&SessionId::new("s1").unwrap()).is_none());
        assert!(t.get(&SessionId::new("s2").unwrap()).is_some());
    }

    #[test]
    fn connection_for_forward_filters() {
        let t = ConnectionTable::new();
        t.insert(mkconn("c1", "f1"));
        t.insert(mkconn("c2", "f1"));
        t.insert(mkconn("c3", "f2"));
        let f1 = t.for_forward(&ForwardId::new("f1").unwrap());
        assert_eq!(f1.len(), 2);
    }
}
