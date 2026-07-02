//! SFTP-session factory trait.
//!
//! Each authenticated FTP control session asks the factory to open an
//! SFTP client on its behalf. Two implementations ship:
//!
//! * `crate::mock::MockSftpFactory` — a filesystem-backed mock used by
//!   the integration test suite. Gated behind `feature = "testing"`.
//! * [`Ssh2SftpFactory`] — production-grade factory that opens a real
//!   russh SFTP session per FTP user via
//!   [`spt_ssh2::Ssh2Protocol::connect_sftp`]. Sessions are pooled by
//!   username so two FTP control sessions for the same user share one
//!   SSH session.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use spt_auth::AuthConfig;
use spt_protocol::Endpoint;
use spt_ssh2::{CryptoPolicy, Ssh2Protocol, TrustPolicy};
use tokio::sync::Mutex;

use crate::error::TranslatorError;

/// Source of [`spt_sftp::SftpClient`] instances per FTP user.
#[async_trait]
pub trait SftpFactory: Send + Sync {
    /// Open an SFTP session for the given (already-authenticated) user.
    /// Errors propagate as `TranslatorError::Sftp` to the FTP reply layer.
    async fn open_for(&self, user: &str) -> Result<Arc<spt_sftp::SftpClient>, TranslatorError>;
}

/// One FTP-user → SSH backing binding.
///
/// The translator does not know about `[[profiles]]` directly; the spt-bin
/// glue translates a `Profile` into this small struct so the translator
/// keeps a minimal compile-time dep surface (no `spt-config` pull-in).
#[derive(Clone)]
pub struct Ssh2UserBinding {
    /// Connect target — host + port + address-family pin.
    pub endpoint: Endpoint,
    /// Auth identity and methods.
    pub auth: AuthConfig,
    /// Trust verifier (known_hosts + sha256 pins).
    pub trust: TrustPolicy,
    /// Crypto policy (kex / cipher / mac / host_key allowlists).
    pub crypto: CryptoPolicy,
}

/// Resolves an FTP username into the SSH backing it should use.
///
/// Returning `None` causes [`Ssh2SftpFactory::open_for`] to fail with
/// [`TranslatorError::Sftp`] (the FTP layer surfaces that as `530 SFTP
/// backend unavailable`).
pub type ProfileResolver = Arc<dyn Fn(&str) -> Option<Ssh2UserBinding> + Send + Sync>;

/// Default upper bound on the number of concurrently-pooled SFTP sessions.
///
/// Each pool entry pins a live SSH session (memory + file descriptors + a
/// background task), so an unbounded pool keyed by attacker-influenced FTP
/// usernames (a wildcard/pattern [`ProfileResolver`]) is a memory/fd-exhaustion
/// vector. 64 comfortably covers realistic distinct-user fan-out on one
/// translator while capping worst-case retention. Override with
/// [`Ssh2SftpFactory::with_capacity`]; `0` opts back into unbounded.
pub const DEFAULT_MAX_POOLED_SESSIONS: usize = 64;

/// A pooled session plus the last time it was handed out — the LRU key used to
/// pick an eviction victim when the pool is full.
type PoolEntry = (Arc<spt_sftp::SftpClient>, Instant);

/// Enforce the max-entries cap on `pool` by evicting the least-recently-used
/// entry when it is already full. Returns the evicted value (if any) so the
/// caller can close it *outside* the pool lock. `max_entries == 0` disables the
/// cap (unbounded). Generic over the value so the LRU logic is unit-testable
/// without constructing a real [`spt_sftp::SftpClient`].
fn enforce_cap<T>(pool: &mut HashMap<String, (T, Instant)>, max_entries: usize) -> Option<T> {
    if max_entries == 0 || pool.len() < max_entries {
        return None;
    }
    let victim = pool
        .iter()
        .min_by_key(|(_, (_, last_used))| *last_used)
        .map(|(k, _)| k.clone())?;
    pool.remove(&victim).map(|(v, _)| v)
}

/// Production factory: opens a russh SFTP session per FTP user.
///
/// Sessions are pooled in a `HashMap<String, (Arc<SftpClient>, Instant)>`. The
/// lock covers the whole resolve+connect+insert sequence so two concurrent
/// `open_for` calls for the same user do not race to open two sessions — the
/// second call observes the first's insertion and reuses it.
///
/// The pool is bounded at [`DEFAULT_MAX_POOLED_SESSIONS`] (configurable via
/// [`Ssh2SftpFactory::with_capacity`]). When a new user would push the pool
/// over the cap, the least-recently-used entry is evicted and its `SftpClient`
/// closed cleanly (only when the factory holds the last reference — an entry
/// still in use by a live FTP control session is dropped from the pool but not
/// force-closed, so active transfers are never interrupted). Reuse for active
/// users is preserved because every hit refreshes the entry's LRU timestamp.
pub struct Ssh2SftpFactory {
    resolver: ProfileResolver,
    pool: Mutex<HashMap<String, PoolEntry>>,
    max_entries: usize,
}

impl Ssh2SftpFactory {
    /// New factory with the [`DEFAULT_MAX_POOLED_SESSIONS`] cap.
    ///
    /// `resolver` is consulted on the first `open_for(user)` call for a
    /// given username; subsequent calls reuse the pooled session.
    #[must_use]
    pub fn new(resolver: ProfileResolver) -> Self {
        Self::with_capacity(resolver, DEFAULT_MAX_POOLED_SESSIONS)
    }

    /// New factory with an explicit pool cap. `max_entries = 0` disables the
    /// cap (unbounded — not recommended for attacker-facing resolvers).
    #[must_use]
    pub fn with_capacity(resolver: ProfileResolver, max_entries: usize) -> Self {
        Self {
            resolver,
            pool: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    /// Number of distinct users currently in the session pool. Useful
    /// for tests asserting pool re-use.
    pub async fn pool_size(&self) -> usize {
        self.pool.lock().await.len()
    }
}

#[async_trait]
impl SftpFactory for Ssh2SftpFactory {
    async fn open_for(&self, user: &str) -> Result<Arc<spt_sftp::SftpClient>, TranslatorError> {
        // Check the pool first. A real session open is on the order of
        // 200 ms — slow enough that double-open would surface as a
        // visible regression in audit logs, hence the re-check pattern
        // below.
        {
            let mut guard = self.pool.lock().await;
            if let Some(entry) = guard.get_mut(user) {
                entry.1 = Instant::now(); // refresh LRU on hit → keep active users
                return Ok(entry.0.clone());
            }
        }

        // Resolve outside the lock — the resolver may block briefly on
        // a config-read path.
        let binding = (self.resolver)(user).ok_or_else(|| {
            TranslatorError::Sftp(format!("no SSH binding configured for FTP user `{user}`"))
        })?;

        let protocol = Ssh2Protocol::builder()
            .crypto(binding.crypto)
            .trust(binding.trust)
            .build();
        let sftp = protocol
            .connect_sftp(&binding.endpoint, &binding.auth)
            .await
            .map_err(|e| TranslatorError::Sftp(format!("ssh connect for `{user}`: {e}")))?;
        let arc = Arc::new(sftp);

        // Re-acquire the lock to insert. Another concurrent `open_for`
        // may have raced ahead — if so, prefer that one (drop ours).
        let evicted = {
            let mut guard = self.pool.lock().await;
            if let Some(winner) = guard.get_mut(user) {
                winner.1 = Instant::now();
                return Ok(winner.0.clone());
            }
            // Bound the pool: evict the least-recently-used session before
            // inserting the new one. The victim is returned so it is closed
            // after the lock is released (a network close must not block the
            // pool). `arc` we just opened is always the most-recently-used, so
            // it is never the victim.
            let evicted = enforce_cap(&mut guard, self.max_entries);
            guard.insert(user.to_string(), (arc.clone(), Instant::now()));
            evicted
        };

        if let Some(client) = evicted {
            // Only close when the factory held the last reference: an entry
            // still shared with a live FTP control session must not be
            // force-closed mid-transfer — dropping our Arc lets that session
            // close it on its own `Drop`.
            if Arc::strong_count(&client) == 1 {
                if let Err(e) = client.close().await {
                    tracing::debug!(error = %e, "closing evicted pooled SFTP session");
                }
            }
        }
        Ok(arc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The pool cap evicts the least-recently-used entry once full, and never
    /// evicts while under the cap. `0` disables the cap. This exercises the
    /// bounding/eviction logic directly (a real `SftpClient` needs a live SSH
    /// server — covered by the `translator` integration suite).
    #[test]
    fn enforce_cap_evicts_lru_when_full() {
        let base = Instant::now();
        let mut pool: HashMap<String, (u32, Instant)> = HashMap::new();
        pool.insert("a".into(), (1, base));
        pool.insert("b".into(), (2, base + Duration::from_secs(1)));
        pool.insert("c".into(), (3, base + Duration::from_secs(2)));

        // Full at cap 3 → the oldest ("a") is evicted and returned.
        let evicted = enforce_cap(&mut pool, 3);
        assert_eq!(evicted, Some(1), "LRU victim must be the oldest entry");
        assert_eq!(pool.len(), 2);
        assert!(!pool.contains_key("a"));
        assert!(pool.contains_key("b") && pool.contains_key("c"));

        // Now under cap → no eviction.
        assert_eq!(enforce_cap(&mut pool, 3), None);
        assert_eq!(pool.len(), 2);

        // Cap 0 = unbounded → never evicts, even when non-empty.
        assert_eq!(enforce_cap(&mut pool, 0), None);
        assert_eq!(pool.len(), 2);
    }

    /// The default pool cap is finite and non-zero — the pool is bounded by
    /// default, not the unbounded (`0`) escape hatch.
    const _: () = assert!(
        DEFAULT_MAX_POOLED_SESSIONS > 0,
        "default pool must be bounded"
    );
}
