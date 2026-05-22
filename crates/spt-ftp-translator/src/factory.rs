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

/// Production factory: opens a russh SFTP session per FTP user.
///
/// Sessions are pooled in a `HashMap<String, Arc<SftpClient>>`. The lock
/// covers the whole resolve+connect+insert sequence so two concurrent
/// `open_for` calls for the same user do not race to open two sessions
/// — the second call observes the first's insertion and reuses it.
///
/// The pool currently does not evict stale entries (SSH sessions are
/// long-lived by design). A future enhancement could add a periodic
/// `keepalive`/health-check sweep; for now, the only path that drops a
/// pooled session is dropping the factory itself.
pub struct Ssh2SftpFactory {
    resolver: ProfileResolver,
    pool: Mutex<HashMap<String, Arc<spt_sftp::SftpClient>>>,
}

impl Ssh2SftpFactory {
    /// New factory.
    ///
    /// `resolver` is consulted on the first `open_for(user)` call for a
    /// given username; subsequent calls reuse the pooled session.
    #[must_use]
    pub fn new(resolver: ProfileResolver) -> Self {
        Self {
            resolver,
            pool: Mutex::new(HashMap::new()),
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
            let guard = self.pool.lock().await;
            if let Some(existing) = guard.get(user) {
                return Ok(existing.clone());
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
        let mut guard = self.pool.lock().await;
        if let Some(winner) = guard.get(user) {
            return Ok(winner.clone());
        }
        guard.insert(user.to_string(), arc.clone());
        Ok(arc)
    }
}
