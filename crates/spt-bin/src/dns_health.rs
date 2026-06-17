//! Concrete [`spt_dns::HealthSource`] backed by the supervisor status snapshot
//! (GAP 3).
//!
//! `spt-dns` health-gates `AnswerWhenListening` / `AnswerWhenHealthy` records
//! through the [`spt_dns::HealthSource`] trait, but deliberately does NOT depend
//! on `spt-supervisor` (the dependency arrow points supervisor → dns). So the
//! concrete source lives here in the binary.
//!
//! [`ProfileSupervisorHealthSource`] resolves a `forward_id` of the form
//! `"<profile>/<forward>"` against the live [`spt_state::status::StatusSnapshot`]
//! the supervisor's `StatusWriter` maintains on disk — the same file
//! [`crate::mcp_server::StateDirSource`] reads. Reading the persisted snapshot
//! (rather than reaching into supervisor internals) keeps the dns runtime
//! decoupled and robust: a missing/corrupt snapshot maps every id to
//! [`spt_dns::ForwardHealth::down`] (fail-closed), so health-gated records are
//! suppressed until the supervisor has actually reported a listening/healthy
//! forward.

use std::path::PathBuf;

use async_trait::async_trait;

use spt_dns::{ForwardHealth, HealthSource};
use spt_state::status::{ForwardStatus, ProfileStatus, StatusSnapshot};

/// [`HealthSource`] over the on-disk supervisor status snapshot.
#[derive(Debug, Clone)]
pub struct ProfileSupervisorHealthSource {
    state_dir: PathBuf,
}

impl ProfileSupervisorHealthSource {
    /// Build over the state directory the `StatusWriter` flushes into.
    #[must_use]
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
        }
    }

    fn read_snapshot(&self) -> StatusSnapshot {
        let path = spt_state::paths::status_path(&self.state_dir);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<StatusSnapshot>(&bytes).unwrap_or_default(),
            Err(_) => StatusSnapshot::default(),
        }
    }
}

/// Split a `"<profile>/<forward>"` id into its two halves. Returns `None` when
/// the id is not in that shape (an unknown id ⇒ `ForwardHealth::down()`).
fn split_forward_id(forward_id: &str) -> Option<(&str, &str)> {
    forward_id.split_once('/')
}

/// Map a forward + its owning profile's snapshot rows into [`ForwardHealth`].
///
/// `listening` is true when the forward has a bound listener socket (state
/// `listening`/`active`, or a recorded `local_addr`). `healthy` additionally
/// requires the owning profile to be in a running/active state (a live session)
/// — mirroring the trait contract that "profile + forward FSMs both report
/// healthy".
fn health_from_rows(forward: &ForwardStatus, profile: Option<&ProfileStatus>) -> ForwardHealth {
    let fwd_state = forward.state.to_ascii_lowercase();
    let listening = forward.local_addr.is_some()
        || matches!(
            fwd_state.as_str(),
            "listening" | "active" | "running" | "up"
        );

    let profile_running = profile.is_some_and(|p| {
        matches!(
            p.state.to_ascii_lowercase().as_str(),
            "active" | "running" | "connected" | "up"
        )
    });

    ForwardHealth {
        listening,
        healthy: listening && profile_running,
    }
}

#[async_trait]
impl HealthSource for ProfileSupervisorHealthSource {
    async fn forward_health(&self, forward_id: &str) -> ForwardHealth {
        let Some((profile, forward)) = split_forward_id(forward_id) else {
            return ForwardHealth::down();
        };
        let snap = self.read_snapshot();
        // Forward rows are identified by `id` (the forward name) + `profile`.
        let Some(fwd) = snap
            .forwards
            .iter()
            .find(|f| f.profile == profile && f.id == forward)
        else {
            return ForwardHealth::down();
        };
        let prof = snap.profiles.iter().find(|p| p.id == profile);
        health_from_rows(fwd, prof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with(forward: ForwardStatus, profile: ProfileStatus) -> StatusSnapshot {
        StatusSnapshot {
            forwards: vec![forward],
            profiles: vec![profile],
            ..Default::default()
        }
    }

    fn write_snapshot(dir: &std::path::Path, snap: &StatusSnapshot) {
        let path = spt_state::paths::status_path(dir);
        std::fs::write(&path, serde_json::to_vec(snap).unwrap()).unwrap();
    }

    #[test]
    fn maps_listening_and_healthy_forward() {
        let fwd = ForwardStatus {
            id: "web".into(),
            profile: "alpha".into(),
            state: "listening".into(),
            local_addr: Some("127.0.0.1:8080".into()),
            ..Default::default()
        };
        let prof = ProfileStatus {
            id: "alpha".into(),
            state: "active".into(),
            ..Default::default()
        };
        let h = health_from_rows(&fwd, Some(&prof));
        assert!(h.listening);
        assert!(h.healthy);
    }

    #[test]
    fn listening_but_profile_down_is_not_healthy() {
        let fwd = ForwardStatus {
            id: "web".into(),
            profile: "alpha".into(),
            state: "listening".into(),
            local_addr: Some("127.0.0.1:8080".into()),
            ..Default::default()
        };
        let prof = ProfileStatus {
            id: "alpha".into(),
            state: "backoff".into(),
            ..Default::default()
        };
        let h = health_from_rows(&fwd, Some(&prof));
        assert!(h.listening);
        assert!(!h.healthy, "profile not running ⇒ unhealthy");
    }

    #[tokio::test]
    async fn unknown_id_is_down() {
        let dir = tempfile::tempdir().unwrap();
        let src = ProfileSupervisorHealthSource::new(dir.path().to_path_buf());
        // No snapshot on disk, and a malformed id.
        assert_eq!(src.forward_health("no-slash").await, ForwardHealth::down());
        assert_eq!(
            src.forward_health("alpha/missing").await,
            ForwardHealth::down()
        );
    }

    #[tokio::test]
    async fn reads_snapshot_and_maps_health() {
        let dir = tempfile::tempdir().unwrap();
        let snap = snapshot_with(
            ForwardStatus {
                id: "web".into(),
                profile: "alpha".into(),
                state: "active".into(),
                local_addr: Some("127.0.0.1:8080".into()),
                ..Default::default()
            },
            ProfileStatus {
                id: "alpha".into(),
                state: "active".into(),
                ..Default::default()
            },
        );
        write_snapshot(dir.path(), &snap);

        let src = ProfileSupervisorHealthSource::new(dir.path().to_path_buf());
        let h = src.forward_health("alpha/web").await;
        assert_eq!(h, ForwardHealth::up());
    }
}
