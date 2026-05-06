//! Top-level orchestrator (spec §17.2).
//!
//! Owns a map of [`ProfileSupervisor`]s keyed by profile name and exposes a
//! reload entrypoint that translates a [`crate::ReloadPlan`] into start /
//! stop / restart calls.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use spt_auth::AuthConfig;
use spt_config::schema::Profile;
use spt_protocol::{Endpoint, TunnelProtocol};

use crate::profile::{ProfileSupervisor, ProfileSupervisorConfig};
use crate::reload::{ReloadAction, ReloadPlan};

/// Top-level orchestrator.
#[derive(Debug)]
pub struct Orchestrator {
    profiles: Mutex<HashMap<String, ProfileSupervisor>>,
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl Orchestrator {
    /// New empty orchestrator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: Mutex::new(HashMap::new()),
        }
    }

    /// Number of profiles currently supervised.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.lock().len()
    }

    /// Whether no profiles are running.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.lock().is_empty()
    }

    /// Start a profile.
    pub fn start_profile(
        &self,
        profile: &Profile,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        endpoints: Vec<Endpoint>,
        cfg: ProfileSupervisorConfig,
    ) {
        let sup = ProfileSupervisor::spawn(
            profile.name.clone(),
            protocol,
            auth,
            endpoints,
            profile.forwards.clone(),
            cfg,
        );
        self.profiles.lock().insert(profile.name.clone(), sup);
    }

    /// Stop a profile, if present, awaiting shutdown.
    pub async fn stop_profile(&self, name: &str) {
        let sup = self.profiles.lock().remove(name);
        if let Some(s) = sup {
            s.stop().await;
        }
    }

    /// Apply a reload plan. New profiles use the values from `provider`, which
    /// resolves auth, endpoints, and config per profile name.
    pub async fn apply<F>(&self, plan: &ReloadPlan, mut provider: F)
    where
        F: FnMut(&str)
            -> Option<(
                Profile,
                Arc<dyn TunnelProtocol>,
                AuthConfig,
                Vec<Endpoint>,
                ProfileSupervisorConfig,
            )>,
    {
        for action in &plan.actions {
            match action {
                ReloadAction::StopProfile(n) => self.stop_profile(n).await,
                ReloadAction::StartProfile(n) | ReloadAction::RestartProfile(n) => {
                    if matches!(action, ReloadAction::RestartProfile(_)) {
                        self.stop_profile(n).await;
                    }
                    if let Some((p, proto, auth, eps, cfg)) = provider(n) {
                        self.start_profile(&p, proto, auth, eps, cfg);
                    }
                }
                ReloadAction::AddForward { profile, .. }
                | ReloadAction::RemoveForward { profile, .. }
                | ReloadAction::RestartForward { profile, .. } => {
                    // Per-forward edits in v0.1: we restart the whole profile.
                    // The supervisor doesn't yet support hot per-forward
                    // mutation through a public API; once it does, this match
                    // arm becomes a `sup.restart_forward(name)`.
                    self.stop_profile(profile).await;
                    if let Some((p, proto, auth, eps, cfg)) = provider(profile) {
                        self.start_profile(&p, proto, auth, eps, cfg);
                    }
                }
            }
        }
    }

    /// Stop every profile.
    pub async fn shutdown(&self) {
        let names: Vec<String> = self.profiles.lock().keys().cloned().collect();
        for n in names {
            self.stop_profile(&n).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_auth::AuthConfig;
    use spt_config::load::load_str;
    use spt_forward::testing::MockTunnelProtocol;

    fn auth() -> AuthConfig {
        AuthConfig::new("u", vec![])
    }

    #[tokio::test]
    async fn start_and_stop_profile() {
        let orch = Orchestrator::new();
        let proto = Arc::new(MockTunnelProtocol::new());
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        orch.start_profile(
            &c.profiles[0],
            proto,
            auth(),
            vec![Endpoint::new("h", 22)],
            ProfileSupervisorConfig::default(),
        );
        assert_eq!(orch.len(), 1);
        orch.stop_profile("p").await;
        assert!(orch.is_empty());
    }

    #[tokio::test]
    async fn apply_plan_starts_then_stops() {
        let orch = Orchestrator::new();
        let proto = Arc::new(MockTunnelProtocol::new());
        let proto2 = Arc::clone(&proto);

        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let prof = c.profiles[0].clone();

        let plan = ReloadPlan {
            actions: vec![ReloadAction::StartProfile("p".into())],
        };
        orch.apply(&plan, |_| {
            Some((
                prof.clone(),
                proto2.clone(),
                auth(),
                vec![Endpoint::new("h", 22)],
                ProfileSupervisorConfig::default(),
            ))
        })
        .await;
        assert_eq!(orch.len(), 1);

        let plan = ReloadPlan {
            actions: vec![ReloadAction::StopProfile("p".into())],
        };
        orch.apply(&plan, |_| None).await;
        assert!(orch.is_empty());
    }
}
