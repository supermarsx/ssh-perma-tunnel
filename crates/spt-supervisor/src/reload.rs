//! Reload reconciler — diff two [`spt_config::Config`]s and produce a list of
//! per-profile / per-forward actions.

use spt_config::diff::{diff, ChangeKind};
use spt_config::schema::{Config, Forward, Profile};

/// One action in a reload plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadAction {
    /// Start a new profile.
    StartProfile(String),
    /// Stop a profile that was removed.
    StopProfile(String),
    /// Restart a profile because connection-level fields changed.
    RestartProfile(String),
    /// Add a forward to an existing profile.
    AddForward {
        /// Profile name.
        profile: String,
        /// Forward name.
        forward: String,
    },
    /// Remove a forward from an existing profile.
    RemoveForward {
        /// Profile name.
        profile: String,
        /// Forward name.
        forward: String,
    },
    /// Restart a forward in place — its settings changed.
    RestartForward {
        /// Profile name.
        profile: String,
        /// Forward name.
        forward: String,
    },
}

/// A reload plan — an ordered list of actions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadPlan {
    /// Actions to apply, in order.
    pub actions: Vec<ReloadAction>,
}

impl ReloadPlan {
    /// Compute the plan from `(old, new)`.
    #[must_use]
    pub fn compute(old: &Config, new: &Config) -> Self {
        let mut actions = Vec::new();
        let changes = diff(old, new);

        // Profile add / remove / restart.
        let old_profiles: Vec<&Profile> = old.profiles.iter().collect();
        let new_profiles: Vec<&Profile> = new.profiles.iter().collect();

        // Removed profiles.
        for op in &old_profiles {
            if !new_profiles.iter().any(|np| np.name == op.name) {
                actions.push(ReloadAction::StopProfile(op.name.clone()));
            }
        }
        // Added profiles.
        for np in &new_profiles {
            if !old_profiles.iter().any(|op| op.name == np.name) {
                actions.push(ReloadAction::StartProfile(np.name.clone()));
            }
        }

        // For profiles present in both, decide whether to restart or only
        // change forwards.
        for op in &old_profiles {
            if let Some(np) = new_profiles.iter().find(|p| p.name == op.name) {
                if connection_level_changed(op, np) {
                    actions.push(ReloadAction::RestartProfile(op.name.clone()));
                    // RestartProfile semantics: forwards come back up via the
                    // restart, no per-forward action emitted.
                } else {
                    diff_forwards(&op.name, &op.forwards, &np.forwards, &mut actions);
                }
            }
        }

        // Top-level (non-profile) sections changed → callers may need to
        // reconfigure shared subsystems. We surface those as side info via
        // logging only; reload-plan focuses on profiles/forwards.
        for c in changes {
            if c.kind == ChangeKind::Modified
                && !c.path.starts_with("profiles[")
                && c.path != "version"
            {
                tracing::info!(target = "spt::reload", section = %c.path, "top-level config change");
            }
        }

        Self { actions }
    }
}

fn diff_forwards(profile: &str, old: &[Forward], new: &[Forward], out: &mut Vec<ReloadAction>) {
    for of in old {
        if !new.iter().any(|nf| nf.name == of.name) {
            out.push(ReloadAction::RemoveForward {
                profile: profile.to_owned(),
                forward: of.name.clone(),
            });
        }
    }
    for nf in new {
        match old.iter().find(|of| of.name == nf.name) {
            None => out.push(ReloadAction::AddForward {
                profile: profile.to_owned(),
                forward: nf.name.clone(),
            }),
            Some(of) if of != nf => out.push(ReloadAction::RestartForward {
                profile: profile.to_owned(),
                forward: nf.name.clone(),
            }),
            _ => {}
        }
    }
}

fn connection_level_changed(a: &Profile, b: &Profile) -> bool {
    a.protocol != b.protocol
        || a.host != b.host
        || a.port != b.port
        || a.endpoint != b.endpoint
        || a.user != b.user
        || a.connect_timeout != b.connect_timeout
        || a.connection != b.connection
        || a.crypto != b.crypto
        || a.auth != b.auth
        || a.trust != b.trust
        || a.tls != b.tls
        || a.ssh3 != b.ssh3
        || a.endpoints != b.endpoints
        || a.hops != b.hops
        || a.enabled != b.enabled
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_config::load::load_str;

    const BASE: &str = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.forwards]]
        name = "f1"
        type = "local"
        transport = "tcp"
        bind = "127.0.0.1:1"
        target = "x:22"
    "#;

    #[test]
    fn no_change_no_actions() {
        let (a, _) = load_str(BASE, false).unwrap();
        let plan = ReloadPlan::compute(&a, &a);
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn add_profile_emits_start() {
        let (a, _) = load_str(BASE, false).unwrap();
        let mut b = a.clone();
        b.profiles.push(spt_config::schema::Profile {
            name: "q".into(),
            protocol: "ssh2".into(),
            host: Some("h2".into()),
            ..Default::default()
        });
        let plan = ReloadPlan::compute(&a, &b);
        assert_eq!(plan.actions, vec![ReloadAction::StartProfile("q".into())]);
    }

    #[test]
    fn remove_profile_emits_stop() {
        let (a, _) = load_str(BASE, false).unwrap();
        let mut b = a.clone();
        b.profiles.clear();
        let plan = ReloadPlan::compute(&a, &b);
        assert_eq!(plan.actions, vec![ReloadAction::StopProfile("p".into())]);
    }

    #[test]
    fn host_change_restarts_profile() {
        let (a, _) = load_str(BASE, false).unwrap();
        let mut b = a.clone();
        b.profiles[0].host = Some("h2".into());
        let plan = ReloadPlan::compute(&a, &b);
        assert_eq!(plan.actions, vec![ReloadAction::RestartProfile("p".into())]);
    }

    #[test]
    fn forward_added_only() {
        let (a, _) = load_str(BASE, false).unwrap();
        let mut b = a.clone();
        b.profiles[0].forwards.push(spt_config::schema::Forward {
            name: "f2".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind: Some("127.0.0.1:2".into()),
            target: Some("x:22".into()),
            ..Default::default()
        });
        let plan = ReloadPlan::compute(&a, &b);
        assert_eq!(
            plan.actions,
            vec![ReloadAction::AddForward {
                profile: "p".into(),
                forward: "f2".into(),
            }]
        );
    }

    #[test]
    fn forward_modified_emits_restart() {
        let (a, _) = load_str(BASE, false).unwrap();
        let mut b = a.clone();
        b.profiles[0].forwards[0].target = Some("y:22".into());
        let plan = ReloadPlan::compute(&a, &b);
        assert_eq!(
            plan.actions,
            vec![ReloadAction::RestartForward {
                profile: "p".into(),
                forward: "f1".into(),
            }]
        );
    }

    #[test]
    fn forward_removed_emits_remove() {
        let (a, _) = load_str(BASE, false).unwrap();
        let mut b = a.clone();
        b.profiles[0].forwards.clear();
        let plan = ReloadPlan::compute(&a, &b);
        assert_eq!(
            plan.actions,
            vec![ReloadAction::RemoveForward {
                profile: "p".into(),
                forward: "f1".into(),
            }]
        );
    }
}
