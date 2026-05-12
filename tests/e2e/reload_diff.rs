//! End-to-end reload-diff: drive the full
//! `Config -> ReloadPlan::compute -> Orchestrator::apply` pipeline that
//! `cli_dispatch::reload_orchestrator` runs at runtime.
//!
//! The unit test `spt_supervisor::orchestrator::tests::apply_plan_starts_then_stops`
//! covers `Orchestrator::apply` with a hand-built `ReloadPlan`. This test is
//! additive: it builds two `Config`s through the public schema, lets
//! `ReloadPlan::compute` derive the action list, then applies it and checks
//! the live profile set transitions accordingly.
//!
//! Profile B exists in both configs and stays running across the reload;
//! profile A is removed; profile C is added. We assert via
//! `Orchestrator::list_profiles` that the running set ends up `{B, C}`.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use spt_auth::AuthConfig;
use spt_config::schema::{Config, Profile};
use spt_config::testing::{ConfigBuilder, ProfileBuilder};
use spt_protocol::Endpoint;
use spt_supervisor::testing::{
    wait_for_state, MockTunnelProtocol, OrchestratorBuilder, ProfileStateName,
    ProfileSupervisorConfig,
};
use spt_supervisor::ReloadPlan;

fn make_profile(name: &str) -> Profile {
    ProfileBuilder::new(name)
        .endpoint("127.0.0.1", 22)
        .user("alice")
        .build()
}

fn config_with(profiles: &[&str]) -> Config {
    let mut b = ConfigBuilder::new();
    for n in profiles {
        b = b.add_profile(make_profile(n));
    }
    b.build()
}

#[tokio::test]
async fn reload_diff_adds_and_removes_profiles_through_the_full_pipeline() {
    // Initial state: profiles A, B running.
    let proto: Arc<MockTunnelProtocol> = Arc::new(MockTunnelProtocol::new());
    let orch = OrchestratorBuilder::new()
        .with_profile_named("a", proto.clone())
        .with_profile_named("b", proto.clone())
        .build();

    // Wait for both supervisors to reach Active so the test exercises a
    // running orchestrator (not a freshly-spawned one mid-handshake).
    wait_for_state(&orch, "a", ProfileStateName::Active, Duration::from_secs(2))
        .await
        .expect("profile a active");
    wait_for_state(&orch, "b", ProfileStateName::Active, Duration::from_secs(2))
        .await
        .expect("profile b active");
    assert_eq!(orch.len(), 2);

    // Old/new configs that reload-compute will diff.
    let old_cfg = config_with(&["a", "b"]);
    let new_cfg = config_with(&["b", "c"]);
    let plan = ReloadPlan::compute(&old_cfg, &new_cfg);

    // Sanity: the plan must Stop(a), Start(c), and leave b alone.
    let action_strs: Vec<String> = plan.actions.iter().map(|a| format!("{a:?}")).collect();
    assert!(
        action_strs
            .iter()
            .any(|s| s.contains("StopProfile") && s.contains("\"a\"")),
        "expected StopProfile(a); got {action_strs:?}"
    );
    assert!(
        action_strs
            .iter()
            .any(|s| s.contains("StartProfile") && s.contains("\"c\"")),
        "expected StartProfile(c); got {action_strs:?}"
    );
    assert!(
        !action_strs.iter().any(|s| {
            s.contains("\"b\"") && (s.contains("StopProfile") || s.contains("RestartProfile"))
        }),
        "expected b to be untouched; got {action_strs:?}"
    );

    // Apply the plan against the live orchestrator. The provider returns
    // wiring for any profile name the apply pump asks about.
    let proto_for_provider = proto.clone();
    let new_profiles: Vec<Profile> = new_cfg.profiles.clone();
    orch.apply(&plan, move |name| {
        new_profiles
            .iter()
            .find(|p| p.name == name)
            .cloned()
            .map(|p| {
                (
                    p,
                    proto_for_provider.clone() as Arc<dyn spt_protocol::TunnelProtocol>,
                    AuthConfig::new("alice", vec![]),
                    vec![Endpoint::new("127.0.0.1", 22)],
                    ProfileSupervisorConfig::default(),
                )
            })
    })
    .await;

    // Expected end-state: a is gone, b still running, c is running.
    assert!(
        orch.profile_handle("a").is_none(),
        "profile a must be stopped after reload"
    );
    assert!(
        orch.profile_handle("b").is_some(),
        "profile b must still be running after reload"
    );
    assert!(
        orch.profile_handle("c").is_some(),
        "profile c must be running after reload"
    );
    wait_for_state(&orch, "c", ProfileStateName::Active, Duration::from_secs(2))
        .await
        .expect("profile c reaches active");
    assert_eq!(orch.len(), 2);

    orch.shutdown().await;
    assert!(orch.is_empty());
}

#[tokio::test]
async fn empty_reload_is_a_noop() {
    // A reload computed against the same config produces no actions. Apply
    // is a noop and the profile set is preserved.
    let proto: Arc<MockTunnelProtocol> = Arc::new(MockTunnelProtocol::new());
    let orch = OrchestratorBuilder::new()
        .with_profile_named("p", proto.clone())
        .build();
    wait_for_state(&orch, "p", ProfileStateName::Active, Duration::from_secs(2))
        .await
        .expect("profile p active");

    let cfg = config_with(&["p"]);
    let plan = ReloadPlan::compute(&cfg, &cfg);
    assert!(plan.actions.is_empty());

    orch.apply(&plan, |_name| None).await;
    assert_eq!(orch.len(), 1);
    assert!(orch.profile_handle("p").is_some());

    orch.shutdown().await;
}
