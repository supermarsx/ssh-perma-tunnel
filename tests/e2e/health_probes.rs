//! e2e (Wave D): the four [`HealthCheckStyle`] probes
//! (`TcpConnect`, `SshHandshake`, `SshAuthPreflight`, `Ssh3Endpoint`) driven
//! through the supervisor against live loopback servers, asserting each probe's
//! outcome flips the supervisor between healthy (`Active`) and unhealthy
//! (`Reconnecting` — the `SessionLost` → reconnect path).
//!
//! ## How each style is exercised
//!
//! The supervisor's `run_active` loop fires the configured probe every
//! `keepalive_interval`; a successful probe keeps the profile `Active`, a failed
//! one breaks `SessionLost` → `Reconnecting` (see
//! `crates/spt-supervisor/src/profile.rs`). We set a tight `keepalive_interval`
//! and observe the state watcher.
//!
//! | Style | session backend | healthy | unhealthy |
//! |---|---|---|---|
//! | `TcpConnect`      | ssh2 `RusshTestServer` via a killable relay | relay+server up → TCP connect to the endpoint succeeds | relay torn down → TCP connect refused |
//! | `SshHandshake`    | ssh2 (default style) | `keepalive()` round-trip over the live session | relay black-holed → transport dies → `keepalive` Err |
//! | `SshAuthPreflight`| ssh2 (with auth)     | `preflight_connect()` re-dials + re-auths OK | relay down → re-dial fails |
//! | `Ssh3Endpoint`    | controllable mock (`preflight_connect`-based) | preflight OK | preflight Err |
//!
//! ### Why `Ssh3Endpoint` uses a mock here
//!
//! The `Ssh3Endpoint` probe calls `TunnelSession::preflight_connect`, which for
//! a real `Ssh3Session` requires the redial parameters captured by a full
//! `Ssh3Protocol::connect` bootstrap (QUIC + TLS + HTTP/3 CONNECT). That
//! bootstrap server needs `spt-ssh3`'s `server-selfsigned` feature (or direct
//! `quinn`/`rcgen`/`rustls`/`spt-trust` deps), none of which the e2e manifest
//! enables — a `start_pair()` session carries no redial params, so its
//! `preflight_connect` would always `Err`. We therefore drive the `Ssh3Endpoint`
//! *style* (which the supervisor dispatches identically for any backend) with a
//! controllable mock session whose `preflight_connect` we flip healthy/unhealthy
//! — the same fixture the in-crate `spt-supervisor` probe-dispatch tests use.
//! COORDINATOR / Linux-gate note: a LIVE ssh3 `preflight` healthy probe is
//! covered by `crates/spt-ssh3/tests/e2e_forward.rs::preflight_connect_ok_against_live_server`
//! and remains the place to assert the real QUIC side-dial.
//!
//! Hermetic: loopback ssh2 (`RusshTestServer`) + a loopback relay + a mock; all
//! ephemeral ports, bounded waits via `wait_for_state` (no fixed sleeps as a
//! readiness signal). Tight backoff so the unhealthy reconnect path is observed
//! quickly.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_config::testing::ProfileBuilder;
use spt_core::{Error, Result};
use spt_protocol::{Endpoint, ProtocolCapabilities, TunnelProtocol, TunnelSession};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};
use spt_supervisor::{BackoffConfig, HealthCheckStyle};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

// -----------------------------------------------------------------------------
// Killable TCP relay: client → relay → server.
// -----------------------------------------------------------------------------

/// A loopback relay that forwards `127.0.0.1:relay_port` → `server_port`. The
/// returned [`RelayHandle::kill`] both stops accepting (closes the listen port,
/// so a fresh TCP connect is refused — exercising `TcpConnect`) and severs every
/// in-flight proxied connection (so an established ssh transport dies —
/// exercising `SshHandshake`/`SshAuthPreflight`).
struct RelayHandle {
    port: u16,
    kill: watch::Sender<bool>,
}

impl RelayHandle {
    fn kill(&self) {
        let _ = self.kill.send(true);
    }
}

async fn spawn_relay(server_port: u16) -> RelayHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let port = listener.local_addr().unwrap().port();
    let (kill_tx, kill_rx) = watch::channel(false);
    let accept_kill = kill_rx.clone();
    tokio::spawn(async move {
        let mut accept_kill = accept_kill;
        loop {
            tokio::select! {
                // On kill, break the accept loop → drop the listener → the
                // relay port closes → fresh TCP connects are refused.
                _ = accept_kill.changed() => break,
                accept = listener.accept() => {
                    let Ok((mut client_side, _)) = accept else { break };
                    let mut conn_kill = kill_rx.clone();
                    tokio::spawn(async move {
                        let Ok(mut server_side) =
                            TcpStream::connect(("127.0.0.1", server_port)).await
                        else {
                            return;
                        };
                        tokio::select! {
                            _ = tokio::io::copy_bidirectional(&mut client_side, &mut server_side) => {}
                            _ = conn_kill.changed() => {} // drop both halves → RST/EOF
                        }
                    });
                }
            }
        }
    });
    RelayHandle {
        port,
        kill: kill_tx,
    }
}

// -----------------------------------------------------------------------------
// ssh2 wiring
// -----------------------------------------------------------------------------

fn ssh2_proto() -> Arc<Ssh2Protocol> {
    Arc::new(
        Ssh2Protocol::builder()
            .trust(spt_ssh2::testing::tofu_trust_verifier())
            .build(),
    )
}

fn ssh2_auth(env_var: &str) -> AuthConfig {
    std::env::set_var(env_var, "anything");
    AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: SecretRef::Env(env_var.into()),
        }],
    )
}

/// Tight backoff so an unhealthy reconnect loop is observed in well under a
/// second; the probe cadence is small so the probe fires promptly after Active.
fn fast_probe_cfg(style: HealthCheckStyle) -> ProfileSupervisorConfig {
    ProfileSupervisorConfig {
        health_check: style,
        keepalive_interval: Duration::from_millis(40),
        keepalive_timeout: Duration::from_secs(3),
        backoff: BackoffConfig {
            initial_delay: Duration::from_millis(20),
            max_delay: Duration::from_millis(80),
            reset_after: Duration::from_secs(120),
            jitter: 1.0,
            max_attempts: 0,
            retry_auth_failures: true,
        },
        ..ProfileSupervisorConfig::default()
    }
}

/// Build an orchestrator running one ssh2 profile (no forwards) through the
/// relay with the given probe style.
fn ssh2_orch(
    name: &str,
    relay_port: u16,
    auth_env: &str,
    style: HealthCheckStyle,
) -> spt_supervisor::Orchestrator {
    let profile = ProfileBuilder::new(name)
        .protocol("ssh2")
        .endpoint("127.0.0.1", relay_port)
        .user("tester")
        .build();
    OrchestratorBuilder::new()
        .with_profile(
            profile,
            ssh2_proto() as Arc<dyn TunnelProtocol>,
            ssh2_auth(auth_env),
            vec![Endpoint::new("127.0.0.1", relay_port)],
            fast_probe_cfg(style),
        )
        .build()
}

// =============================================================================
// TcpConnect
// =============================================================================

/// `TcpConnect` healthy: the endpoint (relay) accepts TCP, so the bare-connect
/// probe succeeds and the profile stays `Active` across several probe cadences.
#[tokio::test]
async fn tcp_connect_healthy_stays_active() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let relay = spawn_relay(server.addr.port()).await;

    let orch = ssh2_orch(
        "tcp-ok",
        relay.port,
        "SPT_HP_TCP_OK_PW",
        HealthCheckStyle::TcpConnect,
    );
    wait_for_state(
        &orch,
        "tcp-ok",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("reach Active");

    // Let several TcpConnect probe cadences elapse; the relay stays up, so the
    // probe keeps succeeding and the profile stays Active.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let sup = orch.profile_handle("tcp-ok").expect("profile running");
    assert_eq!(
        *sup.watch_state().borrow(),
        ProfileStateName::Active,
        "TcpConnect probe against a live endpoint must keep the profile Active"
    );

    orch.shutdown().await;
    server.shutdown().await;
}

/// `TcpConnect` unhealthy: after Active, tear the relay down. A bare TCP connect
/// to the now-closed relay port is refused, so the probe fails → `SessionLost`
/// → `Reconnecting`.
#[tokio::test]
async fn tcp_connect_unhealthy_triggers_reconnect() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let relay = spawn_relay(server.addr.port()).await;

    let orch = ssh2_orch(
        "tcp-bad",
        relay.port,
        "SPT_HP_TCP_BAD_PW",
        HealthCheckStyle::TcpConnect,
    );
    wait_for_state(
        &orch,
        "tcp-bad",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("reach Active");

    // Kill the relay: the listen port closes (TCP connect refused) and any
    // established transport is severed. The next probe must fail.
    relay.kill();

    wait_for_state(
        &orch,
        "tcp-bad",
        ProfileStateName::Reconnecting,
        Duration::from_secs(10),
    )
    .await
    .expect("failed TcpConnect probe must drive Reconnecting");

    orch.shutdown().await;
    server.shutdown().await;
}

// =============================================================================
// SshHandshake (default) — keepalive over the live session
// =============================================================================

/// `SshHandshake` healthy: the live ssh2 session's `keepalive()` round-trip
/// succeeds, keeping the profile `Active`.
#[tokio::test]
async fn ssh_handshake_healthy_stays_active() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let relay = spawn_relay(server.addr.port()).await;

    let orch = ssh2_orch(
        "ssh-ok",
        relay.port,
        "SPT_HP_SSH_OK_PW",
        HealthCheckStyle::SshHandshake,
    );
    wait_for_state(
        &orch,
        "ssh-ok",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("reach Active");

    tokio::time::sleep(Duration::from_millis(250)).await;
    let sup = orch.profile_handle("ssh-ok").expect("profile running");
    assert_eq!(
        *sup.watch_state().borrow(),
        ProfileStateName::Active,
        "SshHandshake keepalive over a live session must keep the profile Active"
    );

    orch.shutdown().await;
    server.shutdown().await;
}

/// `SshHandshake` unhealthy: black-holing the relay severs the established
/// transport, so the next `keepalive()` round-trip fails → `Reconnecting`.
#[tokio::test]
async fn ssh_handshake_unhealthy_triggers_reconnect() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let relay = spawn_relay(server.addr.port()).await;

    let orch = ssh2_orch(
        "ssh-bad",
        relay.port,
        "SPT_HP_SSH_BAD_PW",
        HealthCheckStyle::SshHandshake,
    );
    wait_for_state(
        &orch,
        "ssh-bad",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("reach Active");

    relay.kill();

    wait_for_state(
        &orch,
        "ssh-bad",
        ProfileStateName::Reconnecting,
        Duration::from_secs(15),
    )
    .await
    .expect("severed transport must make keepalive fail → Reconnecting");

    orch.shutdown().await;
    server.shutdown().await;
}

// =============================================================================
// SshAuthPreflight — full connect + auth side-dial
// =============================================================================

/// `SshAuthPreflight` healthy: the probe re-dials + re-authenticates against the
/// live server (a fresh connect+auth, dropped immediately) and succeeds, keeping
/// the profile `Active`.
#[tokio::test]
async fn ssh_auth_preflight_healthy_stays_active() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let relay = spawn_relay(server.addr.port()).await;

    let orch = ssh2_orch(
        "pf-ok",
        relay.port,
        "SPT_HP_PF_OK_PW",
        HealthCheckStyle::SshAuthPreflight,
    );
    wait_for_state(
        &orch,
        "pf-ok",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("reach Active");

    // Each preflight is a full connect+auth; allow a couple of cadences.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sup = orch.profile_handle("pf-ok").expect("profile running");
    assert_eq!(
        *sup.watch_state().borrow(),
        ProfileStateName::Active,
        "SshAuthPreflight re-dial+re-auth against a live server must keep Active"
    );

    orch.shutdown().await;
    server.shutdown().await;
}

/// `SshAuthPreflight` unhealthy: tearing the relay down makes the preflight
/// re-dial fail (the endpoint is unreachable), so the probe fails →
/// `Reconnecting`.
#[tokio::test]
async fn ssh_auth_preflight_unhealthy_triggers_reconnect() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let relay = spawn_relay(server.addr.port()).await;

    let orch = ssh2_orch(
        "pf-bad",
        relay.port,
        "SPT_HP_PF_BAD_PW",
        HealthCheckStyle::SshAuthPreflight,
    );
    wait_for_state(
        &orch,
        "pf-bad",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("reach Active");

    relay.kill();

    wait_for_state(
        &orch,
        "pf-bad",
        ProfileStateName::Reconnecting,
        Duration::from_secs(15),
    )
    .await
    .expect("failed preflight re-dial must drive Reconnecting");

    orch.shutdown().await;
    server.shutdown().await;
}

// =============================================================================
// Ssh3Endpoint — preflight-based, driven via a controllable mock
// =============================================================================

/// A mock ssh3-style session whose liveness primitive is `preflight_connect`
/// (the supervisor's `Ssh3Endpoint` probe). A shared flag flips it
/// healthy/unhealthy so the same fixture covers both transitions.
struct Ssh3MockSession {
    preflight_fail: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl TunnelSession for Ssh3MockSession {
    async fn open_local_forward(
        &mut self,
        _spec: &spt_protocol::LocalForwardSpec,
    ) -> Result<spt_protocol::ForwardHandle> {
        Err(Error::RuntimeFailure(
            "no forwards in health-probe mock".into(),
        ))
    }
    async fn open_remote_forward(
        &mut self,
        _spec: &spt_protocol::RemoteForwardSpec,
    ) -> Result<spt_protocol::ForwardHandle> {
        Err(Error::RuntimeFailure(
            "no forwards in health-probe mock".into(),
        ))
    }
    async fn open_dynamic_forward(
        &mut self,
        _spec: &spt_protocol::DynamicForwardSpec,
    ) -> Result<spt_protocol::ForwardHandle> {
        Err(Error::RuntimeFailure(
            "no forwards in health-probe mock".into(),
        ))
    }
    async fn open_udp_forward(
        &mut self,
        _spec: &spt_protocol::UdpForwardSpec,
    ) -> Result<spt_protocol::ForwardHandle> {
        Err(Error::RuntimeFailure(
            "no forwards in health-probe mock".into(),
        ))
    }
    async fn keepalive(&mut self) -> Result<()> {
        Ok(())
    }
    async fn preflight_connect(&mut self) -> Result<()> {
        if self
            .preflight_fail
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            Err(Error::NetworkUnreachable(
                "ssh3 endpoint unreachable".into(),
            ))
        } else {
            Ok(())
        }
    }
    async fn close(self: Box<Self>) -> Result<()> {
        Ok(())
    }
    fn session_info(&self) -> spt_protocol::SessionInfo {
        spt_protocol::SessionInfo {
            backend: "ssh3".into(),
            peer_version: None,
            negotiated: None,
            established_at: 0,
        }
    }
}

#[derive(Clone)]
struct Ssh3MockProtocol {
    preflight_fail: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl TunnelProtocol for Ssh3MockProtocol {
    async fn connect(
        &self,
        _endpoint: &Endpoint,
        _auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        Ok(Box::new(Ssh3MockSession {
            preflight_fail: Arc::clone(&self.preflight_fail),
        }))
    }
    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh3()
    }
    fn name(&self) -> &'static str {
        "ssh3-mock"
    }
}

fn ssh3_orch(
    name: &str,
    preflight_fail: Arc<std::sync::atomic::AtomicBool>,
) -> spt_supervisor::Orchestrator {
    let profile = ProfileBuilder::new(name)
        .protocol("ssh3")
        .endpoint("127.0.0.1", 443)
        .user("alice")
        .build();
    let proto = Arc::new(Ssh3MockProtocol { preflight_fail });
    OrchestratorBuilder::new()
        .with_profile(
            profile,
            proto as Arc<dyn TunnelProtocol>,
            AuthConfig::new("alice", vec![]),
            vec![Endpoint::new("127.0.0.1", 443)],
            fast_probe_cfg(HealthCheckStyle::Ssh3Endpoint),
        )
        .build()
}

/// `Ssh3Endpoint` healthy: the preflight (QUIC-endpoint reachability+auth
/// side-dial) succeeds, keeping the profile `Active`. Driven through the
/// supervisor so the `Ssh3Endpoint` style is dispatched to `preflight_connect`.
#[tokio::test]
async fn ssh3_endpoint_healthy_stays_active() {
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let orch = ssh3_orch("ssh3-ok", Arc::clone(&fail));

    wait_for_state(
        &orch,
        "ssh3-ok",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("reach Active");

    tokio::time::sleep(Duration::from_millis(250)).await;
    let sup = orch.profile_handle("ssh3-ok").expect("profile running");
    assert_eq!(
        *sup.watch_state().borrow(),
        ProfileStateName::Active,
        "a succeeding Ssh3Endpoint preflight must keep the profile Active"
    );

    orch.shutdown().await;
}

/// `Ssh3Endpoint` unhealthy: flip the preflight to fail; the next probe errors
/// (unreachable QUIC endpoint) → `SessionLost` → `Reconnecting`.
#[tokio::test]
async fn ssh3_endpoint_unhealthy_triggers_reconnect() {
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let orch = ssh3_orch("ssh3-bad", Arc::clone(&fail));

    wait_for_state(
        &orch,
        "ssh3-bad",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("reach Active");

    // Flip the endpoint to unreachable; the next preflight fails.
    fail.store(true, std::sync::atomic::Ordering::SeqCst);

    wait_for_state(
        &orch,
        "ssh3-bad",
        ProfileStateName::Reconnecting,
        Duration::from_secs(10),
    )
    .await
    .expect("a failed Ssh3Endpoint preflight must drive Reconnecting");

    orch.shutdown().await;
}
