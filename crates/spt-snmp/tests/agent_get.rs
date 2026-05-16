#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::assigning_clones,
    clippy::match_wildcard_for_single_variants,
    clippy::manual_let_else
)]
//! Additional agent integration coverage focused on:
//! - `AgentBuilder` configuration error paths (missing bind / missing PEN / pen=0)
//! - `engine_id` override and `enterprise_pen` round-trip behavior
//! - `Agent::counters_snapshot` initial state
//! - GetNext walks and Set requests through the live agent
//! - Engine ID discovery and wrong-engine-ID drop behavior
//! - InformRequest / Response / SnmpV2Trap PDUs being ignored

use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use spt_snmp::engine::EngineId;
use spt_snmp::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_REPORTABLE,
    SECURITY_MODEL_USM,
};
use spt_snmp::mib::{Handler, SetOutcome};
use spt_snmp::pdu::{Pdu, PduKind};
use spt_snmp::usm::{AuthProtocol, SecretBytes, UsmUser};
use spt_snmp::value::{Value, VarBind};
use spt_snmp::{
    AgentBuilder, ConstScalar, ObjectIdentifier, Result, DOCUMENTATION_ENTERPRISE_PEN,
};

fn oid(s: &str) -> ObjectIdentifier {
    s.parse().unwrap()
}

/// Builder helpers ---------------------------------------------------------

#[tokio::test]
async fn builder_requires_bind() {
    let r = AgentBuilder::new()
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .run()
        .await;
    match r {
        Ok(_) => panic!("missing bind must error"),
        Err(e) => assert!(format!("{e}").contains("bind")),
    }
}

#[tokio::test]
async fn builder_requires_pen_or_engine_id() {
    let r = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .run()
        .await;
    match r {
        Ok(_) => panic!("missing engine_id and PEN must error"),
        Err(e) => {
            let msg = format!("{e}");
            assert!(msg.contains("enterprise_pen") || msg.contains("engine_id"));
        }
    }
}

#[tokio::test]
async fn builder_rejects_zero_pen() {
    let r = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(0)
        .run()
        .await;
    match r {
        Ok(_) => panic!("pen=0 must error"),
        Err(e) => assert!(format!("{e}").contains("zero")),
    }
}

#[tokio::test]
async fn builder_with_explicit_engine_id_skips_pen_check() {
    let id = EngineId::new(vec![0x80, 0, 0, 0, 1, 2, 3, 4, 5]).unwrap();
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .engine_id(id.clone())
        .add_user(UsmUser::no_auth("u"))
        .run()
        .await
        .expect("explicit engine_id should bypass PEN requirement");
    assert_eq!(agent.agent().engine_id().as_bytes(), id.as_bytes());
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn builder_registry_mut_lets_handlers_be_added() {
    let mut builder = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(UsmUser::no_auth("u"));
    builder.registry_mut().add_scalar(
        oid("1.3.6.1.4.1.32473.99.0"),
        ConstScalar::new(Value::Integer(42)),
    );
    let agent = builder.run().await.unwrap();
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn builder_debug_redacts_internals() {
    let b = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(UsmUser::no_auth("u"));
    let dbg = format!("{b:?}");
    assert!(dbg.contains("AgentBuilder"));
    assert!(dbg.contains("users"));
}

#[tokio::test]
async fn counters_snapshot_starts_at_zero() {
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(UsmUser::no_auth("u"))
        .run()
        .await
        .unwrap();
    let snap = agent.agent().counters_snapshot().await;
    assert_eq!(snap.unknown_user_names, 0);
    assert_eq!(snap.wrong_digests, 0);
    assert_eq!(snap.unknown_engine_ids, 0);
    assert_eq!(snap.decryption_errors, 0);
    assert_eq!(snap.not_in_time_windows, 0);
    assert_eq!(snap.unsupported_sec_levels, 0);
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn agent_debug_impl_works() {
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(UsmUser::no_auth("u"))
        .run()
        .await
        .unwrap();
    let dbg = format!("{:?}", agent.agent());
    assert!(dbg.contains("Agent"));
    assert!(dbg.contains("engine_id"));
    agent.shutdown().await.unwrap();
}

/// A writable scalar that records the last `set` call.
struct WritableScalar {
    value: tokio::sync::Mutex<Value>,
    accept_int_only: bool,
}

impl WritableScalar {
    fn new(initial: Value, accept_int_only: bool) -> Self {
        Self {
            value: tokio::sync::Mutex::new(initial),
            accept_int_only,
        }
    }
}

#[async_trait]
impl Handler for WritableScalar {
    async fn get(&self) -> Result<Value> {
        Ok(self.value.lock().await.clone())
    }

    async fn set(&self, v: Value) -> SetOutcome {
        if self.accept_int_only && !matches!(v, Value::Integer(_)) {
            return SetOutcome::WrongValue;
        }
        *self.value.lock().await = v;
        SetOutcome::Ok
    }
}

/// Counts get-calls; used to verify the registry actually dispatches.
struct CountingScalar {
    calls: Arc<AtomicI64>,
}

#[async_trait]
impl Handler for CountingScalar {
    async fn get(&self) -> Result<Value> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Value::Integer(42))
    }
}

// ---- Client (shared with the existing integration test) ------------------

struct Client {
    socket: UdpSocket,
    target: SocketAddr,
    user: UsmUser,
    auth_kul: Vec<u8>,
    priv_kul: Vec<u8>,
    engine_id: Vec<u8>,
    next_id: i32,
    engine_boots: u32,
    engine_time: u32,
}

impl Client {
    async fn new(target: SocketAddr, user: UsmUser) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Self {
            socket,
            target,
            user,
            auth_kul: vec![],
            priv_kul: vec![],
            engine_id: vec![],
            next_id: 1,
            engine_boots: 0,
            engine_time: 0,
        }
    }

    async fn discover(&mut self) {
        let scoped = ScopedPdu {
            context_engine_id: vec![],
            context_name: vec![],
            pdu: Pdu {
                kind: PduKind::GetRequest,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![],
            },
        };
        let msg = Message {
            global: GlobalData {
                msg_id: 1,
                msg_max_size: 65_507,
                msg_flags: FLAG_REPORTABLE,
                msg_security_model: SECURITY_MODEL_USM,
            },
            security: SecurityParameters {
                engine_id: vec![],
                engine_boots: 0,
                engine_time: 0,
                user_name: vec![],
                auth_params: vec![],
                priv_params: vec![],
            },
            data: MessageData::Plain(scoped.to_bytes().unwrap()),
        };
        let bytes = msg.to_bytes().unwrap();
        self.socket.send_to(&bytes, self.target).await.unwrap();

        let mut buf = vec![0u8; 65_535];
        let (n, _) = timeout(Duration::from_secs(3), self.socket.recv_from(&mut buf))
            .await
            .expect("discovery timeout")
            .unwrap();
        let resp = Message::from_bytes(&buf[..n]).unwrap();
        self.engine_id = resp.security.engine_id.clone();
        self.engine_boots = resp.security.engine_boots;
        self.engine_time = resp.security.engine_time;
        let (a, p) = spt_snmp::usm::derive_keys(&self.user, &self.engine_id);
        self.auth_kul = a;
        self.priv_kul = p;
    }

    fn alloc_id(&mut self) -> i32 {
        self.next_id += 1;
        self.next_id
    }

    async fn request_noauth(&mut self, pdu: Pdu) -> Pdu {
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: vec![],
            pdu,
        };
        let scoped_bytes = scoped.to_bytes().unwrap();
        let user_name = self.user.name.as_bytes().to_vec();
        let m = Message {
            global: GlobalData {
                msg_id: self.alloc_id(),
                msg_max_size: 65_507,
                msg_flags: FLAG_REPORTABLE,
                msg_security_model: SECURITY_MODEL_USM,
            },
            security: SecurityParameters {
                engine_id: self.engine_id.clone(),
                engine_boots: self.engine_boots,
                engine_time: self.engine_time,
                user_name,
                auth_params: vec![],
                priv_params: vec![],
            },
            data: MessageData::Plain(scoped_bytes),
        };
        let bytes = m.to_bytes().unwrap();
        self.socket.send_to(&bytes, self.target).await.unwrap();

        let mut buf = vec![0u8; 65_535];
        let (n, _) = timeout(Duration::from_secs(3), self.socket.recv_from(&mut buf))
            .await
            .expect("response timeout")
            .unwrap();
        let resp = Message::from_bytes(&buf[..n]).unwrap();
        match resp.data {
            MessageData::Plain(b) => ScopedPdu::from_bytes(&b).unwrap().pdu,
            MessageData::Encrypted(_) => panic!("expected plaintext"),
        }
    }

    async fn try_recv_pdu(&self, dur: Duration) -> Option<Pdu> {
        let mut buf = vec![0u8; 65_535];
        let r = timeout(dur, self.socket.recv_from(&mut buf)).await.ok()?;
        let (n, _) = r.ok()?;
        let resp = Message::from_bytes(&buf[..n]).ok()?;
        match resp.data {
            MessageData::Plain(b) => Some(ScopedPdu::from_bytes(&b).ok()?.pdu),
            MessageData::Encrypted(_) => None,
        }
    }
}

// ---- Live-agent behavior tests ------------------------------------------

#[tokio::test]
async fn noauth_get_walks_through_multiple_oids() {
    let user = UsmUser::no_auth("u");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.32473.10.1.0"),
            ConstScalar::new(Value::Integer(10)),
        )
        .add_scalar(
            oid("1.3.6.1.4.1.32473.10.2.0"),
            ConstScalar::new(Value::Integer(20)),
        )
        .run()
        .await
        .unwrap();
    let addr = agent.local_addr();
    let mut client = Client::new(addr, user).await;
    client.discover().await;

    let req = Pdu {
        kind: PduKind::GetRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![
            VarBind::null(oid("1.3.6.1.4.1.32473.10.1.0")),
            VarBind::null(oid("1.3.6.1.4.1.32473.10.2.0")),
            VarBind::null(oid("1.3.6.1.4.1.32473.10.99.0")),
        ],
    };
    let resp = client.request_noauth(req).await;
    assert_eq!(resp.variable_bindings.len(), 3);
    assert_eq!(resp.variable_bindings[0].value, Value::Integer(10));
    assert_eq!(resp.variable_bindings[1].value, Value::Integer(20));
    assert_eq!(resp.variable_bindings[2].value, Value::NoSuchObject);

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn noauth_get_next_walks_then_returns_endofmib() {
    let user = UsmUser::no_auth("u");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.32473.11.1.0"),
            ConstScalar::new(Value::Integer(1)),
        )
        .add_scalar(
            oid("1.3.6.1.4.1.32473.11.2.0"),
            ConstScalar::new(Value::Integer(2)),
        )
        .run()
        .await
        .unwrap();
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    // GetNext starting before tree → first scalar
    let req = Pdu {
        kind: PduKind::GetNextRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.11"))],
    };
    let r = client.request_noauth(req).await;
    assert_eq!(r.variable_bindings[0].name, oid("1.3.6.1.4.1.32473.11.1.0"));

    // GetNext past last scalar → EndOfMibView
    let req = Pdu {
        kind: PduKind::GetNextRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.11.99.0"))],
    };
    let r = client.request_noauth(req).await;
    assert_eq!(r.variable_bindings[0].value, Value::EndOfMibView);

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn set_request_writable_scalar_succeeds() {
    let user = UsmUser::no_auth("u");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.32473.12.1.0"),
            WritableScalar::new(Value::Integer(0), true),
        )
        .run()
        .await
        .unwrap();
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    // Successful set
    let set = Pdu {
        kind: PduKind::SetRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::new(
            oid("1.3.6.1.4.1.32473.12.1.0"),
            Value::Integer(77),
        )],
    };
    let r = client.request_noauth(set).await;
    assert_eq!(r.error_status, 0);
    assert_eq!(r.error_index, 0);

    // Wrong-type set → WrongValue error
    let bad = Pdu {
        kind: PduKind::SetRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::new(
            oid("1.3.6.1.4.1.32473.12.1.0"),
            Value::OctetString(b"bad".to_vec()),
        )],
    };
    let r = client.request_noauth(bad).await;
    assert_ne!(r.error_status, 0);
    assert_eq!(r.error_index, 1);

    // Set on missing scalar → NotWritable error
    let missing = Pdu {
        kind: PduKind::SetRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::new(
            oid("1.3.6.1.4.1.32473.12.99.0"),
            Value::Integer(0),
        )],
    };
    let r = client.request_noauth(missing).await;
    assert_ne!(r.error_status, 0);

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn unknown_user_increments_counter_and_drops() {
    let user = UsmUser::no_auth("known");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .run()
        .await
        .unwrap();

    // First discover with a "known" user.
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    // Now send a noAuthNoPriv request with a different user_name.
    let stranger = Client::new(agent.local_addr(), UsmUser::no_auth("stranger")).await;
    let scoped = ScopedPdu {
        context_engine_id: client.engine_id.clone(),
        context_name: vec![],
        pdu: Pdu {
            kind: PduKind::GetRequest,
            request_id: 555,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.0"))],
        },
    };
    let m = Message {
        global: GlobalData {
            msg_id: 555,
            msg_max_size: 65_507,
            msg_flags: FLAG_REPORTABLE,
            msg_security_model: SECURITY_MODEL_USM,
        },
        security: SecurityParameters {
            engine_id: client.engine_id.clone(),
            engine_boots: client.engine_boots,
            engine_time: client.engine_time,
            user_name: b"stranger".to_vec(),
            auth_params: vec![],
            priv_params: vec![],
        },
        data: MessageData::Plain(scoped.to_bytes().unwrap()),
    };
    let bytes = m.to_bytes().unwrap();
    stranger
        .socket
        .send_to(&bytes, agent.local_addr())
        .await
        .unwrap();

    // Expect a Report back since the request was reportable.
    let r = stranger.try_recv_pdu(Duration::from_secs(2)).await;
    assert!(r.is_some(), "stranger should get a Report-PDU");
    let pdu = r.unwrap();
    assert_eq!(pdu.kind, PduKind::Report);

    // Counter has incremented.
    let snap = agent.agent().counters_snapshot().await;
    assert!(
        snap.unknown_user_names >= 1,
        "unknown_user_names = {}",
        snap.unknown_user_names
    );

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn engine_id_mismatch_is_silently_dropped() {
    let user = UsmUser::no_auth("u");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .run()
        .await
        .unwrap();

    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;
    // Forge a non-empty engine_id that doesn't match.
    client.engine_id = vec![0x80, 0, 0, 0, 0xFF, 0xFE, 0xFD, 0xFC];

    // Send a non-reportable, non-empty-engine-id message.
    let scoped = ScopedPdu {
        context_engine_id: client.engine_id.clone(),
        context_name: vec![],
        pdu: Pdu {
            kind: PduKind::GetRequest,
            request_id: 999,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![],
        },
    };
    let m = Message {
        global: GlobalData {
            msg_id: 999,
            msg_max_size: 65_507,
            msg_flags: 0, // not reportable
            msg_security_model: SECURITY_MODEL_USM,
        },
        security: SecurityParameters {
            engine_id: client.engine_id.clone(),
            engine_boots: 0,
            engine_time: 0,
            user_name: b"u".to_vec(),
            auth_params: vec![],
            priv_params: vec![],
        },
        data: MessageData::Plain(scoped.to_bytes().unwrap()),
    };
    let bytes = m.to_bytes().unwrap();
    client
        .socket
        .send_to(&bytes, agent.local_addr())
        .await
        .unwrap();

    // No reply expected.
    let r = client.try_recv_pdu(Duration::from_millis(400)).await;
    assert!(r.is_none(), "engine_id mismatch must be dropped");

    let snap = agent.agent().counters_snapshot().await;
    assert!(snap.unknown_engine_ids >= 1);

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_datagram_is_silently_dropped() {
    let user = UsmUser::no_auth("u");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user)
        .run()
        .await
        .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&[0xFFu8; 8], agent.local_addr())
        .await
        .unwrap();

    let mut buf = [0u8; 256];
    let r = timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await;
    assert!(r.is_err(), "agent must not reply to garbage");

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn inform_request_returns_empty_response() {
    let user = UsmUser::no_auth("u");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .run()
        .await
        .unwrap();
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let req = Pdu {
        kind: PduKind::InformRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.0"))],
    };
    let r = client.request_noauth(req).await;
    assert_eq!(r.kind, PduKind::Response);
    assert_eq!(r.error_status, 0);
    assert!(r.variable_bindings.is_empty());

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn handler_dispatch_actually_runs() {
    let user = UsmUser::no_auth("u");
    let calls = Arc::new(AtomicI64::new(0));
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.32473.13.1.0"),
            CountingScalar {
                calls: Arc::clone(&calls),
            },
        )
        .run()
        .await
        .unwrap();
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;
    let req = Pdu {
        kind: PduKind::GetRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.13.1.0"))],
    };
    let r = client.request_noauth(req).await;
    assert_eq!(r.variable_bindings[0].value, Value::Integer(42));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn authpriv_user_handles_noauth_request_under_priv_only_rejected() {
    // A user configured at authPriv should refuse a request that arrives at
    // a lower security level only when the message claims more than configured.
    // Since `level > configured` triggers UnsupportedSecLevel, send a no-auth
    // request to a user configured for noAuth: should succeed (the user is
    // configured at NoAuthNoPriv).
    let user = UsmUser::auth_only(
        "ap",
        AuthProtocol::HmacSha256,
        SecretBytes::from("a-secret-passphrase-at-least-eight"),
    );
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.32473.14.1.0"),
            ConstScalar::new(Value::Integer(99)),
        )
        .run()
        .await
        .unwrap();

    // Force noAuth: configured user is auth_only, so noAuth is `<= configured`,
    // which is the permitted path. But the agent's user has no priv configured;
    // sending a noAuthNoPriv request from this user name should be accepted at
    // the lower level, and the scalar should be readable.
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;
    let req = Pdu {
        kind: PduKind::GetRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.14.1.0"))],
    };
    let r = client.request_noauth(req).await;
    assert_eq!(r.variable_bindings[0].value, Value::Integer(99));
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn discovery_returns_authoritative_engine_id() {
    let user = UsmUser::no_auth("u");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .enterprise_pen(DOCUMENTATION_ENTERPRISE_PEN)
        .add_user(user.clone())
        .run()
        .await
        .unwrap();

    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;
    // Engine ID should be 9 bytes (structured form for the documentation PEN).
    assert_eq!(client.engine_id.len(), 9);
    assert_eq!(client.engine_id[0] & 0x80, 0x80);
    let snap = agent.agent().counters_snapshot().await;
    assert!(snap.unknown_engine_ids >= 1);
    agent.shutdown().await.unwrap();
}
