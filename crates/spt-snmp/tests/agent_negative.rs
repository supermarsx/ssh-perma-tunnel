#![allow(
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::assigning_clones
)]
//! Hostile / malformed-input tests driven through the agent's real UDP
//! dispatch path (`AgentBuilder::run` → `recv_from` → `handle_datagram`).
//!
//! The headline property proven here is liveness under attack: a malformed,
//! truncated, oversized, or otherwise hostile datagram must make the agent
//! return an error / drop the packet — never panic. Because the release
//! profile uses `panic = "abort"`, a panic in the receive loop would kill the
//! whole process, so each test sends a poison datagram and then proves the
//! agent is *still alive* by completing a normal request afterward.

use std::net::SocketAddr;
use std::time::Duration;

use spt_snmp::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_REPORTABLE,
    SECURITY_MODEL_USM,
};
use spt_snmp::pdu::{Pdu, PduKind};
use spt_snmp::usm::{auth_digest, derive_keys, AuthProtocol, SecretBytes, UsmUser};
use spt_snmp::value::{Value, VarBind};
use spt_snmp::{AgentBuilder, AgentHandle, ConstScalar, ObjectIdentifier};
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn oid(s: &str) -> ObjectIdentifier {
    s.parse().unwrap()
}

fn test_user() -> UsmUser {
    UsmUser::auth_only(
        "probe",
        AuthProtocol::HmacSha256,
        SecretBytes::from("password-must-be-at-least-eight-bytes"),
    )
}

async fn spawn_agent(user: &UsmUser) -> AgentHandle {
    AgentBuilder::new()
        .documentation_enterprise_pen()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.32473.1.1.0"),
            ConstScalar::new(Value::Integer(7)),
        )
        .run()
        .await
        .unwrap()
}

/// A minimal authNoPriv SNMPv3 client that performs engine-id discovery and a
/// single Get, used to prove the agent is alive after a poison datagram.
struct Probe {
    socket: UdpSocket,
    target: SocketAddr,
    user: UsmUser,
    auth_kul: Vec<u8>,
    engine_id: Vec<u8>,
    engine_boots: u32,
    engine_time: u32,
}

impl Probe {
    async fn new(target: SocketAddr, user: UsmUser) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Self {
            socket,
            target,
            user,
            auth_kul: vec![],
            engine_id: vec![],
            engine_boots: 0,
            engine_time: 0,
        }
    }

    /// Sends a raw datagram and waits for a reply, returning the parsed reply.
    /// `None` means the agent dropped the packet (no response within timeout).
    async fn send_raw_expect_maybe(&self, bytes: &[u8]) -> Option<Message> {
        self.socket.send_to(bytes, self.target).await.unwrap();
        let mut buf = vec![0u8; 65_535];
        match timeout(Duration::from_millis(500), self.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Some(Message::from_bytes(&buf[..n]).unwrap()),
            _ => None,
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
        let resp = self
            .send_raw_expect_maybe(&msg.to_bytes().unwrap())
            .await
            .expect("discovery must get a Report reply");
        self.engine_id = resp.security.engine_id.clone();
        self.engine_boots = resp.security.engine_boots;
        self.engine_time = resp.security.engine_time;
        let (a, _) = derive_keys(&self.user, &self.engine_id);
        self.auth_kul = a;
    }

    /// Performs a normal authNoPriv Get and asserts the expected value, proving
    /// the agent process is still alive and serving.
    async fn assert_alive(&mut self) {
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: vec![],
            pdu: Pdu {
                kind: PduKind::GetRequest,
                request_id: 42,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.1.1.0"))],
            },
        };
        let auth_proto = self.user.auth.as_ref().unwrap().0;
        let mut sec = SecurityParameters {
            engine_id: self.engine_id.clone(),
            engine_boots: self.engine_boots,
            engine_time: self.engine_time,
            user_name: self.user.name.as_bytes().to_vec(),
            auth_params: vec![0u8; auth_proto.digest_len()],
            priv_params: vec![],
        };
        let mut m = Message {
            global: GlobalData {
                msg_id: 2,
                msg_max_size: 65_507,
                msg_flags: FLAG_AUTH | FLAG_REPORTABLE,
                msg_security_model: SECURITY_MODEL_USM,
            },
            security: sec.clone(),
            data: MessageData::Plain(scoped.to_bytes().unwrap()),
        };
        let pre = m.to_bytes().unwrap();
        let tag = auth_digest(auth_proto, &self.auth_kul, &pre).unwrap();
        sec.auth_params = tag;
        m.security = sec;

        let resp = self
            .send_raw_expect_maybe(&m.to_bytes().unwrap())
            .await
            .expect("agent must still respond to a valid request");
        // Decode the plaintext scoped PDU from the (authNoPriv) reply.
        let plain = match &resp.data {
            MessageData::Plain(b) => b.clone(),
            MessageData::Encrypted(_) => panic!("unexpected encrypted reply"),
        };
        let pdu = ScopedPdu::from_bytes(&plain).unwrap().pdu;
        assert_eq!(pdu.kind, PduKind::Response);
        assert_eq!(pdu.variable_bindings[0].value, Value::Integer(7));
    }
}

/// Drives a poison datagram through the live UDP dispatch path and proves the
/// agent process survives (still serves a valid request afterward).
async fn poison_then_alive(poison: &[u8]) {
    let user = test_user();
    let agent = spawn_agent(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    // Fire the hostile datagram. The agent must NOT crash; it may or may not
    // reply (malformed messages are silently dropped).
    let _ = probe.send_raw_expect_maybe(poison).await;

    // Prove liveness: a normal request still works.
    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn empty_datagram_survives() {
    poison_then_alive(&[]).await;
}

#[tokio::test]
async fn single_zero_byte_survives() {
    poison_then_alive(&[0x00]).await;
}

#[tokio::test]
async fn the_exact_overflow_datagram_survives() {
    // The audit's panic-DoS datagram: SEQUENCE with an 8-byte long-form length
    // near usize::MAX. Pre-fix, `pos + len` wrapped and the OOB slice panicked
    // → process abort. Must now be dropped cleanly.
    poison_then_alive(&[0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).await;
}

#[tokio::test]
async fn truncated_envelope_survives() {
    // A SEQUENCE that claims 100 bytes but carries only a couple.
    poison_then_alive(&[0x30, 0x64, 0x02, 0x01]).await;
}

#[tokio::test]
async fn oversized_inner_length_survives() {
    // Well-formed outer SEQUENCE wrapping an INTEGER whose length claims far
    // more bytes than remain.
    poison_then_alive(&[0x30, 0x05, 0x02, 0x7F, 0x01, 0x02, 0x03]).await;
}

#[tokio::test]
async fn deeply_nested_sequence_bomb_survives() {
    // Many nested SEQUENCE wrappers. The decoder is iterative, so this must be
    // handled in bounded stack and never crash the agent.
    let mut buf: Vec<u8> = vec![0x05, 0x00]; // NULL at the bottom
    for _ in 0..2000 {
        let len = buf.len();
        let mut next = Vec::with_capacity(len + 4);
        next.push(0x30u8);
        // long-form length where needed
        if len < 128 {
            next.push(len as u8);
        } else {
            let lb = (len as u64).to_be_bytes();
            let first = lb.iter().position(|&b| b != 0).unwrap();
            let nbytes = lb.len() - first;
            next.push(0x80 | nbytes as u8);
            next.extend_from_slice(&lb[first..]);
        }
        next.extend_from_slice(&buf);
        buf = next;
    }
    poison_then_alive(&buf).await;
}

#[tokio::test]
async fn random_garbage_survives() {
    // A grab-bag of high-bit tag/length bytes that previously tickled the
    // wraparound path.
    poison_then_alive(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x88, 0x80, 0x00]).await;
}

#[tokio::test]
async fn unknown_usm_user_is_rejected_agent_survives() {
    // Authenticated request from an unconfigured user must be rejected (no
    // value disclosed) and the agent stays alive.
    let user = test_user();
    let agent = spawn_agent(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    // Build a noAuthNoPriv message claiming an unknown user name.
    let scoped = ScopedPdu {
        context_engine_id: probe.engine_id.clone(),
        context_name: vec![],
        pdu: Pdu {
            kind: PduKind::GetRequest,
            request_id: 9,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.1.1.0"))],
        },
    };
    let msg = Message {
        global: GlobalData {
            msg_id: 9,
            msg_max_size: 65_507,
            msg_flags: FLAG_REPORTABLE,
            msg_security_model: SECURITY_MODEL_USM,
        },
        security: SecurityParameters {
            engine_id: probe.engine_id.clone(),
            engine_boots: probe.engine_boots,
            engine_time: probe.engine_time,
            user_name: b"nobody-such-user".to_vec(),
            auth_params: vec![],
            priv_params: vec![],
        },
        data: MessageData::Plain(scoped.to_bytes().unwrap()),
    };
    // Reportable: agent should reply with a Report (usmStatsUnknownUserNames)
    // or drop. Either way it must not leak the scalar and must stay alive.
    if let Some(reply) = probe.send_raw_expect_maybe(&msg.to_bytes().unwrap()).await {
        let plain = match &reply.data {
            MessageData::Plain(b) => b.clone(),
            MessageData::Encrypted(_) => panic!("unexpected encrypted reply"),
        };
        let pdu = ScopedPdu::from_bytes(&plain).unwrap().pdu;
        assert_eq!(pdu.kind, PduKind::Report, "expected usmStats Report");
        // usmStatsUnknownUserNames OID prefix.
        assert_eq!(
            pdu.variable_bindings[0].name.to_string(),
            "1.3.6.1.6.3.15.1.1.3.0"
        );
    }
    let snap = agent.agent().counters_snapshot().await;
    assert!(snap.unknown_user_names >= 1, "unknown-user counter bumped");
    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn time_window_violation_agent_survives() {
    // Authenticated request with a wildly future engineTime → NotInTimeWindow
    // Report. Agent must survive and keep serving.
    let user = test_user();
    let agent = spawn_agent(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;
    probe.engine_time = probe.engine_time.saturating_add(1_000_000);

    let scoped = ScopedPdu {
        context_engine_id: probe.engine_id.clone(),
        context_name: vec![],
        pdu: Pdu {
            kind: PduKind::GetRequest,
            request_id: 11,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.1.1.0"))],
        },
    };
    let auth_proto = probe.user.auth.as_ref().unwrap().0;
    let mut sec = SecurityParameters {
        engine_id: probe.engine_id.clone(),
        engine_boots: probe.engine_boots,
        engine_time: probe.engine_time,
        user_name: probe.user.name.as_bytes().to_vec(),
        auth_params: vec![0u8; auth_proto.digest_len()],
        priv_params: vec![],
    };
    let mut m = Message {
        global: GlobalData {
            msg_id: 11,
            msg_max_size: 65_507,
            msg_flags: FLAG_AUTH | FLAG_REPORTABLE,
            msg_security_model: SECURITY_MODEL_USM,
        },
        security: sec.clone(),
        data: MessageData::Plain(scoped.to_bytes().unwrap()),
    };
    let pre = m.to_bytes().unwrap();
    let tag = auth_digest(auth_proto, &probe.auth_kul, &pre).unwrap();
    sec.auth_params = tag;
    m.security = sec;

    let reply = probe
        .send_raw_expect_maybe(&m.to_bytes().unwrap())
        .await
        .expect("time-window violation should yield a Report");
    let plain = match &reply.data {
        MessageData::Plain(b) => b.clone(),
        MessageData::Encrypted(_) => panic!("unexpected encrypted reply"),
    };
    let pdu = ScopedPdu::from_bytes(&plain).unwrap().pdu;
    assert_eq!(pdu.kind, PduKind::Report);
    assert_eq!(
        pdu.variable_bindings[0].name.to_string(),
        "1.3.6.1.6.3.15.1.1.2.0",
        "usmStatsNotInTimeWindows"
    );

    // Re-sync to a valid time and prove the agent still serves.
    probe.discover().await;
    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}
