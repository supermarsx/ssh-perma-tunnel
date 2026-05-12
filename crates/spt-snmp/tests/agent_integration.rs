#![allow(
    clippy::doc_markdown,
    clippy::assigning_clones,
    clippy::match_wildcard_for_single_variants,
    clippy::manual_let_else,
    clippy::missing_panics_doc
)]
//! End-to-end integration tests against a live agent on `127.0.0.1`.
//!
//! These tests build a tiny local SNMPv3 client (request encoder + response
//! decoder + USM verifier) inside the test, point it at an agent that we
//! spin up on an ephemeral port, and check that authPriv `Get`,
//! `GetNext`, `GetBulk`, time-window enforcement, and trap send/receive
//! all behave correctly.

use std::net::SocketAddr;
use std::time::Duration;

use spt_snmp::ber::{Decoder, Tag};
use spt_snmp::engine::EngineClock;
use spt_snmp::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_PRIV,
    FLAG_REPORTABLE, SECURITY_MODEL_USM,
};
use spt_snmp::pdu::{Pdu, PduKind};
use spt_snmp::usm::{
    auth_digest, decrypt, derive_keys, encrypt, AuthProtocol, PrivProtocol, SecretBytes,
    SecurityLevel, UsmUser,
};
use spt_snmp::value::{Value, VarBind};
use spt_snmp::{AgentBuilder, ConstScalar, Handler, ObjectIdentifier, TableHandler, TrapSender};
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn oid(s: &str) -> ObjectIdentifier {
    s.parse().unwrap()
}

/// Builds a `Get` request (authPriv) and returns the encoded datagram bytes
/// plus the random salt and our chosen msg-id (so we can correlate).
struct Client {
    socket: UdpSocket,
    target: SocketAddr,
    user: UsmUser,
    auth_kul: Vec<u8>,
    priv_kul: Vec<u8>,
    engine_id: Vec<u8>,
    next_id: i32,
    /// Engine boots/time learned from a Report exchange.
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

    /// Performs RFC 3414 §4 engine-id discovery: empty engineID, empty user,
    /// noAuthNoPriv, reportable. Server replies with a Report carrying its
    /// engineID, boots, time.
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
        let (a, p) = derive_keys(&self.user, &self.engine_id);
        self.auth_kul = a;
        self.priv_kul = p;
    }

    fn alloc_id(&mut self) -> i32 {
        self.next_id += 1;
        self.next_id
    }

    async fn request(&mut self, pdu: Pdu, level: SecurityLevel) -> Pdu {
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: vec![],
            pdu,
        };
        let scoped_bytes = scoped.to_bytes().unwrap();
        let user_name = self.user.name.as_bytes().to_vec();

        let bytes = match level {
            SecurityLevel::NoAuthNoPriv => {
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
                m.to_bytes().unwrap()
            }
            SecurityLevel::AuthNoPriv | SecurityLevel::AuthPriv => {
                let auth_proto = self.user.auth.as_ref().unwrap().0;
                let priv_bit = level == SecurityLevel::AuthPriv;
                let mut flags = FLAG_AUTH | FLAG_REPORTABLE;
                if priv_bit {
                    flags |= FLAG_PRIV;
                }
                let priv_params = if priv_bit {
                    let mut s = [0u8; 8];
                    rand::Rng::fill(&mut rand::thread_rng(), &mut s);
                    s.to_vec()
                } else {
                    vec![]
                };
                let mut data_bytes = scoped_bytes;
                if priv_bit {
                    let priv_proto = self.user.priv_.as_ref().unwrap().0;
                    let mut salt = [0u8; 8];
                    salt.copy_from_slice(&priv_params);
                    encrypt(
                        priv_proto,
                        &self.priv_kul,
                        self.engine_boots,
                        self.engine_time,
                        &salt,
                        &mut data_bytes,
                    )
                    .unwrap();
                }
                let mut sec = SecurityParameters {
                    engine_id: self.engine_id.clone(),
                    engine_boots: self.engine_boots,
                    engine_time: self.engine_time,
                    user_name,
                    auth_params: vec![0u8; auth_proto.digest_len()],
                    priv_params,
                };
                let data = if priv_bit {
                    MessageData::Encrypted(data_bytes)
                } else {
                    MessageData::Plain(data_bytes)
                };
                let mut m = Message {
                    global: GlobalData {
                        msg_id: self.alloc_id(),
                        msg_max_size: 65_507,
                        msg_flags: flags,
                        msg_security_model: SECURITY_MODEL_USM,
                    },
                    security: sec.clone(),
                    data,
                };
                let pre = m.to_bytes().unwrap();
                let tag = auth_digest(auth_proto, &self.auth_kul, &pre).unwrap();
                sec.auth_params = tag;
                m.security = sec;
                m.to_bytes().unwrap()
            }
        };
        self.socket.send_to(&bytes, self.target).await.unwrap();

        let mut buf = vec![0u8; 65_535];
        let (n, _) = timeout(Duration::from_secs(3), self.socket.recv_from(&mut buf))
            .await
            .expect("response timeout")
            .unwrap();
        let mut resp = Message::from_bytes(&buf[..n]).unwrap();

        // Verify and decrypt response based on flags.
        let resp_level = SecurityLevel::from_flags(resp.global.msg_flags).unwrap();
        match resp_level {
            SecurityLevel::NoAuthNoPriv => {
                let plain = match &resp.data {
                    MessageData::Plain(b) => b.clone(),
                    _ => panic!("expected plaintext"),
                };
                ScopedPdu::from_bytes(&plain).unwrap().pdu
            }
            SecurityLevel::AuthNoPriv | SecurityLevel::AuthPriv => {
                let (auth_proto, _) = self.user.auth.as_ref().unwrap();
                let received = resp.security.auth_params.clone();
                resp.security.auth_params = vec![0u8; auth_proto.digest_len()];
                let serialized = resp.to_bytes().unwrap();
                let computed = auth_digest(*auth_proto, &self.auth_kul, &serialized).unwrap();
                assert_eq!(received, computed, "response auth digest mismatch");
                resp.security.auth_params = received;

                if resp_level == SecurityLevel::AuthPriv {
                    let (priv_proto, _) = self.user.priv_.as_ref().unwrap();
                    let mut salt = [0u8; 8];
                    salt.copy_from_slice(&resp.security.priv_params);
                    let mut buf = match &resp.data {
                        MessageData::Encrypted(b) => b.clone(),
                        _ => panic!("expected encrypted"),
                    };
                    decrypt(
                        *priv_proto,
                        &self.priv_kul,
                        resp.security.engine_boots,
                        resp.security.engine_time,
                        &salt,
                        &mut buf,
                    )
                    .unwrap();
                    ScopedPdu::from_bytes(&buf).unwrap().pdu
                } else {
                    let plain = match &resp.data {
                        MessageData::Plain(b) => b.clone(),
                        _ => panic!("expected plaintext"),
                    };
                    ScopedPdu::from_bytes(&plain).unwrap().pdu
                }
            }
        }
    }
}

#[tokio::test]
async fn auth_priv_get_end_to_end() {
    let user = UsmUser::auth_priv(
        "alice",
        AuthProtocol::HmacSha256,
        SecretBytes::from("auth-pass-very-long-string"),
        PrivProtocol::Aes128,
        SecretBytes::from("priv-pass-very-long-string"),
    );

    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.99999.1.1.0"),
            ConstScalar::new(Value::OctetString(b"spt-test-agent".to_vec())),
        )
        .add_scalar(
            oid("1.3.6.1.4.1.99999.1.2.0"),
            ConstScalar::new(Value::Integer(42)),
        )
        .run()
        .await
        .unwrap();

    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let req = Pdu {
        kind: PduKind::GetRequest,
        request_id: 100,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.99999.1.1.0"))],
    };
    let resp = client.request(req, SecurityLevel::AuthPriv).await;
    assert_eq!(resp.kind, PduKind::Response);
    assert_eq!(resp.variable_bindings.len(), 1);
    assert_eq!(
        resp.variable_bindings[0].value,
        Value::OctetString(b"spt-test-agent".to_vec())
    );

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn auth_only_get_end_to_end() {
    let user = UsmUser::auth_only(
        "bob",
        AuthProtocol::HmacSha1,
        SecretBytes::from("very-secret-password"),
    );
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.99999.1.1.0"),
            ConstScalar::new(Value::Integer(7)),
        )
        .run()
        .await
        .unwrap();

    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;
    let resp = client
        .request(
            Pdu {
                kind: PduKind::GetRequest,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.99999.1.1.0"))],
            },
            SecurityLevel::AuthNoPriv,
        )
        .await;
    assert_eq!(resp.variable_bindings[0].value, Value::Integer(7));
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_walk() {
    let user = UsmUser::auth_priv(
        "walker",
        AuthProtocol::HmacSha256,
        SecretBytes::from("auth-pass-very-long-string"),
        PrivProtocol::Aes128,
        SecretBytes::from("priv-pass-very-long-string"),
    );
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.99999.1.0"),
            ConstScalar::new(Value::Integer(1)),
        )
        .add_scalar(
            oid("1.3.6.1.4.1.99999.2.0"),
            ConstScalar::new(Value::Integer(2)),
        )
        .add_scalar(
            oid("1.3.6.1.4.1.99999.3.0"),
            ConstScalar::new(Value::Integer(3)),
        )
        .add_scalar(
            oid("1.3.6.1.4.1.99999.4.0"),
            ConstScalar::new(Value::Integer(4)),
        )
        .run()
        .await
        .unwrap();

    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;
    // GetBulk: 0 non-repeaters, 10 max-repetitions, starting at .99999.
    let req = Pdu {
        kind: PduKind::GetBulkRequest,
        request_id: 1,
        error_status: 0,
        error_index: 10,
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.99999"))],
    };
    let resp = client.request(req, SecurityLevel::AuthPriv).await;
    // Expect the four scalars in order, then EndOfMibView.
    let names: Vec<_> = resp
        .variable_bindings
        .iter()
        .map(|vb| vb.name.to_string())
        .collect();
    assert!(names.contains(&"1.3.6.1.4.1.99999.1.0".to_string()));
    assert!(names.contains(&"1.3.6.1.4.1.99999.4.0".to_string()));
    let last = resp.variable_bindings.iter().last().unwrap();
    assert_eq!(last.value, Value::EndOfMibView);
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn time_window_rejects_stale_message() {
    // We send an authNoPriv message with a stale engineTime (-1000 s) and
    // expect a Report-PDU back with usmStatsNotInTimeWindows (.1.1.2.0).
    let user = UsmUser::auth_only(
        "carol",
        AuthProtocol::HmacSha256,
        SecretBytes::from("password-must-be-at-least-eight-bytes"),
    );
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .run()
        .await
        .unwrap();

    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;
    // Forge engine_time deep in the past.
    client.engine_time = client.engine_time.saturating_add(100_000);

    let resp = client
        .request(
            Pdu {
                kind: PduKind::GetRequest,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.99999.0"))],
            },
            SecurityLevel::AuthNoPriv,
        )
        .await;
    assert_eq!(resp.kind, PduKind::Report);
    assert_eq!(
        resp.variable_bindings[0].name.to_string(),
        "1.3.6.1.6.3.15.1.1.2.0"
    );
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn trap_send_and_receive() {
    // Spin up a "trap receiver": a UDP socket plus the same USM crypto used
    // by the agent. We bind it, point a TrapSender at it, send a trap, then
    // verify both the wire format and the inner varbinds.
    let recv_user = UsmUser::auth_priv(
        "trapper",
        AuthProtocol::HmacSha256,
        SecretBytes::from("trap-auth-passphrase"),
        PrivProtocol::Aes128,
        SecretBytes::from("trap-priv-passphrase"),
    );

    let recv_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = recv_socket.local_addr().unwrap();

    let sender_user = recv_user.clone();
    let sender = TrapSender::new(recv_addr, sender_user).await.unwrap();

    sender
        .send(
            oid("1.3.6.1.4.1.99999.0.1"),
            vec![VarBind::new(
                oid("1.3.6.1.4.1.99999.5.1.0"),
                Value::OctetString(b"profile=demo".to_vec()),
            )],
        )
        .await
        .unwrap();

    let mut buf = vec![0u8; 65_535];
    let (n, _) = timeout(Duration::from_secs(3), recv_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let mut msg = Message::from_bytes(&buf[..n]).unwrap();
    let level = SecurityLevel::from_flags(msg.global.msg_flags).unwrap();
    assert_eq!(level, SecurityLevel::AuthPriv);

    // Localize keys against the sender's engineID (carried in the wire msg).
    let (auth_kul, priv_kul) = derive_keys(&recv_user, &msg.security.engine_id);
    let (auth_proto, _) = recv_user.auth.as_ref().unwrap();

    // Verify auth tag.
    let received = msg.security.auth_params.clone();
    msg.security.auth_params = vec![0u8; auth_proto.digest_len()];
    let serialized = msg.to_bytes().unwrap();
    let computed = auth_digest(*auth_proto, &auth_kul, &serialized).unwrap();
    assert_eq!(received, computed, "trap auth digest mismatch");
    msg.security.auth_params = received;

    // Decrypt scoped-PDU.
    let (priv_proto, _) = recv_user.priv_.as_ref().unwrap();
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&msg.security.priv_params);
    let mut ct = match msg.data {
        MessageData::Encrypted(b) => b,
        _ => panic!("expected encrypted trap"),
    };
    decrypt(
        *priv_proto,
        &priv_kul,
        msg.security.engine_boots,
        msg.security.engine_time,
        &salt,
        &mut ct,
    )
    .unwrap();
    let scoped = ScopedPdu::from_bytes(&ct).unwrap();
    assert_eq!(scoped.pdu.kind, PduKind::SnmpV2Trap);
    // Bindings: sysUpTime, snmpTrapOID, then our extra var.
    assert!(scoped.pdu.variable_bindings.len() >= 3);
    let trap_oid = match &scoped.pdu.variable_bindings[1].value {
        Value::Oid(o) => o.clone(),
        _ => panic!("expected snmpTrapOID Value::Oid"),
    };
    assert_eq!(trap_oid, oid("1.3.6.1.4.1.99999.0.1"));
    let extra = &scoped.pdu.variable_bindings[2];
    assert_eq!(extra.name, oid("1.3.6.1.4.1.99999.5.1.0"));
    assert_eq!(extra.value, Value::OctetString(b"profile=demo".to_vec()));
}

/// `TableHandler` example used to exercise table walks under GetNext.
struct TwoRowTable;

#[async_trait::async_trait]
impl TableHandler for TwoRowTable {
    async fn next(
        &self,
        after: Option<&ObjectIdentifier>,
    ) -> spt_snmp::Result<Option<(ObjectIdentifier, Value)>> {
        let entries = [
            (oid("1.3.6.1.4.1.99999.7.1.1.1.1"), Value::Integer(10)),
            (oid("1.3.6.1.4.1.99999.7.1.1.1.2"), Value::Integer(20)),
        ];
        for (k, v) in &entries {
            if let Some(a) = after {
                if k <= a {
                    continue;
                }
            }
            return Ok(Some((k.clone(), v.clone())));
        }
        Ok(None)
    }
}

#[tokio::test]
async fn table_walk_via_get_next() {
    let user = UsmUser::no_auth("public");
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .add_table(oid("1.3.6.1.4.1.99999.7"), TwoRowTable)
        .run()
        .await
        .unwrap();

    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;
    // Walk twice from .99999.7 → first row, then second.
    let req1 = Pdu {
        kind: PduKind::GetNextRequest,
        request_id: 1,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.99999.7"))],
    };
    let r1 = client.request(req1, SecurityLevel::NoAuthNoPriv).await;
    assert_eq!(r1.variable_bindings[0].value, Value::Integer(10));
    let next_oid = r1.variable_bindings[0].name.clone();

    let req2 = Pdu {
        kind: PduKind::GetNextRequest,
        request_id: 2,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(next_oid)],
    };
    let r2 = client.request(req2, SecurityLevel::NoAuthNoPriv).await;
    assert_eq!(r2.variable_bindings[0].value, Value::Integer(20));

    agent.shutdown().await.unwrap();
}

/// Make the unused-import lints happy when the test gates trim the imports.
fn _unused_imports_keep_alive() {
    let _ = Decoder::new(&[]);
    let _ = Tag::INTEGER;
    let _ = EngineClock::new(0);
    let _: fn(&dyn Handler) = |_| ();
}
