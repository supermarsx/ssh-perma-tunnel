#![allow(
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::assigning_clones,
    clippy::too_many_lines,
    clippy::match_wildcard_for_single_variants
)]
//! Regression tests for **C1 — the SNMPv3 USM security-level DOWNGRADE auth
//! bypass** (and the companion `handle_get` work-budget fix), driven through
//! the agent's real UDP dispatch entry point.
//!
//! The vulnerability: `usm_verify` only rejected a security level *higher* than
//! the user's provisioned level; it never enforced a *floor*. A user
//! provisioned `authPriv`/`authNoPriv` would therefore process a `msgFlags=0`
//! (noAuthNoPriv) plaintext request with NO HMAC verification and NO knowledge
//! of any password — an unauthenticated attacker who knows a `securityName`
//! could Get/GetBulk, and SET if the user was writable.
//!
//! RFC 3414 fix: a request's security level MUST equal the user's provisioned
//! level (ceiling *and* floor). A downgraded request is rejected BEFORE the PDU
//! is acted on, so the auth (HMAC) and priv (decrypt) steps actually run.
//!
//! Each "rejected" test additionally proves the agent is still alive and
//! serving afterwards (liveness under attack).

use std::net::SocketAddr;
use std::time::Duration;

use spt_snmp::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_PRIV,
    FLAG_REPORTABLE, SECURITY_MODEL_USM,
};
use spt_snmp::pdu::{ErrorStatus, Pdu, PduKind};
use spt_snmp::usm::{
    auth_digest, decrypt, derive_keys, encrypt, AuthProtocol, PrivProtocol, SecretBytes,
    SecurityLevel, UsmUser,
};
use spt_snmp::value::{Value, VarBind};
use spt_snmp::{AgentBuilder, AgentHandle, ConstScalar, ObjectIdentifier};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const SCALAR_OID: &str = "1.3.6.1.4.1.32473.50.1.0";
const BIG_OID: &str = "1.3.6.1.4.1.32473.50.2.0";

fn oid(s: &str) -> ObjectIdentifier {
    s.parse().unwrap()
}

fn authpriv_user(writable: bool) -> UsmUser {
    UsmUser::auth_priv(
        "secure",
        AuthProtocol::HmacSha256,
        SecretBytes::from("auth-passphrase-at-least-eight-bytes"),
        PrivProtocol::Aes128,
        SecretBytes::from("priv-passphrase-at-least-eight-bytes"),
    )
    .writable(writable)
}

fn authnopriv_user() -> UsmUser {
    UsmUser::auth_only(
        "authuser",
        AuthProtocol::HmacSha256,
        SecretBytes::from("auth-passphrase-at-least-eight-bytes"),
    )
}

/// A writable scalar holding an integer, so we can prove an *unauthenticated*
/// SET never mutates it.
struct IntCell {
    value: tokio::sync::Mutex<i64>,
}

#[async_trait::async_trait]
impl spt_snmp::mib::Handler for IntCell {
    async fn get(&self) -> spt_snmp::Result<Value> {
        Ok(Value::Integer(*self.value.lock().await))
    }
    async fn set(&self, v: Value) -> spt_snmp::mib::SetOutcome {
        if let Value::Integer(i) = v {
            *self.value.lock().await = i;
            spt_snmp::mib::SetOutcome::Ok
        } else {
            spt_snmp::mib::SetOutcome::WrongValue
        }
    }
}

async fn spawn_agent(user: &UsmUser) -> AgentHandle {
    AgentBuilder::new()
        .documentation_enterprise_pen()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .add_scalar(oid(SCALAR_OID), ConstScalar::new(Value::Integer(7)))
        // A deliberately large value so the response byte-budget can be
        // exercised by the handle_get tests.
        .add_scalar(
            oid(BIG_OID),
            ConstScalar::new(Value::OctetString(vec![0xCD; 4000])),
        )
        .run()
        .await
        .unwrap()
}

async fn spawn_agent_writable(user: &UsmUser, cell: IntCell) -> AgentHandle {
    AgentBuilder::new()
        .documentation_enterprise_pen()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .add_scalar(oid(SCALAR_OID), cell)
        .run()
        .await
        .unwrap()
}

/// A test client that can emit a request at an arbitrary claimed security
/// level — independent of the user's provisioned level — so downgrade attacks
/// can be simulated faithfully.
struct Client {
    socket: UdpSocket,
    target: SocketAddr,
    user: UsmUser,
    auth_kul: Vec<u8>,
    priv_kul: Vec<u8>,
    engine_id: Vec<u8>,
    engine_boots: u32,
    engine_time: u32,
    next_id: i32,
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
            engine_boots: 0,
            engine_time: 0,
            next_id: 1,
        }
    }

    fn alloc_id(&mut self) -> i32 {
        self.next_id += 1;
        self.next_id
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
        self.socket
            .send_to(&msg.to_bytes().unwrap(), self.target)
            .await
            .unwrap();
        let resp = self
            .recv_msg(500)
            .await
            .expect("discovery must get a Report reply");
        self.engine_id = resp.security.engine_id.clone();
        self.engine_boots = resp.security.engine_boots;
        self.engine_time = resp.security.engine_time;
        let (a, p) = derive_keys(&self.user, &self.engine_id);
        self.auth_kul = a;
        self.priv_kul = p;
    }

    async fn recv_msg(&self, ms: u64) -> Option<Message> {
        let mut buf = vec![0u8; 65_535];
        match timeout(Duration::from_millis(ms), self.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Some(Message::from_bytes(&buf[..n]).unwrap()),
            _ => None,
        }
    }

    /// Builds and sends `pdu` at the *claimed* `level`, then decodes the reply
    /// PDU (if any). `reportable` controls the reportable flag, `msg_max_size`
    /// the advertised buffer. Returns `None` if no reply arrives in `ms`.
    async fn send(
        &mut self,
        pdu: Pdu,
        level: SecurityLevel,
        reportable: bool,
        msg_max_size: i32,
        ms: u64,
    ) -> Option<Pdu> {
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: vec![],
            pdu,
        };
        let scoped_bytes = scoped.to_bytes().unwrap();
        let user_name = self.user.name.as_bytes().to_vec();
        let msg_id = self.alloc_id();

        let bytes = match level {
            SecurityLevel::NoAuthNoPriv => {
                let mut flags = 0u8;
                if reportable {
                    flags |= FLAG_REPORTABLE;
                }
                let m = Message {
                    global: GlobalData {
                        msg_id,
                        msg_max_size,
                        msg_flags: flags,
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
                let mut flags = FLAG_AUTH;
                if reportable {
                    flags |= FLAG_REPORTABLE;
                }
                let mut priv_params = vec![];
                let mut data_bytes = scoped_bytes;
                if priv_bit {
                    flags |= FLAG_PRIV;
                    let mut salt = [0u8; 8];
                    rand::Rng::fill(&mut rand::thread_rng(), &mut salt);
                    let priv_proto = self.user.priv_.as_ref().unwrap().0;
                    encrypt(
                        priv_proto,
                        &self.priv_kul,
                        self.engine_boots,
                        self.engine_time,
                        &salt,
                        &mut data_bytes,
                    )
                    .unwrap();
                    priv_params = salt.to_vec();
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
                        msg_id,
                        msg_max_size,
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
        let resp = self.recv_msg(ms).await?;
        Some(self.decode_reply(&resp))
    }

    fn decode_reply(&self, resp: &Message) -> Pdu {
        match &resp.data {
            MessageData::Plain(b) => ScopedPdu::from_bytes(b).unwrap().pdu,
            MessageData::Encrypted(b) => {
                let mut salt = [0u8; 8];
                salt.copy_from_slice(&resp.security.priv_params);
                let priv_proto = self.user.priv_.as_ref().unwrap().0;
                let mut buf = b.clone();
                decrypt(
                    priv_proto,
                    &self.priv_kul,
                    resp.security.engine_boots,
                    resp.security.engine_time,
                    &salt,
                    &mut buf,
                )
                .unwrap();
                ScopedPdu::from_bytes(&buf).unwrap().pdu
            }
        }
    }

    /// Proves the agent is still serving by issuing a correct request at the
    /// user's provisioned level and reading back the scalar value 7.
    async fn assert_alive(&mut self, level: SecurityLevel) {
        let pdu = Pdu {
            kind: PduKind::GetRequest,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(oid(SCALAR_OID))],
        };
        let r = self
            .send(pdu, level, true, 65_507, 1500)
            .await
            .expect("agent must still answer a correctly-authenticated request");
        assert_eq!(r.kind, PduKind::Response);
        assert_eq!(r.variable_bindings[0].value, Value::Integer(7));
    }
}

fn get_pdu(id: i32, names: &[&str]) -> Pdu {
    Pdu {
        kind: PduKind::GetRequest,
        request_id: id,
        error_status: 0,
        error_index: 0,
        variable_bindings: names.iter().map(|n| VarBind::null(oid(n))).collect(),
    }
}

// ---------------------------------------------------------------------------
// C1 — security-level downgrade is rejected (the exploit regressions).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plaintext_get_against_authpriv_user_is_rejected() {
    // THE EXPLOIT: an unauthenticated, plaintext (msgFlags=0) Get against a
    // user provisioned authPriv. Pre-fix this returned the scalar value with no
    // HMAC/no password. Post-fix it must be rejected — a reportable request
    // yields a usmStatsUnsupportedSecLevels Report, never a Response with data.
    let user = authpriv_user(false);
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let resp = client
        .send(
            get_pdu(10, &[SCALAR_OID]),
            SecurityLevel::NoAuthNoPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("reportable rejection should produce a Report-PDU");

    assert_eq!(
        resp.kind,
        PduKind::Report,
        "plaintext Get against an authPriv user must be rejected, not processed"
    );
    assert!(
        !resp
            .variable_bindings
            .iter()
            .any(|vb| vb.value == Value::Integer(7)),
        "the scalar value must NOT be leaked to an unauthenticated request"
    );

    let snap = agent.agent().counters_snapshot().await;
    assert!(snap.unsupported_sec_levels >= 1);

    client.assert_alive(SecurityLevel::AuthPriv).await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn plaintext_get_against_authpriv_user_nonreportable_is_dropped() {
    // Same downgrade but non-reportable: the agent must drop it silently (no
    // reply at all) — definitely not a Response carrying the value.
    let user = authpriv_user(false);
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let resp = client
        .send(
            get_pdu(11, &[SCALAR_OID]),
            SecurityLevel::NoAuthNoPriv,
            false,
            65_507,
            500,
        )
        .await;
    assert!(
        resp.is_none(),
        "non-reportable downgrade must be silently dropped"
    );

    client.assert_alive(SecurityLevel::AuthPriv).await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn plaintext_getbulk_against_authpriv_user_is_rejected() {
    // GetBulk variant of the exploit — also must never reach the walk path.
    let user = authpriv_user(false);
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let pdu = Pdu {
        kind: PduKind::GetBulkRequest,
        request_id: 12,
        error_status: 0,       // non-repeaters
        error_index: i32::MAX, // max-repetitions
        variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.50"))],
    };
    let resp = client
        .send(pdu, SecurityLevel::NoAuthNoPriv, true, 65_507, 1500)
        .await
        .expect("reportable rejection should produce a Report-PDU");
    assert_eq!(
        resp.kind,
        PduKind::Report,
        "plaintext GetBulk against an authPriv user must be rejected"
    );

    client.assert_alive(SecurityLevel::AuthPriv).await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn plaintext_get_against_authnopriv_user_is_rejected() {
    // authNoPriv user, plaintext noAuth request → must require at least auth.
    let user = authnopriv_user();
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let resp = client
        .send(
            get_pdu(13, &[SCALAR_OID]),
            SecurityLevel::NoAuthNoPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("reportable rejection should produce a Report-PDU");
    assert_eq!(resp.kind, PduKind::Report);
    assert!(!resp
        .variable_bindings
        .iter()
        .any(|vb| vb.value == Value::Integer(7)));

    client.assert_alive(SecurityLevel::AuthNoPriv).await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn authnopriv_downgrade_against_authpriv_user_is_rejected() {
    // A request that IS authenticated (valid HMAC) but NOT encrypted, against
    // an authPriv user. Pre-fix the agent accepted it (HMAC verified, but the
    // PDU sent in cleartext — a confidentiality downgrade). Post-fix the priv
    // requirement is a floor: it must be rejected. Proves decrypt is enforced.
    let user = authpriv_user(false);
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let resp = client
        .send(
            get_pdu(14, &[SCALAR_OID]),
            SecurityLevel::AuthNoPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("reportable rejection should produce a Report-PDU");
    assert_eq!(
        resp.kind,
        PduKind::Report,
        "authNoPriv downgrade against an authPriv user must be rejected"
    );
    assert!(!resp
        .variable_bindings
        .iter()
        .any(|vb| vb.value == Value::Integer(7)));

    client.assert_alive(SecurityLevel::AuthPriv).await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn unauthenticated_set_against_writable_authpriv_user_is_rejected() {
    // The SET half of C1: a writable authPriv user. An unauthenticated
    // plaintext SET must be rejected at the security-level floor and MUST NOT
    // mutate the OID (the SET path can no longer be reached below the required
    // level).
    let user = authpriv_user(true);
    let cell = IntCell {
        value: tokio::sync::Mutex::new(100),
    };
    let agent = spawn_agent_writable(&user, cell).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let set = Pdu {
        kind: PduKind::SetRequest,
        request_id: 15,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::new(oid(SCALAR_OID), Value::Integer(999))],
    };
    let resp = client
        .send(set, SecurityLevel::NoAuthNoPriv, true, 65_507, 1500)
        .await
        .expect("reportable rejection should produce a Report-PDU");
    assert_eq!(
        resp.kind,
        PduKind::Report,
        "unauthenticated SET against a writable authPriv user must be rejected"
    );

    // The OID must be unchanged: a correctly-authenticated Get still reads 100.
    let r = client
        .send(
            get_pdu(16, &[SCALAR_OID]),
            SecurityLevel::AuthPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("authPriv Get must succeed");
    assert_eq!(
        r.variable_bindings[0].value,
        Value::Integer(100),
        "the unauthenticated SET must not have mutated the OID"
    );

    agent.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// No regression: correctly-authenticated requests at the proper level succeed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn correct_authpriv_request_succeeds() {
    let user = authpriv_user(false);
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let r = client
        .send(
            get_pdu(20, &[SCALAR_OID]),
            SecurityLevel::AuthPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("authPriv Get must succeed");
    assert_eq!(r.kind, PduKind::Response);
    assert_eq!(r.variable_bindings[0].value, Value::Integer(7));

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn correct_authnopriv_request_succeeds() {
    let user = authnopriv_user();
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let r = client
        .send(
            get_pdu(21, &[SCALAR_OID]),
            SecurityLevel::AuthNoPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("authNoPriv Get must succeed");
    assert_eq!(r.kind, PduKind::Response);
    assert_eq!(r.variable_bindings[0].value, Value::Integer(7));

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn noauth_user_noauth_request_still_succeeds() {
    // A genuinely noAuthNoPriv user is unchanged by the floor (level ==
    // configured).
    let user = UsmUser::no_auth("public");
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let r = client
        .send(
            get_pdu(22, &[SCALAR_OID]),
            SecurityLevel::NoAuthNoPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("noAuthNoPriv Get must succeed for a noAuthNoPriv user");
    assert_eq!(r.kind, PduKind::Response);
    assert_eq!(r.variable_bindings[0].value, Value::Integer(7));

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn authenticated_set_at_proper_level_still_succeeds() {
    // No regression for legitimate writes: a writable authPriv user issuing a
    // correctly-encrypted SET at authPriv mutates the OID.
    let user = authpriv_user(true);
    let cell = IntCell {
        value: tokio::sync::Mutex::new(1),
    };
    let agent = spawn_agent_writable(&user, cell).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let set = Pdu {
        kind: PduKind::SetRequest,
        request_id: 23,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::new(oid(SCALAR_OID), Value::Integer(555))],
    };
    let r = client
        .send(set, SecurityLevel::AuthPriv, true, 65_507, 1500)
        .await
        .expect("authPriv SET must succeed");
    assert_eq!(r.kind, PduKind::Response);
    assert_eq!(r.error_status, 0, "legitimate SET must not error");

    let g = client
        .send(
            get_pdu(24, &[SCALAR_OID]),
            SecurityLevel::AuthPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("authPriv Get must succeed");
    assert_eq!(g.variable_bindings[0].value, Value::Integer(555));

    agent.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// Companion: handle_get response-size / work budget.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handle_get_response_size_is_bounded() {
    // A Get whose response would exceed the (small advertised) budget must be
    // bounded — the agent returns `tooBig` with no varbinds rather than
    // allocating/serving an oversized response. Each varbind here resolves to a
    // 4000-byte value, so two of them blow a 2 KiB budget.
    let user = authpriv_user(false);
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let r = client
        .send(
            get_pdu(30, &[BIG_OID, BIG_OID, BIG_OID]),
            SecurityLevel::AuthPriv,
            true,
            2048, // small advertised msgMaxSize -> small budget
            2000,
        )
        .await
        .expect("agent must reply (bounded), not spin/over-allocate");
    assert_eq!(r.kind, PduKind::Response);
    assert_eq!(
        r.error_status,
        ErrorStatus::TooBig as i32,
        "an oversized Get must be answered with tooBig"
    );
    assert!(
        r.variable_bindings.is_empty(),
        "tooBig response carries no varbinds"
    );

    client.assert_alive(SecurityLevel::AuthPriv).await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn handle_get_within_budget_returns_all_varbinds() {
    // No regression: a Get that fits the budget returns every requested
    // varbind.
    let user = authpriv_user(false);
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    let r = client
        .send(
            get_pdu(31, &[SCALAR_OID, SCALAR_OID]),
            SecurityLevel::AuthPriv,
            true,
            65_507,
            1500,
        )
        .await
        .expect("normal Get must succeed");
    assert_eq!(r.kind, PduKind::Response);
    assert_eq!(r.error_status, 0);
    assert_eq!(r.variable_bindings.len(), 2);
    assert_eq!(r.variable_bindings[0].value, Value::Integer(7));
    assert_eq!(r.variable_bindings[1].value, Value::Integer(7));

    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn agent_survives_repeated_downgrade_attempts() {
    // Liveness: hammer the agent with downgrade attempts; it must stay
    // responsive to a correctly-authenticated request throughout.
    let user = authpriv_user(false);
    let agent = spawn_agent(&user).await;
    let mut client = Client::new(agent.local_addr(), user).await;
    client.discover().await;

    for i in 0..8 {
        let _ = client
            .send(
                get_pdu(40 + i, &[SCALAR_OID]),
                SecurityLevel::NoAuthNoPriv,
                false,
                65_507,
                200,
            )
            .await;
    }
    client.assert_alive(SecurityLevel::AuthPriv).await;
    agent.shutdown().await.unwrap();
}
