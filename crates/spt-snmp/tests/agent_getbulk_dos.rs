#![allow(
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::assigning_clones
)]
//! Regression tests for the GetBulk amplification / OOM DoS (offensive finding
//! O2), driven through the agent's real UDP dispatch path.
//!
//! The vulnerability: `max-repetitions` (an `i32` straight off the wire, up to
//! `i32::MAX`) drove `for _ in 0..max_rep { ... }` pushing varbinds into an
//! UNcapped `Vec`. With a registered table subtree that always yields a
//! successor, one ~50-byte UDP datagram makes the agent allocate/spin
//! enormously → OOM/abort (and under `panic = "abort"` the whole process dies).
//!
//! The headline property proven here is the same liveness invariant as
//! `agent_negative.rs`: **poison packet in → bounded response out → agent still
//! alive and serving the next valid request**. Each test fires a hostile
//! GetBulk and then proves the agent answers a normal Get, all within tight
//! timeouts (a spinning/allocating agent would blow the timeout or abort).

use std::net::SocketAddr;
use std::time::Duration;

use spt_snmp::agent::{MAX_BULK_REPETITIONS, MAX_DATAGRAM};
use spt_snmp::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_REPORTABLE,
    SECURITY_MODEL_USM,
};
use spt_snmp::mib::TableHandler;
use spt_snmp::pdu::{Pdu, PduKind};
use spt_snmp::usm::{auth_digest, derive_keys, AuthProtocol, SecretBytes, UsmUser};
use spt_snmp::value::{Value, VarBind};
use spt_snmp::{AgentBuilder, AgentHandle, ConstScalar, ObjectIdentifier, Result};
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

/// A table whose subtree is effectively INFINITE: `next(after)` always returns
/// a strictly-greater OID, so the GetBulk repeating loop would never terminate
/// on its own. Each row carries a non-trivial OCTET STRING so an unbounded walk
/// would also grow the response quickly. This is the worst case for the
/// amplification bug — without the clamp/budget the agent never stops.
#[derive(Clone)]
struct InfiniteTable {
    prefix: ObjectIdentifier,
}

#[async_trait::async_trait]
impl TableHandler for InfiniteTable {
    async fn next(
        &self,
        after: Option<&ObjectIdentifier>,
    ) -> Result<Option<(ObjectIdentifier, Value)>> {
        // Determine the next index. Start at 1 on the first walk; otherwise take
        // the last arc of `after` and add one.
        let next_idx = match after {
            None => 1u32,
            Some(a) => {
                if a.starts_with(&self.prefix) && a.arcs().len() > self.prefix.arcs().len() {
                    a.arcs().last().copied().unwrap_or(0).saturating_add(1)
                } else {
                    1
                }
            }
        };
        let mut arcs: Vec<u32> = self.prefix.arcs().to_vec();
        arcs.push(next_idx);
        let oid = ObjectIdentifier::from(arcs);
        // 64-byte value so a runaway walk would balloon the response fast.
        Ok(Some((oid, Value::OctetString(vec![0xAB; 64]))))
    }
}

async fn spawn_agent_with_table(user: &UsmUser) -> AgentHandle {
    AgentBuilder::new()
        .documentation_enterprise_pen()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_user(user.clone())
        .add_scalar(
            oid("1.3.6.1.4.1.32473.1.1.0"),
            ConstScalar::new(Value::Integer(7)),
        )
        .add_table(
            oid("1.3.6.1.4.1.32473.2"),
            InfiniteTable {
                prefix: oid("1.3.6.1.4.1.32473.2"),
            },
        )
        .run()
        .await
        .unwrap()
}

/// Minimal authNoPriv probe: engine-id discovery, a liveness Get, and a helper
/// to send an authenticated GetBulk and read the response.
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

    async fn recv_within(&self, ms: u64) -> Option<Message> {
        let mut buf = vec![0u8; 65_535];
        match timeout(Duration::from_millis(ms), self.socket.recv_from(&mut buf)).await {
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
                msg_max_size: MAX_DATAGRAM as i32,
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
            .recv_within(500)
            .await
            .expect("discovery must get a Report reply");
        self.engine_id = resp.security.engine_id.clone();
        self.engine_boots = resp.security.engine_boots;
        self.engine_time = resp.security.engine_time;
        let (a, _) = derive_keys(&self.user, &self.engine_id);
        self.auth_kul = a;
    }

    /// Builds an authenticated message wrapping `pdu` at this probe's engine
    /// context, advertising `msg_max_size`.
    fn build_auth_msg(&self, pdu: Pdu, msg_id: i32, msg_max_size: i32) -> Vec<u8> {
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: vec![],
            pdu,
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
                msg_id,
                msg_max_size,
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
        m.to_bytes().unwrap()
    }

    /// Sends an authenticated GetBulk and returns the response PDU (decoded).
    /// Times out after `ms` — a runaway agent never returns in time.
    async fn get_bulk(
        &self,
        non_repeaters: i32,
        max_repetitions: i32,
        names: &[ObjectIdentifier],
        msg_id: i32,
        msg_max_size: i32,
        ms: u64,
    ) -> Option<Pdu> {
        let pdu = Pdu {
            kind: PduKind::GetBulkRequest,
            request_id: msg_id,
            error_status: non_repeaters,
            error_index: max_repetitions,
            variable_bindings: names.iter().cloned().map(VarBind::null).collect(),
        };
        let bytes = self.build_auth_msg(pdu, msg_id, msg_max_size);
        self.socket.send_to(&bytes, self.target).await.unwrap();
        let resp = self.recv_within(ms).await?;
        let plain = match &resp.data {
            MessageData::Plain(b) => b.clone(),
            MessageData::Encrypted(_) => panic!("unexpected encrypted reply"),
        };
        Some(ScopedPdu::from_bytes(&plain).unwrap().pdu)
    }

    /// Performs a normal authNoPriv Get and asserts the expected value, proving
    /// the agent process is still alive and serving.
    async fn assert_alive(&mut self) {
        let pdu = Pdu {
            kind: PduKind::GetRequest,
            request_id: 4242,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(oid("1.3.6.1.4.1.32473.1.1.0"))],
        };
        let bytes = self.build_auth_msg(pdu, 4242, MAX_DATAGRAM as i32);
        self.socket.send_to(&bytes, self.target).await.unwrap();
        let resp = self
            .recv_within(1000)
            .await
            .expect("agent must still respond to a valid request");
        let plain = match &resp.data {
            MessageData::Plain(b) => b.clone(),
            MessageData::Encrypted(_) => panic!("unexpected encrypted reply"),
        };
        let pdu = ScopedPdu::from_bytes(&plain).unwrap().pdu;
        assert_eq!(pdu.kind, PduKind::Response);
        assert_eq!(pdu.variable_bindings[0].value, Value::Integer(7));
    }
}

/// Re-encodes a Response PDU's varbind list and returns its byte length, used
/// to assert the response stayed within the datagram cap.
fn encoded_varbinds_len(pdu: &Pdu) -> usize {
    use spt_snmp::ber::Encoder;
    let mut e = Encoder::new();
    pdu.encode(&mut e).unwrap();
    e.as_slice().len()
}

// --- The DoS regression: i32::MAX max-repetitions over an infinite table. ---

#[tokio::test]
async fn get_bulk_max_repetitions_i32_max_is_bounded_and_agent_survives() {
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    // The poison packet: max-repetitions = i32::MAX over the infinite table.
    // Pre-fix this looped ~2.1 billion times into an uncapped Vec → OOM/abort.
    // It must now return promptly with a BOUNDED response.
    let resp = probe
        .get_bulk(
            0,
            i32::MAX,
            &[oid("1.3.6.1.4.1.32473.2")],
            10,
            MAX_DATAGRAM as i32,
            3000,
        )
        .await
        .expect("agent must return a bounded GetBulk response, not spin/OOM");

    assert_eq!(resp.kind, PduKind::Response);
    // Repetitions clamped: at most MAX_BULK_REPETITIONS varbinds for one cursor.
    assert!(
        resp.variable_bindings.len() <= MAX_BULK_REPETITIONS,
        "expected <= {} varbinds, got {}",
        MAX_BULK_REPETITIONS,
        resp.variable_bindings.len()
    );
    // And the encoded response stays within the datagram cap.
    assert!(
        encoded_varbinds_len(&resp) <= MAX_DATAGRAM,
        "response must fit the datagram cap"
    );

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_negative_max_repetitions_is_safe() {
    // RFC says non-negative, but the wire carries an i32. A negative value must
    // not panic or underflow; it yields zero repetitions.
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            0,
            -1,
            &[oid("1.3.6.1.4.1.32473.2")],
            11,
            MAX_DATAGRAM as i32,
            2000,
        )
        .await
        .expect("negative max-repetitions must yield a prompt response");
    assert_eq!(resp.kind, PduKind::Response);
    // Zero repetitions and zero non-repeaters → empty bindings.
    assert!(resp.variable_bindings.is_empty());

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_i32_min_max_repetitions_is_safe() {
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            0,
            i32::MIN,
            &[oid("1.3.6.1.4.1.32473.2")],
            12,
            MAX_DATAGRAM as i32,
            2000,
        )
        .await
        .expect("i32::MIN max-repetitions must yield a prompt response");
    assert_eq!(resp.kind, PduKind::Response);
    assert!(resp.variable_bindings.is_empty());

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_zero_max_repetitions_is_safe() {
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            0,
            0,
            &[oid("1.3.6.1.4.1.32473.2")],
            13,
            MAX_DATAGRAM as i32,
            2000,
        )
        .await
        .expect("zero max-repetitions must yield a prompt response");
    assert_eq!(resp.kind, PduKind::Response);
    assert!(resp.variable_bindings.is_empty());

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_oversized_non_repeaters_is_safe() {
    // non-repeaters = i32::MAX but only one varbind sent. It must clamp to the
    // varbinds actually present (1) and not over-iterate.
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            i32::MAX,
            0,
            &[oid("1.3.6.1.4.1.32473.2")],
            14,
            MAX_DATAGRAM as i32,
            2000,
        )
        .await
        .expect("oversized non-repeaters must yield a prompt response");
    assert_eq!(resp.kind, PduKind::Response);
    // One non-repeating successor for the single varbind; max_rep=0 so no
    // repeating part.
    assert_eq!(resp.variable_bindings.len(), 1);
    assert!(encoded_varbinds_len(&resp) <= MAX_DATAGRAM);

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_both_counts_i32_max_is_bounded() {
    // Worst case: both non-repeaters AND max-repetitions at i32::MAX, with two
    // varbinds over the infinite table.
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            i32::MAX,
            i32::MAX,
            &[oid("1.3.6.1.4.1.32473.2"), oid("1.3.6.1.4.1.32473.2.0")],
            15,
            MAX_DATAGRAM as i32,
            3000,
        )
        .await
        .expect("agent must bound the response and reply promptly");
    assert_eq!(resp.kind, PduKind::Response);
    assert!(
        encoded_varbinds_len(&resp) <= MAX_DATAGRAM,
        "response must fit the datagram cap"
    );

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_small_msg_max_size_shrinks_response() {
    // A peer advertising a tiny msgMaxSize must get a correspondingly small
    // response — the byte cap honours min(MAX_BULK_RESPONSE_BYTES, msgMaxSize).
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            0,
            i32::MAX,
            &[oid("1.3.6.1.4.1.32473.2")],
            16,
            1024, // small advertised msgMaxSize
            3000,
        )
        .await
        .expect("agent must reply within the small budget");
    assert_eq!(resp.kind, PduKind::Response);
    // The accumulated varbinds must fit comfortably under the advertised size.
    assert!(
        encoded_varbinds_len(&resp) <= 1024,
        "response varbinds must respect the advertised msgMaxSize budget, got {}",
        encoded_varbinds_len(&resp)
    );
    // And it must still return at least one varbind (forward progress).
    assert!(!resp.variable_bindings.is_empty());

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn legitimate_small_get_bulk_returns_expected_varbinds() {
    // Behaviour preservation: a normal GetBulk with a small max-repetitions
    // returns exactly that many successive rows from the table.
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            0,
            5,
            &[oid("1.3.6.1.4.1.32473.2")],
            17,
            MAX_DATAGRAM as i32,
            2000,
        )
        .await
        .expect("normal GetBulk must return promptly");
    assert_eq!(resp.kind, PduKind::Response);
    // Exactly 5 repetitions over the single cursor.
    assert_eq!(resp.variable_bindings.len(), 5);
    // Rows are the first five entries of the infinite table.
    assert_eq!(resp.variable_bindings[0].name, oid("1.3.6.1.4.1.32473.2.1"));
    assert_eq!(resp.variable_bindings[4].name, oid("1.3.6.1.4.1.32473.2.5"));

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_with_non_repeaters_and_repetitions_ordering() {
    // A two-varbind request: one non-repeating scalar successor plus repeating
    // table walk. Verifies normal mixed-mode GetBulk still works after the fix.
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            1, // first varbind non-repeating
            3, // 3 repetitions of the second
            &[
                oid("1.3.6.1.4.1.32473.1.0"), // before the scalar 1.1.0
                oid("1.3.6.1.4.1.32473.2"),   // table cursor
            ],
            18,
            MAX_DATAGRAM as i32,
            2000,
        )
        .await
        .expect("mixed GetBulk must return promptly");
    assert_eq!(resp.kind, PduKind::Response);
    // 1 non-repeater + 3 repetitions = 4 varbinds.
    assert_eq!(resp.variable_bindings.len(), 4);
    // First binding is the scalar successor 1.1.0.
    assert_eq!(
        resp.variable_bindings[0].name,
        oid("1.3.6.1.4.1.32473.1.1.0")
    );
    // Remaining are the first three table rows.
    assert_eq!(resp.variable_bindings[1].name, oid("1.3.6.1.4.1.32473.2.1"));
    assert_eq!(resp.variable_bindings[3].name, oid("1.3.6.1.4.1.32473.2.3"));

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn rapid_fire_poison_get_bulks_agent_stays_alive() {
    // Fire several i32::MAX GetBulks back-to-back; the agent must stay
    // responsive throughout (no cumulative memory blowup, no abort).
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    for i in 0..5 {
        let resp = probe
            .get_bulk(
                0,
                i32::MAX,
                &[oid("1.3.6.1.4.1.32473.2")],
                100 + i,
                MAX_DATAGRAM as i32,
                3000,
            )
            .await
            .expect("each poison GetBulk must return bounded and promptly");
        assert_eq!(resp.kind, PduKind::Response);
        assert!(resp.variable_bindings.len() <= MAX_BULK_REPETITIONS);
    }

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_bulk_response_pdu_encodes_within_datagram() {
    // Explicit end-to-end byte-cap assertion: even at i32::MAX repetitions with
    // 64-byte values, the produced Response PDU encodes within MAX_DATAGRAM.
    let user = test_user();
    let agent = spawn_agent_with_table(&user).await;
    let mut probe = Probe::new(agent.local_addr(), user).await;
    probe.discover().await;

    let resp = probe
        .get_bulk(
            0,
            i32::MAX,
            &[oid("1.3.6.1.4.1.32473.2")],
            200,
            MAX_DATAGRAM as i32,
            3000,
        )
        .await
        .expect("bounded response expected");
    let len = encoded_varbinds_len(&resp);
    assert!(len <= MAX_DATAGRAM, "encoded response {len} exceeds cap");
    assert!(len > 0);

    probe.assert_alive().await;
    agent.shutdown().await.unwrap();
}
