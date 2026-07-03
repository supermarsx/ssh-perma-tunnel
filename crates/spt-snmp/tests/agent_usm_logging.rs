//! USM authentication-failure logging (audit-logging CRIT #3).
//!
//! Before this wiring, an auth failure only bumped an opaque `usmStats*`
//! counter — brute-force / replay / spoofing against the SNMP agent was
//! invisible in the log stream. These tests assert the agent now emits a
//! structured `WARN` at the failure site carrying the peer, the (untrusted,
//! escaped) user name, and a stable failure `reason` — and NEVER any secret /
//! key / digest bytes.
//!
//! They FAIL against the pre-fix dead state (no WARN was emitted).

use std::io::Write;
use std::sync::{Arc, Mutex};

use spt_snmp::testing::{LocalhostAgent, TestSnmpClient};
use spt_snmp::value::VarBind;
use spt_snmp::{
    AuthProtocol, ObjectIdentifier, Pdu, PduKind, PrivProtocol, SecretBytes, SecurityLevel, UsmUser,
};

/// A `MakeWriter` that appends every formatted log line to a shared buffer so
/// the test can assert on the emitted structured fields.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(SharedBuf(buf.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (buf, guard)
}

fn logged(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(buf.lock().unwrap().clone()).unwrap()
}

/// A `WrongDigest` failure (right user, wrong password) must be logged with the
/// peer, user, and `reason = "wrong-digest"`.
#[tokio::test(flavor = "current_thread")]
async fn wrong_digest_emits_warn_with_peer_user_reason() {
    let (buf, _guard) = capture();

    // Agent user `alice` with password P1.
    let agent_user = UsmUser::auth_priv(
        "alice",
        AuthProtocol::HmacSha256,
        SecretBytes::from("agent-side-passphrase-very-long"),
        PrivProtocol::Aes128,
        SecretBytes::from("agent-side-priv-passphrase-long"),
    );
    let agent = LocalhostAgent::ephemeral(agent_user).await.unwrap();

    // Client claims `alice` but with a DIFFERENT password → HMAC mismatch.
    let client_user = UsmUser::auth_priv(
        "alice",
        AuthProtocol::HmacSha256,
        SecretBytes::from("WRONG-client-passphrase-very-long"),
        PrivProtocol::Aes128,
        SecretBytes::from("WRONG-client-priv-passphrase-long"),
    );
    let mut client = TestSnmpClient::new(agent.addr(), client_user).await;
    client.discover().await;

    let oid: ObjectIdentifier = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let pdu = Pdu {
        kind: PduKind::GetRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid)],
    };
    // The agent replies with a usmStats Report at noAuthNoPriv; the client does
    // not panic on it.
    let _resp = client.request(pdu, SecurityLevel::AuthPriv).await;

    let out = logged(&buf);
    assert!(
        out.contains("snmp usm authentication failed"),
        "auth failure not logged; captured=\n{out}"
    );
    assert!(
        out.contains("wrong-digest"),
        "reason missing; captured=\n{out}"
    );
    assert!(out.contains("alice"), "user missing; captured=\n{out}");
    assert!(out.contains("127.0.0.1"), "peer missing; captured=\n{out}");

    // No secret material may appear in the log.
    assert!(!out.contains("WRONG-client-passphrase-very-long"));
    assert!(!out.contains("agent-side-passphrase-very-long"));

    agent.shutdown().await;
}

/// An `UnknownUserName` failure (user the agent never provisioned) must be
/// logged with `reason = "unknown-user"`.
#[tokio::test(flavor = "current_thread")]
async fn unknown_user_emits_warn() {
    let (buf, _guard) = capture();

    let agent_user = UsmUser::auth_only(
        "known",
        AuthProtocol::HmacSha256,
        SecretBytes::from("agent-side-passphrase-very-long"),
    );
    let agent = LocalhostAgent::ephemeral(agent_user).await.unwrap();

    let client_user = UsmUser::auth_only(
        "intruder",
        AuthProtocol::HmacSha256,
        SecretBytes::from("some-passphrase-that-is-long-eno"),
    );
    let mut client = TestSnmpClient::new(agent.addr(), client_user).await;
    client.discover().await;

    let oid: ObjectIdentifier = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let pdu = Pdu {
        kind: PduKind::GetRequest,
        request_id: client.alloc_id(),
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(oid)],
    };
    let _resp = client.request(pdu, SecurityLevel::AuthNoPriv).await;

    let out = logged(&buf);
    assert!(
        out.contains("snmp usm authentication failed"),
        "auth failure not logged; captured=\n{out}"
    );
    assert!(
        out.contains("unknown-user"),
        "reason missing; captured=\n{out}"
    );
    assert!(out.contains("intruder"), "user missing; captured=\n{out}");

    agent.shutdown().await;
}
