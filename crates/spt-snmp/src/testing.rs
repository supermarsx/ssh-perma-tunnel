//! Test fixtures for `spt-snmp`.
//!
//! Gated behind the `testing` feature. Provides a localhost agent harness,
//! a minimal SNMPv3 client (USM-aware), the RFC 3414 §A.3 test vectors, and
//! a default user fixture.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::agent::{AgentBuilder, AgentHandle};
use crate::error::Result;
use crate::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_PRIV,
    FLAG_REPORTABLE, SECURITY_MODEL_USM,
};
use crate::pdu::{Pdu, PduKind};
use crate::usm::{
    auth_digest, decrypt, derive_keys, encrypt, AuthProtocol, PrivProtocol, SecretBytes,
    SecurityLevel, UsmUser,
};
use crate::value::VarBind;

/// Localhost SNMPv3 agent bound to `127.0.0.1:0`.
///
/// Wraps an [`AgentHandle`] with a stable accessor for the bound address.
/// The agent shuts down when dropped (the underlying `AgentHandle` aborts
/// the task on drop); call [`LocalhostAgent::shutdown`] for an awaited
/// graceful stop.
///
/// # Examples
///
/// ```no_run
/// use spt_snmp::testing::{fixtures, LocalhostAgent};
///
/// # async fn run() -> spt_snmp::Result<()> {
/// let agent = LocalhostAgent::ephemeral(fixtures::default_user()).await?;
/// let _addr = agent.addr();
/// agent.shutdown().await;
/// # Ok(()) }
/// ```
pub struct LocalhostAgent {
    handle: AgentHandle,
    addr: SocketAddr,
}

impl LocalhostAgent {
    /// Build and start an agent on `127.0.0.1:0` with the supplied user
    /// preloaded.
    ///
    /// # Errors
    /// Returns the underlying [`crate::Error`] if binding the socket or
    /// starting the agent fails.
    pub async fn ephemeral(user: UsmUser) -> Result<Self> {
        let bind: SocketAddr = "127.0.0.1:0".parse().expect("static parse");
        let handle = AgentBuilder::new().bind(bind).add_user(user).run().await?;
        let addr = handle.local_addr();
        Ok(Self { handle, addr })
    }

    /// Build and start an agent on `127.0.0.1:0` with extra configuration
    /// applied to the builder before `.run()`. The default user is added
    /// automatically.
    ///
    /// # Errors
    /// Returns the underlying [`crate::Error`] if binding fails.
    pub async fn ephemeral_with<F>(user: UsmUser, configure: F) -> Result<Self>
    where
        F: FnOnce(AgentBuilder) -> AgentBuilder,
    {
        let bind: SocketAddr = "127.0.0.1:0".parse().expect("static parse");
        let builder = AgentBuilder::new().bind(bind).add_user(user);
        let builder = configure(builder);
        let handle = builder.run().await?;
        let addr = handle.local_addr();
        Ok(Self { handle, addr })
    }

    /// Address actually bound (with the kernel-assigned port).
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Borrow the underlying [`AgentHandle`].
    #[must_use]
    pub fn handle(&self) -> &AgentHandle {
        &self.handle
    }

    /// Shut down gracefully, awaiting the agent task.
    pub async fn shutdown(self) {
        let _ = self.handle.shutdown().await;
    }
}

/// Minimal SNMPv3 USM client suitable for round-trip tests against
/// [`LocalhostAgent`]. Performs engine-id discovery on construction, then
/// sends `Get`/`GetNext` requests at the configured security level.
///
/// This is the same client lifted from the integration test rig, exposed so
/// downstream crates exercising SNMP integrations don't need to reimplement
/// it.
///
/// # Examples
///
/// ```no_run
/// use spt_snmp::testing::{fixtures, LocalhostAgent, TestSnmpClient};
///
/// # async fn run() -> spt_snmp::Result<()> {
/// let agent = LocalhostAgent::ephemeral(fixtures::default_user()).await?;
/// let mut client = TestSnmpClient::new(agent.addr(), fixtures::default_user()).await;
/// client.discover().await;
/// # Ok(()) }
/// ```
pub struct TestSnmpClient {
    socket: UdpSocket,
    target: SocketAddr,
    user: UsmUser,
    auth_kul: Vec<u8>,
    priv_kul: Vec<u8>,
    engine_id: Vec<u8>,
    next_id: i32,
    /// Engine boots learned from the discovery Report.
    pub engine_boots: u32,
    /// Engine time learned from the discovery Report.
    pub engine_time: u32,
}

impl TestSnmpClient {
    /// Bind a UDP socket on `127.0.0.1:0` aimed at `target`.
    ///
    /// # Panics
    /// Panics if the loopback bind fails, which would indicate a broken
    /// network stack rather than a test failure.
    pub async fn new(target: SocketAddr, user: UsmUser) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("loopback bind for snmp test client");
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

    /// Perform RFC 3414 §4 engine-id discovery and derive localized USM keys.
    ///
    /// # Panics
    /// Panics on UDP I/O errors, response-parse errors, or timeout (3s).
    /// These are programming errors in the test scaffold rather than
    /// recoverable conditions.
    pub async fn discover(&mut self) {
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
            data: MessageData::Plain(scoped.to_bytes().expect("encode discovery")),
        };
        let bytes = msg.to_bytes().expect("encode discovery message");
        self.socket
            .send_to(&bytes, self.target)
            .await
            .expect("send discovery");

        let mut buf = vec![0u8; 65_535];
        let (n, _) = timeout(Duration::from_secs(3), self.socket.recv_from(&mut buf))
            .await
            .expect("discovery timeout")
            .expect("discovery recv");
        let resp = Message::from_bytes(&buf[..n]).expect("parse discovery response");
        self.engine_id.clone_from(&resp.security.engine_id);
        self.engine_boots = resp.security.engine_boots;
        self.engine_time = resp.security.engine_time;
        let (a, p) = derive_keys(&self.user, &self.engine_id);
        self.auth_kul = a;
        self.priv_kul = p;
    }

    /// Allocate a fresh request-id.
    pub fn alloc_id(&mut self) -> i32 {
        self.next_id += 1;
        self.next_id
    }

    /// Borrow the discovered engine-id (empty before [`Self::discover`]).
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    /// Send a single PDU at `level` and return the response PDU.
    ///
    /// # Panics
    /// Panics on I/O errors, response decryption failures, auth-tag
    /// mismatches, or timeout (3s) — see notes on [`Self::discover`].
    pub async fn request(&mut self, pdu: Pdu, level: SecurityLevel) -> Pdu {
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: vec![],
            pdu,
        };
        let scoped_bytes = scoped.to_bytes().expect("encode scoped");
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
                m.to_bytes().expect("encode noAuthNoPriv message")
            }
            SecurityLevel::AuthNoPriv | SecurityLevel::AuthPriv => {
                let auth_proto = self
                    .user
                    .auth
                    .as_ref()
                    .expect("auth-required user must have auth_proto")
                    .0;
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
                    let priv_proto = self
                        .user
                        .priv_
                        .as_ref()
                        .expect("authPriv user must have priv_proto")
                        .0;
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
                    .expect("encrypt scoped PDU");
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
                let pre = m.to_bytes().expect("pre-auth encode");
                let tag = auth_digest(auth_proto, &self.auth_kul, &pre).expect("auth digest");
                sec.auth_params = tag;
                m.security = sec;
                m.to_bytes().expect("auth message encode")
            }
        };
        self.socket
            .send_to(&bytes, self.target)
            .await
            .expect("send request");

        let mut buf = vec![0u8; 65_535];
        let (n, _) = timeout(Duration::from_secs(3), self.socket.recv_from(&mut buf))
            .await
            .expect("response timeout")
            .expect("recv response");
        let mut resp = Message::from_bytes(&buf[..n]).expect("parse response");

        let resp_level = SecurityLevel::from_flags(resp.global.msg_flags).expect("level");
        match resp_level {
            SecurityLevel::NoAuthNoPriv => match &resp.data {
                MessageData::Plain(b) => ScopedPdu::from_bytes(b).expect("parse scoped").pdu,
                MessageData::Encrypted(_) => panic!("expected plaintext response"),
            },
            SecurityLevel::AuthNoPriv | SecurityLevel::AuthPriv => {
                let (auth_proto, _) = self
                    .user
                    .auth
                    .as_ref()
                    .expect("auth_proto on auth response");
                let received = resp.security.auth_params.clone();
                resp.security.auth_params = vec![0u8; auth_proto.digest_len()];
                let serialized = resp.to_bytes().expect("re-encode for auth");
                let computed =
                    auth_digest(*auth_proto, &self.auth_kul, &serialized).expect("auth digest");
                assert_eq!(received, computed, "response auth digest mismatch");
                resp.security.auth_params = received;

                if resp_level == SecurityLevel::AuthPriv {
                    let (priv_proto, _) = self.user.priv_.as_ref().expect("priv_proto on authPriv");
                    let mut salt = [0u8; 8];
                    salt.copy_from_slice(&resp.security.priv_params);
                    let mut buf = match resp.data {
                        MessageData::Encrypted(b) => b,
                        MessageData::Plain(_) => panic!("expected encrypted authPriv response"),
                    };
                    decrypt(
                        *priv_proto,
                        &self.priv_kul,
                        resp.security.engine_boots,
                        resp.security.engine_time,
                        &salt,
                        &mut buf,
                    )
                    .expect("decrypt response");
                    ScopedPdu::from_bytes(&buf).expect("parse scoped").pdu
                } else {
                    match &resp.data {
                        MessageData::Plain(b) => {
                            ScopedPdu::from_bytes(b).expect("parse scoped").pdu
                        }
                        MessageData::Encrypted(_) => panic!("expected plaintext authNoPriv"),
                    }
                }
            }
        }
    }

    /// Convenience: send a `Get` for `oid` at `level` and return the first
    /// returned [`VarBind`].
    ///
    /// # Panics
    /// Panics if the response contains zero variable-bindings (which would
    /// indicate a malformed reply from the agent).
    pub async fn get(&mut self, oid: crate::ObjectIdentifier, level: SecurityLevel) -> VarBind {
        let req = Pdu {
            kind: PduKind::GetRequest,
            request_id: self.alloc_id(),
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(oid)],
        };
        let resp = self.request(req, level).await;
        resp.variable_bindings
            .into_iter()
            .next()
            .expect("at least one varbind in response")
    }
}

/// RFC 3414 §A.3 test vectors used for regression-locking the password-to-key
/// + localization implementation.
#[derive(Debug, Clone)]
pub struct UsmTestVectors {
    /// Password used by all §A.3 vectors.
    pub password: &'static [u8],
    /// Authoritative engine-id used by §A.3 vectors (`00…02` form).
    pub engine_id: Vec<u8>,
    /// Expected SHA-1 localized key (§A.3.1).
    pub sha1_localized: Vec<u8>,
    /// Expected MD5 localized key (§A.3.2).
    pub md5_localized: Vec<u8>,
}

/// Returns the RFC 3414 §A.3 test vectors.
///
/// # Examples
///
/// ```
/// use spt_snmp::testing::usm_test_keys;
/// use spt_snmp::usm::{localize_key, password_to_key, AuthProtocol};
///
/// let v = usm_test_keys();
/// let ku = password_to_key(AuthProtocol::HmacSha1, v.password);
/// let kul = localize_key(AuthProtocol::HmacSha1, &ku, &v.engine_id);
/// assert_eq!(kul, v.sha1_localized);
/// ```
#[must_use]
pub fn usm_test_keys() -> UsmTestVectors {
    UsmTestVectors {
        password: b"maplesyrup",
        engine_id: hex_decode("000000000000000000000002"),
        sha1_localized: hex_decode("6695febc9288e36282235fc7151f128497b38f3f"),
        md5_localized: hex_decode("526f5eed9fcce26f8964c2930787d82b"),
    }
}

/// Decode a hex string into bytes. Panics on malformed input — only used
/// internally with constants.
fn hex_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_nibble(bytes[i]);
        let lo = hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => panic!("invalid hex nibble {b:#x}"),
    }
}

/// Pre-built [`UsmUser`] fixtures used by tests across crates.
pub mod fixtures {
    use super::{AuthProtocol, PrivProtocol, SecretBytes, UsmUser};

    /// Default `authPriv` user used by [`super::LocalhostAgent::ephemeral`]:
    /// SHA-256 auth, AES-128 priv, fixed long passphrases. Deterministic and
    /// safe to compare against in tests.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_snmp::testing::fixtures;
    /// let u = fixtures::default_user();
    /// assert_eq!(u.name, "spt-test");
    /// ```
    #[must_use]
    pub fn default_user() -> UsmUser {
        UsmUser::auth_priv(
            "spt-test",
            AuthProtocol::HmacSha256,
            SecretBytes::from("spt-test-auth-passphrase-very-long"),
            PrivProtocol::Aes128,
            SecretBytes::from("spt-test-priv-passphrase-very-long"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usm::{localize_key, password_to_key};
    use crate::value::Value;
    use crate::ConstScalar;

    #[tokio::test]
    async fn vectors_match_rfc_3414() {
        let v = usm_test_keys();
        let ku_sha1 = password_to_key(AuthProtocol::HmacSha1, v.password);
        let kul_sha1 = localize_key(AuthProtocol::HmacSha1, &ku_sha1, &v.engine_id);
        assert_eq!(kul_sha1, v.sha1_localized);
        let ku_md5 = password_to_key(AuthProtocol::HmacMd5, v.password);
        let kul_md5 = localize_key(AuthProtocol::HmacMd5, &ku_md5, &v.engine_id);
        assert_eq!(kul_md5, v.md5_localized);
    }

    #[tokio::test]
    async fn localhost_agent_round_trip_authpriv_get() {
        let user = fixtures::default_user();
        let oid: crate::ObjectIdentifier = "1.3.6.1.4.1.99999.1.1.0".parse().unwrap();
        let oid_for_register = oid.clone();
        let agent = LocalhostAgent::ephemeral_with(user.clone(), |b| {
            b.add_scalar(
                oid_for_register,
                ConstScalar::new(Value::OctetString(b"hello".to_vec())),
            )
        })
        .await
        .unwrap();

        let mut client = TestSnmpClient::new(agent.addr(), user).await;
        client.discover().await;
        assert!(!client.engine_id().is_empty());

        let vb = client.get(oid, SecurityLevel::AuthPriv).await;
        assert_eq!(vb.value, Value::OctetString(b"hello".to_vec()));

        agent.shutdown().await;
    }

    #[test]
    fn default_user_is_auth_priv() {
        let u = fixtures::default_user();
        assert_eq!(u.security_level(), SecurityLevel::AuthPriv);
    }
}
