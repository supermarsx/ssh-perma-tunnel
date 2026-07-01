//! Outbound `SNMPv2-Trap` sender.
//!
//! Each [`TrapSender`] targets a single destination. Per RFC 3414 §3.1 the
//! sender is the *authoritative* engine for the security parameters in a
//! trap, so the engine id, boots and time used in the message are ours.

use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::engine::{generate_engine_id, EngineClock, EngineId};
use crate::error::{Error, Result, UsmError};
use crate::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_PRIV,
    SECURITY_MODEL_USM,
};
use crate::oid::ObjectIdentifier;
use crate::pdu::{Pdu, PduKind};
use crate::usm::{
    auth_digest, derive_keys, encrypt, AuthProtocol, PrivProtocol, SecurityLevel, UsmUser,
};
use crate::value::{Value, VarBind};

/// SNMPv2 standard `sysUpTime.0` OID.
pub const SYS_UPTIME_OID: &str = "1.3.6.1.2.1.1.3.0";
/// SNMPv2 standard `snmpTrapOID.0` OID.
pub const SNMP_TRAP_OID_OID: &str = "1.3.6.1.6.3.1.1.4.1.0";

/// Outbound trap sender.
///
/// # Examples
///
/// ```no_run
/// use spt_snmp::{TrapSender, UsmUser, AuthProtocol, PrivProtocol, SecretBytes,
///                ObjectIdentifier, Value, VarBind};
///
/// # async fn run() -> spt_snmp::Result<()> {
/// let user = UsmUser::auth_priv(
///     "trapuser",
///     AuthProtocol::HmacSha256,
///     SecretBytes::from("auth-pass-very-long"),
///     PrivProtocol::Aes128,
///     SecretBytes::from("priv-pass-very-long"),
/// );
/// let sender = TrapSender::new("127.0.0.1:162".parse().unwrap(), user).await?;
/// sender
///     .send(
///         "1.3.6.1.4.1.32473.0.1".parse::<ObjectIdentifier>()?,
///         vec![],
///     )
///     .await?;
/// # Ok(()) }
/// ```
pub struct TrapSender {
    socket: UdpSocket,
    dest: SocketAddr,
    engine_id: EngineId,
    clock: EngineClock,
    user: UsmUser,
    auth_kul: Vec<u8>,
    priv_kul: Vec<u8>,
    msg_id: Mutex<i32>,
}

impl std::fmt::Debug for TrapSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrapSender")
            .field("dest", &self.dest)
            .field("engine_id", &self.engine_id)
            .field("user", &self.user.name)
            // Never render the derived localized key material. Emit explicit
            // redaction markers so the omission is intentional and testable
            // (F-T2): a future change that swaps a marker for the real bytes
            // is caught by `debug_redacts_credentials`.
            .field("auth_kul", &"<redacted>")
            .field("priv_kul", &"<redacted>")
            .finish()
    }
}

impl TrapSender {
    /// Builds a trap sender that auto-generates an engine id using the default
    /// spt enterprise PEN. Use [`TrapSender::with_engine_id`] to override.
    pub async fn new(dest: SocketAddr, user: UsmUser) -> Result<Self> {
        let engine_id = generate_engine_id(crate::agent::DOCUMENTATION_ENTERPRISE_PEN);
        Self::with_engine_id(dest, user, engine_id).await
    }

    /// Builds a trap sender with an explicit engine id and user.
    pub async fn with_engine_id(
        dest: SocketAddr,
        user: UsmUser,
        engine_id: EngineId,
    ) -> Result<Self> {
        // Bind an ephemeral source port. Match v4/v6 family with the destination.
        let bind: SocketAddr = match dest {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("v4 wildcard parses"),
            SocketAddr::V6(_) => "[::]:0".parse().expect("v6 wildcard parses"),
        };
        let socket = UdpSocket::bind(bind).await?;
        let (auth_kul, priv_kul) = derive_keys(&user, engine_id.as_bytes());
        Ok(Self {
            socket,
            dest,
            engine_id,
            clock: EngineClock::new(1),
            user,
            auth_kul,
            priv_kul,
            msg_id: Mutex::new(1),
        })
    }

    /// Sends an `SNMPv2-Trap-PDU` carrying `(sysUpTime.0, TimeTicks)` and
    /// `(snmpTrapOID.0, OID(trap_oid))` followed by `extra_varbinds`.
    pub async fn send(
        &self,
        trap_oid: ObjectIdentifier,
        extra_varbinds: Vec<VarBind>,
    ) -> Result<()> {
        let mut bindings = Vec::with_capacity(2 + extra_varbinds.len());
        // sysUpTime in hundredths of seconds.
        let uptime =
            u32::try_from(u64::from(self.clock.time()).saturating_mul(100)).unwrap_or(u32::MAX);
        bindings.push(VarBind::new(
            SYS_UPTIME_OID.parse()?,
            Value::TimeTicks(uptime),
        ));
        bindings.push(VarBind::new(
            SNMP_TRAP_OID_OID.parse()?,
            Value::Oid(trap_oid),
        ));
        bindings.extend(extra_varbinds);

        let request_id = {
            let mut g = self.msg_id.lock().await;
            *g = g.wrapping_add(1);
            *g
        };

        let pdu = Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: bindings,
        };
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.as_bytes().to_vec(),
            context_name: vec![],
            pdu,
        };

        let bytes = self.assemble(scoped, request_id).await?;
        self.socket.send_to(&bytes, self.dest).await?;
        Ok(())
    }

    async fn assemble(&self, scoped: ScopedPdu, msg_id: i32) -> Result<Vec<u8>> {
        let level = self.user.security_level();
        let scoped_bytes = scoped.to_bytes()?;
        let user_name = self.user.name.as_bytes().to_vec();

        match level {
            SecurityLevel::NoAuthNoPriv => {
                let security = SecurityParameters {
                    engine_id: self.engine_id.as_bytes().to_vec(),
                    engine_boots: self.clock.boots(),
                    engine_time: self.clock.time(),
                    user_name,
                    auth_params: vec![],
                    priv_params: vec![],
                };
                let msg = Message {
                    global: GlobalData {
                        msg_id,
                        msg_max_size: 65_507,
                        msg_flags: 0,
                        msg_security_model: SECURITY_MODEL_USM,
                    },
                    security,
                    data: MessageData::Plain(scoped_bytes),
                };
                msg.to_bytes()
            }
            SecurityLevel::AuthNoPriv => {
                let (auth_proto, _) = self
                    .user
                    .auth
                    .as_ref()
                    .ok_or(Error::Usm(UsmError::UnsupportedSecLevel))?;
                self.assemble_auth(scoped_bytes, user_name, msg_id, *auth_proto, None)
            }
            SecurityLevel::AuthPriv => {
                let (auth_proto, _) = self
                    .user
                    .auth
                    .as_ref()
                    .ok_or(Error::Usm(UsmError::UnsupportedSecLevel))?;
                let (priv_proto, _) = self
                    .user
                    .priv_
                    .as_ref()
                    .ok_or(Error::Usm(UsmError::UnsupportedSecLevel))?;
                let mut salt = [0u8; 8];
                rand::Rng::fill(&mut rand::thread_rng(), &mut salt);
                let mut body = scoped_bytes;
                encrypt(
                    *priv_proto,
                    &self.priv_kul,
                    self.clock.boots(),
                    self.clock.time(),
                    &salt,
                    &mut body,
                )?;
                self.assemble_auth(
                    body,
                    user_name,
                    msg_id,
                    *auth_proto,
                    Some((*priv_proto, salt)),
                )
            }
        }
    }

    fn assemble_auth(
        &self,
        body: Vec<u8>,
        user_name: Vec<u8>,
        msg_id: i32,
        auth_proto: AuthProtocol,
        priv_info: Option<(PrivProtocol, [u8; 8])>,
    ) -> Result<Vec<u8>> {
        let priv_bit = priv_info.is_some();
        let mut flags = FLAG_AUTH;
        if priv_bit {
            flags |= FLAG_PRIV;
        }
        let priv_params = priv_info.map(|(_, s)| s.to_vec()).unwrap_or_default();

        let mut sec = SecurityParameters {
            engine_id: self.engine_id.as_bytes().to_vec(),
            engine_boots: self.clock.boots(),
            engine_time: self.clock.time(),
            user_name,
            auth_params: vec![0u8; auth_proto.digest_len()],
            priv_params,
        };
        let data = if priv_bit {
            MessageData::Encrypted(body)
        } else {
            MessageData::Plain(body)
        };
        let mut msg = Message {
            global: GlobalData {
                msg_id,
                msg_max_size: 65_507,
                msg_flags: flags,
                msg_security_model: SECURITY_MODEL_USM,
            },
            security: sec.clone(),
            data,
        };
        let pre = msg.to_bytes()?;
        let tag = auth_digest(auth_proto, &self.auth_kul, &pre)?;
        sec.auth_params = tag;
        msg.security = sec;
        msg.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineId;
    use crate::message::Message;
    use crate::usm::SecretBytes;

    fn local_dest() -> SocketAddr {
        // Use the documentation/example "blackhole" IPv4 — we never actually
        // send on this socket in these tests.
        "127.0.0.1:0".parse().expect("static parse")
    }

    #[tokio::test]
    async fn debug_redacts_credentials() {
        // F-T2: build an authPriv user so `derive_keys` yields NON-empty
        // localized key material (kuls). A `no_auth` user derives EMPTY kuls,
        // so redaction would never be exercised and the test would be vacuous.
        let user = UsmUser::auth_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretBytes::from("the-quick-brown-fox-jumped-over"),
            PrivProtocol::Aes128,
            SecretBytes::from("the-quick-brown-fox-jumped-over"),
        );
        let id = EngineId::new(vec![0x80, 0, 0, 0, 1]).unwrap();
        let sender = TrapSender::with_engine_id(local_dest(), user, id)
            .await
            .unwrap();

        // Sanity: the derived secret material actually exists, so the leak
        // assertions below are non-vacuous.
        assert!(
            !sender.auth_kul.is_empty(),
            "authPriv user must derive a non-empty auth_kul"
        );
        assert!(
            !sender.priv_kul.is_empty(),
            "authPriv user must derive a non-empty priv_kul"
        );

        let dbg = format!("{sender:?}");
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("TrapSender"));

        // The ACTUAL derived key bytes must not surface anywhere in the debug
        // output. If someone re-adds `.field("auth_kul", &self.auth_kul)` to
        // the Debug impl, the `Vec<u8>` renders as `[b1, b2, ...]`; that exact
        // substring is what we assert is ABSENT, so such a regression fails
        // this test (unlike the old field-name-only check).
        let auth_leak = format!("{:?}", sender.auth_kul);
        let priv_leak = format!("{:?}", sender.priv_kul);
        assert!(
            !dbg.contains(&auth_leak),
            "derived auth_kul bytes leaked into Debug output: {dbg}"
        );
        assert!(
            !dbg.contains(&priv_leak),
            "derived priv_kul bytes leaked into Debug output: {dbg}"
        );

        // And an explicit redaction marker IS present for the omitted secrets.
        assert!(
            dbg.contains("<redacted>"),
            "Debug output must carry an explicit redaction marker: {dbg}"
        );
    }

    #[tokio::test]
    async fn explicit_engine_id_is_honored() {
        let id = EngineId::new(vec![0x80, 0, 0, 0, 0x99, 0xAA, 0xBB]).unwrap();
        let user = UsmUser::no_auth("u");
        let s = TrapSender::with_engine_id(local_dest(), user, id.clone())
            .await
            .unwrap();
        assert_eq!(s.engine_id.as_bytes(), id.as_bytes());
    }

    #[tokio::test]
    async fn v6_destination_binds_v6_socket() {
        let dest: SocketAddr = "[::1]:0".parse().unwrap();
        let user = UsmUser::no_auth("u");
        let sender =
            TrapSender::with_engine_id(dest, user, EngineId::new(vec![0x80, 0, 0, 0, 1]).unwrap())
                .await
                .unwrap();
        assert!(sender.socket.local_addr().unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn assemble_no_auth_produces_parseable_message() {
        let user = UsmUser::no_auth("alice");
        let id = EngineId::new(vec![0x80, 0, 0, 0, 1]).unwrap();
        let sender = TrapSender::with_engine_id(local_dest(), user, id)
            .await
            .unwrap();
        let scoped = ScopedPdu {
            context_engine_id: sender.engine_id.as_bytes().to_vec(),
            context_name: vec![],
            pdu: Pdu {
                kind: PduKind::SnmpV2Trap,
                request_id: 7,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![],
            },
        };
        let bytes = sender.assemble(scoped, 7).await.unwrap();
        let back = Message::from_bytes(&bytes).unwrap();
        // noAuthNoPriv → flags zero, plaintext data.
        assert_eq!(back.global.msg_flags, 0);
        match back.data {
            MessageData::Plain(_) => {}
            MessageData::Encrypted(_) => panic!("expected plaintext"),
        }
    }

    #[tokio::test]
    async fn assemble_auth_priv_marks_flags() {
        let user = UsmUser::auth_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretBytes::from("the-quick-brown-fox-jumped-over"),
            PrivProtocol::Aes128,
            SecretBytes::from("the-quick-brown-fox-jumped-over"),
        );
        let id = EngineId::new(vec![0x80, 0, 0, 0, 1]).unwrap();
        let sender = TrapSender::with_engine_id(local_dest(), user, id)
            .await
            .unwrap();
        let scoped = ScopedPdu {
            context_engine_id: sender.engine_id.as_bytes().to_vec(),
            context_name: vec![],
            pdu: Pdu {
                kind: PduKind::SnmpV2Trap,
                request_id: 11,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![],
            },
        };
        let bytes = sender.assemble(scoped, 11).await.unwrap();
        let back = Message::from_bytes(&bytes).unwrap();
        assert!(back.global.auth_bit());
        assert!(back.global.priv_bit());
        // priv params should be the 8-byte salt the sender chose.
        assert_eq!(back.security.priv_params.len(), 8);
    }

    #[test]
    fn standard_oid_constants_parse() {
        let up: ObjectIdentifier = SYS_UPTIME_OID.parse().unwrap();
        let trap: ObjectIdentifier = SNMP_TRAP_OID_OID.parse().unwrap();
        assert_eq!(up.to_string(), "1.3.6.1.2.1.1.3.0");
        assert_eq!(trap.to_string(), "1.3.6.1.6.3.1.1.4.1.0");
    }
}
