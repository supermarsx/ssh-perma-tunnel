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
