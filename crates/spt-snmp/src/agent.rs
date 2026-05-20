//! SNMPv3 UDP agent.
//!
//! [`AgentBuilder`] configures users, the engine id, and the MIB registry.
//! Calling [`AgentBuilder::run`] spawns a background task that listens on the
//! configured UDP socket and processes inbound messages.
//!
//! ## Request handling pipeline
//!
//! 1. **Parse** the SNMPv3 envelope ([`crate::message::Message::from_bytes`]).
//! 2. **USM verify**: locate the user, derive localized keys, verify the
//!    HMAC tag (constant-time), decrypt if `authPriv`.
//! 3. **Engine ID discovery**: respond to `usmStatsUnknownEngineIDs` Reports
//!    so peers can discover us before sending authenticated requests.
//! 4. **Time-window check** ([`crate::engine::EngineClock::check_time_window`]).
//! 5. **Dispatch** to the [`crate::mib::MibRegistry`] (Get/GetNext/GetBulk/Set).
//! 6. **Encode response**: re-encrypt and re-HMAC if needed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};

use crate::engine::{generate_engine_id, EngineClock, EngineId};
use crate::error::{Error, Result, UsmError};
use crate::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_PRIV,
    SECURITY_MODEL_USM,
};
use crate::mib::{Handler, MibRegistry, TableHandler};
use crate::oid::ObjectIdentifier;
use crate::pdu::{ErrorStatus, Pdu, PduKind};
use crate::usm::{
    auth_digest, decrypt, derive_keys, digests_match, encrypt, AuthProtocol, PrivProtocol,
    SecurityLevel, UsmCounters, UsmUser,
};
use crate::value::{Value, VarBind};

/// RFC documentation PEN from RFC 5612 / RFC 9371 examples.
///
/// This is useful for tests and examples only. Production SNMP deployments
/// must configure a registered IANA Private Enterprise Number.
pub const DOCUMENTATION_ENTERPRISE_PEN: u32 = 32_473;

/// Legacy placeholder PEN used by early SPT builds before the project moved to
/// the RFC documentation PEN for template MIBs.
///
/// This value is reserved for migration diagnostics and must not be used by a
/// production SNMP agent.
pub const OLD_PLACEHOLDER_ENTERPRISE_PEN: u32 = 99_999;

/// Returns `true` when `pen` is reserved for documentation, examples, tests,
/// or migration diagnostics rather than production SNMP service.
#[must_use]
pub const fn is_reserved_enterprise_pen(pen: u32) -> bool {
    matches!(
        pen,
        DOCUMENTATION_ENTERPRISE_PEN | OLD_PLACEHOLDER_ENTERPRISE_PEN
    )
}

/// Validates that `pen` is suitable for production SNMP engine-id generation.
///
/// # Errors
/// Returns [`Error::Config`] when the PEN is zero or one of SPT's reserved
/// documentation/placeholder identifiers.
pub fn validate_production_enterprise_pen(pen: u32) -> Result<()> {
    if pen == 0 {
        return Err(Error::Config(
            "SNMP enterprise PEN must be greater than zero".into(),
        ));
    }
    if is_reserved_enterprise_pen(pen) {
        return Err(Error::Config(format!(
            "SNMP enterprise PEN {pen} is reserved for documentation, tests, \
             or migration diagnostics; configure a registered IANA Private \
             Enterprise Number for production"
        )));
    }
    Ok(())
}

/// Maximum UDP datagram we will accept (matches `msgMaxSize` default).
pub const MAX_DATAGRAM: usize = 65_507;

/// Agent builder: configure addresses, users and the MIB then `run()`.
#[derive(Default)]
pub struct AgentBuilder {
    bind_addr: Option<SocketAddr>,
    engine_id: Option<EngineId>,
    enterprise_pen: Option<u32>,
    allow_documentation_pen: bool,
    users: Vec<UsmUser>,
    registry: MibRegistry,
}

impl std::fmt::Debug for AgentBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentBuilder")
            .field("bind_addr", &self.bind_addr)
            .field("engine_id", &self.engine_id)
            .field("enterprise_pen", &self.enterprise_pen)
            .field("allow_documentation_pen", &self.allow_documentation_pen)
            .field("users", &self.users.len())
            .field("registry", &self.registry)
            .finish()
    }
}

impl AgentBuilder {
    /// Creates an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the listen address (typically `0.0.0.0:161` or `[::]:161`).
    #[must_use]
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Sets the registered IANA Private Enterprise Number used when generating
    /// a random RFC-3411 §5.1 format-5 engine id.
    #[must_use]
    pub fn enterprise_pen(mut self, pen: u32) -> Self {
        self.enterprise_pen = Some(pen);
        self.allow_documentation_pen = false;
        self
    }

    /// Uses the RFC documentation PEN for tests, examples, and fixture agents.
    ///
    /// Production callers must use [`AgentBuilder::enterprise_pen`] with their
    /// registered IANA Private Enterprise Number. This method exists so tests
    /// and documentation examples can keep exercising the RFC 5612 / RFC 9371
    /// documentation subtree without weakening the production default.
    #[must_use]
    pub fn documentation_enterprise_pen(mut self) -> Self {
        self.enterprise_pen = Some(DOCUMENTATION_ENTERPRISE_PEN);
        self.allow_documentation_pen = true;
        self
    }

    /// Overrides the engine id. If unset, [`AgentBuilder::enterprise_pen`]
    /// must be set so a production engine id can be generated from a registered
    /// enterprise number.
    #[must_use]
    pub fn engine_id(mut self, id: EngineId) -> Self {
        self.engine_id = Some(id);
        self
    }

    /// Adds a USM user (any of `noAuthNoPriv` / `authNoPriv` / `authPriv`).
    #[must_use]
    pub fn add_user(mut self, user: UsmUser) -> Self {
        self.users.push(user);
        self
    }

    /// Registers a scalar handler.
    #[must_use]
    pub fn add_scalar<H: Handler>(mut self, oid: ObjectIdentifier, h: H) -> Self {
        self.registry.add_scalar(oid, h);
        self
    }

    /// Registers a table handler.
    #[must_use]
    pub fn add_table<H: TableHandler>(mut self, oid: ObjectIdentifier, h: H) -> Self {
        self.registry.add_table(oid, h);
        self
    }

    /// Returns mutable access to the registry being built (advanced use).
    pub fn registry_mut(&mut self) -> &mut MibRegistry {
        &mut self.registry
    }

    /// Binds the socket and spawns the agent task. Returns a handle that can
    /// be used to read the bound address and to shut the agent down.
    pub async fn run(self) -> Result<AgentHandle> {
        let bind = self.bind_addr.ok_or_else(|| {
            Error::Config("AgentBuilder::bind() must be called before run()".into())
        })?;
        let engine_id = match self.engine_id {
            Some(id) => id,
            None => {
                let pen = self.enterprise_pen.ok_or_else(|| {
                    Error::Config(
                        "AgentBuilder::enterprise_pen() or engine_id() must be set before run(); \
                         production SNMP requires a registered IANA Private Enterprise Number"
                            .into(),
                    )
                })?;
                if self.allow_documentation_pen {
                    if pen == 0 {
                        return Err(Error::Config(
                            "SNMP enterprise PEN must be greater than zero".into(),
                        ));
                    }
                } else {
                    validate_production_enterprise_pen(pen)?;
                }
                generate_engine_id(pen)
            }
        };
        let socket = UdpSocket::bind(bind).await?;
        let local_addr = socket.local_addr()?;

        // Pre-derive localized keys per user — cheap to do up front.
        let mut user_keys: HashMap<String, UserKeys> = HashMap::new();
        for u in &self.users {
            let (auth_kul, priv_kul) = derive_keys(u, engine_id.as_bytes());
            user_keys.insert(
                u.name.clone(),
                UserKeys {
                    user: u.clone(),
                    auth_kul,
                    priv_kul,
                },
            );
        }

        let agent = Arc::new(Agent {
            socket,
            engine_id,
            clock: EngineClock::new(1),
            users: user_keys,
            registry: self.registry,
            counters: Mutex::new(UsmCounters::default()),
        });
        let agent_for_task = Arc::clone(&agent);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            agent_for_task.run_loop(shutdown_rx).await;
        });
        Ok(AgentHandle {
            agent,
            local_addr,
            join: Some(handle),
            shutdown: Some(shutdown_tx),
        })
    }
}

#[derive(Debug)]
struct UserKeys {
    user: UsmUser,
    auth_kul: Vec<u8>,
    priv_kul: Vec<u8>,
}

/// Running agent. Held inside [`AgentHandle`].
pub struct Agent {
    socket: UdpSocket,
    engine_id: EngineId,
    clock: EngineClock,
    users: HashMap<String, UserKeys>,
    registry: MibRegistry,
    counters: Mutex<UsmCounters>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("engine_id", &self.engine_id)
            .field("users", &self.users.len())
            .field("registry", &self.registry)
            .finish()
    }
}

impl Agent {
    /// Returns this agent's authoritative engine id.
    #[must_use]
    pub fn engine_id(&self) -> &EngineId {
        &self.engine_id
    }

    /// Returns a snapshot of USM counters.
    pub async fn counters_snapshot(&self) -> UsmCountersSnapshot {
        let g = self.counters.lock().await;
        UsmCountersSnapshot {
            unsupported_sec_levels: g.unsupported_sec_levels,
            not_in_time_windows: g.not_in_time_windows,
            unknown_user_names: g.unknown_user_names,
            unknown_engine_ids: g.unknown_engine_ids,
            wrong_digests: g.wrong_digests,
            decryption_errors: g.decryption_errors,
        }
    }

    async fn run_loop(self: Arc<Self>, mut shutdown: oneshot::Receiver<()>) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::debug!("snmp agent shutting down");
                    return;
                }
                r = self.socket.recv_from(&mut buf) => {
                    match r {
                        Ok((n, peer)) => {
                            let datagram = buf[..n].to_vec();
                            let agent = Arc::clone(&self);
                            // Process synchronously on this task — we already
                            // have just one socket; spawning per packet would
                            // reorder responses for no win.
                            if let Err(e) = agent.handle_datagram(&datagram, peer).await {
                                tracing::warn!(?peer, error = %e, "snmp agent packet error");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "snmp agent recv error");
                        }
                    }
                }
            }
        }
    }

    async fn handle_datagram(self: Arc<Self>, bytes: &[u8], peer: SocketAddr) -> Result<()> {
        let mut msg = match Message::from_bytes(bytes) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(?peer, error = %e, "drop malformed snmp message");
                return Ok(());
            }
        };

        let level =
            SecurityLevel::from_flags(msg.global.msg_flags).unwrap_or(SecurityLevel::NoAuthNoPriv);

        // Engine-ID discovery: empty engine id from the peer means "tell me
        // who you are". We answer with a Report-PDU carrying our engine id
        // and the `usmStatsUnknownEngineIDs` counter (RFC 3414 §3.2 step 7
        // and §4 — Engine ID Discovery).
        if msg.security.engine_id.is_empty() {
            self.bump_counter(UsmError::UnknownEngineId).await;
            let scoped = self.build_report(&msg, UsmError::UnknownEngineId).await?;
            let reply = self
                .build_response_message(&msg, scoped, SecurityLevel::NoAuthNoPriv, None)
                .await?;
            self.socket.send_to(&reply, peer).await?;
            return Ok(());
        }

        // Confirm peer is talking to us.
        if msg.security.engine_id != self.engine_id.as_bytes() {
            self.bump_counter(UsmError::UnknownEngineId).await;
            return Ok(());
        }

        // USM verification + decryption.
        let scoped = match self.usm_verify(&mut msg, level).await {
            Ok(s) => s,
            Err(Error::Usm(e)) => {
                self.bump_counter(e.clone()).await;
                // For reportable messages we should send a Report-PDU back.
                if msg.global.reportable_bit() {
                    if let Ok(scoped) = self.build_report(&msg, e).await {
                        // Reply at noAuthNoPriv since auth/priv may have failed.
                        let reply = self
                            .build_response_message(&msg, scoped, SecurityLevel::NoAuthNoPriv, None)
                            .await?;
                        self.socket.send_to(&reply, peer).await?;
                    }
                }
                return Ok(());
            }
            Err(other) => return Err(other),
        };

        // Dispatch the PDU.
        let response = self.dispatch_pdu(scoped.pdu).await?;
        let resp_scoped = ScopedPdu {
            context_engine_id: self.engine_id.as_bytes().to_vec(),
            context_name: scoped.context_name.clone(),
            pdu: response,
        };

        // Reply at the same security level. For authPriv we need the user's
        // keys.
        let user_name = String::from_utf8_lossy(&msg.security.user_name).to_string();
        let user_keys = self.users.get(&user_name).cloned();
        let reply = self
            .build_response_message(&msg, resp_scoped, level, user_keys)
            .await?;
        self.socket.send_to(&reply, peer).await?;
        Ok(())
    }

    async fn bump_counter(&self, e: UsmError) {
        self.counters.lock().await.record(&e);
    }

    /// Verifies the inbound message's USM parameters and decrypts the
    /// scoped-PDU if `authPriv`. Returns the parsed scoped-PDU on success.
    async fn usm_verify(
        self: &Arc<Self>,
        msg: &mut Message,
        level: SecurityLevel,
    ) -> Result<ScopedPdu> {
        let user_name = String::from_utf8_lossy(&msg.security.user_name).to_string();

        // noAuthNoPriv with empty user_name is allowed for engine discovery
        // (handled above) — at this point we expect a real user.
        let keys = match self.users.get(&user_name) {
            Some(k) => k,
            None => return Err(Error::Usm(UsmError::UnknownUserName)),
        };

        let configured = keys.user.security_level();
        if level > configured {
            return Err(Error::Usm(UsmError::UnsupportedSecLevel));
        }

        if level == SecurityLevel::NoAuthNoPriv {
            // Plaintext path.
            return match &msg.data {
                MessageData::Plain(b) => ScopedPdu::from_bytes(b),
                MessageData::Encrypted(_) => Err(Error::Usm(UsmError::UnsupportedSecLevel)),
            };
        }

        // From here on, level >= AuthNoPriv, so an auth protocol is required.
        let (auth_proto, _) = keys
            .user
            .auth
            .as_ref()
            .ok_or(Error::Usm(UsmError::UnsupportedSecLevel))?;

        // Time window check.
        self.clock
            .check_time_window(msg.security.engine_boots, msg.security.engine_time)?;

        // Verify HMAC: zero out auth_params, re-serialize whole message,
        // compute HMAC, constant-time compare.
        let received_tag = msg.security.auth_params.clone();
        if received_tag.len() != auth_proto.digest_len() {
            return Err(Error::Usm(UsmError::WrongDigest));
        }
        msg.security.auth_params = vec![0u8; auth_proto.digest_len()];
        let serialized = msg.to_bytes()?;
        let computed = auth_digest(*auth_proto, &keys.auth_kul, &serialized)?;
        if !digests_match(&received_tag, &computed) {
            // Restore original tag bytes for completeness (caller may inspect).
            msg.security.auth_params = received_tag;
            return Err(Error::Usm(UsmError::WrongDigest));
        }
        msg.security.auth_params = received_tag;

        // If priv: decrypt msgData (an OCTET STRING) using AES-CFB.
        if level == SecurityLevel::AuthPriv {
            let ciphertext = match &msg.data {
                MessageData::Encrypted(b) => b.clone(),
                MessageData::Plain(_) => return Err(Error::Usm(UsmError::DecryptionError)),
            };
            let (priv_proto, _) = keys
                .user
                .priv_
                .as_ref()
                .ok_or(Error::Usm(UsmError::UnsupportedSecLevel))?;
            if msg.security.priv_params.len() != 8 {
                return Err(Error::Usm(UsmError::DecryptionError));
            }
            let mut salt = [0u8; 8];
            salt.copy_from_slice(&msg.security.priv_params);
            let mut buf = ciphertext;
            decrypt(
                *priv_proto,
                &keys.priv_kul,
                msg.security.engine_boots,
                msg.security.engine_time,
                &salt,
                &mut buf,
            )
            .map_err(|_| Error::Usm(UsmError::DecryptionError))?;
            return ScopedPdu::from_bytes(&buf);
        }

        // authNoPriv: msgData is a plaintext SEQUENCE.
        match &msg.data {
            MessageData::Plain(b) => ScopedPdu::from_bytes(b),
            MessageData::Encrypted(_) => Err(Error::Usm(UsmError::DecryptionError)),
        }
    }

    /// Dispatches a request PDU to the MIB registry and produces a Response.
    async fn dispatch_pdu(&self, req: Pdu) -> Result<Pdu> {
        match req.kind {
            PduKind::GetRequest => Ok(self.handle_get(req).await),
            PduKind::GetNextRequest => Ok(self.handle_get_next(req).await),
            PduKind::GetBulkRequest => Ok(self.handle_get_bulk(req).await),
            PduKind::SetRequest => Ok(self.handle_set(req).await),
            PduKind::Response | PduKind::Report => {
                // Agents shouldn't normally receive these. Drop with a no-op.
                Ok(Pdu {
                    kind: PduKind::Response,
                    request_id: req.request_id,
                    error_status: ErrorStatus::GenErr as i32,
                    error_index: 0,
                    variable_bindings: vec![],
                })
            }
            PduKind::SnmpV2Trap | PduKind::InformRequest => {
                // We're an agent, not an NMS — ignore.
                Ok(Pdu {
                    kind: PduKind::Response,
                    request_id: req.request_id,
                    error_status: 0,
                    error_index: 0,
                    variable_bindings: vec![],
                })
            }
        }
    }

    async fn handle_get(&self, req: Pdu) -> Pdu {
        let mut bindings = Vec::with_capacity(req.variable_bindings.len());
        for vb in &req.variable_bindings {
            let value = match self.registry.get(&vb.name).await {
                Ok(Some(v)) => v,
                Ok(None) => Value::NoSuchObject,
                Err(_) => Value::NoSuchObject,
            };
            bindings.push(VarBind {
                name: vb.name.clone(),
                value,
            });
        }
        Pdu {
            kind: PduKind::Response,
            request_id: req.request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: bindings,
        }
    }

    async fn handle_get_next(&self, req: Pdu) -> Pdu {
        let mut bindings = Vec::with_capacity(req.variable_bindings.len());
        for vb in &req.variable_bindings {
            let resp = match self.registry.next(&vb.name).await {
                Ok(Some((oid, v))) => VarBind {
                    name: oid,
                    value: v,
                },
                _ => VarBind {
                    name: vb.name.clone(),
                    value: Value::EndOfMibView,
                },
            };
            bindings.push(resp);
        }
        Pdu {
            kind: PduKind::Response,
            request_id: req.request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: bindings,
        }
    }

    async fn handle_get_bulk(&self, req: Pdu) -> Pdu {
        // RFC 3416 §4.2.3: error_status -> non_repeaters, error_index -> max_repetitions.
        let n = usize::try_from(req.error_status.max(0)).unwrap_or(0);
        let max_rep = usize::try_from(req.error_index.max(0)).unwrap_or(0);
        let total = req.variable_bindings.len();
        let n = n.min(total);

        let mut bindings: Vec<VarBind> = Vec::new();

        // Non-repeating part.
        for vb in req.variable_bindings.iter().take(n) {
            match self.registry.next(&vb.name).await {
                Ok(Some((oid, v))) => bindings.push(VarBind {
                    name: oid,
                    value: v,
                }),
                _ => bindings.push(VarBind {
                    name: vb.name.clone(),
                    value: Value::EndOfMibView,
                }),
            }
        }

        // Repeating part.
        if total > n && max_rep > 0 {
            let mut cursors: Vec<ObjectIdentifier> = req
                .variable_bindings
                .iter()
                .skip(n)
                .map(|vb| vb.name.clone())
                .collect();
            for _ in 0..max_rep {
                let mut all_end = true;
                for cur in &mut cursors {
                    match self.registry.next(cur).await {
                        Ok(Some((oid, v))) => {
                            *cur = oid.clone();
                            bindings.push(VarBind {
                                name: oid,
                                value: v,
                            });
                            all_end = false;
                        }
                        _ => {
                            bindings.push(VarBind {
                                name: cur.clone(),
                                value: Value::EndOfMibView,
                            });
                        }
                    }
                }
                if all_end {
                    break;
                }
            }
        }

        Pdu {
            kind: PduKind::Response,
            request_id: req.request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: bindings,
        }
    }

    async fn handle_set(&self, req: Pdu) -> Pdu {
        let mut error_status = ErrorStatus::NoError as i32;
        let mut error_index: i32 = 0;
        for (i, vb) in req.variable_bindings.iter().enumerate() {
            if let Some(h) = self.registry.scalar(&vb.name) {
                let outcome = h.set(vb.value.clone()).await;
                if outcome != crate::mib::SetOutcome::Ok {
                    error_status = outcome.to_error_status() as i32;
                    error_index = (i + 1) as i32;
                    break;
                }
            } else {
                error_status = ErrorStatus::NotWritable as i32;
                error_index = (i + 1) as i32;
                break;
            }
        }
        Pdu {
            kind: PduKind::Response,
            request_id: req.request_id,
            error_status,
            error_index,
            variable_bindings: req.variable_bindings,
        }
    }

    async fn build_report(&self, msg: &Message, err: UsmError) -> Result<ScopedPdu> {
        // OID prefix for usmStats* counters.
        let oid = match err {
            UsmError::UnsupportedSecLevel => "1.3.6.1.6.3.15.1.1.1.0",
            UsmError::NotInTimeWindow => "1.3.6.1.6.3.15.1.1.2.0",
            UsmError::UnknownUserName => "1.3.6.1.6.3.15.1.1.3.0",
            UsmError::UnknownEngineId => "1.3.6.1.6.3.15.1.1.4.0",
            UsmError::WrongDigest => "1.3.6.1.6.3.15.1.1.5.0",
            UsmError::DecryptionError => "1.3.6.1.6.3.15.1.1.6.0",
        };
        let snapshot = self.counters_snapshot().await;
        let value = match err {
            UsmError::UnsupportedSecLevel => snapshot.unsupported_sec_levels,
            UsmError::NotInTimeWindow => snapshot.not_in_time_windows,
            UsmError::UnknownUserName => snapshot.unknown_user_names,
            UsmError::UnknownEngineId => snapshot.unknown_engine_ids,
            UsmError::WrongDigest => snapshot.wrong_digests,
            UsmError::DecryptionError => snapshot.decryption_errors,
        };
        let pdu = Pdu {
            kind: PduKind::Report,
            request_id: extract_request_id(msg).unwrap_or(0),
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::new(oid.parse()?, Value::Counter32(value))],
        };
        Ok(ScopedPdu {
            context_engine_id: self.engine_id.as_bytes().to_vec(),
            context_name: vec![],
            pdu,
        })
    }

    /// Builds a complete reply message at the requested security level.
    /// `user_keys` MUST be supplied for `AuthNoPriv` / `AuthPriv` levels.
    async fn build_response_message(
        &self,
        request: &Message,
        scoped: ScopedPdu,
        level: SecurityLevel,
        user_keys: Option<UserKeys>,
    ) -> Result<Vec<u8>> {
        let scoped_bytes = scoped.to_bytes()?;
        let user_name_bytes = user_keys
            .as_ref()
            .map(|k| k.user.name.clone().into_bytes())
            .unwrap_or_default();

        match level {
            SecurityLevel::NoAuthNoPriv => {
                let security = SecurityParameters {
                    engine_id: self.engine_id.as_bytes().to_vec(),
                    engine_boots: self.clock.boots(),
                    engine_time: self.clock.time(),
                    user_name: user_name_bytes,
                    auth_params: vec![],
                    priv_params: vec![],
                };
                let msg = Message {
                    global: GlobalData {
                        msg_id: request.global.msg_id,
                        msg_max_size: request.global.msg_max_size.max(484),
                        msg_flags: 0,
                        msg_security_model: SECURITY_MODEL_USM,
                    },
                    security,
                    data: MessageData::Plain(scoped_bytes),
                };
                msg.to_bytes()
            }
            SecurityLevel::AuthNoPriv => {
                let keys = user_keys.ok_or(Error::Usm(UsmError::UnknownUserName))?;
                let (auth_proto, _) = keys
                    .user
                    .auth
                    .as_ref()
                    .ok_or(Error::Usm(UsmError::UnsupportedSecLevel))?;
                self.assemble_auth(
                    request,
                    scoped_bytes,
                    keys.user.name.as_bytes().to_vec(),
                    *auth_proto,
                    &keys.auth_kul,
                    None,
                )
            }
            SecurityLevel::AuthPriv => {
                let keys = user_keys.ok_or(Error::Usm(UsmError::UnknownUserName))?;
                let (auth_proto, _) = keys
                    .user
                    .auth
                    .as_ref()
                    .ok_or(Error::Usm(UsmError::UnsupportedSecLevel))?;
                let (priv_proto, _) = keys
                    .user
                    .priv_
                    .as_ref()
                    .ok_or(Error::Usm(UsmError::UnsupportedSecLevel))?;
                let mut salt = [0u8; 8];
                rand::Rng::fill(&mut rand::thread_rng(), &mut salt);
                let mut ciphertext = scoped_bytes;
                encrypt(
                    *priv_proto,
                    &keys.priv_kul,
                    self.clock.boots(),
                    self.clock.time(),
                    &salt,
                    &mut ciphertext,
                )?;
                self.assemble_auth(
                    request,
                    ciphertext,
                    keys.user.name.as_bytes().to_vec(),
                    *auth_proto,
                    &keys.auth_kul,
                    Some((priv_proto, salt)),
                )
            }
        }
    }

    fn assemble_auth(
        &self,
        request: &Message,
        body: Vec<u8>,
        user_name: Vec<u8>,
        auth_proto: AuthProtocol,
        auth_kul: &[u8],
        priv_info: Option<(&PrivProtocol, [u8; 8])>,
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
                msg_id: request.global.msg_id,
                msg_max_size: request.global.msg_max_size.max(484),
                msg_flags: flags,
                msg_security_model: SECURITY_MODEL_USM,
            },
            security: sec.clone(),
            data,
        };

        // First serialize with zeroed auth, then HMAC, patch, re-serialize.
        let pre = msg.to_bytes()?;
        let tag = auth_digest(auth_proto, auth_kul, &pre)?;
        sec.auth_params = tag;
        msg.security = sec;
        msg.to_bytes()
    }
}

// We need a Clone for `UserKeys` to pass into async builders. Implement it.
impl Clone for UserKeys {
    fn clone(&self) -> Self {
        Self {
            user: self.user.clone(),
            auth_kul: self.auth_kul.clone(),
            priv_kul: self.priv_kul.clone(),
        }
    }
}

fn extract_request_id(msg: &Message) -> Option<i32> {
    if let MessageData::Plain(b) = &msg.data {
        if let Ok(scoped) = ScopedPdu::from_bytes(b) {
            return Some(scoped.pdu.request_id);
        }
    }
    None
}

/// Snapshot of the agent's USM counters.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsmCountersSnapshot {
    pub unsupported_sec_levels: u32,
    pub not_in_time_windows: u32,
    pub unknown_user_names: u32,
    pub unknown_engine_ids: u32,
    pub wrong_digests: u32,
    pub decryption_errors: u32,
}

/// Handle returned by [`AgentBuilder::run`].
#[allow(missing_debug_implementations)]
pub struct AgentHandle {
    agent: Arc<Agent>,
    local_addr: SocketAddr,
    join: Option<tokio::task::JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl AgentHandle {
    /// The address actually bound (useful when port 0 was requested).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Reference to the running agent (for counter inspection etc.).
    #[must_use]
    pub fn agent(&self) -> &Arc<Agent> {
        &self.agent
    }

    /// Signals the agent to stop and awaits its task. Must be called explicitly;
    /// dropping the handle does not stop the agent (it logs and continues).
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
        Ok(())
    }
}

impl Drop for AgentHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            j.abort();
        }
    }
}
