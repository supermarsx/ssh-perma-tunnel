//! SNMPv3 message envelope (RFC 3412 §6).
//!
//! Wire layout:
//!
//! ```text
//! SNMPv3Message ::= SEQUENCE {
//!   msgVersion              INTEGER (3),
//!   msgGlobalData           HeaderData,
//!   msgSecurityParameters   OCTET STRING,    -- BER-encoded UsmSecurityParameters
//!   msgData                 ScopedPduData    -- ScopedPDU or encrypted OCTET STRING
//! }
//!
//! HeaderData ::= SEQUENCE {
//!   msgID         INTEGER (0..2147483647),
//!   msgMaxSize    INTEGER (484..2147483647),
//!   msgFlags      OCTET STRING (SIZE(1)),    -- bit0=auth, bit1=priv, bit2=reportable
//!   msgSecurityModel  INTEGER (3 = USM)
//! }
//!
//! UsmSecurityParameters ::= SEQUENCE {
//!   msgAuthoritativeEngineID     OCTET STRING,
//!   msgAuthoritativeEngineBoots  INTEGER,
//!   msgAuthoritativeEngineTime   INTEGER,
//!   msgUserName                  OCTET STRING,
//!   msgAuthenticationParameters  OCTET STRING,
//!   msgPrivacyParameters         OCTET STRING
//! }
//!
//! ScopedPDU ::= SEQUENCE {
//!   contextEngineID  OCTET STRING,
//!   contextName      OCTET STRING,
//!   data             ANY        -- the PDU
//! }
//! ```

use crate::ber::{Decoder, Encoder, Tag};
use crate::error::{Error, Result};
use crate::pdu::Pdu;

/// SNMPv3 reserved version number.
pub const SNMP_VERSION_3: i32 = 3;
/// USM security model number.
pub const SECURITY_MODEL_USM: i32 = 3;
/// `msgFlags` bit indicating authentication is in use.
pub const FLAG_AUTH: u8 = 0b001;
/// `msgFlags` bit indicating privacy is in use.
pub const FLAG_PRIV: u8 = 0b010;
/// `msgFlags` bit requesting a Report-PDU on errors.
pub const FLAG_REPORTABLE: u8 = 0b100;

/// `msgGlobalData` (header) of an SNMPv3 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalData {
    /// `msgID`.
    pub msg_id: i32,
    /// `msgMaxSize`. RFC 3412 floor is 484; default 65 507 (UDP MTU - headers).
    pub msg_max_size: i32,
    /// `msgFlags`.
    pub msg_flags: u8,
    /// `msgSecurityModel` (3 = USM).
    pub msg_security_model: i32,
}

impl GlobalData {
    /// Returns true when bit 0 (`auth`) is set.
    #[must_use]
    pub fn auth_bit(&self) -> bool {
        self.msg_flags & FLAG_AUTH != 0
    }

    /// Returns true when bit 1 (`priv`) is set.
    #[must_use]
    pub fn priv_bit(&self) -> bool {
        self.msg_flags & FLAG_PRIV != 0
    }

    /// Returns true when bit 2 (`reportable`) is set.
    #[must_use]
    pub fn reportable_bit(&self) -> bool {
        self.msg_flags & FLAG_REPORTABLE != 0
    }
}

/// `UsmSecurityParameters`. The `auth_params` field holds the truncated HMAC
/// tag at the position used during digest computation; before computing the
/// digest the implementation zeroes it to `digest_len(auth)` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityParameters {
    /// `msgAuthoritativeEngineID`.
    pub engine_id: Vec<u8>,
    /// `msgAuthoritativeEngineBoots`.
    pub engine_boots: u32,
    /// `msgAuthoritativeEngineTime`.
    pub engine_time: u32,
    /// `msgUserName`.
    pub user_name: Vec<u8>,
    /// `msgAuthenticationParameters` (HMAC tag, possibly all-zero pre-digest).
    pub auth_params: Vec<u8>,
    /// `msgPrivacyParameters` (8-byte AES salt or 8-byte DES salt).
    pub priv_params: Vec<u8>,
}

impl SecurityParameters {
    /// Encodes the parameters as the body of an OCTET STRING.
    pub fn encode_inner(&self, enc: &mut Encoder) {
        enc.write_sequence(|inner| {
            inner.write_octet_string(&self.engine_id);
            inner.write_u32(self.engine_boots);
            inner.write_u32(self.engine_time);
            inner.write_octet_string(&self.user_name);
            inner.write_octet_string(&self.auth_params);
            inner.write_octet_string(&self.priv_params);
        });
    }

    /// Returns the BER-serialized SEQUENCE bytes (the value placed inside the
    /// outer `msgSecurityParameters` OCTET STRING).
    #[must_use]
    pub fn to_inner_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_inner(&mut e);
        e.finish()
    }

    /// Decodes from the body of `msgSecurityParameters` (after stripping the
    /// outer OCTET STRING tag).
    pub fn decode_inner(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let mut s = d.read_sequence()?;
        let engine_id = s.read_octet_string()?.to_vec();
        let engine_boots = s.read_u32()?;
        let engine_time = s.read_u32()?;
        let user_name = s.read_octet_string()?.to_vec();
        let auth_params = s.read_octet_string()?.to_vec();
        let priv_params = s.read_octet_string()?.to_vec();
        Ok(Self {
            engine_id,
            engine_boots,
            engine_time,
            user_name,
            auth_params,
            priv_params,
        })
    }
}

/// `ScopedPDU` — the inner PDU plus its routing context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPdu {
    /// `contextEngineID`.
    pub context_engine_id: Vec<u8>,
    /// `contextName`.
    pub context_name: Vec<u8>,
    /// The actual PDU.
    pub pdu: Pdu,
}

impl ScopedPdu {
    /// Encodes the SEQUENCE and returns its bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        let mut inner = Encoder::new();
        inner.write_octet_string(&self.context_engine_id);
        inner.write_octet_string(&self.context_name);
        self.pdu.encode(&mut inner)?;
        e.write_tlv(Tag::SEQUENCE, inner.as_slice());
        Ok(e.finish())
    }

    /// Parses a `ScopedPDU` SEQUENCE from `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let mut s = d.read_sequence()?;
        let context_engine_id = s.read_octet_string()?.to_vec();
        let context_name = s.read_octet_string()?.to_vec();
        let pdu = Pdu::decode(&mut s)?;
        Ok(Self {
            context_engine_id,
            context_name,
            pdu,
        })
    }
}

/// `msgData` — either a plaintext `ScopedPDU` (`noPriv`) or its AES-encrypted
/// ciphertext wrapped in an OCTET STRING (`authPriv`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageData {
    /// `noPriv` — plaintext SEQUENCE bytes.
    Plain(Vec<u8>),
    /// `authPriv` — encrypted bytes inside an OCTET STRING.
    Encrypted(Vec<u8>),
}

/// Full SNMPv3 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// `msgGlobalData`.
    pub global: GlobalData,
    /// `msgSecurityParameters` payload (USM).
    pub security: SecurityParameters,
    /// `msgData` payload.
    pub data: MessageData,
}

impl Message {
    /// Serializes the message to the wire.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut outer = Encoder::new();
        outer.write_sequence(|e| {
            e.write_i64(i64::from(SNMP_VERSION_3));
            // Global data SEQUENCE
            e.write_sequence(|g| {
                g.write_i64(i64::from(self.global.msg_id));
                g.write_i64(i64::from(self.global.msg_max_size));
                g.write_octet_string(&[self.global.msg_flags]);
                g.write_i64(i64::from(self.global.msg_security_model));
            });
            // Security params: BER-encoded SEQUENCE wrapped in an OCTET STRING.
            let sec_bytes = self.security.to_inner_bytes();
            e.write_octet_string(&sec_bytes);
            // msgData
            match &self.data {
                MessageData::Plain(b) => e.write_raw(b),
                MessageData::Encrypted(b) => e.write_octet_string(b),
            }
        });
        Ok(outer.finish())
    }

    /// Parses a message from the wire.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let mut outer = d.read_sequence()?;
        let version = i32::try_from(outer.read_i64()?)
            .map_err(|_| Error::Message("version overflow".into()))?;
        if version != SNMP_VERSION_3 {
            return Err(Error::Message(format!(
                "unsupported version {version} (only SNMPv3 is implemented)"
            )));
        }

        let mut g = outer.read_sequence()?;
        let msg_id =
            i32::try_from(g.read_i64()?).map_err(|_| Error::Message("msgID overflow".into()))?;
        let msg_max_size = i32::try_from(g.read_i64()?)
            .map_err(|_| Error::Message("msgMaxSize overflow".into()))?;
        let flags_bytes = g.read_octet_string()?;
        if flags_bytes.len() != 1 {
            return Err(Error::Message(format!(
                "msgFlags must be 1 byte, got {}",
                flags_bytes.len()
            )));
        }
        let msg_flags = flags_bytes[0];
        let msg_security_model = i32::try_from(g.read_i64()?)
            .map_err(|_| Error::Message("msgSecurityModel overflow".into()))?;

        let sec_outer = outer.read_octet_string()?;
        let security = SecurityParameters::decode_inner(sec_outer)?;

        // msgData: peek tag. If priv bit set we expect an OCTET STRING; else SEQUENCE.
        let priv_bit = msg_flags & FLAG_PRIV != 0;
        let (tag, body) = outer.read_tlv()?;
        let data = if priv_bit {
            if tag != Tag::OCTET_STRING {
                return Err(Error::Message(format!(
                    "encrypted msgData must be OCTET STRING (got 0x{:02x})",
                    tag.0
                )));
            }
            MessageData::Encrypted(body.to_vec())
        } else {
            if tag != Tag::SEQUENCE {
                return Err(Error::Message(format!(
                    "plaintext msgData must be SEQUENCE (got 0x{:02x})",
                    tag.0
                )));
            }
            // Re-emit the SEQUENCE TLV.
            let mut e = Encoder::new();
            e.write_tlv(Tag::SEQUENCE, body);
            MessageData::Plain(e.finish())
        };

        Ok(Self {
            global: GlobalData {
                msg_id,
                msg_max_size,
                msg_flags,
                msg_security_model,
            },
            security,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::ObjectIdentifier;
    use crate::pdu::PduKind;
    use crate::value::{Value, VarBind};

    fn sample_message() -> Message {
        let pdu = Pdu {
            kind: PduKind::GetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::null(ObjectIdentifier::new([
                1u32, 3, 6, 1, 2, 1, 1, 1, 0,
            ]))],
        };
        let scoped = ScopedPdu {
            context_engine_id: vec![0x80, 0, 0, 0, 1],
            context_name: vec![],
            pdu,
        };
        Message {
            global: GlobalData {
                msg_id: 42,
                msg_max_size: 65507,
                msg_flags: FLAG_AUTH | FLAG_REPORTABLE,
                msg_security_model: SECURITY_MODEL_USM,
            },
            security: SecurityParameters {
                engine_id: vec![0x80, 0, 0, 0, 1],
                engine_boots: 1,
                engine_time: 100,
                user_name: b"alice".to_vec(),
                auth_params: vec![0u8; 12],
                priv_params: vec![],
            },
            data: MessageData::Plain(scoped.to_bytes().unwrap()),
        }
    }

    #[test]
    fn message_roundtrip_plain() {
        let m = sample_message();
        let bytes = m.to_bytes().unwrap();
        let back = Message::from_bytes(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn scoped_pdu_roundtrip() {
        let scoped = ScopedPdu {
            context_engine_id: vec![1, 2, 3],
            context_name: b"ctx".to_vec(),
            pdu: Pdu {
                kind: PduKind::Response,
                request_id: 7,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![VarBind::new(
                    ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 5, 0]),
                    Value::OctetString(b"name".to_vec()),
                )],
            },
        };
        let bytes = scoped.to_bytes().unwrap();
        let back = ScopedPdu::from_bytes(&bytes).unwrap();
        assert_eq!(scoped, back);
    }

    #[test]
    fn security_params_roundtrip() {
        let sp = SecurityParameters {
            engine_id: vec![0x80, 0, 0, 0, 1, 2, 3],
            engine_boots: 5,
            engine_time: 6789,
            user_name: b"bob".to_vec(),
            auth_params: vec![0xAA; 24],
            priv_params: vec![0xBB; 8],
        };
        let bytes = sp.to_inner_bytes();
        let back = SecurityParameters::decode_inner(&bytes).unwrap();
        assert_eq!(sp, back);
    }
}
