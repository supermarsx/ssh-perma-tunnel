//! SNMPv2c/SNMPv3 PDU types.
//!
//! Per RFC 3416 the PDU body is a SEQUENCE of:
//! - `request-id` INTEGER
//! - `error-status` INTEGER (or `non-repeaters` for GetBulk)
//! - `error-index` INTEGER (or `max-repetitions` for GetBulk)
//! - `variable-bindings` SEQUENCE OF VarBind

use crate::ber::{Decoder, Encoder, Tag};
use crate::error::{Error, Result};
use crate::value::VarBind;

/// PDU kind. Distinguishes the wire tag (`0xA0`..=`0xA8`) used at encode time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduKind {
    /// `GetRequest-PDU` (`0xA0`).
    GetRequest,
    /// `GetNextRequest-PDU` (`0xA1`).
    GetNextRequest,
    /// `Response-PDU` (`0xA2`).
    Response,
    /// `SetRequest-PDU` (`0xA3`).
    SetRequest,
    /// `GetBulkRequest-PDU` (`0xA5`).
    GetBulkRequest,
    /// `InformRequest-PDU` (`0xA6`).
    InformRequest,
    /// `SNMPv2-Trap-PDU` (`0xA7`).
    SnmpV2Trap,
    /// `Report-PDU` (`0xA8`).
    Report,
}

impl PduKind {
    /// Returns the BER tag used when encoding this PDU kind.
    #[must_use]
    pub fn tag(self) -> Tag {
        match self {
            Self::GetRequest => Tag::GET_REQUEST,
            Self::GetNextRequest => Tag::GET_NEXT_REQUEST,
            Self::Response => Tag::RESPONSE,
            Self::SetRequest => Tag::SET_REQUEST,
            Self::GetBulkRequest => Tag::GET_BULK_REQUEST,
            Self::InformRequest => Tag::INFORM_REQUEST,
            Self::SnmpV2Trap => Tag::SNMPV2_TRAP,
            Self::Report => Tag::REPORT,
        }
    }

    /// Maps a wire tag back to a PDU kind.
    pub fn from_tag(tag: Tag) -> Result<Self> {
        Ok(match tag {
            Tag::GET_REQUEST => Self::GetRequest,
            Tag::GET_NEXT_REQUEST => Self::GetNextRequest,
            Tag::RESPONSE => Self::Response,
            Tag::SET_REQUEST => Self::SetRequest,
            Tag::GET_BULK_REQUEST => Self::GetBulkRequest,
            Tag::INFORM_REQUEST => Self::InformRequest,
            Tag::SNMPV2_TRAP => Self::SnmpV2Trap,
            Tag::REPORT => Self::Report,
            t => return Err(Error::Message(format!("unknown PDU tag 0x{:02x}", t.0))),
        })
    }
}

/// `error-status` values per RFC 3416.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorStatus {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
    NoAccess = 6,
    WrongType = 7,
    WrongLength = 8,
    WrongEncoding = 9,
    WrongValue = 10,
    NoCreation = 11,
    InconsistentValue = 12,
    ResourceUnavailable = 13,
    CommitFailed = 14,
    UndoFailed = 15,
    AuthorizationError = 16,
    NotWritable = 17,
    InconsistentName = 18,
}

/// Concrete PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    /// PDU kind / wire tag.
    pub kind: PduKind,
    /// Request id.
    pub request_id: i32,
    /// `error-status` (or `non-repeaters` for `GetBulkRequest`).
    pub error_status: i32,
    /// `error-index` (or `max-repetitions` for `GetBulkRequest`).
    pub error_index: i32,
    /// Bindings.
    pub variable_bindings: Vec<VarBind>,
}

impl Pdu {
    /// Encodes the PDU TLV (kind tag + body) into `enc`.
    pub fn encode(&self, enc: &mut Encoder) -> Result<()> {
        let mut body = Encoder::new();
        body.write_i64(i64::from(self.request_id));
        body.write_i64(i64::from(self.error_status));
        body.write_i64(i64::from(self.error_index));

        let mut vbs = Encoder::new();
        for vb in &self.variable_bindings {
            vb.encode(&mut vbs)?;
        }
        body.write_tlv(Tag::SEQUENCE, vbs.as_slice());

        enc.write_tlv(self.kind.tag(), body.as_slice());
        Ok(())
    }

    /// Decodes a PDU from a sub-decoder positioned at the kind tag.
    pub fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let (tag, body) = dec.read_tlv()?;
        let kind = PduKind::from_tag(tag)?;
        let mut bd = Decoder::new(body);
        let request_id = i32::try_from(bd.read_i64()?)
            .map_err(|_| Error::Message("request-id overflow".into()))?;
        let error_status = i32::try_from(bd.read_i64()?)
            .map_err(|_| Error::Message("error-status overflow".into()))?;
        let error_index = i32::try_from(bd.read_i64()?)
            .map_err(|_| Error::Message("error-index overflow".into()))?;
        let mut vbs = bd.read_sequence()?;
        let mut bindings = Vec::new();
        while !vbs.is_empty() {
            bindings.push(VarBind::decode(&mut vbs)?);
        }
        Ok(Self {
            kind,
            request_id,
            error_status,
            error_index,
            variable_bindings: bindings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::ObjectIdentifier;
    use crate::value::Value;

    #[test]
    fn pdu_roundtrip() {
        let pdu = Pdu {
            kind: PduKind::GetRequest,
            request_id: 12345,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![
                VarBind::null(ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 1, 0])),
                VarBind::null(ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 5, 0])),
            ],
        };
        let mut e = Encoder::new();
        pdu.encode(&mut e).unwrap();
        let mut d = Decoder::new(e.as_slice());
        let back = Pdu::decode(&mut d).unwrap();
        assert_eq!(pdu, back);
    }

    #[test]
    fn from_tag_round_trip_all_kinds() {
        for kind in [
            PduKind::GetRequest,
            PduKind::GetNextRequest,
            PduKind::Response,
            PduKind::SetRequest,
            PduKind::GetBulkRequest,
            PduKind::InformRequest,
            PduKind::SnmpV2Trap,
            PduKind::Report,
        ] {
            let tag = kind.tag();
            let back = PduKind::from_tag(tag).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn from_tag_unknown_errors() {
        assert!(PduKind::from_tag(Tag(0xA4)).is_err());
        assert!(PduKind::from_tag(Tag(0x00)).is_err());
    }

    #[test]
    fn error_status_repr_matches_rfc() {
        assert_eq!(ErrorStatus::NoError as i32, 0);
        assert_eq!(ErrorStatus::TooBig as i32, 1);
        assert_eq!(ErrorStatus::NotWritable as i32, 17);
        assert_eq!(ErrorStatus::InconsistentName as i32, 18);
    }

    #[test]
    fn get_bulk_roundtrip() {
        let pdu = Pdu {
            kind: PduKind::GetBulkRequest,
            request_id: 7,
            error_status: 0,
            error_index: 10,
            variable_bindings: vec![VarBind::null(ObjectIdentifier::new([
                1u32, 3, 6, 1, 4, 1, 32_473,
            ]))],
        };
        let mut e = Encoder::new();
        pdu.encode(&mut e).unwrap();
        let mut d = Decoder::new(e.as_slice());
        let back = Pdu::decode(&mut d).unwrap();
        assert_eq!(pdu, back);
    }

    #[test]
    fn report_roundtrip() {
        let pdu = Pdu {
            kind: PduKind::Report,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![],
        };
        let mut e = Encoder::new();
        pdu.encode(&mut e).unwrap();
        let mut d = Decoder::new(e.as_slice());
        let back = Pdu::decode(&mut d).unwrap();
        assert_eq!(pdu, back);
    }

    #[test]
    fn response_with_value() {
        let pdu = Pdu {
            kind: PduKind::Response,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::new(
                ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 1, 0]),
                Value::OctetString(b"spt-test".to_vec()),
            )],
        };
        let mut e = Encoder::new();
        pdu.encode(&mut e).unwrap();
        let mut d = Decoder::new(e.as_slice());
        let back = Pdu::decode(&mut d).unwrap();
        assert_eq!(pdu, back);
    }
}
