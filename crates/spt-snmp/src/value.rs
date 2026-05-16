//! SNMP `Variable Binding` value type and serialization.

use crate::ber::{Decoder, Encoder, Tag};
use crate::error::{Error, Result};
use crate::oid::ObjectIdentifier;

/// An SNMP variable value: any of the BER application or universal types
/// permitted by RFC 3416 §3 plus the three GetNext/GetBulk exception markers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Value {
    /// `INTEGER`
    Integer(i64),
    /// `OCTET STRING`
    OctetString(Vec<u8>),
    /// `NULL`
    Null,
    /// `OBJECT IDENTIFIER`
    Oid(ObjectIdentifier),
    /// `Counter32 [APPLICATION 1]`
    Counter32(u32),
    /// `Gauge32 [APPLICATION 2]`
    Gauge32(u32),
    /// `TimeTicks [APPLICATION 3]` — hundredths of a second.
    TimeTicks(u32),
    /// `Opaque [APPLICATION 4]`
    Opaque(Vec<u8>),
    /// `Counter64 [APPLICATION 6]`
    Counter64(u64),
    /// `IpAddress [APPLICATION 0]` — exactly 4 bytes.
    IpAddress([u8; 4]),
    /// `noSuchObject` exception (context-specific 0).
    NoSuchObject,
    /// `noSuchInstance` exception (context-specific 1).
    NoSuchInstance,
    /// `endOfMibView` exception (context-specific 2).
    EndOfMibView,
}

impl Value {
    pub(crate) fn encode(&self, enc: &mut Encoder) -> Result<()> {
        match self {
            Self::Integer(v) => enc.write_i64(*v),
            Self::OctetString(v) => enc.write_octet_string(v),
            Self::Null => enc.write_null(),
            Self::Oid(o) => enc.write_oid(o.arcs())?,
            Self::Counter32(v) => enc.write_app_u32(Tag::COUNTER32, *v),
            Self::Gauge32(v) => enc.write_app_u32(Tag::GAUGE32, *v),
            Self::TimeTicks(v) => enc.write_app_u32(Tag::TIMETICKS, *v),
            Self::Opaque(v) => enc.write_app_octet_string(Tag::OPAQUE, v),
            Self::Counter64(v) => enc.write_counter64(*v),
            Self::IpAddress(v) => enc.write_app_octet_string(Tag::IP_ADDRESS, v),
            Self::NoSuchObject => enc.write_tlv(Tag::NO_SUCH_OBJECT, &[]),
            Self::NoSuchInstance => enc.write_tlv(Tag::NO_SUCH_INSTANCE, &[]),
            Self::EndOfMibView => enc.write_tlv(Tag::END_OF_MIB, &[]),
        }
        Ok(())
    }

    pub(crate) fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let (tag, body) = dec.read_tlv()?;
        Ok(match tag {
            Tag::INTEGER => Self::Integer(decode_i64(body)?),
            Tag::OCTET_STRING => Self::OctetString(body.to_vec()),
            Tag::NULL => {
                if !body.is_empty() {
                    return Err(Error::Ber("NULL must be empty".into()));
                }
                Self::Null
            }
            Tag::OID => Self::Oid(ObjectIdentifier::from(crate::ber::decode_oid(body)?)),
            Tag::COUNTER32 => Self::Counter32(decode_u32_app(body)?),
            Tag::GAUGE32 => Self::Gauge32(decode_u32_app(body)?),
            Tag::TIMETICKS => Self::TimeTicks(decode_u32_app(body)?),
            Tag::OPAQUE => Self::Opaque(body.to_vec()),
            Tag::COUNTER64 => Self::Counter64(decode_u64_app(body)?),
            Tag::IP_ADDRESS => {
                if body.len() != 4 {
                    return Err(Error::Ber(format!(
                        "IpAddress must be 4 bytes, got {}",
                        body.len()
                    )));
                }
                let mut a = [0u8; 4];
                a.copy_from_slice(body);
                Self::IpAddress(a)
            }
            Tag::NO_SUCH_OBJECT => Self::NoSuchObject,
            Tag::NO_SUCH_INSTANCE => Self::NoSuchInstance,
            Tag::END_OF_MIB => Self::EndOfMibView,
            t => {
                return Err(Error::Ber(format!(
                    "unknown varbind value tag 0x{:02x}",
                    t.0
                )))
            }
        })
    }
}

fn decode_i64(body: &[u8]) -> Result<i64> {
    if body.is_empty() {
        return Err(Error::Ber("INTEGER must be non-empty".into()));
    }
    let mut acc: i64 = if body[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in body {
        acc = (acc << 8) | i64::from(b);
    }
    Ok(acc)
}

fn decode_u32_app(body: &[u8]) -> Result<u32> {
    let v = decode_uint(body)?;
    if v > u64::from(u32::MAX) {
        return Err(Error::Ber("application u32 overflow".into()));
    }
    Ok(v as u32)
}

fn decode_u64_app(body: &[u8]) -> Result<u64> {
    decode_uint(body)
}

fn decode_uint(body: &[u8]) -> Result<u64> {
    if body.is_empty() {
        return Err(Error::Ber("uint must be non-empty".into()));
    }
    if body.len() > 9 {
        return Err(Error::Ber("uint too large".into()));
    }
    let slice = if body.len() == 9 {
        if body[0] != 0 {
            return Err(Error::Ber("uint overflow".into()));
        }
        &body[1..]
    } else {
        body
    };
    let mut acc: u64 = 0;
    for &b in slice {
        acc = (acc << 8) | u64::from(b);
    }
    Ok(acc)
}

/// A `(name, value)` pair as carried in a PDU's `variable-bindings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBind {
    /// The OID being bound.
    pub name: ObjectIdentifier,
    /// The value at that OID.
    pub value: Value,
}

impl VarBind {
    /// Constructs a varbind.
    #[must_use]
    pub fn new(name: ObjectIdentifier, value: Value) -> Self {
        Self { name, value }
    }

    /// Convenience for `(name, NULL)` — used in GetRequest / GetNextRequest.
    #[must_use]
    pub fn null(name: ObjectIdentifier) -> Self {
        Self {
            name,
            value: Value::Null,
        }
    }

    pub(crate) fn encode(&self, enc: &mut Encoder) -> Result<()> {
        let mut inner = Encoder::new();
        inner.write_oid(self.name.arcs())?;
        self.value.encode(&mut inner)?;
        enc.write_tlv(Tag::SEQUENCE, inner.as_slice());
        Ok(())
    }

    pub(crate) fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let mut seq = dec.read_sequence()?;
        let name = ObjectIdentifier::from(seq.read_oid()?);
        let value = Value::decode(&mut seq)?;
        Ok(Self { name, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: Value) {
        let mut e = Encoder::new();
        v.encode(&mut e).unwrap();
        let mut d = Decoder::new(e.as_slice());
        let back = Value::decode(&mut d).unwrap();
        assert_eq!(v, back);
        assert!(d.is_empty());
    }

    #[test]
    fn all_value_types_roundtrip() {
        roundtrip(Value::Integer(-42));
        roundtrip(Value::Integer(0));
        roundtrip(Value::Integer(i64::MAX));
        roundtrip(Value::OctetString(b"hello".to_vec()));
        roundtrip(Value::OctetString(vec![]));
        roundtrip(Value::Null);
        roundtrip(Value::Oid(ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1])));
        roundtrip(Value::Counter32(1234));
        roundtrip(Value::Counter32(u32::MAX));
        roundtrip(Value::Gauge32(0));
        roundtrip(Value::TimeTicks(99_999));
        roundtrip(Value::Opaque(vec![0xDE, 0xAD]));
        roundtrip(Value::Counter64(u64::MAX));
        roundtrip(Value::Counter64(0));
        roundtrip(Value::IpAddress([10, 0, 0, 1]));
        roundtrip(Value::NoSuchObject);
        roundtrip(Value::NoSuchInstance);
        roundtrip(Value::EndOfMibView);
    }

    #[test]
    fn ip_address_wrong_length_errors() {
        let bytes = [0x40u8, 0x03, 10, 0, 0];
        let mut d = Decoder::new(&bytes);
        assert!(Value::decode(&mut d).is_err());
    }

    #[test]
    fn null_with_body_errors() {
        let bytes = [0x05u8, 0x01, 0x00];
        let mut d = Decoder::new(&bytes);
        assert!(Value::decode(&mut d).is_err());
    }

    #[test]
    fn unknown_tag_errors() {
        let bytes = [0x7Fu8, 0x00];
        let mut d = Decoder::new(&bytes);
        assert!(Value::decode(&mut d).is_err());
    }

    #[test]
    fn exception_markers_encode_with_zero_body() {
        let mut e = Encoder::new();
        Value::NoSuchObject.encode(&mut e).unwrap();
        Value::NoSuchInstance.encode(&mut e).unwrap();
        Value::EndOfMibView.encode(&mut e).unwrap();
        let bytes = e.finish();
        assert_eq!(bytes, vec![0x80, 0, 0x81, 0, 0x82, 0]);
    }

    #[test]
    fn integer_zero_encodes_single_byte() {
        let mut e = Encoder::new();
        Value::Integer(0).encode(&mut e).unwrap();
        let bytes = e.finish();
        assert_eq!(bytes, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn varbind_null_helper() {
        let oid = ObjectIdentifier::new([1u32, 3, 6, 1, 2]);
        let vb = VarBind::null(oid.clone());
        assert_eq!(vb.value, Value::Null);
        assert_eq!(vb.name, oid);
    }

    #[test]
    fn varbind_roundtrip() {
        let vb = VarBind::new(
            ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 5, 0]),
            Value::OctetString(b"sysName".to_vec()),
        );
        let mut e = Encoder::new();
        vb.encode(&mut e).unwrap();
        let mut d = Decoder::new(e.as_slice());
        let back = VarBind::decode(&mut d).unwrap();
        assert_eq!(vb, back);
    }
}
