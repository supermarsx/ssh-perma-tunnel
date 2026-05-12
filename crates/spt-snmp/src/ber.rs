//! BER/DER encoder and decoder for the subset of ASN.1 used by SNMP.
//!
//! This module implements just enough of X.690 to serialize and parse
//! SNMPv3 messages: universal primitives (INTEGER, OCTET STRING, NULL,
//! OBJECT IDENTIFIER, SEQUENCE) and the SNMP application types from
//! RFC 2578 (Counter32 = 0x41, Gauge32 = 0x42, TimeTicks = 0x43,
//! Opaque = 0x44, Counter64 = 0x46, IpAddress = 0x40).
//!
//! ## Encoding rules
//!
//! - Length: short form for `len < 128`; otherwise `0x80 | n` followed
//!   by `n` big-endian bytes (DER: minimum number of bytes).
//! - INTEGER: signed, two's complement, big-endian, minimum bytes,
//!   sign-bit aware.
//! - OBJECT IDENTIFIER: first two sub-identifiers combined as
//!   `40*a + b`, then base-128 with high-bit continuation.
//!
//! ## Example
//!
//! ```
//! use spt_snmp::ber::{Encoder, Decoder, Tag};
//!
//! // Encode an INTEGER (42).
//! let mut e = Encoder::new();
//! e.write_i64(42);
//! let bytes = e.finish();
//!
//! // Decode it back.
//! let mut d = Decoder::new(&bytes);
//! let v = d.read_i64().unwrap();
//! assert_eq!(v, 42);
//! assert!(d.is_empty());
//! # let _ = Tag::INTEGER;
//! ```

use crate::error::{Error, Result};

/// ASN.1 tag byte for the BER types this crate uses.
///
/// SNMP uses a small fixed set of tags. We expose them as named
/// constants rather than an enum so they can be matched with `match`
/// on raw `u8` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag(pub u8);

impl Tag {
    /// `0x02` — INTEGER (universal, primitive).
    pub const INTEGER: Tag = Tag(0x02);
    /// `0x04` — OCTET STRING (universal, primitive).
    pub const OCTET_STRING: Tag = Tag(0x04);
    /// `0x05` — NULL (universal, primitive).
    pub const NULL: Tag = Tag(0x05);
    /// `0x06` — OBJECT IDENTIFIER.
    pub const OID: Tag = Tag(0x06);
    /// `0x30` — SEQUENCE / SEQUENCE OF (universal, constructed).
    pub const SEQUENCE: Tag = Tag(0x30);
    /// `0x40` — `IpAddress [APPLICATION 0]` IMPLICIT OCTET STRING (4).
    pub const IP_ADDRESS: Tag = Tag(0x40);
    /// `0x41` — `Counter32 [APPLICATION 1]` IMPLICIT INTEGER.
    pub const COUNTER32: Tag = Tag(0x41);
    /// `0x42` — `Gauge32 [APPLICATION 2]` IMPLICIT INTEGER.
    pub const GAUGE32: Tag = Tag(0x42);
    /// `0x43` — `TimeTicks [APPLICATION 3]` IMPLICIT INTEGER.
    pub const TIMETICKS: Tag = Tag(0x43);
    /// `0x44` — `Opaque [APPLICATION 4]` IMPLICIT OCTET STRING.
    pub const OPAQUE: Tag = Tag(0x44);
    /// `0x46` — `Counter64 [APPLICATION 6]` IMPLICIT INTEGER.
    pub const COUNTER64: Tag = Tag(0x46);

    // SNMP varbind error markers (context-specific, primitive).
    /// `0x80` — `noSuchObject` exception.
    pub const NO_SUCH_OBJECT: Tag = Tag(0x80);
    /// `0x81` — `noSuchInstance` exception.
    pub const NO_SUCH_INSTANCE: Tag = Tag(0x81);
    /// `0x82` — `endOfMibView` exception.
    pub const END_OF_MIB: Tag = Tag(0x82);

    // PDU tags ([APPLICATION] CONTEXT-SPECIFIC, constructed).
    /// `0xA0` — `GetRequest-PDU`.
    pub const GET_REQUEST: Tag = Tag(0xA0);
    /// `0xA1` — `GetNextRequest-PDU`.
    pub const GET_NEXT_REQUEST: Tag = Tag(0xA1);
    /// `0xA2` — `Response-PDU`.
    pub const RESPONSE: Tag = Tag(0xA2);
    /// `0xA3` — `SetRequest-PDU`.
    pub const SET_REQUEST: Tag = Tag(0xA3);
    /// `0xA5` — `GetBulkRequest-PDU`.
    pub const GET_BULK_REQUEST: Tag = Tag(0xA5);
    /// `0xA6` — `InformRequest-PDU`.
    pub const INFORM_REQUEST: Tag = Tag(0xA6);
    /// `0xA7` — `SNMPv2-Trap-PDU`.
    pub const SNMPV2_TRAP: Tag = Tag(0xA7);
    /// `0xA8` — `Report-PDU`.
    pub const REPORT: Tag = Tag(0xA8);
}

/// A growable BER encoder.
///
/// All `write_*` methods append a TLV sequence to the internal buffer;
/// the final `finish` returns the full byte vector.
#[derive(Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Creates an empty encoder.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Returns the current byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if no bytes have been written yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consumes the encoder and returns its bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Returns the bytes without consuming the encoder.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Appends a raw TLV (tag, length, value).
    pub fn write_tlv(&mut self, tag: Tag, value: &[u8]) {
        self.buf.push(tag.0);
        write_length(&mut self.buf, value.len());
        self.buf.extend_from_slice(value);
    }

    /// Encodes a signed integer as `INTEGER`.
    pub fn write_i64(&mut self, v: i64) {
        let bytes = encode_int(v);
        self.write_tlv(Tag::INTEGER, &bytes);
    }

    /// Encodes a 32-bit unsigned integer as `INTEGER` (sign-extended if needed).
    pub fn write_u32(&mut self, v: u32) {
        self.write_i64(i64::from(v));
    }

    /// Encodes an unsigned integer with the given application tag (Counter32,
    /// Gauge32, TimeTicks). The wire form is identical to INTEGER but with a
    /// non-`0x02` IMPLICIT tag.
    pub fn write_app_u32(&mut self, tag: Tag, v: u32) {
        let bytes = encode_uint(u64::from(v));
        self.write_tlv(tag, &bytes);
    }

    /// Encodes a 64-bit unsigned integer with `[APPLICATION 6]` (Counter64).
    pub fn write_counter64(&mut self, v: u64) {
        let bytes = encode_uint(v);
        self.write_tlv(Tag::COUNTER64, &bytes);
    }

    /// Encodes an OCTET STRING.
    pub fn write_octet_string(&mut self, v: &[u8]) {
        self.write_tlv(Tag::OCTET_STRING, v);
    }

    /// Encodes an OCTET STRING with the given application tag (Opaque, IpAddress).
    pub fn write_app_octet_string(&mut self, tag: Tag, v: &[u8]) {
        self.write_tlv(tag, v);
    }

    /// Encodes `NULL`.
    pub fn write_null(&mut self) {
        self.write_tlv(Tag::NULL, &[]);
    }

    /// Encodes an `OBJECT IDENTIFIER` from raw 32-bit sub-identifiers.
    pub fn write_oid(&mut self, arcs: &[u32]) -> Result<()> {
        let bytes = encode_oid(arcs)?;
        self.write_tlv(Tag::OID, &bytes);
        Ok(())
    }

    /// Appends raw bytes (already a complete TLV) to the buffer. Used by
    /// callers that need to splice in a pre-encoded SEQUENCE without
    /// re-wrapping it.
    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Wraps the bytes produced by `body` in a SEQUENCE TLV.
    pub fn write_sequence<F>(&mut self, body: F)
    where
        F: FnOnce(&mut Encoder),
    {
        let mut inner = Encoder::new();
        body(&mut inner);
        self.write_tlv(Tag::SEQUENCE, &inner.buf);
    }

    /// Wraps the bytes produced by `body` in a TLV with the given tag.
    /// Useful for context-specific constructed types like PDUs.
    pub fn write_constructed<F>(&mut self, tag: Tag, body: F)
    where
        F: FnOnce(&mut Encoder),
    {
        let mut inner = Encoder::new();
        body(&mut inner);
        self.write_tlv(tag, &inner.buf);
    }
}

/// A zero-copy BER decoder over a byte slice.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Wraps a byte slice for decoding.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Number of bytes left to consume.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Whether the decoder has consumed all bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.bytes.len() {
            Err(Error::Ber(format!(
                "truncated: need {n} byte(s) at offset {}",
                self.pos
            )))
        } else {
            Ok(())
        }
    }

    fn read_byte(&mut self) -> Result<u8> {
        self.need(1)?;
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Peeks the next tag byte without advancing.
    pub fn peek_tag(&self) -> Result<Tag> {
        if self.pos >= self.bytes.len() {
            return Err(Error::Ber("expected tag, got EOF".into()));
        }
        Ok(Tag(self.bytes[self.pos]))
    }

    /// Reads a `(tag, value)` pair.
    pub fn read_tlv(&mut self) -> Result<(Tag, &'a [u8])> {
        let tag = Tag(self.read_byte()?);
        let len = read_length(self)?;
        self.need(len)?;
        let v = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, v))
    }

    /// Reads a TLV and verifies the tag matches `expected`.
    pub fn read_expected(&mut self, expected: Tag) -> Result<&'a [u8]> {
        let (tag, v) = self.read_tlv()?;
        if tag != expected {
            return Err(Error::Ber(format!(
                "expected tag 0x{:02x}, got 0x{:02x}",
                expected.0, tag.0
            )));
        }
        Ok(v)
    }

    /// Reads a SEQUENCE and returns a sub-decoder over its body.
    pub fn read_sequence(&mut self) -> Result<Decoder<'a>> {
        let body = self.read_expected(Tag::SEQUENCE)?;
        Ok(Decoder::new(body))
    }

    /// Reads a constructed TLV with the given tag and returns a sub-decoder.
    pub fn read_constructed(&mut self, tag: Tag) -> Result<Decoder<'a>> {
        let body = self.read_expected(tag)?;
        Ok(Decoder::new(body))
    }

    /// Reads an INTEGER as `i64`. Reads any `INTEGER`-shaped TLV.
    pub fn read_i64(&mut self) -> Result<i64> {
        let v = self.read_expected(Tag::INTEGER)?;
        decode_int(v)
    }

    /// Reads an INTEGER as `u32` (rejects negatives).
    pub fn read_u32(&mut self) -> Result<u32> {
        let v = self.read_i64()?;
        if !(0..=i64::from(u32::MAX)).contains(&v) {
            return Err(Error::Ber(format!("u32 out of range: {v}")));
        }
        Ok(v as u32)
    }

    /// Reads an OCTET STRING.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8]> {
        self.read_expected(Tag::OCTET_STRING)
    }

    /// Reads `NULL` (returns `()` on success).
    pub fn read_null(&mut self) -> Result<()> {
        let v = self.read_expected(Tag::NULL)?;
        if !v.is_empty() {
            return Err(Error::Ber("NULL must have zero-length body".into()));
        }
        Ok(())
    }

    /// Reads an `OBJECT IDENTIFIER` and returns its decoded sub-arcs.
    pub fn read_oid(&mut self) -> Result<Vec<u32>> {
        let v = self.read_expected(Tag::OID)?;
        decode_oid(v)
    }

    /// Reads an unsigned integer with the given application tag (Counter32,
    /// Gauge32, TimeTicks). Returns `0xFFFF_FFFF` saturating cap.
    pub fn read_app_u32(&mut self, tag: Tag) -> Result<u32> {
        let v = self.read_expected(tag)?;
        let n = decode_uint(v)?;
        if n > u64::from(u32::MAX) {
            return Err(Error::Ber("app uint exceeds 32 bits".into()));
        }
        Ok(n as u32)
    }

    /// Reads a `Counter64`.
    pub fn read_counter64(&mut self) -> Result<u64> {
        let v = self.read_expected(Tag::COUNTER64)?;
        decode_uint(v)
    }
}

/// Writes an X.690 length octet sequence.
pub fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
        return;
    }
    // Long form. DER requires the minimum number of length bytes.
    let mut tmp = [0u8; 8];
    let mut n = 0;
    let mut v = len;
    while v > 0 {
        tmp[n] = (v & 0xFF) as u8;
        v >>= 8;
        n += 1;
    }
    // n <= 8 so this is always <= 0x80 | 8 = 0x88.
    out.push(0x80 | n as u8);
    for i in (0..n).rev() {
        out.push(tmp[i]);
    }
}

/// Reads an X.690 length octet sequence.
fn read_length(d: &mut Decoder<'_>) -> Result<usize> {
    let first = d.read_byte()?;
    if first < 0x80 {
        return Ok(usize::from(first));
    }
    if first == 0x80 {
        return Err(Error::Ber("indefinite-length form is not allowed".into()));
    }
    let n = usize::from(first & 0x7F);
    if n > std::mem::size_of::<usize>() {
        return Err(Error::Ber(format!("length encoded in too many bytes: {n}")));
    }
    let mut len = 0usize;
    for _ in 0..n {
        let b = d.read_byte()?;
        len = (len << 8) | usize::from(b);
    }
    Ok(len)
}

/// Encodes a signed `i64` to the minimum number of two's-complement bytes.
fn encode_int(v: i64) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let mut bytes = v.to_be_bytes().to_vec();
    if v > 0 {
        // Strip leading 0x00 bytes, but keep one if the next byte has the high bit set.
        while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
            bytes.remove(0);
        }
    } else {
        // Strip leading 0xFF bytes, but keep one if next has high bit clear.
        while bytes.len() > 1 && bytes[0] == 0xFF && bytes[1] & 0x80 != 0 {
            bytes.remove(0);
        }
    }
    bytes
}

/// Decodes a signed two's-complement big-endian integer.
fn decode_int(bytes: &[u8]) -> Result<i64> {
    if bytes.is_empty() {
        return Err(Error::Ber("INTEGER must have at least one byte".into()));
    }
    if bytes.len() > 9 {
        return Err(Error::Ber(format!(
            "INTEGER too large for i64: {} bytes",
            bytes.len()
        )));
    }
    // Sign-extend the leading byte.
    let mut acc: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        acc = (acc << 8) | i64::from(b);
    }
    // Detect overflow: if input has 9 bytes and is positive, it doesn't fit.
    if bytes.len() == 9 && bytes[0] != 0 {
        return Err(Error::Ber("INTEGER overflow for i64".into()));
    }
    Ok(acc)
}

/// Encodes an unsigned `u64` using minimum bytes; pads with `0x00` if the
/// high bit would otherwise indicate a negative number.
fn encode_uint(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    bytes
}

/// Decodes an unsigned big-endian integer from a BER value (tolerates a
/// leading `0x00` sign-pad byte).
fn decode_uint(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() {
        return Err(Error::Ber("uint must have at least one byte".into()));
    }
    if bytes.len() > 9 {
        return Err(Error::Ber("uint too large".into()));
    }
    let slice = if bytes.len() == 9 {
        if bytes[0] != 0 {
            return Err(Error::Ber("uint overflow".into()));
        }
        &bytes[1..]
    } else {
        bytes
    };
    let mut acc: u64 = 0;
    for &b in slice {
        acc = (acc << 8) | u64::from(b);
    }
    Ok(acc)
}

/// Encodes an OID's sub-arcs using base-128 with high-bit continuation.
pub fn encode_oid(arcs: &[u32]) -> Result<Vec<u8>> {
    if arcs.len() < 2 {
        return Err(Error::BerEncode(
            "OID must have at least 2 sub-identifiers".into(),
        ));
    }
    if arcs[0] > 2 {
        return Err(Error::BerEncode(format!(
            "OID first arc must be 0..=2, got {}",
            arcs[0]
        )));
    }
    if arcs[0] < 2 && arcs[1] >= 40 {
        return Err(Error::BerEncode(format!(
            "OID second arc must be 0..=39 when first arc is {}",
            arcs[0]
        )));
    }
    let mut out = Vec::with_capacity(arcs.len() * 2);
    encode_arc(&mut out, arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        encode_arc(&mut out, a);
    }
    Ok(out)
}

fn encode_arc(out: &mut Vec<u8>, mut v: u32) {
    if v < 0x80 {
        out.push(v as u8);
        return;
    }
    let mut tmp = [0u8; 5];
    let mut n = 0;
    while v > 0 {
        tmp[n] = (v & 0x7F) as u8;
        v >>= 7;
        n += 1;
    }
    // Emit MSB-first; all but the final byte have the continuation bit set.
    for i in (1..n).rev() {
        out.push(tmp[i] | 0x80);
    }
    out.push(tmp[0]);
}

/// Decodes an OID body into its sub-arcs.
pub fn decode_oid(bytes: &[u8]) -> Result<Vec<u32>> {
    if bytes.is_empty() {
        return Err(Error::Ber("OID body must be non-empty".into()));
    }
    // Decode the first base-128 arc, which encodes `40*a + b`.
    let mut idx = 0usize;
    let first_combined = decode_arc(bytes, &mut idx)?;
    let (a, b) = if first_combined < 40 {
        (0u32, first_combined)
    } else if first_combined < 80 {
        (1u32, first_combined - 40)
    } else {
        (2u32, first_combined - 80)
    };
    let mut arcs = vec![a, b];
    while idx < bytes.len() {
        arcs.push(decode_arc(bytes, &mut idx)?);
    }
    Ok(arcs)
}

fn decode_arc(bytes: &[u8], idx: &mut usize) -> Result<u32> {
    let mut acc: u32 = 0;
    let start = *idx;
    while *idx < bytes.len() {
        let b = bytes[*idx];
        if acc & 0xFE00_0000 != 0 {
            return Err(Error::Ber("OID arc exceeds 32 bits".into()));
        }
        acc = (acc << 7) | u32::from(b & 0x7F);
        *idx += 1;
        if b & 0x80 == 0 {
            return Ok(acc);
        }
    }
    let _ = start;
    Err(Error::Ber("OID truncated mid-arc".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_roundtrip_edges() {
        for v in [
            0i64,
            1,
            -1,
            127,
            128,
            -128,
            -129,
            32767,
            -32768,
            i64::MAX,
            i64::MIN,
        ] {
            let mut e = Encoder::new();
            e.write_i64(v);
            let bytes = e.finish();
            let mut d = Decoder::new(&bytes);
            assert_eq!(d.read_i64().unwrap(), v, "value {v}");
        }
    }

    #[test]
    fn integer_minimum_form() {
        // 127 fits in one byte; 128 needs a sign-pad → two bytes.
        let mut e = Encoder::new();
        e.write_i64(127);
        assert_eq!(e.finish(), vec![0x02, 0x01, 0x7F]);

        let mut e = Encoder::new();
        e.write_i64(128);
        assert_eq!(e.finish(), vec![0x02, 0x02, 0x00, 0x80]);

        let mut e = Encoder::new();
        e.write_i64(-128);
        assert_eq!(e.finish(), vec![0x02, 0x01, 0x80]);
    }

    #[test]
    fn length_long_form() {
        let v = vec![0u8; 200];
        let mut e = Encoder::new();
        e.write_octet_string(&v);
        let bytes = e.finish();
        assert_eq!(&bytes[..3], &[0x04, 0x81, 200]);
        assert_eq!(bytes.len(), 3 + 200);
    }

    #[test]
    fn oid_roundtrip_known_value() {
        // 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        let arcs = vec![1u32, 3, 6, 1, 2, 1, 1, 1, 0];
        let body = encode_oid(&arcs).unwrap();
        // First byte = 1*40 + 3 = 43 = 0x2B
        assert_eq!(body[0], 0x2B);
        let back = decode_oid(&body).unwrap();
        assert_eq!(back, arcs);
    }

    #[test]
    fn oid_large_arc() {
        let arcs = vec![1u32, 3, 6, 1, 4, 1, 99_999, 1];
        let body = encode_oid(&arcs).unwrap();
        let back = decode_oid(&body).unwrap();
        assert_eq!(back, arcs);
    }

    #[test]
    fn oid_invalid() {
        assert!(encode_oid(&[]).is_err());
        assert!(encode_oid(&[0]).is_err());
        assert!(encode_oid(&[3, 1, 1]).is_err());
        assert!(encode_oid(&[0, 40, 1]).is_err());
        assert!(decode_oid(&[]).is_err());
        // Truncated continuation
        assert!(decode_oid(&[0x2B, 0x80]).is_err());
    }

    #[test]
    fn sequence_roundtrip() {
        let mut e = Encoder::new();
        e.write_sequence(|inner| {
            inner.write_i64(1);
            inner.write_octet_string(b"hi");
        });
        let bytes = e.finish();
        let mut d = Decoder::new(&bytes);
        let mut seq = d.read_sequence().unwrap();
        assert_eq!(seq.read_i64().unwrap(), 1);
        assert_eq!(seq.read_octet_string().unwrap(), b"hi");
        assert!(seq.is_empty());
        assert!(d.is_empty());
    }

    #[test]
    fn null_roundtrip() {
        let mut e = Encoder::new();
        e.write_null();
        let bytes = e.finish();
        assert_eq!(bytes, vec![0x05, 0x00]);
        let mut d = Decoder::new(&bytes);
        d.read_null().unwrap();
    }

    #[test]
    fn application_types() {
        let mut e = Encoder::new();
        e.write_app_u32(Tag::COUNTER32, 1_234_567);
        e.write_app_u32(Tag::GAUGE32, 99);
        e.write_app_u32(Tag::TIMETICKS, 0);
        e.write_counter64(u64::MAX);
        e.write_app_octet_string(Tag::IP_ADDRESS, &[10, 0, 0, 1]);
        let bytes = e.finish();
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.read_app_u32(Tag::COUNTER32).unwrap(), 1_234_567);
        assert_eq!(d.read_app_u32(Tag::GAUGE32).unwrap(), 99);
        assert_eq!(d.read_app_u32(Tag::TIMETICKS).unwrap(), 0);
        assert_eq!(d.read_counter64().unwrap(), u64::MAX);
        let ip = d.read_expected(Tag::IP_ADDRESS).unwrap();
        assert_eq!(ip, &[10, 0, 0, 1]);
    }

    #[test]
    fn truncated_decode() {
        let mut d = Decoder::new(&[0x02, 0x05, 0x01]);
        assert!(d.read_i64().is_err());
    }
}
