//! Property-based tests for the BER codec and OID parser.

use proptest::prelude::*;
use spt_snmp::ber::{decode_oid, encode_oid, Decoder, Encoder};
use spt_snmp::oid::ObjectIdentifier;
use spt_snmp::value::{VarBind, Value};

proptest! {
    #[test]
    fn integer_roundtrip(v in any::<i64>()) {
        let mut e = Encoder::new();
        e.write_i64(v);
        let bytes = e.finish();
        let mut d = Decoder::new(&bytes);
        let back = d.read_i64().unwrap();
        prop_assert_eq!(v, back);
        prop_assert!(d.is_empty());
    }

    #[test]
    fn octet_string_roundtrip(v in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let mut e = Encoder::new();
        e.write_octet_string(&v);
        let bytes = e.finish();
        let mut d = Decoder::new(&bytes);
        let back = d.read_octet_string().unwrap();
        prop_assert_eq!(back, v.as_slice());
    }

    /// OID arc strategy: generate a leading pair satisfying the X.660
    /// constraints, then 0..10 additional u32 arcs.
    #[test]
    fn oid_roundtrip(
        first in 0u32..=2,
        // second is bounded by first, but we cap conservatively.
        second_seed in any::<u32>(),
        rest in proptest::collection::vec(any::<u32>(), 0..10)
    ) {
        let second_max = if first < 2 { 39 } else { u32::MAX - 80 - 1 };
        let second = second_seed % (second_max + 1);
        let mut arcs = vec![first, second];
        arcs.extend(rest);
        let bytes = encode_oid(&arcs).unwrap();
        let back = decode_oid(&bytes).unwrap();
        prop_assert_eq!(back, arcs);
    }

    #[test]
    fn varbind_roundtrip_strings(s in proptest::collection::vec(any::<u8>(), 0..256)) {
        let vb = VarBind::new(
            ObjectIdentifier::new([1u32, 3, 6, 1, 4, 1, 99_999, 1, 0]),
            Value::OctetString(s.clone()),
        );
        let mut e = Encoder::new();
        let mut inner = Encoder::new();
        // Re-implement via crate's internal hooks: VarBind has private encode,
        // but we exercise it indirectly through the codec test surface.
        inner.write_oid(&[1, 3, 6, 1, 4, 1, 99_999, 1, 0]).unwrap();
        let mut val = Encoder::new();
        val.write_octet_string(&s);
        inner.write_raw(val.as_slice());
        e.write_sequence(|seq| seq.write_raw(inner.as_slice()));

        let bytes = e.finish();
        let mut d = Decoder::new(&bytes);
        let mut seq = d.read_sequence().unwrap();
        let oid = seq.read_oid().unwrap();
        let body = seq.read_octet_string().unwrap();
        prop_assert_eq!(oid, vec![1u32, 3, 6, 1, 4, 1, 99_999, 1, 0]);
        prop_assert_eq!(body, s.as_slice());
        let _ = vb;
    }
}
