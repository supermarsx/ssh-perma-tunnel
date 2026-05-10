//! Property: arbitrary SNMPv3 messages and components survive
//! `encode → decode` as the identity transformation.

use arbitrary::Unstructured;
use spt_property_tests::run_property;
use spt_snmp::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_PRIV,
    FLAG_REPORTABLE, SECURITY_MODEL_USM,
};
use spt_snmp::oid::ObjectIdentifier;
use spt_snmp::pdu::{Pdu, PduKind};
use spt_snmp::value::{VarBind, Value};

fn arb_oid(u: &mut Unstructured<'_>) -> arbitrary::Result<ObjectIdentifier> {
    // RFC 3416-ish: at least two arcs, all 32-bit subidentifiers.
    let len = u.int_in_range(2u8..=8)? as usize;
    let mut arcs = Vec::with_capacity(len);
    arcs.push(u.int_in_range(0u32..=2)?);
    arcs.push(u.int_in_range(0u32..=39)?);
    for _ in 2..len {
        arcs.push(u.int_in_range(0u32..=4096)?);
    }
    Ok(ObjectIdentifier::new(arcs))
}

fn arb_octet_string(u: &mut Unstructured<'_>, max: usize) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0u16..=(max as u16))? as usize;
    let mut v = vec![0u8; len];
    u.fill_buffer(&mut v)?;
    Ok(v)
}

fn arb_pdu_kind(u: &mut Unstructured<'_>) -> arbitrary::Result<PduKind> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 => PduKind::GetRequest,
        1 => PduKind::GetNextRequest,
        2 => PduKind::Response,
        3 => PduKind::SetRequest,
        4 => PduKind::GetBulkRequest,
        5 => PduKind::InformRequest,
        6 => PduKind::SnmpV2Trap,
        _ => PduKind::Report,
    })
}

fn arb_pdu(u: &mut Unstructured<'_>) -> arbitrary::Result<Pdu> {
    let n_var = u.int_in_range(0u8..=3)?;
    let mut vars = Vec::new();
    for _ in 0..n_var {
        vars.push(VarBind::new(arb_oid(u)?, Value::Null));
    }
    Ok(Pdu {
        kind: arb_pdu_kind(u)?,
        request_id: u.int_in_range(0i32..=i32::MAX)?,
        error_status: u.int_in_range(0i32..=18)?,
        error_index: u.int_in_range(0i32..=255)?,
        variable_bindings: vars,
    })
}

fn arb_security(u: &mut Unstructured<'_>) -> arbitrary::Result<SecurityParameters> {
    Ok(SecurityParameters {
        engine_id: arb_octet_string(u, 32)?,
        engine_boots: u.arbitrary::<u32>()?,
        engine_time: u.arbitrary::<u32>()?,
        user_name: arb_octet_string(u, 32)?,
        // Real digests are 12 (MD5/SHA1) or 16/24/32 (SHA-2). The encoder
        // treats this as opaque OCTET STRING bytes — round-trip with any
        // length is valid.
        auth_params: arb_octet_string(u, 32)?,
        priv_params: arb_octet_string(u, 16)?,
    })
}

fn arb_global(u: &mut Unstructured<'_>, with_priv: bool) -> arbitrary::Result<GlobalData> {
    let mut flags = 0u8;
    if u.arbitrary()? {
        flags |= FLAG_AUTH;
    }
    if with_priv {
        flags |= FLAG_PRIV;
    }
    if u.arbitrary()? {
        flags |= FLAG_REPORTABLE;
    }
    Ok(GlobalData {
        msg_id: u.int_in_range(0i32..=i32::MAX)?,
        msg_max_size: u.int_in_range(484i32..=65_535)?,
        msg_flags: flags,
        msg_security_model: SECURITY_MODEL_USM,
    })
}

fn make_plain_message(u: &mut Unstructured<'_>) -> arbitrary::Result<Message> {
    let pdu = arb_pdu(u)?;
    let scoped = ScopedPdu {
        context_engine_id: arb_octet_string(u, 16)?,
        context_name: arb_octet_string(u, 16)?,
        pdu,
    };
    let scoped_bytes = scoped.to_bytes().expect("scoped encode");
    Ok(Message {
        global: arb_global(u, false)?,
        security: arb_security(u)?,
        data: MessageData::Plain(scoped_bytes),
    })
}

// ---- Properties (12 invariants) -------------------------------------------

#[test]
fn message_plain_roundtrip() {
    run_property("message_plain_roundtrip", |u| {
        let m = make_plain_message(u)?;
        let bytes = m.to_bytes().expect("encode");
        let back = Message::from_bytes(&bytes).expect("decode");
        assert_eq!(m, back);
        Ok(())
    });
}

#[test]
fn message_encrypted_roundtrip() {
    run_property("message_encrypted_roundtrip", |u| {
        let global = arb_global(u, true)?; // priv bit forced
        let m = Message {
            global,
            security: arb_security(u)?,
            data: MessageData::Encrypted(arb_octet_string(u, 256)?),
        };
        let bytes = m.to_bytes().expect("encode");
        let back = Message::from_bytes(&bytes).expect("decode");
        assert_eq!(m, back);
        Ok(())
    });
}

#[test]
fn scoped_pdu_roundtrip() {
    run_property("scoped_pdu_roundtrip", |u| {
        let s = ScopedPdu {
            context_engine_id: arb_octet_string(u, 32)?,
            context_name: arb_octet_string(u, 32)?,
            pdu: arb_pdu(u)?,
        };
        let bytes = s.to_bytes().expect("encode");
        let back = ScopedPdu::from_bytes(&bytes).expect("decode");
        assert_eq!(s, back);
        Ok(())
    });
}

#[test]
fn security_parameters_roundtrip() {
    run_property("security_parameters_roundtrip", |u| {
        let s = arb_security(u)?;
        let bytes = s.to_inner_bytes();
        let back = SecurityParameters::decode_inner(&bytes).expect("decode");
        assert_eq!(s, back);
        Ok(())
    });
}

#[test]
fn pdu_get_request_roundtrip() {
    run_property("pdu_get_request_roundtrip", |u| {
        let mut p = arb_pdu(u)?;
        p.kind = PduKind::GetRequest;
        let scoped = ScopedPdu {
            context_engine_id: vec![0x80, 0, 0, 0, 1],
            context_name: vec![],
            pdu: p,
        };
        let bytes = scoped.to_bytes().expect("encode");
        let back = ScopedPdu::from_bytes(&bytes).expect("decode");
        assert_eq!(scoped, back);
        Ok(())
    });
}

#[test]
fn pdu_get_next_request_roundtrip() {
    run_property("pdu_get_next_request_roundtrip", |u| {
        let mut p = arb_pdu(u)?;
        p.kind = PduKind::GetNextRequest;
        let scoped = ScopedPdu {
            context_engine_id: vec![],
            context_name: vec![],
            pdu: p,
        };
        let bytes = scoped.to_bytes().expect("encode");
        assert_eq!(scoped, ScopedPdu::from_bytes(&bytes).expect("decode"));
        Ok(())
    });
}

#[test]
fn pdu_response_roundtrip() {
    run_property("pdu_response_roundtrip", |u| {
        let mut p = arb_pdu(u)?;
        p.kind = PduKind::Response;
        let scoped = ScopedPdu {
            context_engine_id: vec![1, 2, 3],
            context_name: vec![],
            pdu: p,
        };
        let bytes = scoped.to_bytes().expect("encode");
        assert_eq!(scoped, ScopedPdu::from_bytes(&bytes).expect("decode"));
        Ok(())
    });
}

#[test]
fn pdu_set_request_roundtrip() {
    run_property("pdu_set_request_roundtrip", |u| {
        let mut p = arb_pdu(u)?;
        p.kind = PduKind::SetRequest;
        let scoped = ScopedPdu {
            context_engine_id: vec![0xff],
            context_name: vec![],
            pdu: p,
        };
        let bytes = scoped.to_bytes().expect("encode");
        assert_eq!(scoped, ScopedPdu::from_bytes(&bytes).expect("decode"));
        Ok(())
    });
}

#[test]
fn pdu_v2trap_roundtrip() {
    run_property("pdu_v2trap_roundtrip", |u| {
        let mut p = arb_pdu(u)?;
        p.kind = PduKind::SnmpV2Trap;
        let scoped = ScopedPdu {
            context_engine_id: vec![],
            context_name: vec![],
            pdu: p,
        };
        let bytes = scoped.to_bytes().expect("encode");
        assert_eq!(scoped, ScopedPdu::from_bytes(&bytes).expect("decode"));
        Ok(())
    });
}

#[test]
fn pdu_report_roundtrip() {
    run_property("pdu_report_roundtrip", |u| {
        let mut p = arb_pdu(u)?;
        p.kind = PduKind::Report;
        let scoped = ScopedPdu {
            context_engine_id: vec![],
            context_name: vec![],
            pdu: p,
        };
        let bytes = scoped.to_bytes().expect("encode");
        assert_eq!(scoped, ScopedPdu::from_bytes(&bytes).expect("decode"));
        Ok(())
    });
}

#[test]
fn global_flags_combinations_roundtrip() {
    run_property("global_flags_combinations_roundtrip", |u| {
        // All 8 flag combinations must survive the round-trip when the
        // `priv` bit's setting is consistent with the data variant.
        let with_priv = u.arbitrary()?;
        let global = arb_global(u, with_priv)?;
        let data = if global.priv_bit() {
            MessageData::Encrypted(arb_octet_string(u, 32)?)
        } else {
            // plain SEQUENCE bytes
            let scoped = ScopedPdu {
                context_engine_id: vec![],
                context_name: vec![],
                pdu: arb_pdu(u)?,
            };
            MessageData::Plain(scoped.to_bytes().expect("encode"))
        };
        let m = Message {
            global,
            security: arb_security(u)?,
            data,
        };
        let bytes = m.to_bytes().expect("encode");
        let back = Message::from_bytes(&bytes).expect("decode");
        assert_eq!(m, back);
        Ok(())
    });
}

#[test]
fn oid_roundtrip_via_varbind() {
    run_property("oid_roundtrip_via_varbind", |u| {
        let o = arb_oid(u)?;
        let p = Pdu {
            kind: PduKind::GetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind::new(o.clone(), Value::Null)],
        };
        let scoped = ScopedPdu {
            context_engine_id: vec![],
            context_name: vec![],
            pdu: p,
        };
        let bytes = scoped.to_bytes().expect("encode");
        let back = ScopedPdu::from_bytes(&bytes).expect("decode");
        assert_eq!(back.pdu.variable_bindings.len(), 1);
        assert_eq!(back.pdu.variable_bindings[0].name, o);
        Ok(())
    });
}
