//! Emit valid SNMPv3 envelopes with various PDUs, plus boundary cases for
//! the message decoder.

use spt_fuzz_generators::{out_dir_from_args, write_file};
use spt_snmp::ber::Encoder;
use spt_snmp::message::{
    GlobalData, Message, MessageData, ScopedPdu, SecurityParameters, FLAG_AUTH, FLAG_PRIV,
    FLAG_REPORTABLE,
};
use spt_snmp::oid::ObjectIdentifier;
use spt_snmp::pdu::{Pdu, PduKind};
use spt_snmp::value::{VarBind, Value};

fn pdu_get(req_id: i32) -> Pdu {
    Pdu {
        kind: PduKind::GetRequest,
        request_id: req_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::null(ObjectIdentifier::new([
            1u32, 3, 6, 1, 2, 1, 1, 1, 0,
        ]))],
    }
}

fn pdu_response(req_id: i32) -> Pdu {
    Pdu {
        kind: PduKind::Response,
        request_id: req_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind::new(
            ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 1, 0]),
            Value::OctetString(b"spt-fuzz-seed".to_vec()),
        )],
    }
}

fn pdu_trap() -> Pdu {
    Pdu {
        kind: PduKind::SnmpV2Trap,
        request_id: 9,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![
            VarBind::new(
                ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 3, 0]),
                Value::TimeTicks(12_345),
            ),
            VarBind::new(
                ObjectIdentifier::new([1u32, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
                Value::Oid(ObjectIdentifier::new([1u32, 3, 6, 1, 6, 3, 1, 1, 5, 1])),
            ),
        ],
    }
}

fn pdu_bulk() -> Pdu {
    Pdu {
        kind: PduKind::GetBulkRequest,
        request_id: 5,
        error_status: 0, // non-repeaters
        error_index: 10, // max-repetitions
        variable_bindings: vec![VarBind::null(ObjectIdentifier::new([
            1u32, 3, 6, 1, 2, 1, 2, 2, 1,
        ]))],
    }
}

fn build(global: GlobalData, security: SecurityParameters, pdu: Pdu) -> Vec<u8> {
    let scoped = ScopedPdu {
        context_engine_id: security.engine_id.clone(),
        context_name: Vec::new(),
        pdu,
    };
    let plain = scoped.to_bytes().expect("encode scoped pdu");
    let msg = Message {
        global,
        security,
        data: MessageData::Plain(plain),
    };
    let bytes = msg.to_bytes().expect("encode message");
    // Round-trip sanity.
    let _ = Message::from_bytes(&bytes).expect("round-trip parse");
    bytes
}

fn default_global(flags: u8) -> GlobalData {
    GlobalData {
        msg_id: 1,
        msg_max_size: 65_507,
        msg_flags: flags,
        msg_security_model: 3,
    }
}

fn default_sec(engine_id: &[u8]) -> SecurityParameters {
    SecurityParameters {
        engine_id: engine_id.to_vec(),
        engine_boots: 1,
        engine_time: 0,
        user_name: b"fuzz".to_vec(),
        auth_params: Vec::new(),
        priv_params: Vec::new(),
    }
}

fn main() {
    let dir = out_dir_from_args();

    let eid = b"\x80\x00\x1f\x88\x80\x73\x70\x74";

    write_file(&dir, "valid_get_noauth.bin",
        &build(default_global(0), default_sec(eid), pdu_get(7)));
    write_file(&dir, "valid_get_reportable.bin",
        &build(default_global(FLAG_REPORTABLE), default_sec(eid), pdu_get(8)));
    write_file(&dir, "valid_response.bin",
        &build(default_global(0), default_sec(eid), pdu_response(7)));
    write_file(&dir, "valid_v2trap.bin",
        &build(default_global(0), default_sec(eid), pdu_trap()));
    write_file(&dir, "valid_bulk.bin",
        &build(default_global(0), default_sec(eid), pdu_bulk()));

    // authNoPriv: auth_params has the right length placeholder (12 bytes for
    // SHA-1; size doesn't matter for the framer test, only presence does).
    {
        let mut sec = default_sec(eid);
        sec.auth_params = vec![0u8; 12];
        write_file(&dir, "valid_authnopriv.bin",
            &build(default_global(FLAG_AUTH | FLAG_REPORTABLE), sec, pdu_get(9)));
    }

    // authPriv: msgData is wrapped as OCTET STRING. We have to bypass `build`
    // because `build` always produces Plain.
    {
        let mut sec = default_sec(eid);
        sec.auth_params = vec![0u8; 12];
        sec.priv_params = vec![0u8; 8];
        let scoped = ScopedPdu {
            context_engine_id: eid.to_vec(),
            context_name: Vec::new(),
            pdu: pdu_get(10),
        };
        let plain = scoped.to_bytes().unwrap();
        // Pretend the plaintext is the "ciphertext" — the parser doesn't try
        // to decrypt at this layer, it just unwraps the OCTET STRING.
        let msg = Message {
            global: default_global(FLAG_AUTH | FLAG_PRIV | FLAG_REPORTABLE),
            security: sec,
            data: MessageData::Encrypted(plain),
        };
        let bytes = msg.to_bytes().unwrap();
        let _ = Message::from_bytes(&bytes).expect("round-trip authPriv");
        write_file(&dir, "valid_authpriv.bin", &bytes);
    }

    // Long engine_id and user_name — exercise the OCTET STRING long-form path.
    {
        let mut sec = default_sec(&[0xAB; 32]);
        sec.user_name = b"a-very-long-user-name-that-uses-multi-byte-len".to_vec();
        write_file(&dir, "valid_long_engine_user.bin",
            &build(default_global(0), sec, pdu_get(11)));
    }

    // SecurityParameters inner-only seeds.
    {
        let mut e = Encoder::new();
        default_sec(eid).encode_inner(&mut e);
        write_file(&dir, "valid_secparams_inner.bin", &e.finish());
    }
    {
        let mut sec = default_sec(eid);
        sec.engine_boots = u32::MAX;
        sec.engine_time = u32::MAX;
        let mut e = Encoder::new();
        sec.encode_inner(&mut e);
        write_file(&dir, "valid_secparams_max_counters.bin", &e.finish());
    }

    // ScopedPdu seeds.
    {
        let scoped = ScopedPdu {
            context_engine_id: eid.to_vec(),
            context_name: b"ctx".to_vec(),
            pdu: pdu_get(1),
        };
        write_file(&dir, "valid_scoped_pdu.bin", &scoped.to_bytes().unwrap());
    }
    {
        let scoped = ScopedPdu {
            context_engine_id: Vec::new(),
            context_name: Vec::new(),
            pdu: pdu_response(1),
        };
        write_file(&dir, "valid_scoped_empty_ids.bin", &scoped.to_bytes().unwrap());
    }

    // Boundaries --------------------------------------------------------
    write_file(&dir, "boundary_empty.bin", b"");
    write_file(&dir, "boundary_just_seq_tag.bin", &[0x30]);
    write_file(&dir, "boundary_v2_version.bin",
        &[0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00]); // version=1, not 3
    write_file(&dir, "boundary_truncated_outer.bin",
        &[0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x03]);
    write_file(&dir, "boundary_short_flags.bin",
        &[0x30, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x05, 0x00]);
    write_file(&dir, "boundary_all_zero_64.bin", &[0u8; 64]);
    write_file(&dir, "boundary_all_ff_64.bin", &[0xFFu8; 64]);

    println!("snmpv3_message: corpus generated under {}", dir.display());
}
