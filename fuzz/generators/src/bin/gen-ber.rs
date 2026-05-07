//! Emit valid BER encodings of every ASN.1 type spt-snmp supports, plus
//! boundary cases the Decoder is likely to mishandle.

use spt_fuzz_generators::{out_dir_from_args, write_file};
use spt_snmp::ber::{Encoder, Tag};

fn main() {
    let dir = out_dir_from_args();

    // Universal types ----------------------------------------------------
    {
        let mut e = Encoder::new();
        e.write_i64(0);
        write_file(&dir, "valid_int_zero.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_i64(127);
        write_file(&dir, "valid_int_127.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_i64(-1);
        write_file(&dir, "valid_int_neg_one.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_i64(i64::MAX);
        write_file(&dir, "valid_int_i64_max.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_i64(i64::MIN);
        write_file(&dir, "valid_int_i64_min.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_u32(0xDEAD_BEEF);
        write_file(&dir, "valid_u32.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_null();
        write_file(&dir, "valid_null.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_octet_string(b"");
        write_file(&dir, "valid_octet_empty.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_octet_string(b"hello");
        write_file(&dir, "valid_octet_hello.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        // 200-byte octet — exercises the multi-byte length form (0x81 0xC8).
        let big = vec![0x42u8; 200];
        e.write_octet_string(&big);
        write_file(&dir, "valid_octet_long_form.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
        write_file(&dir, "valid_oid_sysDescr.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_oid(&[1, 3, 6, 1, 4, 1, 99999, 0]).unwrap();
        write_file(&dir, "valid_oid_long_arc.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_oid(&[2, 100, 3]).unwrap();
        write_file(&dir, "valid_oid_high_first.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_counter64(u64::MAX);
        write_file(&dir, "valid_counter64_max.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_app_u32(Tag::COUNTER32, 1234);
        write_file(&dir, "valid_counter32.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_app_u32(Tag::GAUGE32, 99);
        write_file(&dir, "valid_gauge32.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_app_u32(Tag::TIMETICKS, 60_000);
        write_file(&dir, "valid_timeticks.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_app_octet_string(Tag::IP_ADDRESS, &[127, 0, 0, 1]);
        write_file(&dir, "valid_ipaddress.bin", &e.finish());
    }
    {
        let mut e = Encoder::new();
        e.write_app_octet_string(Tag::OPAQUE, b"opaque");
        write_file(&dir, "valid_opaque.bin", &e.finish());
    }
    {
        // A SEQUENCE containing an INTEGER and an OCTET STRING.
        let mut e = Encoder::new();
        e.write_sequence(|s| {
            s.write_i64(42);
            s.write_octet_string(b"forty-two");
        });
        write_file(&dir, "valid_seq_int_octet.bin", &e.finish());
    }
    {
        // Nested SEQUENCEs three deep.
        let mut e = Encoder::new();
        e.write_sequence(|s1| {
            s1.write_sequence(|s2| {
                s2.write_sequence(|s3| {
                    s3.write_i64(7);
                });
            });
        });
        write_file(&dir, "valid_nested_seq.bin", &e.finish());
    }
    {
        // SEQUENCE OF many integers.
        let mut e = Encoder::new();
        e.write_sequence(|s| {
            for i in 0..32i64 {
                s.write_i64(i);
            }
        });
        write_file(&dir, "valid_seq_of_int.bin", &e.finish());
    }
    {
        // empty SEQUENCE
        let mut e = Encoder::new();
        e.write_sequence(|_| {});
        write_file(&dir, "valid_seq_empty.bin", &e.finish());
    }
    {
        // Constructed PDU body (GetRequest).
        let mut e = Encoder::new();
        e.write_constructed(Tag::GET_REQUEST, |b| {
            b.write_i64(1); // request-id
            b.write_i64(0); // error-status
            b.write_i64(0); // error-index
            b.write_sequence(|_| {}); // empty varbinds
        });
        write_file(&dir, "valid_pdu_getrequest.bin", &e.finish());
    }

    // Boundary / malformed -----------------------------------------------
    write_file(&dir, "boundary_empty.bin", b"");
    write_file(&dir, "boundary_one_byte_tag.bin", &[0x02]);
    write_file(&dir, "boundary_tag_no_len.bin", &[0x02, 0x05]);
    write_file(&dir, "boundary_truncated_value.bin", &[0x04, 0x05, b'a', b'b']);
    write_file(&dir, "boundary_indefinite_len.bin", &[0x30, 0x80, 0x00, 0x00]);
    write_file(&dir, "boundary_long_form_zero.bin", &[0x04, 0x80]);
    write_file(&dir, "boundary_long_form_5byte_len.bin",
        &[0x04, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05]);
    write_file(&dir, "boundary_huge_len.bin",
        &[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]);
    write_file(&dir, "boundary_int_empty.bin", &[0x02, 0x00]);
    write_file(&dir, "boundary_null_with_body.bin", &[0x05, 0x01, 0x00]);
    write_file(&dir, "boundary_oid_empty.bin", &[0x06, 0x00]);
    write_file(&dir, "boundary_oid_unterminated_subid.bin",
        &[0x06, 0x03, 0x80, 0x80, 0x80]);
    write_file(&dir, "boundary_all_zeros.bin", &[0u8; 16]);
    write_file(&dir, "boundary_all_ff.bin", &[0xFFu8; 16]);
    write_file(&dir, "boundary_seq_short_len.bin", &[0x30, 0x10, 0x02, 0x01, 0x01]);

    println!("ber_decode: corpus generated under {}", dir.display());
}
