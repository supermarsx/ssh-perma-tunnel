//! Property: arbitrary `BindAddr` and `Endpoint` instances round-trip
//! through their text and JSON encodings.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use arbitrary::Unstructured;
use spt_core::address::BindAddr;
use spt_property_tests::run_property;
use spt_protocol::endpoint::Endpoint;

fn arb_ipv4(u: &mut Unstructured<'_>) -> arbitrary::Result<Ipv4Addr> {
    Ok(Ipv4Addr::new(
        u.arbitrary()?,
        u.arbitrary()?,
        u.arbitrary()?,
        u.arbitrary()?,
    ))
}

fn arb_ipv6(u: &mut Unstructured<'_>) -> arbitrary::Result<Ipv6Addr> {
    let mut octets = [0u8; 16];
    u.fill_buffer(&mut octets)?;
    Ok(Ipv6Addr::from(octets))
}

fn arb_host(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let len = u.int_in_range(1u8..=10)? as usize;
    let mut s = String::with_capacity(len);
    for i in 0..len {
        let c = if i == 0 {
            (u.int_in_range(0u8..=25)? + b'a') as char
        } else {
            let pick = u.int_in_range(0u8..=36)?;
            match pick {
                0..=25 => (pick + b'a') as char,
                26..=35 => (pick - 26 + b'0') as char,
                _ => '-',
            }
        };
        s.push(c);
    }
    Ok(format!("{s}.example.invalid"))
}

// ---- Properties (10 invariants) -------------------------------------------

#[test]
fn bindaddr_ipv4_round_trip() {
    run_property("bindaddr_ipv4_round_trip", |u| {
        let ip = arb_ipv4(u)?;
        let port = u.int_in_range(0u16..=65_535)?;
        let s = SocketAddr::new(IpAddr::V4(ip), port).to_string();
        let parsed = BindAddr::parse(&s).expect("parse ipv4");
        let rendered = parsed.to_string();
        let reparsed = BindAddr::parse(&rendered).expect("reparse");
        assert_eq!(parsed, reparsed);
        Ok(())
    });
}

#[test]
fn bindaddr_ipv6_round_trip() {
    run_property("bindaddr_ipv6_round_trip", |u| {
        let ip = arb_ipv6(u)?;
        let port = u.int_in_range(0u16..=65_535)?;
        let s = SocketAddr::new(IpAddr::V6(ip), port).to_string();
        let parsed = BindAddr::parse(&s).expect("parse ipv6");
        let rendered = parsed.to_string();
        let reparsed = BindAddr::parse(&rendered).expect("reparse");
        assert_eq!(parsed, reparsed);
        Ok(())
    });
}

#[test]
fn bindaddr_unix_round_trip() {
    run_property("bindaddr_unix_round_trip", |u| {
        let len = u.int_in_range(1u8..=24)? as usize;
        let mut path = String::with_capacity(len);
        for _ in 0..len {
            let c: u8 = u.int_in_range(b'a'..=b'z')?;
            path.push(c as char);
        }
        let s = format!("unix:///tmp/{path}.sock");
        let parsed = BindAddr::parse(&s).expect("parse unix");
        let rendered = parsed.to_string();
        let reparsed = BindAddr::parse(&rendered).expect("reparse");
        assert_eq!(parsed, reparsed);
        Ok(())
    });
}

#[test]
fn bindaddr_host_port_round_trip() {
    run_property("bindaddr_host_port_round_trip", |u| {
        let host = arb_host(u)?;
        let port = u.int_in_range(1u16..=65_535)?;
        let s = format!("{host}:{port}");
        let parsed = BindAddr::parse(&s).expect("parse host:port");
        let rendered = parsed.to_string();
        let reparsed = BindAddr::parse(&rendered).expect("reparse");
        assert_eq!(parsed, reparsed);
        Ok(())
    });
}

#[test]
fn bindaddr_from_str_alias() {
    run_property("bindaddr_from_str_alias", |u| {
        let host = arb_host(u)?;
        let port = u.int_in_range(1u16..=65_535)?;
        let s = format!("{host}:{port}");
        let a = BindAddr::from_str(&s).expect("FromStr");
        let b = BindAddr::parse(&s).expect("parse");
        assert_eq!(a, b);
        Ok(())
    });
}

#[test]
fn bindaddr_serde_round_trip() {
    run_property("bindaddr_serde_round_trip", |u| {
        let host = arb_host(u)?;
        let port = u.int_in_range(1u16..=65_535)?;
        let s = format!("{host}:{port}");
        let a = BindAddr::parse(&s).expect("parse");
        let json = serde_json::to_string(&a).expect("ser");
        let back: BindAddr = serde_json::from_str(&json).expect("de");
        assert_eq!(a, back);
        Ok(())
    });
}

#[test]
fn endpoint_serde_round_trip() {
    run_property("endpoint_serde_round_trip", |u| {
        let host = arb_host(u)?;
        let port = u.int_in_range(1u16..=65_535)?;
        let e = Endpoint::new(host, port);
        let json = serde_json::to_string(&e).expect("ser");
        let back: Endpoint = serde_json::from_str(&json).expect("de");
        assert_eq!(e, back);
        Ok(())
    });
}

#[test]
fn endpoint_with_priority_weight_round_trip() {
    run_property("endpoint_with_priority_weight_round_trip", |u| {
        let host = arb_host(u)?;
        let port = u.int_in_range(1u16..=65_535)?;
        let mut e = Endpoint::new(host, port);
        e.priority = u.int_in_range(0u32..=100)?;
        e.weight = u.int_in_range(1u32..=100)?;
        let json = serde_json::to_string(&e).expect("ser");
        let back: Endpoint = serde_json::from_str(&json).expect("de");
        assert_eq!(e, back);
        Ok(())
    });
}

#[test]
fn bindaddr_empty_rejected() {
    run_property("bindaddr_empty_rejected", |_u| {
        assert!(BindAddr::parse("").is_err());
        assert!(BindAddr::parse("   ").is_err());
        Ok(())
    });
}

#[test]
fn bindaddr_loopback_round_trip() {
    run_property("bindaddr_loopback_round_trip", |u| {
        let port = u.int_in_range(1u16..=65_535)?;
        for s in [format!("127.0.0.1:{port}"), format!("[::1]:{port}")] {
            let parsed = BindAddr::parse(&s).expect("parse loopback");
            let back = BindAddr::parse(&parsed.to_string()).expect("reparse");
            assert_eq!(parsed, back);
        }
        Ok(())
    });
}
