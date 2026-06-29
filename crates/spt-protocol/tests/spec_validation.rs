//! Input-validation / boundary tests for the `spt-protocol` public type boundary.
//!
//! `spt-protocol` is a pure type/trait crate: there are no string parsers or
//! fallible constructors that reject malformed input — the port fields are
//! `u16`, so out-of-range ports are rejected *at the serde boundary* rather
//! than by a constructor. These tests therefore exercise the contract that
//! actually exists:
//!
//! * port bounds (0, 65535) accepted; out-of-range (65536, -1) rejected by serde,
//! * weight/priority bounds (`u32::MAX`, 0) round-trip losslessly,
//! * host/name fields tolerate empty / oversized / control-char content as
//!   opaque strings (this crate intentionally does NOT validate them — that is
//!   `spt-config`'s job — so we pin the *current* contract: they round-trip),
//! * `Default` / serde round-trip for every spec type,
//! * `ProtocolCapabilities` flag consistency (ssh2 vs ssh3 invariants),
//! * `TargetResolve::from_config_str` parser rejecting malformed input,
//! * `ForwardState` terminal classification, `ForwardId` monotonicity/Display.

use std::path::PathBuf;
use std::time::Duration;

use spt_core::BindAddr;
use spt_protocol::endpoint::AddressFamily;
use spt_protocol::forward::{ForwardDirection, ForwardTransport};
use spt_protocol::{
    BindConflictPolicy, DynamicForwardSpec, Endpoint, ForwardId, ForwardRateLimits, ForwardState,
    LocalForwardSpec, ProtocolCapabilities, RemoteForwardSpec, RemoteUdsForwardSpec, SessionInfo,
    TargetAddr, TargetResolve, UdpForwardSpec, UdsForwardSpec,
};

// ---------------------------------------------------------------------------
// Endpoint port / weight / host boundaries
// ---------------------------------------------------------------------------

#[test]
fn endpoint_port_boundaries_round_trip() {
    for port in [0u16, 1, 22, 1024, 65535] {
        let e = Endpoint::new("h", port);
        assert_eq!(e.port, port);
        let de: Endpoint = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(de.port, port, "port {port} must survive a round-trip");
    }
}

#[test]
fn endpoint_port_above_u16_is_rejected_by_serde() {
    // 65536 overflows u16 — serde must reject rather than truncate to 0.
    let json = r#"{"host":"h","port":65536}"#;
    let r: Result<Endpoint, _> = serde_json::from_str(json);
    assert!(r.is_err(), "port 65536 must not deserialize");
}

#[test]
fn endpoint_negative_port_is_rejected_by_serde() {
    let json = r#"{"host":"h","port":-1}"#;
    let r: Result<Endpoint, _> = serde_json::from_str(json);
    assert!(r.is_err(), "negative port must not deserialize");
}

#[test]
fn endpoint_defaults_are_applied_for_omitted_fields() {
    // priority/weight have serde defaults; weight defaults to 1, not 0.
    let json = r#"{"host":"h","port":22}"#;
    let e: Endpoint = serde_json::from_str(json).unwrap();
    assert_eq!(e.priority, 0);
    assert_eq!(
        e.weight, 1,
        "weight default must be 1 (so a missing weight is selectable)"
    );
    assert_eq!(e.address_family, None);
}

#[test]
fn endpoint_weight_and_priority_extremes_round_trip() {
    let e = Endpoint {
        host: "h".into(),
        port: 22,
        address_family: Some(AddressFamily::Ipv6),
        priority: u32::MAX,
        weight: u32::MAX,
    };
    let de: Endpoint = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
    assert_eq!(de.weight, u32::MAX);
    assert_eq!(de.priority, u32::MAX);
    assert_eq!(de.address_family, Some(AddressFamily::Ipv6));
}

#[test]
fn endpoint_weight_zero_round_trips() {
    // Zero weight is a legitimate "never select via weighted pick" marker; it
    // must round-trip rather than be coerced back to the default of 1.
    let e = Endpoint {
        host: "h".into(),
        port: 1,
        address_family: None,
        priority: 0,
        weight: 0,
    };
    let de: Endpoint = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
    assert_eq!(de.weight, 0);
}

#[test]
fn endpoint_host_tolerates_empty_oversized_and_control_chars() {
    // This crate does not validate host content; pin the contract that opaque
    // host strings (empty, very long, embedded NUL/newline) round-trip intact.
    for host in [
        String::new(),
        "x".repeat(10_000),
        "a\0b".to_string(),
        "line1\nline2".to_string(),
        "[2001:db8::1]".to_string(), // IPv6 bracket literal
        "ünîcödé.example".to_string(),
    ] {
        let e = Endpoint::new(host.clone(), 22);
        let de: Endpoint = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(de.host, host);
    }
}

#[test]
fn endpoint_hash_and_eq_consistent() {
    use std::collections::HashSet;
    let a = Endpoint::new("h", 22);
    let b = Endpoint::new("h", 22);
    let mut set = HashSet::new();
    set.insert(a.clone());
    assert!(set.contains(&b), "equal endpoints must hash equal");
}

#[test]
fn address_family_serializes_lowercase() {
    assert_eq!(
        serde_json::to_string(&AddressFamily::Ipv4).unwrap(),
        "\"ipv4\""
    );
    assert_eq!(
        serde_json::to_string(&AddressFamily::Ipv6).unwrap(),
        "\"ipv6\""
    );
    // Unknown variant rejected.
    let r: Result<AddressFamily, _> = serde_json::from_str("\"ipv5\"");
    assert!(r.is_err());
}

// ---------------------------------------------------------------------------
// TargetAddr / TargetResolve
// ---------------------------------------------------------------------------

#[test]
fn target_addr_port_boundaries_round_trip() {
    for port in [0u16, 65535] {
        let t = TargetAddr::new("t", port);
        let de: TargetAddr = serde_json::from_str(&serde_json::to_string(&t).unwrap()).unwrap();
        assert_eq!(de.port, port);
    }
}

#[test]
fn target_addr_port_overflow_rejected() {
    let r: Result<TargetAddr, _> = serde_json::from_str(r#"{"host":"t","port":70000}"#);
    assert!(r.is_err());
}

#[test]
fn target_resolve_parser_accepts_known_and_aliases() {
    assert_eq!(
        TargetResolve::from_config_str("remote"),
        Some(TargetResolve::Remote)
    );
    assert_eq!(
        TargetResolve::from_config_str("local"),
        Some(TargetResolve::Local)
    );
    assert_eq!(
        TargetResolve::from_config_str("previous-hop"),
        Some(TargetResolve::PreviousHop)
    );
    assert_eq!(
        TargetResolve::from_config_str("previous_hop"),
        Some(TargetResolve::PreviousHop)
    );
}

#[test]
fn target_resolve_parser_rejects_malformed() {
    for bad in [
        "",
        "Remote",
        "LOCAL",
        "previoushop",
        "peer",
        " local",
        "local ",
    ] {
        assert_eq!(
            TargetResolve::from_config_str(bad),
            None,
            "{bad:?} must not parse"
        );
    }
}

#[test]
fn target_resolve_default_and_is_local() {
    assert_eq!(TargetResolve::default(), TargetResolve::Remote);
    assert!(TargetResolve::Local.is_local());
    assert!(!TargetResolve::Remote.is_local());
    assert!(!TargetResolve::PreviousHop.is_local());
}

// ---------------------------------------------------------------------------
// ForwardRateLimits bounds
// ---------------------------------------------------------------------------

#[test]
fn rate_limits_default_is_unlimited_and_extremes_round_trip() {
    assert!(ForwardRateLimits::default().is_unlimited());
    let l = ForwardRateLimits {
        rate_bps_up: u64::MAX,
        rate_bps_down: u64::MAX,
        burst_up: u64::MAX,
        burst_down: u64::MAX,
        max_new_conns_per_sec: u32::MAX,
        max_packets_per_sec: u32::MAX,
    };
    assert!(!l.is_unlimited());
    let de: ForwardRateLimits = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
    assert_eq!(
        de, l,
        "max rate-limit values must round-trip without overflow"
    );
}

#[test]
fn rate_limits_partial_nonzero_is_limited() {
    // Each individual knob being non-zero flips is_unlimited to false.
    let fields: [fn() -> ForwardRateLimits; 6] = [
        || ForwardRateLimits {
            rate_bps_up: 1,
            ..Default::default()
        },
        || ForwardRateLimits {
            rate_bps_down: 1,
            ..Default::default()
        },
        || ForwardRateLimits {
            burst_up: 1,
            ..Default::default()
        },
        || ForwardRateLimits {
            burst_down: 1,
            ..Default::default()
        },
        || ForwardRateLimits {
            max_new_conns_per_sec: 1,
            ..Default::default()
        },
        || ForwardRateLimits {
            max_packets_per_sec: 1,
            ..Default::default()
        },
    ];
    for mk in fields {
        assert!(!mk().is_unlimited());
    }
}

#[test]
fn rate_limits_overflow_value_rejected_by_serde() {
    // A value past u64::MAX must not silently wrap.
    let json = r#"{"rate_bps_up":18446744073709551616}"#; // u64::MAX + 1
    let r: Result<ForwardRateLimits, _> = serde_json::from_str(json);
    assert!(r.is_err(), "u64 overflow must be rejected");
}

// ---------------------------------------------------------------------------
// Forward spec defaults & round-trips (the public contract for omitted fields)
// ---------------------------------------------------------------------------

#[test]
fn local_forward_spec_defaults_for_omitted_optionals() {
    let json = r#"{"name":"l","listen":"127.0.0.1:8080","target":{"host":"localhost","port":80}}"#;
    let s: LocalForwardSpec = serde_json::from_str(json).unwrap();
    assert!(s.limits.is_unlimited());
    assert_eq!(s.idle_timeout, None);
    assert_eq!(s.max_connections, None);
    assert_eq!(s.on_bind_conflict, BindConflictPolicy::Fail);
    assert!(!s.required);
}

#[test]
fn local_forward_spec_full_round_trip() {
    let s = LocalForwardSpec {
        name: "l".into(),
        listen: BindAddr::Tcp("127.0.0.1:0".parse().unwrap()),
        target: TargetAddr::new("t", 65535),
        max_connections: Some(u32::MAX),
        limits: ForwardRateLimits {
            rate_bps_up: 7,
            ..Default::default()
        },
        idle_timeout: Some(Duration::from_secs(99)),
        on_bind_conflict: BindConflictPolicy::NextPort,
        required: true,
    };
    let de: LocalForwardSpec = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(de, s);
}

#[test]
fn remote_forward_spec_full_round_trip() {
    let s = RemoteForwardSpec {
        name: "r".into(),
        listen: BindAddr::Tcp("0.0.0.0:2222".parse().unwrap()),
        target: TargetAddr::new("internal", 22),
        max_connections: None,
        limits: ForwardRateLimits::default(),
        idle_timeout: None,
        on_bind_conflict: BindConflictPolicy::Retry,
        required: false,
    };
    let de: RemoteForwardSpec = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(de, s);
}

#[test]
fn dynamic_forward_spec_round_trip_all_socks_flags() {
    let s = DynamicForwardSpec {
        name: "d".into(),
        listen: BindAddr::Tcp("127.0.0.1:1080".parse().unwrap()),
        max_connections: Some(0), // zero = explicit "no extra connections"
        allow_socks4: true,
        allow_socks4a: true,
        allow_socks5: true,
        allow_http_connect: true,
        allow_targets: Vec::new(),
        deny_targets: Vec::new(),
        limits: ForwardRateLimits::default(),
        idle_timeout: Some(Duration::from_millis(1)),
        on_bind_conflict: BindConflictPolicy::Fail,
        required: false,
    };
    let de: DynamicForwardSpec = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(de, s);
}

#[test]
fn udp_forward_spec_idle_timeout_extremes_round_trip() {
    let s = UdpForwardSpec {
        name: "u".into(),
        direction: ForwardDirection::Remote,
        listen: BindAddr::Tcp("127.0.0.1:53".parse().unwrap()),
        target: TargetAddr::new("resolver", 53),
        idle_timeout_secs: u32::MAX,
        max_flows: Some(0), // 0 = unbounded per the field contract
        limits: ForwardRateLimits::default(),
    };
    let de: UdpForwardSpec = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(de, s);
    assert_eq!(de.idle_timeout_secs, u32::MAX);
}

#[test]
fn udp_forward_spec_requires_idle_timeout_field() {
    // idle_timeout_secs has no serde default — a body omitting it must fail.
    let json = r#"{"name":"u","direction":"local","listen":"127.0.0.1:53","target":{"host":"r","port":53}}"#;
    let r: Result<UdpForwardSpec, _> = serde_json::from_str(json);
    assert!(
        r.is_err(),
        "missing idle_timeout_secs must be a deserialize error"
    );
}

#[test]
fn uds_and_remote_uds_specs_default_and_round_trip() {
    let u = UdsForwardSpec::default();
    assert!(u.limits.is_unlimited());
    assert!(!u.required);
    assert_eq!(u.name, "");
    assert_eq!(u.listen_path, PathBuf::new());

    let full = UdsForwardSpec {
        name: "u".into(),
        listen_path: PathBuf::from("/tmp/a.sock"),
        remote_socket_path: "/run/b.sock".into(),
        limits: ForwardRateLimits {
            burst_up: 5,
            ..Default::default()
        },
        required: true,
    };
    let de: UdsForwardSpec = serde_json::from_str(&serde_json::to_string(&full).unwrap()).unwrap();
    assert_eq!(de, full);

    let r = RemoteUdsForwardSpec {
        name: "ru".into(),
        remote_socket_path: "/run/remote.sock".into(),
        local_socket_path: PathBuf::from("/tmp/local.sock"),
        limits: ForwardRateLimits::default(),
        idle_timeout: Some(Duration::from_secs(5)),
        required: false,
    };
    let de: RemoteUdsForwardSpec =
        serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(de, r);
    assert_eq!(RemoteUdsForwardSpec::default().name, "");
}

// ---------------------------------------------------------------------------
// Enum wire forms (the contract downstream config relies on)
// ---------------------------------------------------------------------------

#[test]
fn bind_conflict_policy_wire_forms() {
    assert_eq!(
        serde_json::to_string(&BindConflictPolicy::Fail).unwrap(),
        "\"fail\""
    );
    assert_eq!(
        serde_json::to_string(&BindConflictPolicy::Retry).unwrap(),
        "\"retry\""
    );
    assert_eq!(
        serde_json::to_string(&BindConflictPolicy::NextPort).unwrap(),
        "\"next_port\""
    );
    assert!(serde_json::from_str::<BindConflictPolicy>("\"explode\"").is_err());
    assert_eq!(BindConflictPolicy::default(), BindConflictPolicy::Fail);
}

#[test]
fn forward_direction_and_transport_wire_forms() {
    assert_eq!(
        serde_json::to_string(&ForwardDirection::Local).unwrap(),
        "\"local\""
    );
    assert_eq!(
        serde_json::to_string(&ForwardDirection::Remote).unwrap(),
        "\"remote\""
    );
    assert_eq!(
        serde_json::to_string(&ForwardTransport::Tcp).unwrap(),
        "\"tcp\""
    );
    assert_eq!(
        serde_json::to_string(&ForwardTransport::Udp).unwrap(),
        "\"udp\""
    );
    assert!(serde_json::from_str::<ForwardDirection>("\"both\"").is_err());
    assert!(serde_json::from_str::<ForwardTransport>("\"sctp\"").is_err());
}

#[test]
fn forward_state_wire_forms_and_terminal_classification() {
    // snake_case wire form.
    assert_eq!(
        serde_json::to_string(&ForwardState::RemoteRequested).unwrap(),
        "\"remote_requested\""
    );
    assert_eq!(
        serde_json::to_string(&ForwardState::RetryWait).unwrap(),
        "\"retry_wait\""
    );
    // terminal classification contract.
    for s in [
        ForwardState::Stopped,
        ForwardState::Failed,
        ForwardState::Disabled,
    ] {
        assert!(s.is_terminal(), "{s:?} must be terminal");
    }
    for s in [
        ForwardState::Binding,
        ForwardState::Listening,
        ForwardState::RemoteRequested,
        ForwardState::Active,
        ForwardState::Degraded,
        ForwardState::RetryWait,
    ] {
        assert!(!s.is_terminal(), "{s:?} must not be terminal");
    }
    assert!(serde_json::from_str::<ForwardState>("\"zombie\"").is_err());
}

// ---------------------------------------------------------------------------
// ProtocolCapabilities flag consistency
// ---------------------------------------------------------------------------

#[test]
fn ssh2_capability_invariants() {
    let c = ProtocolCapabilities::ssh2();
    // SSH2 has TCP both ways and host keys, but no UDP (spec §10.4).
    assert!(c.local_tcp && c.remote_tcp);
    assert!(!c.local_udp && !c.remote_udp);
    assert!(c.host_keys);
    assert!(c.dynamic_tcp && c.multi_hop && c.agent_forwarding && c.multiplex);
    assert!(c.local_uds && c.remote_uds);
}

#[test]
fn ssh3_capability_invariants() {
    let c = ProtocolCapabilities::ssh3();
    // SSH3 has full TCP+UDP, TLS (no SSH host keys), no SOCKS/multi-hop/agent.
    assert!(c.local_tcp && c.remote_tcp && c.local_udp && c.remote_udp);
    assert!(!c.host_keys);
    assert!(!c.dynamic_tcp && !c.multi_hop && !c.agent_forwarding);
    assert!(c.multiplex);
    assert!(c.local_uds && c.remote_uds);
}

#[test]
fn capabilities_round_trip_and_distinct() {
    let s2 = ProtocolCapabilities::ssh2();
    let s3 = ProtocolCapabilities::ssh3();
    assert_ne!(s2, s3, "ssh2 and ssh3 capability sets must differ");
    let de: ProtocolCapabilities =
        serde_json::from_str(&serde_json::to_string(&s2).unwrap()).unwrap();
    assert_eq!(de, s2);
    // A backend advertising remote_udp but not local_udp would be inconsistent
    // for our two real backends; assert neither real preset has that shape.
    for c in [s2, s3] {
        if c.remote_udp {
            assert!(c.local_udp, "a UDP-remote backend must also do local UDP");
        }
    }
}

// ---------------------------------------------------------------------------
// SessionInfo / ForwardId
// ---------------------------------------------------------------------------

#[test]
fn session_info_round_trip_with_optionals_absent() {
    let s = SessionInfo {
        backend: "ssh2".into(),
        peer_version: None,
        negotiated: None,
        established_at: u64::MAX,
    };
    let de: SessionInfo = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(de, s);
}

#[test]
fn session_info_round_trip_with_optionals_present() {
    let s = SessionInfo {
        backend: "ssh3".into(),
        peer_version: Some("SSH-2.0-Example".into()),
        negotiated: Some("chacha20-poly1305".into()),
        established_at: 0,
    };
    let de: SessionInfo = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(de, s);
}

#[test]
fn forward_id_is_monotonic_and_display_prefixed() {
    let a = ForwardId::new();
    let b = ForwardId::new();
    assert_ne!(a, b);
    assert!(b.0 > a.0, "ids must be monotonically increasing");
    assert_eq!(format!("{}", ForwardId(7)), "fwd-7");
    // round-trips as a transparent u64.
    let de: ForwardId = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
    assert_eq!(de, a);
}
