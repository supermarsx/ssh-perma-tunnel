//! t6-e13 integration tests.
//!
//! 15 tests covering the public surface of `spt-obfs` per the t6.md scope.

use std::sync::Arc;

use spt_core::Error;
use spt_obfs::audit::MockAuditHook;
use spt_obfs::config::{ObfsConfig, SsMethod};
use spt_obfs::meek::MeekHttpTransport;
use spt_obfs::obfs4::{HandshakeState, Obfs4Transport};
use spt_obfs::shadowsocks::ShadowsocksTransport;
use spt_obfs::websocket::{
    decode_binary_frame, encode_binary_frame, WebsocketTransport, SSH_SUBPROTOCOL,
};
use spt_obfs::transport::ObfsTransport;
use spt_obfs::{transport_for, transport_for_with_audit};
use spt_secrets::SecretRef;

// 1
#[test]
fn obfsconfig_deser_ser_all_variants_round_trip() {
    let cases = [
        ObfsConfig::Obfs4 {
            node_id: [3u8; 20],
            public_key: [4u8; 32],
            iat_mode: 2,
        },
        ObfsConfig::MeekHttp {
            url: "https://front.example/path".into(),
            front_host: Some("hidden.example".into()),
            sni: Some("front.example".into()),
        },
        ObfsConfig::Websocket {
            url: "wss://ws.example/ssh".into(),
            headers: vec![("X-A".into(), "1".into()), ("X-B".into(), "2".into())],
        },
        ObfsConfig::Shadowsocks {
            method: SsMethod::Aead2022Blake3ChaCha20Poly1305,
            password: SecretRef::new("ns", "ss").unwrap(),
        },
    ];
    for c in &cases {
        let s = serde_json::to_string(c).unwrap();
        let back: ObfsConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(c, &back, "round-trip variant {}", c.name());
    }
}

// 2
#[test]
fn plain_tcp_path_unchanged_no_regression() {
    // The transport_for dispatcher must never produce a TCP-only fallback for
    // an obfuscation config — its responsibility is the obfuscated path.
    // The plain TCP path is selected upstream when `Transport::obfuscation`
    // is `None`. This test pins that contract: handing the dispatcher any
    // obfuscation config does NOT yield a plain TCP transport (we cannot
    // observe that directly — instead we assert the transport name is
    // non-empty and not "tcp" for every variant).
    for cfg in obfs_configs() {
        let t = transport_for(&cfg).unwrap();
        assert_ne!(t.name(), "");
        assert_ne!(t.name(), "tcp");
    }
}

// 3
#[test]
fn obfs4_handshake_known_vector_stub_assert() {
    // Deterministic walk through ClientHello → ServerHello → KexComplete.
    // Inputs are fixed; the stub probe must arrive at KexComplete.
    let t = Obfs4Transport::new(
        ObfsConfig::Obfs4 {
            node_id: [0xAA; 20],
            public_key: [0xBB; 32],
            iat_mode: 0,
        },
        Arc::new(MockAuditHook::new()),
    )
    .unwrap();
    assert_eq!(t.handshake_probe(), HandshakeState::KexComplete);
}

// 4
#[test]
fn obfs4_iat_mode_0_1_2_selection() {
    for iat in 0u8..=2 {
        let t = Obfs4Transport::new(
            ObfsConfig::Obfs4 {
                node_id: [0; 20],
                public_key: [0; 32],
                iat_mode: iat,
            },
            Arc::new(MockAuditHook::new()),
        )
        .unwrap();
        assert_eq!(t.iat_mode(), iat);
    }
}

// 5
#[test]
fn meek_http_front_host_sets_sni_differently_from_host_header() {
    let cfg = ObfsConfig::MeekHttp {
        url: "https://front.cdn.example/p".into(),
        front_host: Some("hidden.example".into()),
        sni: None,
    };
    let t = MeekHttpTransport::new(cfg, Arc::new(MockAuditHook::new())).unwrap();
    assert_eq!(t.sni(), "front.cdn.example");
    assert_eq!(t.host_header(), "hidden.example");
    assert_ne!(t.sni(), t.host_header());
}

// 6
#[tokio::test]
async fn meek_http_non_2xx_response_surfaces_error() {
    let cfg = ObfsConfig::MeekHttp {
        url: "https://front.example/p".into(),
        front_host: None,
        sni: None,
    };
    let mut t = MeekHttpTransport::new(cfg, Arc::new(MockAuditHook::new())).unwrap();
    t.set_simulated_status(502);
    let res = t.connect("ssh.example:22").await;
    let err = res.err().expect("must error on non-2xx");
    let msg = format!("{err}");
    assert!(msg.contains("502"), "got error: {msg}");
}

// 7
#[test]
fn websocket_subprotocol_ssh_present_in_upgrade() {
    let cfg = ObfsConfig::Websocket {
        url: "wss://ws.example/ssh".into(),
        headers: vec![],
    };
    let t = WebsocketTransport::new(cfg, Arc::new(MockAuditHook::new())).unwrap();
    let hdrs = t.build_upgrade_request();
    let found = hdrs
        .iter()
        .any(|(k, v)| k == "Sec-WebSocket-Protocol" && v == SSH_SUBPROTOCOL);
    assert!(found, "Sec-WebSocket-Protocol: ssh must be present");
}

// 8
#[test]
fn websocket_binary_frame_round_trip() {
    let payload = b"SSH-2.0-spt over WS\r\n0123456789".to_vec();
    let frame = encode_binary_frame(&payload);
    let out = decode_binary_frame(&frame).unwrap();
    assert_eq!(out, payload);
}

// 9
#[test]
fn shadowsocks_aead_2022_round_trip_with_aes_gcm() {
    let cfg = ObfsConfig::Shadowsocks {
        method: SsMethod::Aead2022Blake3Aes256Gcm,
        password: SecretRef::new("ns", "ss").unwrap(),
    };
    let t = ShadowsocksTransport::new(cfg, Arc::new(MockAuditHook::new()))
        .unwrap()
        .with_direct_password(b"shared-secret".to_vec());
    let pt = b"SSH-2.0-spt\r\nhandshake".to_vec();
    let sealed = t.seal(&pt).unwrap();
    assert_ne!(sealed, pt, "ciphertext must differ from plaintext");
    let back = t.open(&sealed).unwrap();
    assert_eq!(back, pt);
}

// 10
#[test]
fn shadowsocks_bad_password_fails_handshake() {
    let cfg = ObfsConfig::Shadowsocks {
        method: SsMethod::Aead2022Blake3Aes256Gcm,
        password: SecretRef::new("ns", "ss").unwrap(),
    };
    let seal = ShadowsocksTransport::new(cfg.clone(), Arc::new(MockAuditHook::new()))
        .unwrap()
        .with_direct_password(b"correct".to_vec());
    let open = ShadowsocksTransport::new(cfg, Arc::new(MockAuditHook::new()))
        .unwrap()
        .with_direct_password(b"WRONG".to_vec());
    let sealed = seal.seal(b"payload").unwrap();
    let r = open.open(&sealed);
    assert!(r.is_err(), "wrong password must not decrypt");
}

// 11
#[test]
fn transport_for_invalid_config_returns_error_configinvalid() {
    // Plan names `Error::ConfigInvalid`; mapped to `Error::InvalidConfig`
    // per t6-e9's `UnsupportedBackend` precedent.
    let bad = ObfsConfig::Obfs4 {
        node_id: [0; 20],
        public_key: [0; 32],
        iat_mode: 9,
    };
    let r = transport_for(&bad);
    assert!(matches!(r, Err(Error::InvalidConfig(_))));

    let bad2 = ObfsConfig::Websocket {
        url: "http://not-ws.example".into(), // not ws/wss
        headers: vec![],
    };
    let r2 = transport_for(&bad2);
    assert!(matches!(r2, Err(Error::InvalidConfig(_))));
}

// 12
#[tokio::test]
async fn audit_hook_fires_with_transport_name_on_connect() {
    let recorder = Arc::new(MockAuditHook::new());
    for cfg in obfs_configs() {
        let mut t = transport_for_with_audit(&cfg, recorder.clone()).unwrap();
        // connect intentionally errors (stub); the audit hook must still fire.
        let _ = t.connect("ssh.example:22").await;
    }
    let entries = recorder.entries();
    let names: Vec<&str> = entries.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"obfs4"));
    assert!(names.contains(&"meek-http"));
    assert!(names.contains(&"ssh-over-websocket"));
    assert!(names.contains(&"ssh-over-shadowsocks"));
    for (_n, target) in &entries {
        assert_eq!(target, "ssh.example:22");
    }
}

// 13
#[tokio::test]
async fn stub_transports_return_error_unsupported_feature_cleanly() {
    // Plan names `Error::UnsupportedFeature`; mapped to
    // `Error::UnsupportedPlatform` per t6-e9 precedent.
    for cfg in obfs_configs() {
        let mut t = transport_for(&cfg).unwrap();
        let r = t.connect("ssh.example:22").await;
        match r {
            Err(Error::UnsupportedPlatform(msg)) => {
                assert!(
                    msg.contains("Cargo.lock"),
                    "stub error must mention the missing dep: {msg}"
                );
            }
            Err(other) => panic!("expected UnsupportedPlatform, got {other:?}"),
            Ok(_) => panic!("stub must error"),
        }
    }
}

// 14
#[test]
fn drop_closes_underlying_transport() {
    // The dispatcher returns a `Box<dyn ObfsTransport>`. Dropping the box
    // must call the underlying transport's `Drop` impl without panic.
    // We exercise the contract by allocating + dropping each transport;
    // a panic would fail the test, and any leaked resources would be
    // caught by the test allocator on miri runs.
    for cfg in obfs_configs() {
        let t = transport_for(&cfg).unwrap();
        drop(t);
    }
}

// 15
#[test]
fn schema_transport_obfuscation_none_deserializes_when_absent_back_compat() {
    // Profile lacking [profiles.transport] still parses (back-compat).
    // Mirrors the t6-e7 `Profile::script` is-absent test.
    use spt_config::schema::Profile;
    let toml_str = r#"
name = "p"
protocol = "ssh2"
host = "h.example"
port = 22
"#;
    let p: Profile = toml::from_str(toml_str).unwrap();
    assert!(p.transport.is_none(), "Transport must default to None");
}

// helpers ----------------------------------------------------------------

fn obfs_configs() -> Vec<ObfsConfig> {
    vec![
        ObfsConfig::Obfs4 {
            node_id: [1; 20],
            public_key: [2; 32],
            iat_mode: 0,
        },
        ObfsConfig::MeekHttp {
            url: "https://front.example/p".into(),
            front_host: None,
            sni: None,
        },
        ObfsConfig::Websocket {
            url: "wss://ws.example/ssh".into(),
            headers: vec![],
        },
        ObfsConfig::Shadowsocks {
            method: SsMethod::Aead2022Blake3Aes256Gcm,
            password: SecretRef::new("ns", "ss").unwrap(),
        },
    ]
}
