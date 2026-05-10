//! Property: any *validating* `Config` survives `render → load → validate`
//! as the identity transformation.
//!
//! We construct configs by composition of the validated `*Builder` types in
//! `spt_config::testing` rather than randomizing every field — this
//! guarantees the input passes validation, so the property reduces to
//! "rendering preserves shape" (the actual interesting invariant).

use arbitrary::Unstructured;
use spt_config::schema::{Endpoint, Logging, Mcp, Reconnect, Runtime};
use spt_config::testing::{
    assert_validates, canonical_toml, ConfigBuilder, ForwardBuilder, ProfileBuilder,
};
use spt_config::validate;
use spt_property_tests::run_property;

fn arb_name(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    // ASCII-lowercase + digits + dash, 1..=12 chars, must start with a letter.
    let len = u.int_in_range(1u8..=12)? as usize;
    let mut out = String::with_capacity(len);
    for i in 0..len {
        let c = if i == 0 {
            u.int_in_range(0u8..=25)? + b'a'
        } else {
            let pick = u.int_in_range(0u8..=37)?;
            match pick {
                0..=25 => pick + b'a',
                26..=35 => pick - 26 + b'0',
                _ => b'-',
            }
        };
        out.push(c as char);
    }
    Ok(out)
}

fn arb_port(u: &mut Unstructured<'_>) -> arbitrary::Result<u16> {
    Ok(u.int_in_range(1u16..=65_535)?)
}

fn arb_host(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let label = arb_name(u)?;
    let suffix = match u.int_in_range(0u8..=2)? {
        0 => ".example.invalid",
        1 => ".test.local",
        _ => ".internal",
    };
    Ok(format!("{label}{suffix}"))
}

fn arb_profile(u: &mut Unstructured<'_>) -> arbitrary::Result<spt_config::schema::Profile> {
    let name = arb_name(u)?;
    let host = arb_host(u)?;
    let port = arb_port(u)?;
    let user = arb_name(u)?;
    let mut p = ProfileBuilder::new(&name)
        .endpoint(&host, port)
        .user(&user);

    // Optional auth.
    p = match u.int_in_range(0u8..=2)? {
        0 => p.auth_agent(),
        1 => p.auth_pubkey("~/.ssh/id_ed25519"),
        _ => p, // no auth
    };

    // Optional forwards (0..=3).
    let n_fwd = u.int_in_range(0u8..=3)?;
    for i in 0..n_fwd {
        let fname = format!("fwd{i}");
        let bind_port = u.int_in_range(1024u16..=65_534)?;
        let target_port = arb_port(u)?;
        let target_host = arb_host(u)?;
        let bind = format!("127.0.0.1:{bind_port}");
        let target = format!("{target_host}:{target_port}");
        let f = match u.int_in_range(0u8..=1)? {
            0 => ForwardBuilder::local_tcp(&fname, &bind, &target).build(),
            _ => ForwardBuilder::remote_tcp(&fname, &bind, &target).build(),
        };
        p = p.add_forward(f);
    }

    // Optional reconnect.
    if u.arbitrary::<bool>()? {
        let mut r = Reconnect::default();
        r.initial_delay = Some("1s".into());
        r.max_delay = Some("30s".into());
        p = p.reconnect(r);
    }

    // Optional failover endpoints.
    let n_ep = u.int_in_range(0u8..=2)?;
    for i in 0..n_ep {
        let h = arb_host(u)?;
        let prio = u.int_in_range(0u32..=10)?;
        p = p.add_endpoint(Endpoint {
            name: format!("ep{i}"),
            host: h,
            port: 22,
            priority: Some(prio),
            weight: None,
        });
    }

    Ok(p.build())
}

fn arb_config(u: &mut Unstructured<'_>) -> arbitrary::Result<spt_config::schema::Config> {
    let mut c = ConfigBuilder::new();
    let n = u.int_in_range(0u8..=3)?;
    let mut names = std::collections::HashSet::new();
    for _ in 0..n {
        let p = arb_profile(u)?;
        if names.insert(p.name.clone()) {
            c = c.add_profile(p);
        }
    }
    if u.arbitrary::<bool>()? {
        c = c.runtime(Runtime::default());
    }
    if u.arbitrary::<bool>()? {
        let mut l = Logging::default();
        l.level = Some("info".into());
        c = c.with_logging(l);
    }
    if u.arbitrary::<bool>()? {
        c = c.mcp(Mcp::default());
    }
    Ok(c.build())
}

fn assert_roundtrip_identity(c: &spt_config::schema::Config) {
    assert_validates(c);
    let toml1 = canonical_toml(c);
    let (parsed, _warnings) = spt_config::load::load_str(&toml1, false)
        .expect("rendered config must re-parse");
    let toml2 = canonical_toml(&parsed);
    assert_eq!(toml1, toml2, "canonical render is not a fixed point");
    assert_eq!(c.version, parsed.version);
    assert_eq!(c.profiles.len(), parsed.profiles.len());
    let d = validate::validate(&parsed);
    assert!(d.errors.is_empty(), "re-parsed config failed validate: {:?}", d.errors);
}

// ---- Properties (10 invariants) -------------------------------------------

#[test]
fn config_render_parse_validate_identity() {
    run_property("config_render_parse_validate_identity", |u| {
        let c = arb_config(u)?;
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn empty_config_is_identity() {
    run_property("empty_config_is_identity", |_u| {
        let c = ConfigBuilder::new().build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn single_profile_is_identity() {
    run_property("single_profile_is_identity", |u| {
        let p = arb_profile(u)?;
        let c = ConfigBuilder::new().add_profile(p).build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn profile_with_only_agent_auth() {
    run_property("profile_with_only_agent_auth", |u| {
        let name = arb_name(u)?;
        let host = arb_host(u)?;
        let port = arb_port(u)?;
        let p = ProfileBuilder::new(&name)
            .endpoint(&host, port)
            .auth_agent()
            .build();
        let c = ConfigBuilder::new().add_profile(p).build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn profile_with_pubkey_auth() {
    run_property("profile_with_pubkey_auth", |u| {
        let name = arb_name(u)?;
        let host = arb_host(u)?;
        let port = arb_port(u)?;
        let p = ProfileBuilder::new(&name)
            .endpoint(&host, port)
            .auth_pubkey("~/.ssh/id_rsa")
            .build();
        let c = ConfigBuilder::new().add_profile(p).build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn profile_with_forwards() {
    run_property("profile_with_forwards", |u| {
        let name = arb_name(u)?;
        let host = arb_host(u)?;
        let port = arb_port(u)?;
        let bind_port = u.int_in_range(1024u16..=65_534)?;
        let p = ProfileBuilder::new(&name)
            .endpoint(&host, port)
            .auth_agent()
            .add_forward(
                ForwardBuilder::local_tcp(
                    "f",
                    &format!("127.0.0.1:{bind_port}"),
                    "h.test.local:80",
                )
                .build(),
            )
            .build();
        let c = ConfigBuilder::new().add_profile(p).build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn config_with_runtime_table() {
    run_property("config_with_runtime_table", |_u| {
        let c = ConfigBuilder::new().runtime(Runtime::default()).build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn config_with_logging_table() {
    run_property("config_with_logging_table", |_u| {
        let mut l = Logging::default();
        l.level = Some("info".into());
        let c = ConfigBuilder::new().with_logging(l).build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn config_with_mcp_table() {
    run_property("config_with_mcp_table", |_u| {
        let c = ConfigBuilder::new().mcp(Mcp::default()).build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}

#[test]
fn ssh3_profile_identity() {
    run_property("ssh3_profile_identity", |u| {
        let name = arb_name(u)?;
        let p = ProfileBuilder::new(&name)
            .protocol("ssh3")
            .ssh3_endpoint("https://h.test.local:443/ssh3?user={username}")
            .auth_bearer_token("secret://ns/tok")
            .build();
        let c = ConfigBuilder::new().add_profile(p).build();
        assert_roundtrip_identity(&c);
        Ok(())
    });
}
