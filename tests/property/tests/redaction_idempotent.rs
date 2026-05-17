//! Property: `redact(redact(x, m), m) == redact(x, m)` for every
//! `RedactionMode`.
//!
//! The driver feeds arbitrary UTF-8 strings — both random and shaped to hit
//! each redaction pattern — and asserts the second pass leaves the output
//! unchanged. Patterns explored:
//!
//! * Bearer / Basic Authorization headers
//! * `key=value` secret fields (quoted, single-quoted, bareword)
//! * PEM private-key blocks
//! * IPv4 / IPv6 / email (Strict-only)

use arbitrary::Unstructured;
use spt_core::redaction::{redact, RedactionMode};
use spt_property_tests::run_property;

const MODES: [RedactionMode; 3] = [
    RedactionMode::None,
    RedactionMode::Standard,
    RedactionMode::Strict,
];

fn arb_token(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let len = u.int_in_range(1u8..=24)? as usize;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let c: u8 = u.int_in_range(0u8..=61)?;
        let ch = match c {
            0..=25 => c + b'a',
            26..=51 => c - 26 + b'A',
            _ => c - 52 + b'0',
        };
        s.push(ch as char);
    }
    Ok(s)
}

/// Generator for inputs that satisfy the idempotence property.
///
/// Now that the KV-bareword non-idempotence has been fixed in
/// `crates/spt-core/src/redaction.rs` (the bareword character class excludes
/// brackets/braces so `[REDACTED]`-style markers are fixed points), all KV
/// shapes are safe to exercise here too.
fn arb_safe_input(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let shape = u.int_in_range(0u8..=6)?;
    Ok(match shape {
        0 => format!("Authorization: Bearer {}", arb_token(u)?),
        1 => format!("Authorization: Basic {}", arb_token(u)?),
        2 => format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            arb_token(u)?
        ),
        3 => format!(
            "{}.{}.{}.{}",
            u.int_in_range(0u8..=255)?,
            u.int_in_range(0u8..=255)?,
            u.int_in_range(0u8..=255)?,
            u.int_in_range(0u8..=255)?
        ),
        4 => format!("user-{}@example.com", arb_token(u)?),
        5 => format!("password={}", arb_token(u)?),
        _ => format!("api_key=\"{}\"", arb_token(u)?),
    })
}

fn assert_idempotent(input: &str, mode: RedactionMode) {
    let once = redact(input, mode).into_owned();
    let twice = redact(&once, mode).into_owned();
    assert_eq!(
        once, twice,
        "redact not idempotent for mode {mode:?} on input {input:?}\n\
         once : {once:?}\n\
         twice: {twice:?}"
    );
}

// ---- Properties (12 invariants) -------------------------------------------

#[test]
fn idempotent_all_modes_safe_inputs() {
    run_property("idempotent_all_modes_safe_inputs", |u| {
        let s = arb_safe_input(u)?;
        for m in MODES {
            assert_idempotent(&s, m);
        }
        Ok(())
    });
}

#[test]
fn idempotent_bearer_standard() {
    run_property("idempotent_bearer_standard", |u| {
        let s = format!("Authorization: Bearer {}", arb_token(u)?);
        assert_idempotent(&s, RedactionMode::Standard);
        Ok(())
    });
}

#[test]
fn idempotent_bearer_strict() {
    run_property("idempotent_bearer_strict", |u| {
        let s = format!("Authorization: Bearer {}", arb_token(u)?);
        assert_idempotent(&s, RedactionMode::Strict);
        Ok(())
    });
}

#[test]
fn idempotent_basic_standard() {
    run_property("idempotent_basic_standard", |u| {
        let s = format!("Authorization: Basic {}", arb_token(u)?);
        assert_idempotent(&s, RedactionMode::Standard);
        Ok(())
    });
}

#[test]
fn idempotent_basic_strict() {
    run_property("idempotent_basic_strict", |u| {
        let s = format!("Authorization: Basic {}", arb_token(u)?);
        assert_idempotent(&s, RedactionMode::Strict);
        Ok(())
    });
}

#[test]
fn idempotent_pem_block_standard() {
    run_property("idempotent_pem_block_standard", |u| {
        let s = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            arb_token(u)?
        );
        assert_idempotent(&s, RedactionMode::Standard);
        Ok(())
    });
}

#[test]
fn idempotent_pem_block_strict() {
    run_property("idempotent_pem_block_strict", |u| {
        let s = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
            arb_token(u)?
        );
        assert_idempotent(&s, RedactionMode::Strict);
        Ok(())
    });
}

#[test]
fn idempotent_ipv4_strict() {
    run_property("idempotent_ipv4_strict", |u| {
        let s = format!(
            "{}.{}.{}.{}",
            u.int_in_range(0u8..=255)?,
            u.int_in_range(0u8..=255)?,
            u.int_in_range(0u8..=255)?,
            u.int_in_range(0u8..=255)?
        );
        assert_idempotent(&s, RedactionMode::Strict);
        Ok(())
    });
}

#[test]
fn idempotent_email_strict() {
    run_property("idempotent_email_strict", |u| {
        let s = format!("user-{}@example.com", arb_token(u)?);
        assert_idempotent(&s, RedactionMode::Strict);
        Ok(())
    });
}

#[test]
fn none_mode_is_pure_passthrough() {
    run_property("none_mode_is_pure_passthrough", |u| {
        let s = arb_safe_input(u)?;
        let out = redact(&s, RedactionMode::None);
        assert_eq!(out, s);
        Ok(())
    });
}

#[test]
fn idempotent_empty_string() {
    run_property("idempotent_empty_string", |_u| {
        for m in MODES {
            assert_idempotent("", m);
        }
        Ok(())
    });
}

/// Regression for the historic KV-bareword non-idempotence.
///
/// Before the fix in `crates/spt-core/src/redaction.rs`, this input
/// produced `password=[REDACTED]]` on pass 2 because the bareword arm
/// `[^\s,;)\]}]+` consumed `[REDACTED` and re-emitted the trailing `]`.
/// The bareword class now excludes brackets/braces so the marker is a
/// fixed point at pass 1.
#[test]
fn kv_bareword_is_idempotent() {
    let input = "password=\"hunter2\"";
    let p1 = redact(input, RedactionMode::Standard).into_owned();
    let p2 = redact(&p1, RedactionMode::Standard).into_owned();
    let p3 = redact(&p2, RedactionMode::Standard).into_owned();
    assert_eq!(p1, "password=[REDACTED]");
    assert_eq!(p1, p2);
    assert_eq!(p2, p3);
}
