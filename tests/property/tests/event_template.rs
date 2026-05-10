//! Property: `render_template` never panics and always produces valid
//! UTF-8, regardless of the template text or the event field contents.

use arbitrary::Unstructured;
use chrono::Utc;
use serde_json::{json, Value};
use spt_core::ProfileId;
use spt_events::event::{Event, EventBuilder, Severity};
use spt_events::template::render_template;
use spt_property_tests::run_property;

fn arb_severity(u: &mut Unstructured<'_>) -> arbitrary::Result<Severity> {
    Ok(match u.int_in_range(0u8..=5)? {
        0 => Severity::Trace,
        1 => Severity::Debug,
        2 => Severity::Info,
        3 => Severity::Warn,
        4 => Severity::Error,
        _ => Severity::Critical,
    })
}

fn arb_token(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let len = u.int_in_range(1u8..=12)? as usize;
    let mut s = String::with_capacity(len);
    for i in 0..len {
        let c = if i == 0 {
            (u.int_in_range(0u8..=25)? + b'a') as char
        } else {
            let pick = u.int_in_range(0u8..=35)?;
            match pick {
                0..=25 => (pick + b'a') as char,
                _ => (pick - 26 + b'0') as char,
            }
        };
        s.push(c);
    }
    Ok(s)
}

/// Build a small "noisy" template string from the seed bytes, so we exercise
/// both well-formed `{{name}}` placeholders and ill-formed `{` / `{{` / `}}`
/// sequences.
fn arb_template(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let parts = u.int_in_range(1u8..=6)?;
    let mut out = String::new();
    for _ in 0..parts {
        match u.int_in_range(0u8..=4)? {
            0 => out.push_str(" lit "),
            1 => out.push_str(&format!("{{{{ {} }}}}", arb_token(u)?)),
            2 => out.push_str("{{nope}}"),
            3 => out.push_str("{{ broken"),
            _ => out.push_str(&format!("{{{{{}}}}}", arb_token(u)?)),
        }
    }
    Ok(out)
}

fn arb_event(u: &mut Unstructured<'_>) -> arbitrary::Result<Event> {
    let pid = format!("p-{}", arb_token(u)?);
    let mut b: EventBuilder = Event::builder("test.event", arb_severity(u)?)
        .ts(Utc::now())
        .profile(ProfileId::new(&pid).expect("valid profile id"))
        .message(arb_token(u)?);

    let n_fields = u.int_in_range(0u8..=4)?;
    for _ in 0..n_fields {
        let key = arb_token(u)?;
        let v: Value = match u.int_in_range(0u8..=4)? {
            0 => json!(arb_token(u)?),
            1 => json!(u.arbitrary::<i64>()?),
            2 => json!(u.arbitrary::<bool>()?),
            3 => Value::Null,
            _ => json!({ "nested": arb_token(u)? }),
        };
        b = b.field(key, v);
    }
    Ok(b.build())
}

// ---- Properties (~14 invariants) ------------------------------------------

#[test]
fn render_never_panics_on_arbitrary_template() {
    run_property("render_never_panics_on_arbitrary_template", |u| {
        let ev = arb_event(u)?;
        let tmpl = arb_template(u)?;
        let _ = render_template(&tmpl, &ev);
        Ok(())
    });
}

#[test]
fn rendered_output_is_utf8_for_random_input() {
    run_property("rendered_output_is_utf8_for_random_input", |u| {
        let ev = arb_event(u)?;
        let tmpl = arb_template(u)?;
        let (s, _missing) = render_template(&tmpl, &ev);
        // String is UTF-8 by Rust invariant; this re-verifies via bytes.
        assert!(std::str::from_utf8(s.as_bytes()).is_ok());
        Ok(())
    });
}

#[test]
fn empty_template_renders_empty() {
    run_property("empty_template_renders_empty", |u| {
        let ev = arb_event(u)?;
        let (s, missing) = render_template("", &ev);
        assert_eq!(s, "");
        assert!(missing.is_empty());
        Ok(())
    });
}

#[test]
fn literal_template_passes_through() {
    run_property("literal_template_passes_through", |u| {
        let ev = arb_event(u)?;
        let lit = "hello world: no placeholders here";
        let (s, missing) = render_template(lit, &ev);
        assert_eq!(s, lit);
        assert!(missing.is_empty());
    Ok(())
    });
}

#[test]
fn missing_field_keeps_placeholder_and_collects() {
    run_property("missing_field_keeps_placeholder_and_collects", |u| {
        let ev = arb_event(u)?;
        let key = format!("__missing_{}", arb_token(u)?);
        let tmpl = format!("x={{{{{key}}}}}");
        let (s, missing) = render_template(&tmpl, &ev);
        assert!(s.contains(&format!("{{{{{key}}}}}")));
        assert!(missing.iter().any(|m| m == &key));
        Ok(())
    });
}

#[test]
fn known_field_substitutes() {
    run_property("known_field_substitutes", |u| {
        let pid = format!("p-{}", arb_token(u)?);
        let ev = Event::builder("k", Severity::Info)
            .profile(ProfileId::new(&pid).expect("valid"))
            .build();
        let (s, missing) = render_template("id={{profile_id}}", &ev);
        assert_eq!(s, format!("id={pid}"));
        assert!(missing.is_empty());
        Ok(())
    });
}

#[test]
fn whitespace_in_braces_tolerated() {
    run_property("whitespace_in_braces_tolerated", |u| {
        let pid = format!("p-{}", arb_token(u)?);
        let ev = Event::builder("k", Severity::Info)
            .profile(ProfileId::new(&pid).expect("valid"))
            .build();
        let (s, _) = render_template("[{{   profile_id   }}]", &ev);
        assert_eq!(s, format!("[{pid}]"));
        Ok(())
    });
}

#[test]
fn unmatched_open_braces_pass_through() {
    run_property("unmatched_open_braces_pass_through", |u| {
        let ev = arb_event(u)?;
        let tmpl = "before {{ never closes";
        let (s, missing) = render_template(tmpl, &ev);
        assert_eq!(s, tmpl);
        assert!(missing.is_empty());
        Ok(())
    });
}

#[test]
fn nested_braces_do_not_panic() {
    run_property("nested_braces_do_not_panic", |u| {
        let ev = arb_event(u)?;
        // Carefully constructed pathological input.
        let tmpl = "{{{{a}}}} {{ {{b}} }}";
        let _ = render_template(tmpl, &ev);
        Ok(())
    });
}

#[test]
fn many_repeated_substitutions() {
    run_property("many_repeated_substitutions", |u| {
        let pid = format!("p-{}", arb_token(u)?);
        let ev = Event::builder("k", Severity::Info)
            .profile(ProfileId::new(&pid).expect("valid"))
            .build();
        let mut tmpl = String::new();
        for _ in 0..16 {
            tmpl.push_str("{{profile_id}};");
        }
        let (s, _) = render_template(&tmpl, &ev);
        let expected = format!("{pid};").repeat(16);
        assert_eq!(s, expected);
        Ok(())
    });
}

#[test]
fn severity_field_renders_as_lowercase() {
    run_property("severity_field_renders_as_lowercase", |u| {
        let sev = arb_severity(u)?;
        let ev = Event::builder("k", sev).build();
        let (s, _) = render_template("{{severity}}", &ev);
        assert_eq!(s, sev.as_str());
        Ok(())
    });
}

#[test]
fn kind_field_renders_verbatim() {
    run_property("kind_field_renders_verbatim", |u| {
        let kind = arb_token(u)?;
        let ev = Event::builder(kind.clone(), Severity::Info).build();
        let (s, _) = render_template("{{kind}}", &ev);
        assert_eq!(s, kind);
        Ok(())
    });
}

#[test]
fn message_field_renders_verbatim() {
    run_property("message_field_renders_verbatim", |u| {
        let msg = arb_token(u)?;
        let ev = Event::builder("k", Severity::Info).message(msg.clone()).build();
        let (s, _) = render_template("{{message}}", &ev);
        assert_eq!(s, msg);
        Ok(())
    });
}

#[test]
fn custom_field_renders_string_unquoted() {
    run_property("custom_field_renders_string_unquoted", |u| {
        let v = arb_token(u)?;
        let ev = Event::builder("k", Severity::Info).field("f", v.clone()).build();
        let (s, _) = render_template("{{f}}", &ev);
        assert_eq!(s, v);
        Ok(())
    });
}
