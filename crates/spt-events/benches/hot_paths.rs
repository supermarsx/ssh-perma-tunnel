//! Microbenchmarks for the `spt-events` hot paths.
//!
//! Three groups:
//!
//! * `template_render`   — [`spt_events::template::render_template`] over
//!   ASCII-only fixtures of 1 / 10 / 50 placeholders. ASCII-only because the
//!   current implementation has a known `bytes[i] as char` UTF-8 correctness
//!   bug at `src/template.rs:48` that Phase C c1 will fix — exercising it
//!   here with non-ASCII would conflate two changes.
//! * `binding_match`     — [`spt_events::BindingMatch::matches`] for three
//!   shapes (kinds-only, expr-only, combined) against a fixed `Event`.
//! * `dispatcher_fanout` — `DispatcherInner::dispatch` from
//!   [`spt_events::dispatcher::build_for_test`] fanning one event out to
//!   N = 1, 4, 16 in-process [`CapturingSink`]s. Tokio runtime-backed via
//!   `Runtime::block_on`.
//!
//! Run explicitly with:
//!
//! ```text
//! cargo bench -p spt-events --features bench --bench hot_paths
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tempfile::TempDir;
use tokio::runtime::Runtime;

use spt_core::{ForwardId, ProfileId};
use spt_events::binding::{Binding, BindingMatch, ExprFilter, ExprOp, SinkRef};
use spt_events::dispatcher::{build_for_test, DispatcherConfig};
use spt_events::event::{Event, Severity};
use spt_events::sinks::Sink;
use spt_events::template::render_template;
use spt_events::testing::CapturingSink;

/// Build an ASCII-only `Event` used by every group.
fn fixture_event() -> Event {
    Event::builder("forward.connection_failed", Severity::Error)
        .profile(ProfileId::new("smtp-relay").unwrap())
        .forward(ForwardId::new("inbound-25").unwrap())
        .message("connection refused")
        .field("error", "connect timeout after 5s")
        .field("count", 5)
        .field("remote", "192.0.2.10:25")
        .field("attempt", 3)
        .field("retry_in", "10s")
        .field("category", "transient")
        .build()
}

/// Build a template repeating `{{count}}` `n` times surrounded by short ASCII
/// literals so the literal/placeholder ratio matches a realistic subject line.
fn template_with_n_placeholders(n: usize) -> String {
    let mut s = String::with_capacity(n * 16);
    s.push_str("[alert] ");
    for i in 0..n {
        if i > 0 {
            s.push_str(" | ");
        }
        // Rotate across a few known-good ASCII field names.
        let field = match i % 5 {
            0 => "{{count}}",
            1 => "{{message}}",
            2 => "{{profile_id}}",
            3 => "{{forward_id}}",
            _ => "{{kind}}",
        };
        s.push_str(field);
    }
    s.push_str(" end");
    s
}

fn bench_template_render(c: &mut Criterion) {
    let mut group = c.benchmark_group("template_render");
    let ev = fixture_event();
    for n in [1_usize, 10, 50] {
        let tpl = template_with_n_placeholders(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &tpl, |b, tpl| {
            b.iter(|| {
                let (s, missing) = render_template(black_box(tpl.as_str()), black_box(&ev));
                black_box((s, missing));
            });
        });
    }
    group.finish();
}

fn bench_binding_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("binding_match");
    let ev = fixture_event();

    // Kinds-only: wildcard suffix that matches.
    let kinds_only = BindingMatch {
        kinds: vec!["forward.*".into()],
        ..Default::default()
    };
    // Expr-only: substring match on an existing string field.
    let expr_only = BindingMatch {
        exprs: vec![ExprFilter {
            field: "error".into(),
            op: ExprOp::Contains,
            value: serde_json::Value::String("timeout".into()),
        }],
        ..Default::default()
    };
    // Combined: kinds AND severity AND expr.
    let combined = BindingMatch {
        kinds: vec!["forward.*".into()],
        min_severity: Some(Severity::Warn),
        exprs: vec![ExprFilter {
            field: "error".into(),
            op: ExprOp::Contains,
            value: serde_json::Value::String("timeout".into()),
        }],
        ..Default::default()
    };

    group.bench_function("kinds_only", |b| {
        b.iter(|| black_box(black_box(&kinds_only).matches(black_box(&ev))));
    });
    group.bench_function("expr_only", |b| {
        b.iter(|| black_box(black_box(&expr_only).matches(black_box(&ev))));
    });
    group.bench_function("combined", |b| {
        b.iter(|| black_box(black_box(&combined).matches(black_box(&ev))));
    });

    group.finish();
}

/// Build a `DispatcherInner` wired to `n` `CapturingSink`s, all subscribed to
/// the wildcard `forward.*` binding. Returns the dispatcher and the tempdir
/// that owns its spool root (the tempdir must outlive the dispatcher).
fn build_fanout_dispatcher(n: usize) -> (spt_events::dispatcher::DispatcherInner, TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    let mut sink_refs = Vec::with_capacity(n);
    for i in 0..n {
        let name = format!("sink_{i}");
        sink_refs.push(SinkRef::new(&name));
        sinks.insert(
            name.clone(),
            Arc::new(CapturingSink::new(name)) as Arc<dyn Sink>,
        );
    }
    let bindings = vec![Binding {
        name: "bench".into(),
        r#match: BindingMatch {
            kinds: vec!["forward.*".into()],
            ..Default::default()
        },
        sinks: sink_refs,
        dedupe: None,
    }];
    let d = build_for_test(bindings, sinks, cfg).expect("build dispatcher");
    (d, tmp)
}

fn bench_dispatcher_fanout(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio rt");
    let mut group = c.benchmark_group("dispatcher_fanout");
    let ev = Arc::new(fixture_event());
    for n in [1_usize, 4, 16] {
        // `tmp` must outlive `dispatcher` (dispatcher holds spool files under
        // it). Both are dropped at the end of this loop iteration, in reverse
        // declaration order (dispatcher first, then tmp).
        let (dispatcher, tmp) = build_fanout_dispatcher(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _n| {
            b.iter(|| {
                rt.block_on(async {
                    dispatcher.dispatch(black_box(ev.clone())).await;
                });
            });
        });
        drop(dispatcher);
        drop(tmp);
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_template_render,
    bench_binding_match,
    bench_dispatcher_fanout
);
criterion_main!(benches);
