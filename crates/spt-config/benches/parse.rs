//! Microbenchmarks for `spt_config::load` + `spt_config::validate`.
//!
//! Exercises the canonical `examples/*.toml` corpus that ships with the
//! repo so the benchmark stays in sync with the schemas users actually run.
//! Two phases are measured per fixture:
//!
//! * `load`     — `load_str` (TOML parse + serde deserialize).
//! * `validate` — `validate` over the parsed `Config`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use spt_config::{load::load_str, validate::validate};

const FIXTURES: &[(&str, &str)] = &[
    ("minimal", include_str!("../../../examples/minimal.toml")),
    (
        "smtp_relay",
        include_str!("../../../examples/smtp-relay.toml"),
    ),
    (
        "jump_host",
        include_str!("../../../examples/jump-host.toml"),
    ),
    ("reverse", include_str!("../../../examples/reverse.toml")),
    ("ssh3", include_str!("../../../examples/ssh3.toml")),
    (
        "dns_split_horizon",
        include_str!("../../../examples/dns-split-horizon.toml"),
    ),
    ("mcp", include_str!("../../../examples/mcp.toml")),
    (
        "multi_profile_fleet",
        include_str!("../../../examples/multi-profile-fleet.toml"),
    ),
];

fn bench_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_load");
    for (name, raw) in FIXTURES {
        group.bench_with_input(BenchmarkId::from_parameter(name), raw, |b, raw| {
            b.iter(|| {
                let (cfg, warns) = load_str(black_box(raw), false).expect("parse");
                black_box((cfg, warns));
            });
        });
    }
    group.finish();
}

fn bench_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_validate");
    for (name, raw) in FIXTURES {
        let (cfg, _) = load_str(raw, false).expect("parse");
        group.bench_with_input(BenchmarkId::from_parameter(name), &cfg, |b, cfg| {
            b.iter(|| {
                let d = validate(black_box(cfg));
                black_box(d);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_load, bench_validate);
criterion_main!(benches);
