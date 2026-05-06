//! All representative example configs MUST load and validate clean.
//!
//! Files live in `<workspace>/examples/`. The test walks each one, loads it
//! through [`spt_config::load`], runs [`spt_config::validate`], and asserts
//! both that no errors were produced and that load → render → load is the
//! identity.

use std::path::{Path, PathBuf};

use spt_config::{fingerprint, load, render, validate};
use spt_core::RedactionMode;

fn examples_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().join("examples")
}

const EXPECTED: &[&str] = &[
    "minimal.toml",
    "smtp-relay.toml",
    "jump-host.toml",
    "reverse.toml",
    "ssh3.toml",
    "dns-split-horizon.toml",
    "mcp.toml",
];

#[test]
fn all_examples_present() {
    let dir = examples_dir();
    for name in EXPECTED {
        let p = dir.join(name);
        assert!(p.is_file(), "missing example file: {}", p.display());
    }
}

#[test]
fn all_examples_load_and_validate_clean() {
    let dir = examples_dir();
    for name in EXPECTED {
        let p = dir.join(name);
        let (cfg, warnings) = load(&p, false).unwrap_or_else(|e| panic!("load {name}: {e}"));
        assert!(
            warnings.is_empty(),
            "{name}: unexpected unknown keys: {warnings:?}"
        );

        let diags = validate(&cfg);
        assert!(
            diags.is_ok(),
            "{name}: validation errors: {:?}",
            diags.errors
        );
    }
}

#[test]
fn all_examples_round_trip() {
    let dir = examples_dir();
    for name in EXPECTED {
        let p = dir.join(name);
        let (cfg, _) = load(&p, false).expect("load");
        let rendered = render(&cfg, RedactionMode::None);
        let (cfg2, _) = spt_config::load_str(&rendered, false).expect("re-load");
        assert_eq!(cfg, cfg2, "{name} did not round-trip");
        // Fingerprint is also stable on round-trip.
        assert_eq!(fingerprint(&cfg), fingerprint(&cfg2));
    }
}

#[test]
fn ssh3_example_validates_only_with_ack() {
    // Sanity check: drop acknowledge_experimental, validation must fail.
    let dir = examples_dir();
    let p = dir.join("ssh3.toml");
    let (mut cfg, _) = load(&p, false).unwrap();
    cfg.profiles[0].acknowledge_experimental = Some(false);
    let diags = validate(&cfg);
    assert!(
        diags
            .errors
            .iter()
            .any(|e| e.code == "ssh3_experimental_unack"),
        "expected ssh3_experimental_unack, got {:?}",
        diags.errors
    );
}
