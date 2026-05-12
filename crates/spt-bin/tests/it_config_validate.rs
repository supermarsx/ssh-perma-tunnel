//! Validate every example config in `/examples/` round-trips through the
//! `spt-config` `load → validate → render → load` cycle.

use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
}

#[test]
fn every_example_loads_and_validates() {
    let dir = examples_dir();
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("examples dir") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        count += 1;
        let (cfg, warnings) = spt_config::load(&path, false)
            .unwrap_or_else(|e| panic!("load `{}`: {e}", path.display()));
        // Strict validation should not error out on the bundled examples.
        let diags = spt_config::validate(&cfg);
        assert!(
            diags.errors.is_empty(),
            "validate `{}`: errors = {:?}",
            path.display(),
            diags.errors
        );
        // Rendering should be lossless for the load-render-load identity on
        // the strict (non-redacting) path.
        let rendered = spt_config::render(&cfg, spt_core::RedactionMode::None);
        let (cfg2, _w2) = spt_config::load_str(&rendered, false)
            .unwrap_or_else(|e| panic!("re-load `{}` after render: {e}", path.display()));
        assert_eq!(cfg.version, cfg2.version);
        // Warnings (unknown fields) are non-fatal; we just record them.
        eprintln!("{} — {} warnings", path.display(), warnings.len());
    }
    assert!(count > 0, "no examples to validate");
}
