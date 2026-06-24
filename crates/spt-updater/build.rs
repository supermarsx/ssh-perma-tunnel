//! Build script: expose the compilation target triple to the crate so the
//! updater can pick the matching release artifact at runtime. `$TARGET` is
//! set by Cargo for build scripts; re-export it as `SPT_TARGET` for `env!`.
//!
//! No dependencies — keeps `Cargo.lock` untouched.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=SPT_TARGET={target}");
}
