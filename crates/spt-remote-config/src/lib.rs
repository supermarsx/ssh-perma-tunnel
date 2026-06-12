//! Remote configuration fetch with HTTPS pinning for spt.
//!
//! This crate implements spec §14.3: pull a TOML config from a remote HTTPS
//! endpoint, verify the **body** SHA-256 fingerprint, support
//! `ETag`/`If-None-Match` for conditional GETs, enforce a maximum body size,
//! and write the result to an atomic on-disk cache so a fetch failure cannot
//! replace a known-good local config.
//!
//! Strict TLS is the default — `reqwest` is built with `rustls-tls` on top of
//! the system root store. We do **not** install a custom certificate verifier;
//! the body fingerprint is the integrity guarantee per spec §14.3.
//!
//! # Layout
//! - [`fetch()`] — async fetch entrypoint built on top of an injectable
//!   [`HttpFetcher`] so tests can plug in a fake.
//! - [`cache`] — read/write the atomic cache file + sidecar `.sha256`.
//! - [`http`] — the [`HttpFetcher`] trait + reqwest implementation.

#![deny(missing_docs)]

pub mod cache;
pub mod fetch;
pub mod http;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use cache::{cache_path, fingerprint_sidecar_path, load_cached, save_atomic};
pub use fetch::{
    fetch, fetch_with_plan, fetcher_for_plan, FetchOutcome, FetchResult, RemoteConfigError,
};
pub use http::{HttpFetcher, HttpResponse, ReqwestFetcher};

/// Re-export of the source-of-truth spec/plan types.
pub use spt_config::remote::{PlanError, RemoteConfigPlan, RemoteConfigSpec};
