//! CLI subcommand implementation modules.
//!
//! Each `*_ops.rs` module implements the bodies of one CLI group's
//! subcommands. `cli_dispatch.rs` delegates to these modules, keeping
//! per-area implementations isolated so Phase A executors could work in
//! parallel without colliding.

// Many handler functions are `pub async fn` for dispatch symmetry even
// though some bodies are sync; the same shape lets the dispatcher uniformly
// `.await` them. The Phase A executors landed all 14 modules under that
// contract — match the existing `cli_dispatch.rs` allow set so the joined
// surface clears `-D warnings`.
#![allow(clippy::unused_async)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::manual_pattern_char_comparison)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::default_constructed_unit_structs)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::stable_sort_primitive)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::single_match_else)]
#![allow(clippy::option_as_ref_cloned)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::unnested_or_patterns)]
#![allow(clippy::ignored_unit_patterns)]

pub mod about_ops;
pub mod bench_ops;
pub mod config_ops;
pub mod diag_ops;
pub mod dns_ops;
pub mod event_ops;
pub mod firewall_ops;
pub mod forward_ops;
// t6-e6:start
pub mod ftp_ops;
// t6-e6:end
pub mod key_ops;
pub mod kill_ops;
pub mod log_ops;
pub mod observe_ops;
pub mod profile_ops;
pub mod secret_ops;
pub mod sftp_ops;
pub mod ssh3_ops;
pub mod status_ops;
pub mod style;
pub mod tunnel_ops;
pub mod update_ops;
