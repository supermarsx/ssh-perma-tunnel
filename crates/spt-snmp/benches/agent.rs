//! Microbenchmarks for the agent's PDU-dispatch hot path.
//!
//! ## Scope
//!
//! `Agent::dispatch_pdu` and `Agent::handle_{get,get_next,get_bulk}` are
//! private async fns (see `crates/spt-snmp/src/agent.rs` lines ~435–574).
//! The PUBLIC dispatch entry point — what those handlers actually do once
//! USM verify + decrypt has run — is iteration over the request's
//! `variable_bindings`, calling `MibRegistry::get` (`GetRequest`) or
//! `MibRegistry::next` (`GetNextRequest` / `GetBulkRequest`), assembling
//! response `VarBind`s, and (for `GetBulkRequest`) running the
//! `max_repetitions` cursor loop.
//!
//! These benches reproduce that loop shape verbatim against a real
//! `MibRegistry` populated with the testing fixtures. They DO NOT exercise
//! the UDP socket, the USM HMAC/AES paths (those are `aws-lc-rs` style
//! native crypto and out of scope), or the BER envelope (covered by
//! `ber.rs`).
//!
//! ## MIB sizes
//!
//! Two registry populations, each from `spt_snmp::testing::fixtures::default_user`'s
//! enterprise subtree:
//!
//! * **small** — 10 scalar OIDs.
//! * **scale** — 1000 scalar OIDs.
//!
//! ## Iteration model
//!
//! A single `current_thread` Tokio runtime is built once per group and
//! reused with `rt.block_on(...)` per iter. Creating a runtime per iter
//! dominates the cost on the small-MIB benches.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use tokio::runtime::Runtime;

use spt_snmp::mib::{ConstScalar, MibRegistry};
use spt_snmp::oid::ObjectIdentifier;
use spt_snmp::pdu::{Pdu, PduKind};
use spt_snmp::value::{Value, VarBind};

const MIB_SMALL: usize = 10;
const MIB_SCALE: usize = 1000;

const NON_REPEATERS: usize = 2;
const MAX_REPETITIONS: usize = 10;

/// Builds a registry with `n` scalar OIDs rooted at `1.3.6.1.4.1.32473.1.<i>.0`,
/// each returning `Value::Integer(i)`. The same OID shape the documentation
/// PEN uses in `LocalhostAgent` fixtures, so this is the same dispatch shape
/// production tests see.
fn build_registry(n: usize) -> Arc<MibRegistry> {
    let mut reg = MibRegistry::new();
    for i in 0..n {
        let oid = ObjectIdentifier::new([
            1u32,
            3,
            6,
            1,
            4,
            1,
            32_473,
            1,
            u32::try_from(i).expect("u32 fits"),
            0,
        ]);
        reg.add_scalar(
            oid,
            ConstScalar::new(Value::Integer(i64::try_from(i).expect("i64 fits"))),
        );
    }
    Arc::new(reg)
}

/// Pre-built OID slice for a registry of `n` entries.
fn oids_for(n: usize) -> Vec<ObjectIdentifier> {
    (0..n)
        .map(|i| {
            ObjectIdentifier::new([
                1u32,
                3,
                6,
                1,
                4,
                1,
                32_473,
                1,
                u32::try_from(i).expect("u32 fits"),
                0,
            ])
        })
        .collect()
}

/// Build a `GetRequest`-style PDU that asks for the first `k` OIDs of the MIB.
fn get_request(oids: &[ObjectIdentifier], k: usize) -> Pdu {
    let vbs = oids
        .iter()
        .take(k)
        .map(|o| VarBind::null(o.clone()))
        .collect();
    Pdu {
        kind: PduKind::GetRequest,
        request_id: 1,
        error_status: 0,
        error_index: 0,
        variable_bindings: vbs,
    }
}

// ---------------------------------------------------------------------------
// GetRequest — mirrors `Agent::handle_get`:
//   for each varbind, registry.get(...).await; produce response VarBind.
// ---------------------------------------------------------------------------

async fn dispatch_get(reg: &MibRegistry, req: &Pdu) -> Pdu {
    let mut bindings = Vec::with_capacity(req.variable_bindings.len());
    for vb in &req.variable_bindings {
        let value = match reg.get(&vb.name).await {
            Ok(Some(v)) => v,
            _ => Value::NoSuchObject,
        };
        bindings.push(VarBind {
            name: vb.name.clone(),
            value,
        });
    }
    Pdu {
        kind: PduKind::Response,
        request_id: req.request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: bindings,
    }
}

// ---------------------------------------------------------------------------
// GetNextRequest — mirrors `Agent::handle_get_next`:
//   for each varbind, registry.next(...).await; produce response VarBind
//   (or end-of-MIB-view sentinel).
// ---------------------------------------------------------------------------

async fn dispatch_get_next(reg: &MibRegistry, req: &Pdu) -> Pdu {
    let mut bindings = Vec::with_capacity(req.variable_bindings.len());
    for vb in &req.variable_bindings {
        let resp = match reg.next(&vb.name).await {
            Ok(Some((oid, v))) => VarBind {
                name: oid,
                value: v,
            },
            _ => VarBind {
                name: vb.name.clone(),
                value: Value::EndOfMibView,
            },
        };
        bindings.push(resp);
    }
    Pdu {
        kind: PduKind::Response,
        request_id: req.request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: bindings,
    }
}

// ---------------------------------------------------------------------------
// GetBulkRequest — mirrors `Agent::handle_get_bulk`:
//   non-repeaters slice + `max_repetitions` cursor loop.
//   `error_status` carries non_repeaters; `error_index` carries
//   max_repetitions per RFC 3416 §4.2.3.
// ---------------------------------------------------------------------------

async fn dispatch_get_bulk(reg: &MibRegistry, req: &Pdu) -> Pdu {
    let n = usize::try_from(req.error_status.max(0)).unwrap_or(0);
    let max_rep = usize::try_from(req.error_index.max(0)).unwrap_or(0);
    let total = req.variable_bindings.len();
    let n = n.min(total);

    let mut bindings: Vec<VarBind> = Vec::new();

    for vb in req.variable_bindings.iter().take(n) {
        match reg.next(&vb.name).await {
            Ok(Some((oid, v))) => bindings.push(VarBind {
                name: oid,
                value: v,
            }),
            _ => bindings.push(VarBind {
                name: vb.name.clone(),
                value: Value::EndOfMibView,
            }),
        }
    }

    if total > n && max_rep > 0 {
        let mut cursors: Vec<ObjectIdentifier> = req
            .variable_bindings
            .iter()
            .skip(n)
            .map(|vb| vb.name.clone())
            .collect();
        for _ in 0..max_rep {
            let mut all_end = true;
            for cur in &mut cursors {
                match reg.next(cur).await {
                    Ok(Some((oid, v))) => {
                        *cur = oid.clone();
                        bindings.push(VarBind {
                            name: oid,
                            value: v,
                        });
                        all_end = false;
                    }
                    _ => bindings.push(VarBind {
                        name: cur.clone(),
                        value: Value::EndOfMibView,
                    }),
                }
            }
            if all_end {
                break;
            }
        }
    }

    Pdu {
        kind: PduKind::Response,
        request_id: req.request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: bindings,
    }
}

// ---------------------------------------------------------------------------
// Bench groups.
// ---------------------------------------------------------------------------

fn bench_get_request(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut g = c.benchmark_group("agent_get_request");
    for &(label, n) in &[("small_10", MIB_SMALL), ("scale_1000", MIB_SCALE)] {
        let reg = build_registry(n);
        let oids = oids_for(n);
        // Use up to 10 varbinds per request — typical SNMP get burst.
        let k = n.min(10);
        let req = get_request(&oids, k);
        g.bench_with_input(BenchmarkId::from_parameter(label), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let resp = dispatch_get(black_box(&reg), black_box(&req)).await;
                    black_box(resp);
                });
            });
        });
    }
    g.finish();
}

fn bench_get_next_request(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut g = c.benchmark_group("agent_get_next_request");
    for &(label, n) in &[("small_10", MIB_SMALL), ("scale_1000", MIB_SCALE)] {
        let reg = build_registry(n);
        let oids = oids_for(n);
        // Use up to 10 starting points — drives 10 next-cursor lookups.
        let k = n.min(10);
        let mut req = get_request(&oids, k);
        req.kind = PduKind::GetNextRequest;
        g.bench_with_input(BenchmarkId::from_parameter(label), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let resp = dispatch_get_next(black_box(&reg), black_box(&req)).await;
                    black_box(resp);
                });
            });
        });
    }
    g.finish();
}

fn bench_get_bulk_request(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut g = c.benchmark_group("agent_get_bulk_request");
    for &(label, n) in &[("small_10", MIB_SMALL), ("scale_1000", MIB_SCALE)] {
        let reg = build_registry(n);
        let oids = oids_for(n);
        // Mimic a realistic bulk-walk: a couple of non-repeaters + a few
        // repeaters traversing `MAX_REPETITIONS` rows each.
        let k = (NON_REPEATERS + 3).min(n);
        let mut req = get_request(&oids, k);
        req.kind = PduKind::GetBulkRequest;
        req.error_status = i32::try_from(NON_REPEATERS.min(k)).expect("fits");
        req.error_index = i32::try_from(MAX_REPETITIONS).expect("fits");
        g.bench_with_input(BenchmarkId::from_parameter(label), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let resp = dispatch_get_bulk(black_box(&reg), black_box(&req)).await;
                    black_box(resp);
                });
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_get_request,
    bench_get_next_request,
    bench_get_bulk_request,
);
criterion_main!(benches);
