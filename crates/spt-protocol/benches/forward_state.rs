//! Microbenchmarks for forward state transitions and `ForwardHandle` churn.
//!
//! Two groups:
//!
//! * `state_transitions` — drives a `watch::Sender` through every `ForwardState`
//!   variant; measures the cost of one publish + observer wakeup.
//! * `handle_churn` — repeatedly constructs a fresh `ForwardHandle`
//!   (allocates id + watch + oneshot) and immediately drops it. Approximates
//!   the supervisor open/close hot path on a flapping link.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spt_protocol::{ForwardHandle, ForwardId, ForwardState};
use tokio::sync::{oneshot, watch};

const ALL_STATES: &[ForwardState] = &[
    ForwardState::Disabled,
    ForwardState::Binding,
    ForwardState::Listening,
    ForwardState::RemoteRequested,
    ForwardState::Active,
    ForwardState::Degraded,
    ForwardState::RetryWait,
    ForwardState::Stopped,
    ForwardState::Failed,
];

fn bench_state_transitions(c: &mut Criterion) {
    c.bench_function("forward_state/transition_publish", |b| {
        let (tx, rx) = watch::channel(ForwardState::Binding);
        let _keep = rx.clone();
        let mut idx: usize = 0;
        b.iter(|| {
            let s = ALL_STATES[idx % ALL_STATES.len()];
            idx = idx.wrapping_add(1);
            tx.send(black_box(s)).expect("publish");
        });
    });

    c.bench_function("forward_state/is_terminal", |b| {
        let mut idx: usize = 0;
        b.iter(|| {
            let s = ALL_STATES[idx % ALL_STATES.len()];
            idx = idx.wrapping_add(1);
            black_box(s.is_terminal());
        });
    });
}

fn bench_handle_churn(c: &mut Criterion) {
    c.bench_function("forward_handle/construct_drop", |b| {
        b.iter(|| {
            let (_state_tx, state_rx) = watch::channel(ForwardState::Active);
            let (close_tx, _close_rx) = oneshot::channel();
            let h = ForwardHandle::new(ForwardId::new(), "bench", state_rx, close_tx);
            black_box(&h);
        });
    });

    c.bench_function("forward_handle/id_alloc", |b| {
        b.iter(|| {
            black_box(ForwardId::new());
        });
    });
}

criterion_group!(benches, bench_state_transitions, bench_handle_churn);
criterion_main!(benches);
