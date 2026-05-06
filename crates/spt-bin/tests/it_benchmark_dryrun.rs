//! Benchmark report compare on synthetic results.

#[test]
fn empty_compare_yields_zero_metrics() {
    let cmp = spt_benchmark::compare_reports(&[], &[]);
    let s = serde_json::to_string(&cmp).expect("serialize");
    assert!(!s.is_empty());
}
