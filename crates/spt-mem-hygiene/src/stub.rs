//! Stub back-end for unsupported targets.
//!
//! Emits a single `Skipped` row noting that no primitives are available.

use crate::{HardeningReport, HardeningResult};

pub(crate) fn harden_into(report: &mut HardeningReport) {
    report.push(HardeningResult::skipped(
        "platform",
        "no hardening primitives available for this target",
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_pushes_exactly_one_skipped_row() {
        let mut r = HardeningReport::new();
        harden_into(&mut r);
        assert_eq!(r.results.len(), 1);
        assert!(r.results[0].status.is_skipped());
    }
}
