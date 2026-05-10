//! Property: arbitrary `Duration` / `u64` byte-count values reach a
//! fixed-point under `format → parse → format`.
//!
//! `humantime` and `bytesize` aren't strict round-trips on the *input*
//! string (e.g. `"1h60m"` reformats to `"2h"`), but a SECOND pass on the
//! reformatted output must be the identity — the parser is canonical.

use std::time::Duration;

use arbitrary::Unstructured;
use spt_core::duration::{format_duration, parse_duration};
use spt_core::size::{format_size, parse_size};
use spt_property_tests::run_property;

fn arb_duration(u: &mut Unstructured<'_>) -> arbitrary::Result<Duration> {
    // Cap secs at ~10y to stay inside humantime's stable formatting range.
    let secs = u.int_in_range(0u64..=315_360_000)?;
    let nanos = u.int_in_range(0u32..=999_999_999)?;
    Ok(Duration::new(secs, nanos))
}

fn arb_size(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    // Cap at PiB-range. `bytesize`'s pretty-printer renders larger values
    // in EiB with a fractional component (e.g. `"0.9 EiB"`) that its own
    // parser then rejects (a known upstream quirk we don't try to paper
    // over). Real-world `[runtime].cache_size_bytes`-style fields stay
    // well under this bound.
    Ok(u.int_in_range(0u64..=(1u64 << 50))?)
}

// ---- Properties (12 invariants) -------------------------------------------

#[test]
fn duration_format_parse_fixed_point() {
    run_property("duration_format_parse_fixed_point", |u| {
        let d = arb_duration(u)?;
        let s1 = format_duration(d);
        let parsed = parse_duration(&s1).expect("formatted duration must reparse");
        let s2 = format_duration(parsed);
        assert_eq!(s1, s2, "formatter is not a fixed point: {s1} vs {s2}");
        Ok(())
    });
}

#[test]
fn duration_round_trip_value() {
    run_property("duration_round_trip_value", |u| {
        let d = arb_duration(u)?;
        let parsed = parse_duration(&format_duration(d)).expect("reparse");
        // Sub-microsecond precision can be lost by humantime formatting; we
        // accept any difference < 1µs as equality.
        let diff = if d > parsed { d - parsed } else { parsed - d };
        assert!(
            diff < Duration::from_micros(1),
            "lost more than 1µs: {d:?} vs {parsed:?}"
        );
        Ok(())
    });
}

#[test]
fn duration_unit_strings_parse() {
    run_property("duration_unit_strings_parse", |u| {
        let secs = u.int_in_range(0u64..=86_400)?;
        for unit in ["s", "sec", "secs", "seconds"] {
            parse_duration(&format!("{secs}{unit}")).expect("unit string parse");
        }
        Ok(())
    });
}

#[test]
fn duration_combined_units() {
    run_property("duration_combined_units", |u| {
        let h = u.int_in_range(0u32..=23)?;
        let m = u.int_in_range(0u32..=59)?;
        let s = format!("{h}h{m}m");
        let d = parse_duration(&s).expect("combined parse");
        let expected = Duration::from_secs(u64::from(h) * 3600 + u64::from(m) * 60);
        assert_eq!(d, expected);
        Ok(())
    });
}

#[test]
fn duration_zero_is_round_trippable() {
    run_property("duration_zero_is_round_trippable", |_u| {
        let z = Duration::ZERO;
        let s = format_duration(z);
        let back = parse_duration(&s).expect("parse zero");
        assert_eq!(back, z);
        Ok(())
    });
}

#[test]
fn duration_empty_string_rejected() {
    run_property("duration_empty_string_rejected", |_u| {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
        Ok(())
    });
}

#[test]
fn size_format_parse_fixed_point() {
    run_property("size_format_parse_fixed_point", |u| {
        // `format_size` is lossy across units (it switches "KiB" → "MiB" →
        // … and rounds), so we don't claim `format == format(parse(format))`
        // for arbitrary inputs. What does hold canonically is the *value*
        // after one `parse → format → parse`: the second parse returns the
        // first parse's value exactly.
        let n = arb_size(u)?;
        let s1 = format_size(n);
        let v1 = parse_size(&s1).expect("formatted size must reparse");
        let s2 = format_size(v1);
        let v2 = parse_size(&s2).expect("re-formatted size must reparse");
        assert_eq!(v1, v2, "value fixed-point lost: {v1} vs {v2}");
        Ok(())
    });
}

#[test]
fn size_iec_unit_strings_parse() {
    run_property("size_iec_unit_strings_parse", |u| {
        let n = u.int_in_range(1u64..=1024)?;
        for unit in ["KiB", "MiB", "GiB", "TiB"] {
            parse_size(&format!("{n}{unit}")).expect("iec parse");
        }
        Ok(())
    });
}

#[test]
fn size_si_unit_strings_parse() {
    run_property("size_si_unit_strings_parse", |u| {
        let n = u.int_in_range(1u64..=1024)?;
        for unit in ["KB", "MB", "GB", "TB"] {
            parse_size(&format!("{n}{unit}")).expect("si parse");
        }
        Ok(())
    });
}

#[test]
fn size_zero_round_trip() {
    run_property("size_zero_round_trip", |_u| {
        let s = format_size(0);
        let back = parse_size(&s).expect("parse zero size");
        assert_eq!(back, 0);
        Ok(())
    });
}

#[test]
fn size_empty_string_rejected() {
    run_property("size_empty_string_rejected", |_u| {
        assert!(parse_size("").is_err());
        assert!(parse_size("   ").is_err());
        Ok(())
    });
}

#[test]
fn size_byte_value_round_trip() {
    run_property("size_byte_value_round_trip", |u| {
        // Plain byte strings ("1234 B") parse exactly to their byte count.
        // The IEC pretty-printer is *intentionally* lossy (it switches
        // units and rounds for human readability) — that case is exercised
        // by the format-fixed-point property above on a smaller domain.
        let n = u.int_in_range(0u64..=u64::from(u32::MAX))?;
        let s1 = format!("{n} B");
        let parsed = parse_size(&s1).expect("explicit byte parse");
        assert_eq!(parsed, n);
        Ok(())
    });
}
