//! Byte-level redaction wrapper used by every log sink.
//!
//! The tracing-subscriber field-visitor route mutates structured fields in
//! place, but the `tracing` 0.1 visitor API is read-only — there is no
//! supported way to substitute a `&str` field value as it is being recorded.
//! Doing it through a custom `Layer` would require duplicating the formatter.
//!
//! Instead this module wraps the **already-formatted line bytes** in a
//! [`RedactingWriter`]. The wrapper buffers complete lines (split on `\n`),
//! runs each through [`spt_core::redact`], and forwards the redacted bytes
//! verbatim to the inner writer. Because fmt layers always emit one record
//! per `write_all`, this means every log line — irrespective of format —
//! goes through redaction before it can leave the process.
//!
//! ## Buffering strategy
//!
//! `flush_lines` uses a *cursor* (`consumed`) into a grow-only `Vec<u8>`
//! rather than `Vec::drain(..=idx)` per newline. Draining from the front of
//! a vector is O(remaining), so once-per-newline draining made the whole
//! routine O(n²) over the input — a 1 MiB write that produced many lines
//! cost ~167 ms and throughput collapsed to ~6 MiB/s. The cursor approach
//! processes each newline in O(1) amortized time and compacts the buffer
//! only when the consumed prefix exceeds half its length, giving amortized
//! O(1) per byte. The public API and observable behavior (including the
//! non-UTF8 passthrough on a per-line basis) are unchanged.

use std::io::{self, Write};
use std::sync::Arc;

use parking_lot::Mutex;
use spt_core::{redact, RedactionMode};
use tracing_subscriber::fmt::MakeWriter;

/// `MakeWriter` that wraps every produced writer in a [`RedactingWriter`].
#[derive(Clone)]
pub struct RedactingMakeWriter<M> {
    inner: M,
    mode: RedactionMode,
}

impl<M> RedactingMakeWriter<M> {
    /// Wrap `inner`, redacting at `mode`.
    pub fn new(inner: M, mode: RedactionMode) -> Self {
        Self { inner, mode }
    }
}

impl<'a, M> MakeWriter<'a> for RedactingMakeWriter<M>
where
    M: MakeWriter<'a>,
    M::Writer: Write + 'a,
{
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer(), self.mode)
    }
}

/// A `Write` adapter that redacts complete lines before forwarding.
pub struct RedactingWriter<W: Write> {
    inner: W,
    mode: RedactionMode,
    buf: Vec<u8>,
    /// Byte offset into `buf` at which the next unflushed line begins.
    /// Invariant: `consumed <= buf.len()`. The bytes `buf[..consumed]` have
    /// already been emitted to `inner` and are stale; they are reclaimed
    /// lazily when `consumed > buf.len() / 2` to keep amortized work O(1)
    /// per input byte.
    consumed: usize,
}

impl<W: Write> RedactingWriter<W> {
    /// Wrap `inner`.
    pub fn new(inner: W, mode: RedactionMode) -> Self {
        Self {
            inner,
            mode,
            buf: Vec::new(),
            consumed: 0,
        }
    }

    /// Drop the already-emitted prefix if it now dominates the buffer.
    /// Amortized O(1) per byte: a byte is only shifted left once it has
    /// already paid for itself by sitting in the buffer at least as long as
    /// the live tail.
    fn compact(&mut self) {
        if self.consumed == 0 {
            return;
        }
        // Threshold: reclaim when the stale prefix is at least half the
        // total length, or when the live tail is empty (cheap to clear).
        if self.consumed >= self.buf.len() {
            self.buf.clear();
            self.consumed = 0;
        } else if self.consumed * 2 >= self.buf.len() {
            // Single drain shifts the live tail to the front exactly once.
            self.buf.drain(..self.consumed);
            self.consumed = 0;
        }
    }

    /// Emit every complete (newline-terminated) line currently in the live
    /// region `buf[consumed..]`, redacting on a per-line basis. Leaves any
    /// trailing partial line in place for the next call.
    fn flush_lines(&mut self) -> io::Result<()> {
        loop {
            // Scan only the unflushed tail; convert the local index back to
            // an absolute offset by adding `consumed`.
            let tail = &self.buf[self.consumed..];
            let Some(rel_idx) = tail.iter().position(|&b| b == b'\n') else {
                break;
            };
            let abs_end = self.consumed + rel_idx + 1; // inclusive of '\n'
                                                       // The line including the trailing '\n':
            let line = &self.buf[self.consumed..abs_end];
            // Body without the '\n' for redaction:
            let body = &line[..line.len() - 1];
            match std::str::from_utf8(body) {
                Ok(s) => {
                    // Redact, then re-emit with the trailing newline.
                    // `redact` returns a `Cow<str>`-like value; calling
                    // `as_bytes()` on the result is allocation-free for
                    // the no-match case in upstream callers.
                    let red = redact(s, self.mode);
                    self.inner.write_all(red.as_bytes())?;
                    self.inner.write_all(b"\n")?;
                }
                Err(_) => {
                    // Non-UTF8: pass the whole line (including '\n')
                    // through unchanged, preserving prior semantics.
                    self.inner.write_all(line)?;
                }
            }
            self.consumed = abs_end;
        }
        // Reclaim stale prefix opportunistically; keeps Vec capacity from
        // growing without bound under steady-state line streams.
        self.compact();
        Ok(())
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        self.flush_lines()?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // If there is a partial (unterminated) line still buffered, redact
        // it and emit without appending a newline. This preserves the
        // user-visible behavior that `flush()` after a partial write
        // surfaces what was buffered.
        if self.consumed < self.buf.len() {
            // Take the partial tail, redact it, and clear the buffer.
            // We avoid mutating `self.buf` while borrowing a slice of it
            // by allocating the partial line once.
            let body: Vec<u8> = self.buf[self.consumed..].to_vec();
            self.buf.clear();
            self.consumed = 0;
            match std::str::from_utf8(&body) {
                Ok(s) => {
                    let red = redact(s, self.mode);
                    self.inner.write_all(red.as_bytes())?;
                }
                Err(_) => self.inner.write_all(&body)?,
            }
        } else {
            // Everything has been emitted; just reset the cursor + buffer
            // so subsequent writes start from offset 0.
            self.buf.clear();
            self.consumed = 0;
        }
        self.inner.flush()
    }
}

/// Shared in-memory writer used by tests.
#[derive(Clone, Default)]
pub struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    /// New empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the bytes recorded so far as a String, lossy-decoded.
    #[must_use]
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock()).into_owned()
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_on_complete_line() {
        let buf = SharedBuffer::new();
        let mut w = RedactingWriter::new(buf.clone(), RedactionMode::Standard);
        w.write_all(b"login password=hunter2 ok\n").unwrap();
        let got = buf.contents();
        assert!(!got.contains("hunter2"), "got={got:?}");
        assert!(got.contains("[REDACTED]"));
    }

    #[test]
    fn buffers_partial_until_newline() {
        let buf = SharedBuffer::new();
        let mut w = RedactingWriter::new(buf.clone(), RedactionMode::Standard);
        w.write_all(b"token=").unwrap();
        // Nothing emitted yet.
        assert_eq!(buf.contents(), "");
        w.write_all(b"abcdef\nrest\n").unwrap();
        let got = buf.contents();
        assert!(!got.contains("abcdef"));
        assert!(got.contains("rest"));
    }

    #[test]
    fn flush_emits_partial_line() {
        let buf = SharedBuffer::new();
        let mut w = RedactingWriter::new(buf.clone(), RedactionMode::Standard);
        w.write_all(b"password=secret-tail-no-newline").unwrap();
        w.flush().unwrap();
        let got = buf.contents();
        assert!(!got.contains("secret-tail-no-newline"));
    }

    #[test]
    fn make_writer_wraps_inner() {
        let buf = SharedBuffer::new();
        let mw = RedactingMakeWriter::new(buf.clone(), RedactionMode::Standard);
        let mut w = mw.make_writer();
        w.write_all(b"Bearer abcdefg\n").unwrap();
        let got = buf.contents();
        assert!(!got.contains("abcdefg"));
    }

    #[test]
    fn non_utf8_passes_through() {
        let buf = SharedBuffer::new();
        let mut w = RedactingWriter::new(buf.clone(), RedactionMode::Standard);
        let bytes: &[u8] = &[0xff, 0xfe, b'\n'];
        w.write_all(bytes).unwrap();
        let raw = buf.0.lock().clone();
        assert_eq!(raw.as_slice(), bytes);
    }

    // --- new tests for the cursor-based rewrite -----------------------------

    /// Build a reference output by feeding the entire input to a fresh
    /// `RedactingWriter` in a single `write_all` call, then flushing.
    /// Used as ground truth for the chunked-input stress tests.
    fn reference_output(input: &[u8], mode: RedactionMode) -> Vec<u8> {
        let sink = SharedBuffer::new();
        {
            let mut w = RedactingWriter::new(sink.clone(), mode);
            w.write_all(input).unwrap();
            w.flush().unwrap();
        }
        let out = sink.0.lock().clone();
        out
    }

    /// Drive a `RedactingWriter` by feeding `input` in slices of `chunk`
    /// bytes (last chunk may be short), then flush. Returns the bytes the
    /// inner sink saw.
    fn chunked_output(input: &[u8], chunk: usize, mode: RedactionMode) -> Vec<u8> {
        assert!(chunk > 0);
        let sink = SharedBuffer::new();
        {
            let mut w = RedactingWriter::new(sink.clone(), mode);
            for slice in input.chunks(chunk) {
                w.write_all(slice).unwrap();
            }
            w.flush().unwrap();
        }
        let out = sink.0.lock().clone();
        out
    }

    /// 100 KiB of structured log-like text with periodic newlines and a few
    /// secret-bearing lines sprinkled in. Used to exercise the boundary
    /// handling of `flush_lines` across multiple chunk sizes.
    fn stress_corpus_100kib() -> Vec<u8> {
        let mut out = Vec::with_capacity(110 * 1024);
        let mut i: u32 = 0;
        while out.len() < 100 * 1024 {
            // Vary line length to exercise the cursor at different offsets.
            let len = 16 + (i as usize % 96); // 16..=111
            for _ in 0..len {
                // Printable ASCII; avoid '\n' inside the body.
                let c = 0x20 + ((i.wrapping_mul(2_654_435_761) >> 24) as u8 % 0x5e);
                out.push(c);
                i = i.wrapping_add(1);
            }
            // Inject a secret roughly every 32 lines.
            if i % 32 == 0 {
                out.extend_from_slice(b" password=hunter2");
            }
            out.push(b'\n');
            i = i.wrapping_add(1);
        }
        out
    }

    #[test]
    fn chunked_input_matches_single_write_reference_standard() {
        let corpus = stress_corpus_100kib();
        let want = reference_output(&corpus, RedactionMode::Standard);
        for &chunk in &[1usize, 8, 4096, corpus.len()] {
            let got = chunked_output(&corpus, chunk, RedactionMode::Standard);
            assert_eq!(
                got.len(),
                want.len(),
                "length mismatch at chunk={chunk}: got={} want={}",
                got.len(),
                want.len()
            );
            assert_eq!(got, want, "byte mismatch at chunk={chunk}");
        }
    }

    #[test]
    fn chunked_input_matches_single_write_reference_strict() {
        let corpus = stress_corpus_100kib();
        let want = reference_output(&corpus, RedactionMode::Strict);
        for &chunk in &[1usize, 8, 4096, corpus.len()] {
            let got = chunked_output(&corpus, chunk, RedactionMode::Strict);
            assert_eq!(got, want, "byte mismatch at chunk={chunk} (strict)");
        }
    }

    /// Deterministic pseudo-random corpus: SplitMix64-style state, bytes
    /// drawn from the printable ASCII range plus '\n', with secret
    /// substrings ("Bearer XYZ", "password=...", "token=...") woven in at
    /// pseudo-random offsets. Asserts byte-identical output across a range
    /// of chunk sizes (property: chunking must not change the redacted
    /// output).
    #[test]
    fn pseudo_random_corpus_chunking_is_byte_identical() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let secrets: &[&[u8]] = &[
            b" Bearer abcdef0123456789 ",
            b" password=hunter2-very-long ",
            b" token=xyzabc987 ",
            b" api_key=AKIAEXAMPLEKEY ",
        ];
        let mut corpus = Vec::with_capacity(64 * 1024);
        while corpus.len() < 64 * 1024 {
            let n = (next() % 80) as usize + 8;
            for _ in 0..n {
                let r = (next() % 95) as u8; // 0..95
                let byte = if r == 0 { b'\n' } else { 0x20 + r };
                corpus.push(byte);
            }
            if next() % 4 == 0 {
                let s = secrets[(next() as usize) % secrets.len()];
                corpus.extend_from_slice(s);
            }
            corpus.push(b'\n');
        }
        let want = reference_output(&corpus, RedactionMode::Standard);
        for &chunk in &[1usize, 3, 17, 256, 4096, corpus.len()] {
            let got = chunked_output(&corpus, chunk, RedactionMode::Standard);
            assert_eq!(got, want, "byte mismatch at chunk={chunk}");
        }
        // Sanity: at least one secret must have been redacted (otherwise
        // the test is vacuous on the redaction path).
        assert!(want.windows(10).any(|w| w == b"[REDACTED]"));
    }

    #[test]
    fn many_small_writes_dont_grow_buffer_unbounded() {
        // Regression for the cursor strategy: feeding many short
        // newline-terminated writes must not leave the internal Vec
        // growing without bound. After a write that ends on a newline,
        // either the buffer is empty or its length equals the live tail.
        let sink = SharedBuffer::new();
        let mut w = RedactingWriter::new(sink, RedactionMode::Standard);
        for _ in 0..10_000 {
            w.write_all(b"plain line with no secrets here\n").unwrap();
            // After a fully-terminated write, the live tail (buf[consumed..])
            // must be empty.
            assert_eq!(
                w.buf.len(),
                w.consumed,
                "live tail must be empty after newline-terminated write"
            );
            // And the compaction invariant must hold: the stale prefix is
            // strictly less than half the buffer length, or the buffer
            // has been cleared.
            assert!(
                w.consumed == 0 || w.consumed * 2 < w.buf.len() + 1,
                "compaction invariant: consumed={}, buf.len()={}",
                w.consumed,
                w.buf.len()
            );
        }
        w.flush().unwrap();
        // After flush, both must be zero.
        assert_eq!(w.buf.len(), 0);
        assert_eq!(w.consumed, 0);
    }

    #[test]
    fn partial_line_then_more_then_flush_matches_reference() {
        // Three-step write that crosses chunk boundaries inside a line and
        // around a newline. Reference impl is "single write_all".
        let input: &[u8] = b"alpha password=s1\nbeta token=s2\nrest no newline";
        let want = reference_output(input, RedactionMode::Standard);
        let sink = SharedBuffer::new();
        {
            let mut w = RedactingWriter::new(sink.clone(), RedactionMode::Standard);
            w.write_all(&input[..5]).unwrap(); // "alpha"
            w.write_all(&input[5..20]).unwrap(); // " password=s1\nbe"
            w.write_all(&input[20..]).unwrap(); // rest
            w.flush().unwrap();
        }
        let got = sink.0.lock().clone();
        assert_eq!(got, want);
    }
}
