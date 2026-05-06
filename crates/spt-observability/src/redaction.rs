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
}

impl<W: Write> RedactingWriter<W> {
    /// Wrap `inner`.
    pub fn new(inner: W, mode: RedactionMode) -> Self {
        Self {
            inner,
            mode,
            buf: Vec::new(),
        }
    }

    fn flush_lines(&mut self) -> io::Result<()> {
        // Repeatedly extract `<…>\n` from the front of `buf` and write the
        // redacted line.
        loop {
            let Some(idx) = self.buf.iter().position(|&b| b == b'\n') else {
                break;
            };
            // Drain the line including the newline so the slice is owned.
            let line: Vec<u8> = self.buf.drain(..=idx).collect();
            // Strip the trailing '\n' for redaction; reattach after.
            let (body, _nl) = line.split_at(line.len() - 1);
            match std::str::from_utf8(body) {
                Ok(s) => {
                    let red = redact(s, self.mode);
                    self.inner.write_all(red.as_bytes())?;
                    self.inner.write_all(b"\n")?;
                }
                Err(_) => {
                    // Non-UTF8: pass through unchanged.
                    self.inner.write_all(&line)?;
                }
            }
        }
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
        // If there is a partial line still buffered, redact-then-flush it
        // without an appended newline. This preserves user intent.
        if !self.buf.is_empty() {
            let body = std::mem::take(&mut self.buf);
            match std::str::from_utf8(&body) {
                Ok(s) => {
                    let red = redact(s, self.mode);
                    self.inner.write_all(red.as_bytes())?;
                }
                Err(_) => self.inner.write_all(&body)?,
            }
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
}
