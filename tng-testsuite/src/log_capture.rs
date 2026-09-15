//! A `MakeWriter` that buffers every formatted tracing line into a shared `Vec<String>`,
//! so an integration test can assert that a specific event was emitted by the in-process
//! TNG runtime (see `tng_testsuite::capture_logs`).
//!
//! `tracing_subscriber::fmt::Layer` calls `make_writer` once per event, writes the formatted
//! event bytes, then drops the writer without necessarily flushing it. So each `CaptureWriter`
//! accumulates one event's bytes and pushes the completed line on drop (flush is also
//! implemented in case a caller flushes explicitly).

use std::io::Write;
use std::sync::{Arc, Mutex};

/// Shared buffer of captured, formatted log lines.
pub type LogBuffer = Arc<Mutex<Vec<String>>>;

/// Builds per-event [`CaptureWriter`]s that all drain into the same [`LogBuffer`].
pub(crate) struct CaptureMakeWriter {
    pub buf: LogBuffer,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureMakeWriter {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter {
            pending: Vec::new(),
            buf: self.buf.clone(),
        }
    }
}

/// Writes the bytes of one formatted event into an internal buffer and, on flush or drop,
/// pushes the accumulated line into the shared buffer.
pub struct CaptureWriter {
    pending: Vec<u8>,
    buf: LogBuffer,
}

impl CaptureWriter {
    /// Drain the pending bytes into the shared buffer as one line.
    fn drain(&mut self) {
        let line = String::from_utf8_lossy(&self.pending)
            .trim_end()
            .to_string();
        if !line.is_empty() {
            self.buf.lock().expect("capture buffer poisoned").push(line);
        }
        self.pending.clear();
    }
}

impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drain();
        Ok(())
    }
}

impl Drop for CaptureWriter {
    fn drop(&mut self) {
        // The fmt layer drops the writer after each event without flushing; drain here so the
        // event's line is not lost.
        let _ = std::io::Write::flush(self);
    }
}
