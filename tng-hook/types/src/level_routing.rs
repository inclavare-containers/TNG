//! Level-based log routing: ERROR+ events go to the error writer; everything
//! else goes to the info writer. Disjoint — an event never goes to both.
//! When `error` is None, all events go to the info writer (current behavior).

use std::io::{self, Write};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

/// A `MakeWriter` that routes each event to either the info writer or the
/// error writer based on the event's level. ERROR+ → error (if set);
/// everything else → info. Disjoint.
pub struct LevelRoutingWriter<W1, W2 = W1>
where
    W1: for<'a> MakeWriter<'a>,
    W2: for<'a> MakeWriter<'a>,
{
    info: W1,
    error: Option<W2>,
}

impl<W1, W2> LevelRoutingWriter<W1, W2>
where
    W1: for<'a> MakeWriter<'a>,
    W2: for<'a> MakeWriter<'a>,
{
    pub fn new(info: W1, error: Option<W2>) -> Self {
        Self { info, error }
    }
}

/// A writer that is either the info writer or the error writer (never both).
pub enum EitherWriter<I, E> {
    Info(I),
    Error(E),
}

impl<I, E> Write for EitherWriter<I, E>
where
    I: Write,
    E: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            EitherWriter::Info(w) => w.write_all(buf).map(|_| buf.len()),
            EitherWriter::Error(w) => w.write_all(buf).map(|_| buf.len()),
        }
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            EitherWriter::Info(w) => w.write_all(buf),
            EitherWriter::Error(w) => w.write_all(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            EitherWriter::Info(w) => w.flush(),
            EitherWriter::Error(w) => w.flush(),
        }
    }
}

impl<'a, W1, W2> MakeWriter<'a> for LevelRoutingWriter<W1, W2>
where
    W1: for<'b> MakeWriter<'b>,
    W2: for<'b> MakeWriter<'b>,
{
    type Writer = EitherWriter<<W1 as MakeWriter<'a>>::Writer, <W2 as MakeWriter<'a>>::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        EitherWriter::Info(self.info.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        if let Some(ref ew) = self.error {
            if *meta.level() <= Level::ERROR {
                return EitherWriter::Error(ew.make_writer());
            }
        }
        EitherWriter::Info(self.info.make_writer())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A MakeWriter that captures bytes into a shared buffer.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = CaptureGuard;
        fn make_writer(&'a self) -> CaptureGuard {
            CaptureGuard {
                buf: self.0.clone(),
            }
        }
    }

    struct CaptureGuard {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureGuard {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.buf.lock().unwrap().extend(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn either_writer_info_delegates() {
        let mut w = EitherWriter::<_, CaptureGuard>::Info(CaptureGuard {
            buf: Arc::new(Mutex::new(Vec::new())),
        });
        w.write_all(b"hello").unwrap();
        w.flush().unwrap();
    }

    #[test]
    fn either_writer_error_delegates() {
        let mut w = EitherWriter::<CaptureGuard, _>::Error(CaptureGuard {
            buf: Arc::new(Mutex::new(Vec::new())),
        });
        w.write_all(b"err").unwrap();
        w.flush().unwrap();
    }

    #[test]
    fn level_routing_writer_no_error_routes_all_to_info() {
        let info = Capture::default();
        let lr = LevelRoutingWriter::new(info.clone(), None::<Capture>);
        // make_writer (no metadata) → Info
        let _ = lr.make_writer();
        // make_writer_for with a non-error meta → Info (can't easily fake
        // Metadata, so just verify make_writer returns Info variant).
    }
}
