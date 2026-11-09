use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Re-box an IO error with the stream's source tag, keeping the original
/// `ErrorKind`. `io::Error::other` would flatten every kind to `Other`, which
/// blinds downstream classification: the forward loop's benign-write set
/// (BrokenPipe, ConnectionReset, ...) would then never match a wrapped error.
fn contextualize(error: io::Error, source: &'static str) -> io::Error {
    let kind = error.kind();
    io::Error::new(kind, anyhow::Error::from(error).context(source))
}

/// Wraps a stream and tags IO errors with a source identifier, so error logs
/// can distinguish which component the stream came from.
pub struct ContextualStream<S> {
    inner: S,
    source: &'static str,
}

impl<S> ContextualStream<S> {
    pub fn new(inner: S, source: &'static str) -> Self {
        Self { inner, source }
    }

    /// Get a reference to the inner type, e.g. to call `TcpStream::local_addr()`.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner type.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ContextualStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let source = self.source;
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(|e| contextualize(e, source))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ContextualStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let source = self.source;
        Pin::new(&mut self.inner)
            .poll_write(cx, buf)
            .map_err(|e| contextualize(e, source))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let source = self.source;
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|e| contextualize(e, source))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let source = self.source;
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(|e| contextualize(e, source))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let source = self.source;
        Pin::new(&mut self.inner)
            .poll_write_vectored(cx, bufs)
            .map_err(|e| contextualize(e, source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;

    /// An `AsyncWrite` whose every write fails with a fixed kind.
    struct FailingWriter {
        kind: io::ErrorKind,
    }

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(self.kind)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// `ContextualStream` must tag errors without destroying their kind: the
    /// forward loop's benign-write classification depends on seeing BrokenPipe
    /// through the wrapper.
    #[test]
    fn wrapped_write_error_keeps_kind_and_source() {
        let mut stream = ContextualStream::new(
            FailingWriter {
                kind: io::ErrorKind::BrokenPipe,
            },
            "ingress-mapping",
        );

        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker as &Waker);
        let error = match Pin::new(&mut stream).poll_write(&mut cx, b"x") {
            Poll::Ready(Err(error)) => error,
            other => panic!("expected a write error, got {other:?}"),
        };

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        let debug = format!("{error:?}");
        assert!(
            debug.contains("ingress-mapping"),
            "source tag lost from the wrapped error: {debug}"
        );
    }
}
