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

    /// An IO half whose every operation fails with a fixed kind.
    struct FailingIo {
        kind: io::ErrorKind,
    }

    impl FailingIo {
        fn new() -> Self {
            Self {
                kind: io::ErrorKind::BrokenPipe,
            }
        }
    }

    impl AsyncRead for FailingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(self.kind)))
        }
    }

    impl AsyncWrite for FailingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(self.kind)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(self.kind)))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(self.kind)))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(self.kind)))
        }
    }

    fn assert_wrapped(error: io::Error) {
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        let debug = format!("{error:?}");
        assert!(
            debug.contains("ingress-mapping"),
            "source tag lost from the wrapped error: {debug}"
        );
    }

    /// `ContextualStream` must tag errors without destroying their kind on
    /// every IO path: the forward loop's benign-write classification depends on
    /// seeing BrokenPipe through the wrapper.
    #[test]
    fn wrapped_read_error_keeps_kind_and_source() {
        let mut stream = ContextualStream::new(FailingIo::new(), "ingress-mapping");
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker as &Waker);
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        match Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf) {
            Poll::Ready(Err(error)) => assert_wrapped(error),
            _ => panic!("expected a wrapped IO error"),
        }
    }

    #[test]
    fn wrapped_write_error_keeps_kind_and_source() {
        let mut stream = ContextualStream::new(FailingIo::new(), "ingress-mapping");
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker as &Waker);
        match Pin::new(&mut stream).poll_write(&mut cx, b"x") {
            Poll::Ready(Err(error)) => assert_wrapped(error),
            _ => panic!("expected a wrapped IO error"),
        }
    }

    #[test]
    fn wrapped_flush_error_keeps_kind_and_source() {
        let mut stream = ContextualStream::new(FailingIo::new(), "ingress-mapping");
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker as &Waker);
        match Pin::new(&mut stream).poll_flush(&mut cx) {
            Poll::Ready(Err(error)) => assert_wrapped(error),
            _ => panic!("expected a wrapped IO error"),
        }
    }

    #[test]
    fn wrapped_shutdown_error_keeps_kind_and_source() {
        let mut stream = ContextualStream::new(FailingIo::new(), "ingress-mapping");
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker as &Waker);
        match Pin::new(&mut stream).poll_shutdown(&mut cx) {
            Poll::Ready(Err(error)) => assert_wrapped(error),
            _ => panic!("expected a wrapped IO error"),
        }
    }

    #[test]
    fn wrapped_vectored_write_error_keeps_kind_and_source() {
        let mut stream = ContextualStream::new(FailingIo::new(), "ingress-mapping");
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker as &Waker);
        let pieces = [b"x".as_slice()];
        let slices = [io::IoSlice::new(pieces[0])];
        match Pin::new(&mut stream).poll_write_vectored(&mut cx, &slices) {
            Poll::Ready(Err(error)) => assert_wrapped(error),
            _ => panic!("expected a wrapped IO error"),
        }
    }
}
