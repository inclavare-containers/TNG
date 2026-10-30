use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a stream and tags IO errors with a source identifier, so error logs
/// can distinguish which component the stream came from. The inner
/// `io::ErrorKind` must survive the re-wrap: `forward.rs` classifies write
/// errors by kind (`is_benign_write_kind`), and collapsing every kind into
/// `Other` would turn benign peer-close errors fatal.
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
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(|e| io::Error::new(e.kind(), anyhow::Error::from(e).context(self.source)))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ContextualStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner)
            .poll_write(cx, buf)
            .map_err(|e| io::Error::new(e.kind(), anyhow::Error::from(e).context(self.source)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(e.kind(), anyhow::Error::from(e).context(self.source)))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(|e| io::Error::new(e.kind(), anyhow::Error::from(e).context(self.source)))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner)
            .poll_write_vectored(cx, bufs)
            .map_err(|e| io::Error::new(e.kind(), anyhow::Error::from(e).context(self.source)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Stream whose writes always fail with a benign BrokenPipe, mimicking a
    /// peer that closed its read half.
    struct BrokenPipeStream;

    impl AsyncRead for BrokenPipeStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for BrokenPipeStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// The wrap must preserve the inner `io::ErrorKind`. forward.rs classifies
    /// write errors by kind (is_benign_write_kind); laundering every error
    /// into ErrorKind::Other turns benign egress write errors fatal and makes
    /// the W2 drain rule dead code on the egress path.
    #[tokio::test]
    async fn test_contextual_stream_preserves_write_error_kind() {
        let mut stream = ContextualStream::new(BrokenPipeStream, "test-label");
        let error = stream
            .write(b"payload")
            .await
            .expect_err("inner stream write is set to fail with BrokenPipe");
        assert_eq!(
            error.kind(),
            io::ErrorKind::BrokenPipe,
            "ContextualStream must keep the inner ErrorKind, got {:?}",
            error.kind()
        );
        // The wrap exists to tag error logs; fixing the kind must not drop that.
        assert!(
            error.to_string().contains("test-label"),
            "ContextualStream must keep the source label in Display, got {:?}",
            error.to_string()
        );
    }
}
