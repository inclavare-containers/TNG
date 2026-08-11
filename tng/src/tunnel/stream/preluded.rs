use bytes::Bytes;

/// A duplex wrapper that serves buffered head data (`prelude`) first,
/// then falls through to `stream` for the remaining data.
///
/// Unlike a `tokio::io::Join<Chain<Cursor<Bytes>, ReadHalf<T>>, WriteHalf<T>>`
/// combinator stack, this owns a single `T` and dispatches both `AsyncRead`
/// and `AsyncWrite` to it directly — no `tokio::io::split`/`BiLock` lock
/// contention between the read and write halves, and no `Join`/`Chain`
/// indirection. The prelude is drained via a simple position counter, which
/// also lets kTLS detect "prelude exhausted" without reaching into combinator
/// internals.
pub struct PreludedStream<T> {
    /// The initial bytes that were already read from the stream before this
    /// wrapper was constructed. Served first by `AsyncRead`; once exhausted,
    /// reads fall through to `stream`.
    pub(crate) prelude: Bytes,

    /// Number of bytes already consumed from `prelude`.
    pub(crate) prelude_pos: usize,

    /// The remaining part of the original stream.
    pub(crate) stream: T,
}

impl<T> PreludedStream<T> {
    /// Returns `true` once every byte of `prelude` has been consumed by reads,
    /// so the next read will be served directly from `stream`.
    #[cfg_attr(not(target_os = "linux"), allow(unused))]
    pub(crate) fn prelude_consumed(&self) -> bool {
        self.prelude_pos >= self.prelude.len()
    }
}

impl<T: tokio::io::AsyncRead + std::marker::Unpin> tokio::io::AsyncRead for PreludedStream<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // While there is buffered prelude data, it MUST be drained before the
        // underlying stream is ever touched — the prelude holds the bytes that
        // were consumed ahead of time from the stream, and surfacing them is
        // this wrapper's responsibility alone. This branch therefore never
        // falls through to `stream`, even if `buf` has no room: returning
        // `Ready(Ok)` with 0 bytes filled when `buf.remaining() == 0` is the
        // documented zero-capacity no-progress case, not the EOF signal (EOF
        // is 0 bytes filled with `buf.remaining() > 0`).
        if this.prelude_pos < this.prelude.len() {
            let remaining = &this.prelude[this.prelude_pos..];
            let n = remaining.len().min(buf.remaining());
            if n > 0 {
                buf.put_slice(&remaining[..n]);
                this.prelude_pos += n;
            }
            return std::task::Poll::Ready(Ok(()));
        }

        // Prelude exhausted: delegate to the underlying stream. If it is not
        // ready, `Pending` (with the waker registered by `stream`'s
        // `poll_read`) propagates correctly — no EOF false-positive at the
        // prelude→stream transition.
        std::pin::Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + std::marker::Unpin> tokio::io::AsyncWrite for PreludedStream<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(&self.stream)
    }
}
