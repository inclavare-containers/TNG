use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a TLS server stream so that 0-RTT early data accepted by rustls is
/// delivered to the upstream reader. tokio-rustls's server `TlsStream`
/// `AsyncRead` does not surface accepted early data; the handshake path drains
/// that buffer into `prefix` and hands it here, after which reads delegate to
/// `inner`.
pub struct EarlyDataPrefixStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S> EarlyDataPrefixStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }

    /// Borrow the wrapped stream, e.g. to reach its ALPN session.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EarlyDataPrefixStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EarlyDataPrefixStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // Prefix bytes must come out before any inner-stream bytes.
    #[tokio::test]
    async fn prefix_then_inner() {
        let (mut a, b) = tokio::io::duplex(64);
        // b is moved into the wrapper; writing to a makes the bytes readable from b.
        a.write_all(b"INNER").await.unwrap();
        let mut s = EarlyDataPrefixStream::new(vec![1, 2, 3], b);
        let mut out = vec![0u8; 8];
        let n = s.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], &[1, 2, 3]);
        // next read should yield the inner bytes
        let n = s.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"INNER");
        let _ = a; // keep a alive
    }

    // Prefix spanning multiple small reads, then inner, no byte lost or duped.
    #[tokio::test]
    async fn prefix_across_small_reads() {
        let (_a, b) = tokio::io::duplex(64);
        let mut s = EarlyDataPrefixStream::new(vec![10, 20, 30, 40], b);
        let mut got = Vec::new();
        let mut one = [0u8; 1];
        for _ in 0..4 {
            let n = s.read(&mut one).await.unwrap();
            assert_eq!(n, 1);
            got.push(one[0]);
        }
        assert_eq!(got, vec![10, 20, 30, 40]);
    }

    // Empty prefix: reads go straight to inner.
    #[tokio::test]
    async fn empty_prefix_delegates() {
        let (mut a, b) = tokio::io::duplex(64);
        let mut s = EarlyDataPrefixStream::new(Vec::new(), b);
        a.write_all(b"X").await.unwrap();
        let mut buf = [0u8; 1];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, *b"X");
    }

    // Writes delegate to inner.
    #[tokio::test]
    async fn write_delegates_to_inner() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut s = EarlyDataPrefixStream::new(Vec::new(), a);
        s.write_all(b"W").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 1];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, *b"W");
    }
}
