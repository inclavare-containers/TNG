use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait CommonStreamTrait: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> CommonStreamTrait for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

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
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(|e| io::Error::other(anyhow::anyhow!("[{}] {}", self.source, e)))
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
            .map_err(|e| io::Error::other(anyhow::anyhow!("[{}] {}", self.source, e)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(anyhow::anyhow!("[{}] {}", self.source, e)))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(|e| io::Error::other(anyhow::anyhow!("[{}] {}", self.source, e)))
    }
}
