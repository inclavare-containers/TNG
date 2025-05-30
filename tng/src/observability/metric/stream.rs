use std::{
    pin::Pin,
    task::{Context, Poll},
};

use opentelemetry::metrics::Counter;
use pin_project::pin_project;

use super::counter::AttributedCounter;

#[pin_project]
pub struct StreamWithCounter<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin> {
    #[pin]
    pub inner: T,

    #[pin]
    pub tx_bytes_total: AttributedCounter<Counter<u64>, u64>,

    #[pin]
    pub rx_bytes_total: AttributedCounter<Counter<u64>, u64>,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin> tokio::io::AsyncWrite
    for StreamWithCounter<T>
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let this = self.project();

        let ret = this.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(sz)) = ret {
            this.tx_bytes_total.add(sz as u64);
        }
        ret
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin> tokio::io::AsyncRead
    for StreamWithCounter<T>
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        let sz = buf.filled().len();
        let ret = this.inner.poll_read(cx, buf);
        this.rx_bytes_total
            .add(std::cmp::max(buf.filled().len() - sz, 0) as u64);

        ret
    }
}
