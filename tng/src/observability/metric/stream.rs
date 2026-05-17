use std::{
    pin::Pin,
    task::{Context, Poll},
};

use opentelemetry::metrics::Counter;
use pin_project::pin_project;

use super::counter::AttributedCounter;

const COUNTER_FLUSH_THRESHOLD: u64 = 1024 * 1024; // 1 MB

/// Accumulates bytes and flushes to the counter on drop or threshold breach.
pub(crate) struct PendingCounter {
    pending: u64,
    counter: AttributedCounter<Counter<u64>, u64>,
}

impl PendingCounter {
    pub(crate) fn new(counter: AttributedCounter<Counter<u64>, u64>) -> Self {
        Self {
            pending: 0,
            counter,
        }
    }

    fn add(&mut self, bytes: u64) {
        self.pending += bytes;
        if self.pending >= COUNTER_FLUSH_THRESHOLD {
            self.counter.add(self.pending);
            self.pending = 0;
        }
    }
}

impl Drop for PendingCounter {
    fn drop(&mut self) {
        if self.pending > 0 {
            self.counter.add(self.pending);
        }
    }
}

#[pin_project]
pub struct StreamWithCounter<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin> {
    #[pin]
    pub inner: T,

    pub(crate) tx: PendingCounter,

    pub(crate) rx: PendingCounter,
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
            this.tx.add(sz as u64);
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
        let delta = std::cmp::max(buf.filled().len() - sz, 0) as u64;
        this.rx.add(delta);

        ret
    }
}
