use std::task::Poll;

use bytes::Bytes;
use futures::{FutureExt, StreamExt as _};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::Span;

pub struct H2Stream {
    send_stream: SendStream<bytes::Bytes>,
    recv_stream: RecvStream,
    recv_remain: Option<Bytes>,
    span: Span,
}

impl H2Stream {
    pub fn new(send_stream: SendStream<Bytes>, recv_stream: RecvStream, span: Span) -> Self {
        Self {
            send_stream,
            recv_stream,
            recv_remain: None,
            span,
        }
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        self.send_stream.send_reset(h2::Reason::CANCEL);
        tracing::trace!("H2Stream drop now");
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let span = self.span.clone();
        let _guard = span.enter();

        let len = buf.len();
        tracing::trace!("send {len} bytes to h2 stream");
        match self
            .get_mut()
            .send_stream
            .send_data(Bytes::copy_from_slice(buf), false)
        {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("H2Stream send error: {e:#}"),
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        return Poll::Ready(Ok(()));
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let span = self.span.clone();
        let _guard = span.enter();

        match self.get_mut().send_stream.send_data(Bytes::new(), true) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("H2Stream shutdown error: {e:#}"),
            ))),
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let span = self.span.clone();
        let _guard = span.enter();

        let this = self.get_mut();

        // Use remain bytes first.
        if let Some(ref mut bs) = this.recv_remain {
            if buf.remaining() < bs.len() {
                let to_consume = bs.split_to(buf.remaining());
                buf.put_slice(&to_consume);
                this.recv_remain = Some(bs.clone());
            } else {
                buf.put_slice(&bs);
                this.recv_remain = None;
            }
            return Poll::Ready(Ok(()));
        }

        // Check if the stream is end.
        if this.recv_stream.is_end_stream() {
            return Poll::Ready(Ok(()));
        }

        // Poll next bytes from h2 stream.
        match this.recv_stream.next().poll_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(res) => match res {
                Some(bs) => match bs {
                    Ok(mut bs) => {
                        tracing::trace!("receive {} bytes from h2 stream", bs.len());
                        if buf.remaining() < bs.len() {
                            let to_consume = bs.split_to(buf.remaining());
                            buf.put_slice(&to_consume);
                            this.recv_remain = Some(bs);
                        } else {
                            buf.put_slice(&bs);
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("H2Stream receive error: {e:#}"),
                    ))),
                },
                None => Poll::Ready(Ok(())),
            },
        }
    }
}
