use std::task::Poll;

use bytes::Bytes;
use futures::{FutureExt, StreamExt as _};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct H2Stream {
    send_stream: SendStream<bytes::Bytes>,
    recv_stream: RecvStream,
    recv_remain: Option<Bytes>,
}

impl H2Stream {
    pub fn new(send_stream: SendStream<Bytes>, recv_stream: RecvStream) -> Self {
        Self {
            send_stream,
            recv_stream,
            recv_remain: None,
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let len = buf.len();
        tracing::trace!("send {len} bytes to h2 stream");
        match self
            .get_mut()
            .send_stream
            .send_data(Bytes::copy_from_slice(buf), false)
        {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(e) => Poll::Ready(Err(if e.is_io() {
                e.into_io().unwrap()
            } else {
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            })),
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
        match self.get_mut().send_stream.send_data(Bytes::new(), true) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(if e.is_io() {
                e.into_io().unwrap()
            } else {
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            })),
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
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
                    Err(e) => Poll::Ready(Err(if e.is_io() {
                        e.into_io().unwrap()
                    } else {
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    })),
                },
                None => Poll::Ready(Ok(())),
            },
        }
    }
}
