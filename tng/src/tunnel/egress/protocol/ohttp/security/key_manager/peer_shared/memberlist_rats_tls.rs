use std::{io, marker::PhantomData, net::SocketAddr, sync::Arc};

use anyhow::Context;
use async_stream::stream;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt as _};
use peekable::future::AsyncPeekable;
use serf::{
    agnostic::{
        net::{Net, TcpListener as _, TcpStream as _},
        Runtime,
    },
    net::stream_layer::{Listener, PromisedStream, StreamLayer},
};
use tokio_util::compat::TokioAsyncReadCompatExt as _;
use tokio_util::compat::TokioAsyncWriteCompatExt as _;

use crate::{
    config::ra::RaArgs,
    tunnel::{
        egress::{
            protocol::rats_tls::RatsTlsStreamDecoder,
            stream_manager::trusted::ProtocolStreamDecoder as _,
        },
        endpoint::TngEndpoint,
        ingress::protocol::rats_tls::RatsTlsStreamForwarder,
    },
    CommonStreamTrait, TokioRuntime,
};

/// Rats-TLS stream layer.
pub struct RatsTls<R> {
    forwarder: Arc<RatsTlsStreamForwarder>,
    decoder: Arc<RatsTlsStreamDecoder>,
    phantom: PhantomData<R>,
}

impl<R: Runtime> StreamLayer for RatsTls<R> {
    type Runtime = R;
    type Listener = RatsTlsListener<R>;
    type Stream = RatsTlsStream<R>;
    type Options = (RaArgs, TokioRuntime);

    #[inline]
    async fn new((ra_args, runtime): Self::Options) -> io::Result<Self> {
        Ok(Self {
            forwarder: Arc::new(
                RatsTlsStreamForwarder::new(
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    None,
                    ra_args.clone(),
                    runtime.clone(),
                )
                .await
                .context("Failed to create rats-tls stream forwarder")
                .map_err(io::Error::other)?,
            ),
            decoder: Arc::new(
                RatsTlsStreamDecoder::new(ra_args, runtime)
                    .await
                    .context("Failed to create rats-tls stream decoder")
                    .map_err(io::Error::other)?,
            ),
            phantom: Default::default(),
        })
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<Self::Stream> {
        let (stream, local_addr, _attestation_result) = self
            .forwarder
            .connect(TngEndpoint::new(addr.ip().to_string(), addr.port()))
            .await
            .with_context(|| format!("Failed to connect to {addr:?}"))
            .map_err(io::Error::other)?;

        let stream = Box::new(stream) as Box<dyn CommonStreamTrait + Sync>;
        let (reader, writer) = tokio::io::split(stream);

        Ok(RatsTlsStream {
            local_addr,
            peer_addr: addr,
            reader: AsyncPeekable::new(reader.compat()),
            writer: writer.compat_write(),
            phantom: Default::default(),
        })
    }

    async fn bind(&self, addr: SocketAddr) -> io::Result<Self::Listener> {
        <<R::Net as Net>::TcpListener as serf::agnostic::net::TcpListener>::bind(addr)
            .await
            .and_then(|ln| {
                ln.local_addr().map(|local_addr| {
                    RatsTlsListener::new(ln, local_addr, Arc::clone(&self.decoder))
                })
            })
    }

    fn is_secure() -> bool {
        false
    }
}

/// [`Listener`] of the TCP stream layer
pub struct RatsTlsListener<R: Runtime> {
    local_addr: SocketAddr,
    #[allow(clippy::type_complexity)]
    incoming: tokio::sync::Mutex<
        std::pin::Pin<
            Box<
                dyn futures::Stream<Item = io::Result<(<Self as Listener>::Stream, SocketAddr)>>
                    + Send,
            >,
        >,
    >,
}
// impl Stream<Item = Result<<... as TcpListener>::Stream, ...>> + Send
impl<R: Runtime> RatsTlsListener<R> {
    fn new(
        ln: <R::Net as Net>::TcpListener,
        local_addr: SocketAddr,
        decoder: Arc<RatsTlsStreamDecoder>,
    ) -> Self {
        let incoming = ln.into_incoming().flat_map_unordered(None, move |next| {
            let decoder = decoder.clone();
            Box::pin(stream! {
                match next {
                    Ok(conn) => {
                        let peer_addr = match conn.peer_addr() {
                            Ok(peer_addr) => peer_addr,
                            Err(err) => {yield Err(err); return;},
                        };

                        let pending = decoder
                            .decode_stream(Box::new(conn))
                            .await
                            .context("Failed to decode rats-tls serf stream")
                            .map_err(io::Error::other);

                        match pending {
                            Ok(mut pending) => {
                                while let Some(result) = pending.next().await {
                                    yield result.map(|(stream, _att)| {
                                        let (reader, writer) = tokio::io::split(stream);
                                        (
                                            RatsTlsStream::<R> {
                                                writer: writer.compat_write(),
                                                reader: AsyncPeekable::new(reader.compat()),
                                                local_addr,
                                                peer_addr,
                                                phantom: Default::default(),
                                            },
                                            peer_addr,
                                        )
                                    }).map_err(|err| {
                                        io::Error::other(
                                            format!("Failed to get next rats-tls serf stream: {err:?}"),
                                        )
                                    });
                                }
                            },
                            Err(err) => {
                                yield Err(err)
                            }
                        }
                    },
                    Err(err) => {
                        yield Err(err)
                    }
                }
            })
        });

        Self {
            local_addr,
            incoming: tokio::sync::Mutex::new(Box::pin(incoming)),
        }
    }
}

impl<R: Runtime> Listener for RatsTlsListener<R> {
    type Stream = RatsTlsStream<R>;

    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        self.incoming
            .lock()
            .await
            .next()
            .await
            .context("Failed to get next rats-tls serf stream")
            .map_err(io::Error::other)?
    }

    async fn shutdown(&self) -> io::Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// [`PromisedStream`] of the TCP stream layer
#[pin_project::pin_project]
pub struct RatsTlsStream<R: Runtime> {
    #[pin]
    writer: tokio_util::compat::Compat<tokio::io::WriteHalf<Box<dyn CommonStreamTrait + Sync>>>,
    #[pin]
    reader: AsyncPeekable<
        tokio_util::compat::Compat<tokio::io::ReadHalf<Box<dyn CommonStreamTrait + Sync>>>,
    >,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    phantom: PhantomData<R>,
}

impl<R: Runtime> serf::net::Connection for RatsTlsStream<R> {
    type Reader = AsyncPeekable<
        tokio_util::compat::Compat<tokio::io::ReadHalf<Box<dyn CommonStreamTrait + Sync>>>,
    >;

    type Writer =
        tokio_util::compat::Compat<tokio::io::WriteHalf<Box<dyn CommonStreamTrait + Sync>>>;

    #[inline]
    fn split(self) -> (Self::Reader, Self::Writer) {
        (self.reader, self.writer)
    }

    async fn close(&mut self) -> std::io::Result<()> {
        AsyncWriteExt::close(&mut self.writer).await
    }

    async fn write_all(&mut self, payload: &[u8]) -> std::io::Result<()> {
        AsyncWriteExt::write_all(&mut self.writer, payload).await
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        AsyncWriteExt::flush(&mut self.writer).await
    }

    async fn peek(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.peek(buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        AsyncReadExt::read_exact(&mut self.reader, buf).await
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        AsyncReadExt::read(&mut self.reader, buf).await
    }

    async fn peek_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.reader.peek_exact(buf).await
    }

    fn consume_peek(&mut self) {
        self.reader.consume();
    }
}

impl<R: Runtime> PromisedStream for RatsTlsStream<R> {
    type Instant = R::Instant;

    #[inline]
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[inline]
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}
