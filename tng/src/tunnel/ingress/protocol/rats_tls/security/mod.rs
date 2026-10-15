pub mod pool;

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    num::NonZeroU32,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    task::Poll,
};

use anyhow::{Context as _, Result};
use http::Uri;
use hyper_util::client::legacy::Client;
use pin_project::pin_project;
use pool::{ClientPool, HyperClientType, PoolKey};
use tokio::sync::RwLock;
use tracing::{Instrument, Span};

use crate::{
    tunnel::{
        attestation_result::AttestationState,
        endpoint::{EndpointAddr, TngEndpoint},
        ingress::protocol::rats_tls::wrapping::RatsTlsWrappingLayer,
        ra_context::RaContext,
        utils::{
            runtime::TokioRuntime,
            rustls::config::{alpn::Alpn, TlsConfigGenerator},
            tokio::TokioIo,
        },
    },
    CommonStreamTrait,
};

use super::transport::{RatsTlsTransportLayerConnector, RatsTlsTransportLayerCreator};

#[derive(Clone)]
pub struct RatsTlsClient {
    pub id: u64,
    pub hyper: HyperClientType,
    /// CONNECT streams currently riding this h2 tunnel. Incremented when a
    /// stream is assigned to the shard, decremented when its upgraded stream
    /// is dropped (see `ShardGuardedStream`).
    active: Arc<AtomicU32>,
}

impl RatsTlsClient {
    fn active_streams(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }
}

/// Counts a mux stream against its shard tunnel for as long as the upgraded
/// io is alive. Drop-based so cancelled or failed forwards always release the
/// slot, keeping the shard cap a soft bound instead of leaking quota.
struct ShardGuardedStream {
    inner: Box<dyn CommonStreamTrait + Sync>,
    active: Arc<AtomicU32>,
}

impl Drop for ShardGuardedStream {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl tokio::io::AsyncRead for ShardGuardedStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ShardGuardedStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

pub struct RatsTlsSecurityLayer {
    next_id: AtomicU64,
    pool: RwLock<ClientPool>,
    transport_layer_creator: RatsTlsTransportLayerCreator,
    tls_config_generator: Arc<TlsConfigGenerator>,
    runtime: TokioRuntime,
    multiplex: bool,
    multiplex_max_streams_per_connection: Option<NonZeroU32>,
    multiplex_max_connections: usize,
}

impl RatsTlsSecurityLayer {
    pub fn is_multiplex(&self) -> bool {
        self.multiplex
    }

    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        multiplex: bool,
        multiplex_max_streams_per_connection: Option<NonZeroU32>,
        multiplex_max_connections: Option<NonZeroU32>,
    ) -> Result<Self> {
        let transport_layer_creator = RatsTlsTransportLayerCreator::new(
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            transport_so_mark,
        );
        let tls_config_generator =
            Arc::new(TlsConfigGenerator::new(ra_context, runtime.clone()).await?);

        Ok(Self {
            next_id: AtomicU64::new(0),
            pool: RwLock::new(HashMap::new()),
            transport_layer_creator,
            tls_config_generator,
            runtime,
            multiplex,
            multiplex_max_streams_per_connection,
            multiplex_max_connections: multiplex_max_connections
                .map(|v| v.get() as usize)
                .unwrap_or_else(pool::default_max_connections),
        })
    }

    async fn create_security_connector(
        &self,
        pool_key: &PoolKey,
        parent_span: Span,
    ) -> Result<SecurityConnector> {
        let transport_layer_connector =
            self.transport_layer_creator.create(pool_key, parent_span)?;

        Ok(SecurityConnector {
            tls_config_generator: self.tls_config_generator.clone(),
            transport_layer_connector,
            security_layer_span: Span::current(),
        })
    }

    async fn get_client(&self, pool_key: &PoolKey) -> Result<RatsTlsClient> {
        self.get_client_with_span(pool_key, Span::current())
            .instrument(tracing::info_span!(
                "security",
                session_id = tracing::field::Empty
            ))
            .await
    }

    async fn get_client_with_span(
        &self,
        pool_key: &PoolKey,
        parent_span: Span,
    ) -> Result<RatsTlsClient> {
        let max = self
            .multiplex_max_streams_per_connection
            .map(NonZeroU32::get);
        let max_connections = self.multiplex_max_connections;

        // Try to reuse a shard tunnel with a free stream slot.
        let reused = {
            let read = self.pool.read().await;
            read.get(pool_key).and_then(|shards| {
                pool::pick_shard(shards, max, max_connections).map(|idx| shards[idx].clone())
            })
        };

        let client = match reused {
            Some(c) => {
                c.active.fetch_add(1, Ordering::Relaxed);
                Span::current().record("session_id", c.id);
                tracing::debug!(session_id = c.id, "Reuse existed rats-tls session");
                c
            }
            None => {
                // All shards are at their stream cap (or none exist), so create
                // a new shard tunnel under the write lock. Re-check first: a
                // concurrent allocate may have just added a shard or freed a slot.
                let mut write = self.pool.write().await;
                let shards = write.entry(pool_key.to_owned()).or_default();
                if let Some(idx) = pool::pick_shard(shards, max, max_connections) {
                    let c = shards[idx].clone();
                    c.active.fetch_add(1, Ordering::Relaxed);
                    Span::current().record("session_id", c.id);
                    tracing::debug!(session_id = c.id, "Reuse existed rats-tls session");
                    return Ok(c);
                }

                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                Span::current().record("session_id", id);
                tracing::debug!(
                    session_id = id,
                    "No rats-tls session found, create a new one"
                );

                // Prepare the security connector
                let connector = self
                    .create_security_connector(pool_key, parent_span)
                    .await?;

                // Build the hyper client from the security connector.
                // Windows and frame size match the egress h2 server so
                // the mux tunnel ends negotiate the same data-plane
                // tuning (see the constants' rationale).
                let client = RatsTlsClient {
                    id,
                    active: Arc::new(AtomicU32::new(1)),
                    hyper: Client::builder(self.runtime.clone())
                        .http2_initial_stream_window_size(
                            crate::tunnel::utils::hyper::H2_TUNNEL_INITIAL_STREAM_WINDOW,
                        )
                        .http2_initial_connection_window_size(
                            crate::tunnel::utils::hyper::H2_TUNNEL_INITIAL_CONNECTION_WINDOW,
                        )
                        .http2_max_frame_size(crate::tunnel::utils::hyper::H2_TUNNEL_MAX_FRAME_SIZE)
                        .build(connector),
                };
                shards.push(client.clone());
                client
            }
        };

        Ok(client)
    }

    pub async fn allocate_multiplex_stream(
        &self,
        endpoint: TngEndpoint,
    ) -> Result<(
        Box<dyn CommonStreamTrait + Sync>,
        /* local_addr */ Option<SocketAddr>,
        AttestationState,
        /* session_id */ u64,
    )> {
        // Multiplex path: streams ride shard tunnels, one TLS connection per
        // shard. Each shard attests at its own handshake before its first
        // CONNECT stream rides it; extra shards for the same endpoint usually
        // resume (see the resumption note below), which rustls binds to the
        // attested identity, so the RA contract holds per tunnel either way.
        // The non-multiplex path goes through connect_0rtt + prime in
        // forward_stream, not here.
        // handshake_with_stream already classified attestation into the tri-state
        // carrier (Fresh / Resumed / Unattested); a reconnect can resume if a
        // ticket is cached, so Resumed is possible here too.
        let pool_key = PoolKey::new(endpoint);
        // get_client has already claimed an active-stream slot on the shard.
        // The claimed slot must be released exactly once: the Err arm below is
        // the only fallible step between the claim and handing the guarded box
        // to the caller, whose Drop is the other release site.
        let client = self.get_client(&pool_key).await?;
        match RatsTlsWrappingLayer::create_stream_from_hyper(&client)
            .instrument(tracing::info_span!("wrapping", mode = "h2"))
            .await
        {
            Ok((stream, local_addr, state, session_id)) => {
                let guarded = ShardGuardedStream {
                    inner: Box::new(stream),
                    active: client.active.clone(),
                };
                Ok((Box::new(guarded), local_addr, state, session_id))
            }
            Err(error) => {
                // The stream never materialized; release the claimed slot.
                client.active.fetch_sub(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    /// Open the non-multiplex upstream TLS connection for 0-RTT. Thin delegator
    /// over [`RatsTlsWrappingLayer::create_stream_raw_0rtt`] so `forward_stream`
    /// can keep calling the security layer; the stream-building logic lives in
    /// the wrapping layer alongside `create_stream_from_hyper`.
    pub async fn connect_0rtt(
        &self,
        endpoint: &TngEndpoint,
    ) -> Result<(
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        Option<Arc<crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier>>,
        Option<SocketAddr>,
    )> {
        RatsTlsWrappingLayer::create_stream_raw_0rtt(
            &self.transport_layer_creator,
            &self.tls_config_generator,
            endpoint,
        )
        .await
    }
}

/// Max bytes attempted as 0-RTT early data from the first downstream read.
/// Capped below the server's MAX_EARLY_DATA_SIZE so the whole first chunk
/// qualifies as 0-RTT; the forward loop handles the rest as 1-RTT.
const EARLY_DATA_PRIME_BUF: usize = 64 * 1024;

/// Race the first downstream read against an upstream flush.
///
/// In tokio-rustls's EarlyData state (a resumption ticket was available),
/// `connect_0rtt` returned before the handshake completed; the first write
/// drives the 0-RTT send and completes the handshake (rejected 0-RTT is
/// auto-replayed as 1-RTT by tokio-rustls). If the downstream has no data
/// ready, the flush branch completes the handshake as plain 1-RTT so the
/// connection cannot hang waiting on a write.
///
/// Generic over the upstream so it can drive the raw `TlsStream` (the caller
/// must read `handshake_kind()` off it after this returns, which requires the
/// unboxed stream).
pub(super) async fn prime_0rtt<U: CommonStreamTrait>(
    upstream: &mut U,
    downstream: &mut Box<dyn CommonStreamTrait>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut buf = vec![0u8; EARLY_DATA_PRIME_BUF];
    tokio::select! {
        biased; // prefer sending downstream data as 0-RTT when it is ready
        r = downstream.read(&mut buf) => {
            match r.context("read downstream for 0-RTT prime")? {
                0 => upstream.flush().await.context("flush upstream (downstream EOF)")?,
                n => {
                    upstream
                        .write_all(&buf[..n])
                        .await
                        .context("write upstream 0-RTT prime")?;
                    upstream.flush().await.context("flush upstream 0-RTT prime")?;
                }
            }
        }
        _ = upstream.flush() => {
            // No downstream data ready in time: complete the handshake as 1-RTT.
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct SecurityConnector {
    tls_config_generator: Arc<TlsConfigGenerator>,
    transport_layer_connector: RatsTlsTransportLayerConnector,
    security_layer_span: Span,
}

impl SecurityConnector {}

impl tower::Service<Uri> for SecurityConnector {
    type Response = RatsTlsConnection;

    type Error = anyhow::Error;

    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri /* Not use this as destination endpoint */) -> Self::Future {
        let tls_config_generator = self.tls_config_generator.clone();
        let mut transport_layer_connector = self.transport_layer_connector.clone();
        Box::pin(
            async move {
                let tls_client_config = tls_config_generator
                    .get_lazy_one_time_rustls_client_config(Alpn::Http2)
                    .await?;

                let transport_layer_stream = transport_layer_connector.call(uri.clone()).await?;

                tracing::debug!("Creating rats-tls connection");
                async {
                    let host = uri.host().context("Host is empty")?;
                    // Model the URI host as an `EndpointAddr` so the TLS
                    // handshake can build a `ServerName` without formatting a
                    // string for the IPv4 case.
                    let server_name = EndpointAddr::from_host(host);
                    let (security_layer_stream, attestation_state) = tls_client_config
                        .handshake_with_stream(&server_name, transport_layer_stream.into_inner())
                        .await?;

                    tracing::debug!("New rats-tls connection established");
                    Ok::<_, anyhow::Error>(
                        StreamWithAttestationResult::wrap_with_attestation_result(
                            TokioIo::new(security_layer_stream),
                            attestation_state,
                        ),
                    )
                }
                .await
                .context("Failed to establish rats-tls connection as client")
            }
            .instrument(self.security_layer_span.clone()),
        )
    }
}

pub type RatsTlsConnection =
    StreamWithAttestationResult<TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>;

#[pin_project]
pub struct StreamWithAttestationResult<T> {
    #[pin]
    inner: T,
    attestation_result: AttestationState,
}

impl<T> StreamWithAttestationResult<T> {
    pub fn wrap_with_attestation_result(inner: T, attestation_result: AttestationState) -> Self {
        Self {
            inner,
            attestation_result,
        }
    }
}

impl hyper_util::client::legacy::connect::Connection for RatsTlsConnection {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        let (tcp, tls) = self.inner.inner().get_ref();
        let connected = if tls.alpn_protocol() == Some(b"h2") {
            tcp.connected().negotiated_h2()
        } else {
            tcp.connected()
        };
        connected.extra(self.attestation_result.clone())
    }
}

impl<T: hyper::rt::Read + hyper::rt::Write + Unpin> hyper::rt::Read
    for StreamWithAttestationResult<T>
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T: hyper::rt::Write + hyper::rt::Read + Unpin> hyper::rt::Write
    for StreamWithAttestationResult<T>
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}
