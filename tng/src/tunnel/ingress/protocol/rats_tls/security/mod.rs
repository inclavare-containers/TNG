pub mod pool;

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
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
    config::ingress::RatsTlsArgs,
    tunnel::{
        attestation_result::AttestationResult,
        endpoint::{EndpointAddr, TngEndpoint},
        ingress::protocol::rats_tls::wrapping::RatsTlsWrappingLayer,
        ra_context::RaContext,
        utils::{
            runtime::TokioRuntime,
            rustls::{
                config::{alpn::Alpn, TlsConfigGenerator},
                TlsOutcome,
            },
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
}

pub struct RatsTlsSecurityLayer {
    next_id: AtomicU64,
    pool: RwLock<ClientPool>,
    transport_layer_creator: RatsTlsTransportLayerCreator,
    tls_config_generator: Arc<TlsConfigGenerator>,
    runtime: TokioRuntime,
    multiplex: bool,
    // Read only on the Linux kTLS handshake path; unused (but stored) elsewhere.
    #[cfg(target_os = "linux")]
    ktls: crate::config::ktls::EnvCheckedKtls,
}

pub enum AllocatedSecuredStream {
    Raw(TlsOutcome),
    Multiplexed(Box<dyn CommonStreamTrait + Sync>),
}

impl RatsTlsSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        rats_tls: &RatsTlsArgs,
    ) -> Result<Self> {
        let transport_layer_creator = RatsTlsTransportLayerCreator::new(
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            transport_so_mark,
        );
        let tls_config_generator =
            Arc::new(TlsConfigGenerator::new(ra_context, runtime.clone()).await?);

        // Resolve the kTLS policy once here against the link constraints
        #[cfg(target_os = "linux")]
        let ktls = rats_tls
            .ktls
            .resolve(&crate::config::ktls::KtlsEnvConstraints::link(
                rats_tls.multiplex,
            ))?;

        Ok(Self {
            next_id: AtomicU64::new(0),
            pool: RwLock::new(HashMap::new()),
            transport_layer_creator,
            tls_config_generator,
            runtime,
            multiplex: rats_tls.multiplex,
            #[cfg(target_os = "linux")]
            ktls,
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
        // Try to get the client from pool
        let client = {
            let read = self.pool.read().await;
            read.get(pool_key).cloned()
        };

        let client = match client {
            Some(c) => {
                Span::current().record("session_id", c.id);
                tracing::debug!(session_id = c.id, "Reuse existed rats-tls session");
                c
            }
            None => {
                // If client not exist then we need to create one
                let mut write = self.pool.write().await;
                // Check if client has been created by other "task"
                match write.get(pool_key) {
                    Some(c) => {
                        Span::current().record("session_id", c.id);
                        tracing::debug!(session_id = c.id, "Reuse existed rats-tls session");
                        c.clone()
                    }
                    None => {
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
                        let client = RatsTlsClient {
                            id,
                            hyper: Client::builder(self.runtime.clone()).build(connector),
                        };
                        write.insert(pool_key.to_owned(), client.clone());
                        client
                    }
                }
            }
        };

        Ok(client)
    }

    pub async fn allocate_secured_stream_try_ktls(
        &self,
        endpoint: TngEndpoint,
    ) -> Result<(
        AllocatedSecuredStream,
        /* local_addr */ Option<SocketAddr>,
        Option<AttestationResult>,
    )> {
        if !self.multiplex {
            // Try to create a raw stream and fallback to rustls if ktls failed
            let (stream, local_addr, att) = RatsTlsWrappingLayer::create_stream_raw(
                &self.transport_layer_creator,
                &self.tls_config_generator,
                &endpoint,
                #[cfg(target_os = "linux")]
                self.ktls,
            )
            .instrument(tracing::info_span!("wrapping", mode = "rats-tls"))
            .await?;
            Ok((AllocatedSecuredStream::Raw(stream), local_addr, att))
        } else {
            let (stream, local_addr, att) = self.allocate_secured_stream_rustls(endpoint).await?;
            Ok((
                AllocatedSecuredStream::Multiplexed(Box::new(stream)),
                local_addr,
                att,
            ))
        }
    }

    pub async fn allocate_secured_stream_rustls(
        &self,
        endpoint: TngEndpoint,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ Option<SocketAddr>,
        Option<AttestationResult>,
    )> {
        let pool_key = PoolKey::new(endpoint);
        let client = self.get_client(&pool_key).await?;
        let (stream, local_addr, att) = RatsTlsWrappingLayer::create_stream_from_hyper(&client)
            .instrument(tracing::info_span!("wrapping", mode = "h2"))
            .await?;
        Ok((stream, local_addr, att))
    }

    /// An `IncomingStream::Opaque` downstream has no raw socket, so kTLS (which
    /// installs on a raw fd) is impossible. Apply the policy: `required` bails
    /// the connection, `best-effort`/`disabled` fall back to the rustls data
    /// plane (the caller proceeds with [`Self::allocate_secured_stream_rustls`]).
    #[cfg(target_os = "linux")]
    pub(super) fn check_opaque_downstream(&self) -> Result<()> {
        use crate::config::ktls::{FallbackDecision, KtlsConnUnavailable};
        match self
            .ktls
            .on_connection_unavailable(KtlsConnUnavailable::OpaqueDownstream)
        {
            FallbackDecision::Bail(error) => Err(error),
            FallbackDecision::FallBack => Ok(()),
        }
    }
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
                    let (security_layer_stream, attestation_result) = tls_client_config
                        .handshake_with_stream(&server_name, transport_layer_stream.into_inner())
                        .await?;

                    tracing::debug!("New rats-tls connection established");
                    Ok::<_, anyhow::Error>(
                        StreamWithAttestationResult::wrap_with_attestation_result(
                            TokioIo::new(security_layer_stream),
                            attestation_result,
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
    attestation_result: Option<AttestationResult>,
}

impl<T> StreamWithAttestationResult<T> {
    pub fn wrap_with_attestation_result(
        inner: T,
        attestation_result: Option<AttestationResult>,
    ) -> Self {
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
