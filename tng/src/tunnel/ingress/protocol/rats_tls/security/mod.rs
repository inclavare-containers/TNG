mod cert_verifier;
pub mod pool;
mod rustls_config;

use std::{
    collections::HashMap,
    future::Future,
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
use rustls::pki_types::ServerName;
use rustls_config::OnetimeTlsClientConfig;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::{Instrument, Span};

use crate::{
    config::ra::RaArgs,
    tunnel::{
        attestation_result::AttestationResult,
        endpoint::TngEndpoint,
        ingress::protocol::rats_tls::wrapping::RatsTlsWrappingLayer,
        utils::{runtime::TokioRuntime, rustls_config::TlsConfigGenerator, tokio::TokioIo},
    },
    CommonStreamTrait,
};

use super::transport::{
    RatsTlsTransportLayerConnector, RatsTlsTransportLayerCreator, RatsTlsTransportLayerStream,
};

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
}

impl RatsTlsSecurityLayer {
    pub async fn new(
        transport_so_mark: Option<u32>,
        ra_args: RaArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let transport_layer_creator = RatsTlsTransportLayerCreator::new(transport_so_mark);
        let tls_config_generator = Arc::new(TlsConfigGenerator::new(ra_args).await?);

        Ok(Self {
            next_id: AtomicU64::new(0),
            pool: RwLock::new(HashMap::new()),
            transport_layer_creator,
            tls_config_generator,
            runtime,
        })
    }

    pub async fn prepare(&self) -> Result<()> {
        self.tls_config_generator
            .prepare(self.runtime.clone())
            .await
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

    pub async fn allocate_secured_stream(
        &self,
        endpoint: TngEndpoint,
    ) -> Result<(impl CommonStreamTrait, Option<AttestationResult>)> {
        let pool_key = PoolKey::new(endpoint);

        let client = self.get_client(&pool_key).await?;
        RatsTlsWrappingLayer::create_stream_from_hyper(&client)
            .instrument(tracing::info_span!("wrapping"))
            .await
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
    type Response = SecurityConnection<
        TokioIo<tokio_rustls::client::TlsStream<super::transport::RatsTlsTransportLayerStream>>,
    >;

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
                let OnetimeTlsClientConfig(tls_client_config, verifier) = tls_config_generator
                    .get_one_time_rustls_client_config()
                    .await?;

                let transport_layer_stream = transport_layer_connector.call(uri.clone()).await?;

                tracing::debug!("Creating rats-tls connection");
                async {
                    let security_layer_stream = TokioIo::new(
                        TlsConnector::from(Arc::new(tls_client_config))
                            .connect(
                                ServerName::try_from(uri.host().context("Host is empty")?)?
                                    .to_owned(),
                                transport_layer_stream.into_inner(),
                            )
                            .await?,
                    );

                    let attestation_result = match verifier {
                        Some(verifier) => Some(
                            verifier
                                .verity_pending_cert()
                                .await
                                .context("No attestation result found")?,
                        ),
                        None => None,
                    };

                    tracing::debug!("New rats-tls connection established");
                    Ok::<_, anyhow::Error>(SecurityConnection::wrap_with_attestation_result(
                        security_layer_stream,
                        attestation_result,
                    ))
                }
                .await
                .context("Failed to setup rats-tls connection")
            }
            .instrument(self.security_layer_span.clone()),
        )
    }
}

#[pin_project]
pub struct SecurityConnection<T> {
    #[pin]
    inner: T,
    attestation_result: Option<AttestationResult>,
}

impl<T> SecurityConnection<T> {
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

impl hyper_util::client::legacy::connect::Connection
    for SecurityConnection<TokioIo<tokio_rustls::client::TlsStream<RatsTlsTransportLayerStream>>>
{
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

impl<T: hyper::rt::Read + hyper::rt::Write + Unpin> hyper::rt::Read for SecurityConnection<T> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T: hyper::rt::Write + hyper::rt::Read + Unpin> hyper::rt::Write for SecurityConnection<T> {
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
