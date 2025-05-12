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

use anyhow::{bail, Context as _, Result};
use http::Uri;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use pin_project::pin_project;
use pool::{ClientPool, HyperClientType, PoolKey};
use rustls_config::OnetimeTlsClientConfig;
use tokio::sync::RwLock;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

use crate::{
    config::ra::RaArgs,
    tunnel::{attestation_result::AttestationResult, utils::rustls_config::TlsConfigGenerator},
};

use super::transport::{
    TransportLayerConnector, TransportLayerCreator, TransportLayerCreatorTrait as _,
};

#[derive(Clone)]
pub struct RatsTlsClient {
    pub id: u64,
    pub hyper: HyperClientType,
}

pub struct SecurityLayer {
    next_id: AtomicU64,
    pool: RwLock<ClientPool>,
    transport_layer_creator: TransportLayerCreator,
    tls_config_generator: Arc<TlsConfigGenerator>,
}

impl SecurityLayer {
    pub async fn new(
        transport_layer_creator: TransportLayerCreator,
        ra_args: &RaArgs,
    ) -> Result<Self> {
        // TODO: handle web_page_inject

        let tls_config_generator = Arc::new(TlsConfigGenerator::new(ra_args).await?);

        Ok(Self {
            next_id: AtomicU64::new(0),
            pool: RwLock::new(HashMap::new()),
            transport_layer_creator,
            tls_config_generator,
        })
    }

    pub async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()> {
        self.tls_config_generator.prepare(shutdown_guard).await
    }

    pub async fn create_security_connector(
        &self,
        pool_key: &PoolKey,
        shutdown_guard: ShutdownGuard,
        parent_span: Span,
    ) -> Result<SecurityConnector> {
        let transport_layer_connector =
            self.transport_layer_creator
                .create(&pool_key, shutdown_guard, parent_span)?;

        Ok(SecurityConnector {
            tls_config_generator: self.tls_config_generator.clone(),
            transport_layer_connector,
            security_layer_span: Span::current(),
        })
    }

    pub async fn get_client(
        &self,
        pool_key: &PoolKey,
        shutdown_guard: ShutdownGuard,
    ) -> Result<RatsTlsClient> {
        self.get_client_with_span(pool_key, shutdown_guard, Span::current())
            .instrument(tracing::info_span!(
                "security",
                session_id = tracing::field::Empty
            ))
            .await
    }

    async fn get_client_with_span(
        &self,
        pool_key: &PoolKey,
        shutdown_guard: ShutdownGuard,
        parent_span: Span,
    ) -> Result<RatsTlsClient> {
        // Try to get the client from pool
        let client = {
            let read = self.pool.read().await;
            read.get(pool_key).map(|c| c.clone())
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
                            .create_security_connector(pool_key, shutdown_guard, parent_span)
                            .await?;

                        // Build the hyper client from the security connector.
                        let client = RatsTlsClient {
                            id: id,
                            hyper: Client::builder(TokioExecutor::new()).build(connector),
                        };
                        write.insert(pool_key.to_owned(), client.clone());
                        client
                    }
                }
            }
        };

        Ok(client)
    }

    pub fn transport_layer_creator_ref(&self) -> &TransportLayerCreator {
        &self.transport_layer_creator
    }
}

#[derive(Clone)]
pub struct SecurityConnector {
    tls_config_generator: Arc<TlsConfigGenerator>,
    transport_layer_connector: TransportLayerConnector,
    security_layer_span: Span,
}

impl SecurityConnector {}

impl tower::Service<Uri> for SecurityConnector {
    type Response = SecurityConnection<
        hyper_rustls::MaybeHttpsStream<
            hyper_util::rt::TokioIo<super::transport::TransportLayerStream>,
        >,
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
        let transport_layer_connector = self.transport_layer_connector.clone();
        Box::pin(
            async move {
                let OnetimeTlsClientConfig(tls_client_config, verifier) = tls_config_generator
                    .get_one_time_rustls_client_config()
                    .await?;

                let mut https_connector = hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls_client_config)
                    .https_only() // TODO: support returning notification message on non rats-tls request with https_or_http()
                    .enable_http2()
                    .wrap_connector(transport_layer_connector);

                let res = https_connector
                    .call(uri)
                    .await
                    .map_err(|e| anyhow::Error::from_boxed(e))?;

                if !matches!(res, hyper_rustls::MaybeHttpsStream::Https(_)) {
                    bail!("BUG detected, the connection is not secured by Rats-Tls")
                }

                let attestation_result = match verifier {
                    Some(verifier) => Some(
                        verifier
                            .get_attestation_result()
                            .await
                            .context("No attestation result found")?,
                    ),
                    None => None,
                };
                Ok(SecurityConnection::wrap_with_attestation_result(
                    res,
                    attestation_result,
                ))
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

impl<
        T: hyper::rt::Read
            + hyper::rt::Write
            + hyper_util::client::legacy::connect::Connection
            + Unpin,
    > hyper_util::client::legacy::connect::Connection for SecurityConnection<T>
{
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        let connected = self.inner.connected();
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
