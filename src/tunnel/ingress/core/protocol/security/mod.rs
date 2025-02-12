mod cert_resolver;
mod cert_verifier;

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
use cert_resolver::CoCoClientCertResolver;
use cert_verifier::{coco::CoCoServerCertVerifier, dummy::DummyServerCertVerifier};
use http::Uri;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use pin_project::pin_project;
use tokio::sync::RwLock;
use tokio_graceful::ShutdownGuard;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::{warn, Span};

use crate::{
    config::ra::RaArgs,
    tunnel::{
        attestation_result::AttestationResult, ingress::core::TngEndpoint,
        utils::cert_manager::CertManager,
    },
};

use super::transport::{TransportLayerConnector, TransportLayerCreator};

type PoolKey = TngEndpoint;

type HyperClientType = Client<SecurityConnector, axum::body::Body>;

#[derive(Clone)]
pub struct RatsTlsClient {
    pub id: u64,
    pub hyper: HyperClientType,
}

pub struct SecurityLayer {
    pub next_id: AtomicU64,
    pool: RwLock<HashMap<PoolKey, RatsTlsClient>>,
    security_connector_creator: SecurityConnectorCreator,
}

impl SecurityLayer {
    pub async fn new(
        connector_creator: TransportLayerCreator,
        ra_args: &RaArgs,
        shutdown_guard: ShutdownGuard,
    ) -> Result<Self> {
        // TODO: handle web_page_inject

        Ok(Self {
            next_id: AtomicU64::new(0),
            pool: RwLock::new(HashMap::new()),
            security_connector_creator: SecurityConnectorCreator::new(
                connector_creator,
                ra_args,
                shutdown_guard,
            )
            .await?,
        })
    }

    pub async fn get_client(&self, dst: &TngEndpoint) -> Result<RatsTlsClient> {
        // Try to get the client from pool
        let client = {
            let read = self.pool.read().await;
            read.get(dst).map(|c| c.clone())
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
                match write.get(dst) {
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
                        let connector = self.security_connector_creator.create(&dst);

                        // Build the hyper client from the security connector.
                        let client = RatsTlsClient {
                            id: id,
                            hyper: Client::builder(TokioExecutor::new()).build(connector),
                        };
                        write.insert(dst.to_owned(), client.clone());
                        client
                    }
                }
            }
        };

        Ok(client)
    }
}

struct SecurityConnectorCreator {
    connector_creator: TransportLayerCreator,
    ra_args: RaArgs,
    shutdown_guard: ShutdownGuard,
}
impl SecurityConnectorCreator {
    pub async fn new(
        connector_creator: TransportLayerCreator,
        ra_args: &RaArgs,
        shutdown_guard: ShutdownGuard,
    ) -> Result<Self> {
        // Sanity check for ra_args
        if ra_args.no_ra {
            if ra_args.verify != None {
                bail!("The 'no_ra: true' flag should not be used with 'verify' field");
            }

            if ra_args.attest != None {
                bail!("The 'no_ra: true' flag should not be used with 'attest' field");
            }

            warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment");
        } else if ra_args.attest != None || ra_args.verify != None {
            // Nothing
        } else {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_ingress'");
        }

        Ok(Self {
            connector_creator,
            ra_args: ra_args.clone(),
            shutdown_guard,
        })
    }

    pub fn create(&self, dst: &TngEndpoint) -> SecurityConnector {
        let transport_layer_connector = self.connector_creator.create(&dst);

        SecurityConnector {
            ra_args: self.ra_args.clone(),
            shutdown_guard: self.shutdown_guard.clone(),
            transport_layer_connector,
        }
    }
}

#[derive(Clone)]
pub struct SecurityConnector {
    ra_args: RaArgs,
    shutdown_guard: ShutdownGuard,
    transport_layer_connector: TransportLayerConnector,
}

impl SecurityConnector {
    pub async fn create_config(
        ra_args: RaArgs,
        shutdown_guard: ShutdownGuard,
    ) -> Result<(ClientConfig, Option<Arc<CoCoServerCertVerifier>>)> {
        let mut tls_client_config;
        let mut verifier = None;

        if ra_args.no_ra {
            tls_client_config =
                ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_root_certificates(RootCertStore::empty())
                    .with_no_client_auth();

            tls_client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));
        } else if ra_args.attest != None || ra_args.verify != None {
            let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(RootCertStore::empty());
            if let Some(attest_args) = &ra_args.attest {
                let cert_manager = Arc::new(
                    CertManager::create_and_launch(attest_args.clone(), shutdown_guard).await?,
                );

                tls_client_config = config
                    .with_client_cert_resolver(Arc::new(CoCoClientCertResolver::new(cert_manager)));
            } else {
                tls_client_config = config.with_no_client_auth();
            }

            if let Some(verify_args) = &ra_args.verify {
                let v: Arc<CoCoServerCertVerifier> =
                    Arc::new(CoCoServerCertVerifier::new(verify_args.clone())?);
                verifier = Some(v.clone());
                tls_client_config.dangerous().set_certificate_verifier(v);
            } else {
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));
            }
        } else {
            unreachable!()
        }

        Ok((tls_client_config, verifier))
    }
}

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

    fn call(&mut self, _uri: Uri /* Not use this as destination endpoint */) -> Self::Future {
        let ra_args = self.ra_args.clone();
        let shutdown_guard = self.shutdown_guard.clone();
        let transport_layer_connector = self.transport_layer_connector.clone();
        Box::pin(async {
            let (tls_client_config, verifier) =
                Self::create_config(ra_args, shutdown_guard).await?;

            let mut https_connector = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls_client_config)
                .https_only() // TODO: support returning notification message on non rats-tls request with https_or_http()
                .enable_http2()
                .wrap_connector(transport_layer_connector);

            let res = https_connector
                .call(_uri)
                .await
                .map_err(|e| anyhow::Error::from_boxed(e))?;

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
        })
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
