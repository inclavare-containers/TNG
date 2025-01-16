use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use anyhow::Result;
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use tokio::{net::TcpStream, sync::RwLock};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::tunnel::ingress::core::{client::trusted::verifier::NoRaCertVerifier, TngEndpoint};

type PoolKey = TngEndpoint;

type HyperClientType = Client<HttpsConnector<HttpConnector>, axum::body::Body>;

#[derive(Clone)]
pub struct RatsTlsClient {
    pub id: u64,
    pub hyper: HyperClientType,
}

#[derive(Default)]
pub struct ClientPool {
    pub next_id: AtomicU64,
    clients: RwLock<HashMap<PoolKey, RatsTlsClient>>,
}

impl ClientPool {
    pub async fn get_client(&self, dst: &TngEndpoint) -> Result<RatsTlsClient> {
        // Try to get the client from pool
        let client = {
            let read = self.clients.read().await;
            read.get(dst).map(|c| c.clone())
        };

        let client = match client {
            Some(c) => {
                tracing::debug!(%dst, rats_tls_session_id=c.id, "Reuse existing rats-tls session");
                c
            }
            None => {
                // If client not exist then we need to create one
                let mut write = self.clients.write().await;
                // Check if client has been created by other "task"
                match write.get(dst) {
                    Some(c) => {
                        tracing::debug!(%dst, rats_tls_session_id=c.id, "Reuse existing rats-tls session");
                        c.clone()
                    }
                    None => {
                        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                        tracing::debug!(%dst, rats_tls_session_id=id, "Creating new rats-tls client");
                        let http_connector = HttpConnector::new(dst.clone());

                        // TLS client config using the custom CA store for lookups
                        let mut tls = ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_no_client_auth(); // TODO: use with_client_cert_resolver() to provide client cert
                        tls.dangerous()
                            .set_certificate_verifier(Arc::new(NoRaCertVerifier::new()?));

                        // Prepare the HTTPS connector
                        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
                            .with_tls_config(tls)
                            .https_only() // TODO: support returning notification message on non rats-tls request with https_or_http()
                            .enable_http2()
                            .wrap_connector(http_connector);

                        // Build the hyper client from the HTTPS connector.
                        let client = RatsTlsClient {
                            id: id,
                            hyper: Client::builder(TokioExecutor::new()).build(https_connector),
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

#[derive(Debug, Clone)]
pub struct HttpConnector {
    endpoint: TngEndpoint,
}

impl HttpConnector {
    pub fn new(endpoint: TngEndpoint) -> Self {
        Self { endpoint }
    }
}

impl<Req> tower::Service<Req> for HttpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        tracing::debug!("Establish the underlying tcp connection for rats-tls");

        let endpoint_owned = self.endpoint.to_owned();
        let fut = async move {
            TcpStream::connect((endpoint_owned.host(), endpoint_owned.port()))
                .await
                .map(|s| TokioIo::new(s))
                .map_err(|e| e.into())
        };

        Box::pin(fut)
    }
}
