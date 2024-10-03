use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use hyper::upgrade::Upgraded;
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use tokio::{net::TcpStream, sync::RwLock};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::tunnel::ingress::core::{client::stream::verifier::NoRaCertVerifier, TngEndpoint};

type PoolKey = TngEndpoint;

type ClientType = Client<HttpsConnector<HttpConnector>, axum::body::Body>;

pub struct StreamManager {
    pool: RwLock<HashMap<PoolKey, ClientType>>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            pool: Default::default(),
        }
    }

    async fn get_client(&self, endpoint: &TngEndpoint) -> Result<ClientType> {
        // Try to get the client from pool
        let client = {
            let read = self.pool.read().await;
            read.get(endpoint).map(|c| c.clone())
        };

        let client = match client {
            Some(c) => c,
            None => {
                // If client not exist then we need to create one
                let mut write = self.pool.write().await;
                // Check if client has been created by other "thread"
                match write.get(endpoint) {
                    Some(c) => c.clone(),
                    None => {
                        tracing::info!("Creating client for '{}'", endpoint);
                        let http_connector = HttpConnector::new(endpoint.clone());

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
                        let client = Client::builder(TokioExecutor::new()).build(https_connector);
                        write.insert(endpoint.to_owned(), client.clone());
                        client
                    }
                }
            }
        };

        Ok(client)
    }

    pub async fn new_stream(&self, endpoint: &TngEndpoint) -> Result<Upgraded> {
        let client = self.get_client(endpoint).await?;

        let req = Request::connect("https://tng.internal/")
            .version(Version::HTTP_2)
            .body(axum::body::Body::empty())
            .unwrap();

        tracing::debug!("Send HTTP/2 CONNECT request to '{}'", endpoint);
        let mut resp = client
            .request(req)
            .await
            .context("Failed to send HTTP/2 CONNECT request")?;

        if resp.status() != StatusCode::OK {
            bail!(
                "Failed to send HTTP/2 CONNECT request, bad status '{}', got: {:?}",
                resp.status(),
                resp
            );
        }
        let upgraded = hyper::upgrade::on(&mut resp).await.with_context(|| {
            format!(
                "Failed to establish HTTP/2 CONNECT tunnel with '{}'",
                endpoint
            )
        })?;

        Ok(upgraded)
    }
}

#[derive(Debug, Clone)]
struct HttpConnector {
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
        tracing::debug!("Establish TCP connection to '{}'", self.endpoint);

        let endpoint_owned = self.endpoint.to_owned();
        let fut = async move {
            TcpStream::connect((endpoint_owned.host(), endpoint_owned.port))
                .await
                .map(|s| TokioIo::new(s))
                .map_err(|e| e.into())
        };

        Box::pin(fut)
    }
}
