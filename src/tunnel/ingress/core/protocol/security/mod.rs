mod cert_resolver;
mod cert_verifier;

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{bail, Result};
use cert_resolver::CoCoClientCertResolver;
use cert_verifier::{coco::CoCoServerCertVerifier, dummy::DummyServerCertVerifier};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::sync::RwLock;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::warn;

use crate::{
    config::ra::RaArgs,
    tunnel::{ingress::core::TngEndpoint, utils::cert_manager::CertManager},
};

use super::transport::{TransportLayerConnector, TransportLayerCreator};

type PoolKey = TngEndpoint;

type HyperClientType = Client<HttpsConnector<TransportLayerConnector>, axum::body::Body>;

#[derive(Clone)]
pub struct RatsTlsClient {
    pub id: u64,
    pub hyper: HyperClientType,
}

pub struct SecurityLayer {
    pub next_id: AtomicU64,
    tls_client_config: ClientConfig,
    connector_creator: TransportLayerCreator,
    pool: RwLock<HashMap<PoolKey, RatsTlsClient>>,
}

impl SecurityLayer {
    pub async fn new(connector_creator: TransportLayerCreator, ra_args: &RaArgs) -> Result<Self> {
        // TODO: handle web_page_inject

        // Prepare TLS config
        let mut tls_client_config;

        if ra_args.no_ra {
            if ra_args.verify != None {
                bail!("The 'no_ra: true' flag should not be used with 'verify' field");
            }

            if ra_args.attest != None {
                bail!("The 'no_ra: true' flag should not be used with 'attest' field");
            }

            warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment");

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
                let cert_manager =
                    Arc::new(CertManager::create_and_launch(attest_args.clone()).await?);

                tls_client_config = config
                    .with_client_cert_resolver(Arc::new(CoCoClientCertResolver::new(cert_manager)));
            } else {
                tls_client_config = config.with_no_client_auth();
            }

            if let Some(verify_args) = &ra_args.verify {
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(CoCoServerCertVerifier::new(
                        verify_args.clone(),
                    )?));
            } else {
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));
            }
        } else {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_ingress'");
        }

        Ok(Self {
            next_id: AtomicU64::new(0),
            tls_client_config: tls_client_config,
            connector_creator: connector_creator,
            pool: RwLock::new(HashMap::new()),
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
                tracing::debug!(%dst, rats_tls_session_id=c.id, "Reuse existing rats-tls session");
                c
            }
            None => {
                // If client not exist then we need to create one
                let mut write = self.pool.write().await;
                // Check if client has been created by other "task"
                match write.get(dst) {
                    Some(c) => {
                        tracing::debug!(%dst, rats_tls_session_id=c.id, "Reuse existing rats-tls session");
                        c.clone()
                    }
                    None => {
                        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                        tracing::debug!(%dst, rats_tls_session_id=id, "Creating new rats-tls client");

                        let transport_layer_connector = self.connector_creator.create(&dst);

                        // Prepare the HTTPS connector
                        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
                            .with_tls_config(self.tls_client_config.clone())
                            .https_only() // TODO: support returning notification message on non rats-tls request with https_or_http()
                            .enable_http2()
                            .wrap_connector(transport_layer_connector);

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
