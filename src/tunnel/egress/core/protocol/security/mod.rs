mod cert_resolver;
mod cert_verifier;

use std::sync::Arc;

use crate::{
    config::ra::RaArgs,
    executor::envoy::confgen::{ENVOY_DUMMY_CERT, ENVOY_DUMMY_KEY},
    tunnel::{attestation_result::AttestationResult, utils::cert_manager::CertManager},
};
use anyhow::{bail, Context as _, Result};
use rustls::ServerConfig;
use tokio_graceful::ShutdownGuard;
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

use cert_resolver::CoCoServerCertResolver;
use cert_verifier::CoCoClientCertVerifier;

pub struct SecurityLayer {
    ra_args: RaArgs,
    shutdown_guard: ShutdownGuard,
}

impl SecurityLayer {
    pub async fn new(ra_args: &RaArgs, shutdown_guard: ShutdownGuard) -> Result<Self> {
        // Sanity check for ra_args

        if ra_args.no_ra {
            if ra_args.verify != None {
                bail!("The 'no_ra: true' flag should not be used with 'verify' field");
            }

            if ra_args.attest != None {
                bail!("The 'no_ra: true' flag should not be used with 'attest' field");
            }

            tracing::warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment");
        } else if ra_args.attest != None || ra_args.verify != None {
            // Nothing
        } else {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'");
        }

        Ok(Self {
            ra_args: ra_args.clone(),
            shutdown_guard,
        })
    }

    pub async fn from_stream(
        &self,
        stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    ) -> Result<(
        impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
        Option<AttestationResult>,
    )> {
        // Prepare TLS config
        let ra_args = &self.ra_args;
        let mut tls_server_config;
        let mut verifier = None;

        if ra_args.no_ra {
            tls_server_config =
                ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_no_client_auth()
                    .with_single_cert(
                        rustls_pemfile::certs(&mut ENVOY_DUMMY_CERT.as_bytes())
                            .collect::<Result<Vec<_>, _>>()?,
                        rustls_pemfile::private_key(&mut ENVOY_DUMMY_KEY.as_bytes())
                            .map(|key| key.unwrap())?,
                    )?;
        } else if ra_args.attest != None || ra_args.verify != None {
            let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);

            // Prepare client cert verifier
            let builder = if let Some(verify_args) = &ra_args.verify {
                let v = Arc::new(CoCoClientCertVerifier::new(verify_args.clone())?);
                verifier = Some(v.clone());
                builder.with_client_cert_verifier(v)
            } else {
                builder.with_no_client_auth()
            };

            // Prepare server cert resolver
            if let Some(attest_args) = &ra_args.attest {
                let cert_manager = Arc::new(
                    CertManager::create_and_launch(
                        attest_args.clone(),
                        self.shutdown_guard.clone(),
                    )
                    .await?,
                );

                tls_server_config =
                    builder.with_cert_resolver(Arc::new(CoCoServerCertResolver::new(cert_manager)));
            } else {
                tls_server_config = builder.with_single_cert(
                    rustls_pemfile::certs(&mut ENVOY_DUMMY_CERT.as_bytes())
                        .collect::<Result<Vec<_>, _>>()?,
                    rustls_pemfile::private_key(&mut ENVOY_DUMMY_KEY.as_bytes())
                        .map(|key| key.unwrap())?,
                )?;
            }
        } else {
            unreachable!()
        }

        tls_server_config.alpn_protocols = vec![b"h2".to_vec()];

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));
        let tls_stream = async move {
            tls_acceptor.accept(stream).await.map(|v| {
                tracing::debug!("New rats-tls session established");
                v
            })
        }
        .instrument(tracing::info_span!("security"))
        .await?;

        let attestation_result = match verifier {
            Some(verifier) => Some(
                verifier
                    .get_attestation_result()
                    .await
                    .context("No attestation result found")?,
            ),
            None => None,
        };

        Ok((tls_stream, attestation_result))
    }
}
