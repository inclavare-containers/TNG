use std::sync::Arc;

use crate::tunnel::{
    ra_context::RaContext,
    stream::CommonStreamTrait,
    utils::{
        runtime::TokioRuntime,
        rustls::{
            config::{alpn::Alpn, TlsConfigGenerator},
            early_data_prefix::EarlyDataPrefixStream,
        },
    },
};
use crate::AttestationState;
use anyhow::Result;
use tracing::Instrument;

pub(super) struct RatsTlsSecurityLayer {
    tls_config_generator: TlsConfigGenerator,
    multiplex: bool,
    http1: bool,
}

impl RatsTlsSecurityLayer {
    pub async fn new(
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        multiplex: bool,
        http1: bool,
    ) -> Result<Self> {
        let tls_config_generator =
            TlsConfigGenerator::new_with_stable_key(ra_context, runtime, http1).await?;

        Ok(Self {
            tls_config_generator,
            multiplex,
            http1,
        })
    }

    pub async fn handshake<T: CommonStreamTrait + std::marker::Sync>(
        &self,
        stream: T,
    ) -> Result<(
        EarlyDataPrefixStream<tokio_rustls::server::TlsStream<T>>,
        AttestationState,
    )> {
        async {
            // Prepare TLS config
            let alpn = if self.http1 {
                Alpn::Http1
            } else if self.multiplex {
                Alpn::Http2
            } else {
                Alpn::RatsTls
            };
            let tls_server_config = self
                .tls_config_generator
                .get_lazy_one_time_rustls_server_config(alpn)
                .await?;

            tracing::debug!("Start to estabilish rats-tls connection");

            let (security_layer_stream, attestation_state) =
                tls_server_config.handshake_with_stream(stream).await?;

            tracing::debug!("New rats-tls connection established");
            Ok((security_layer_stream, attestation_state))
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}

#[cfg(all(test, unix))]
mod http1_tests {
    use super::*;
    use crate::config::ra::RaArgsUnchecked;
    use crate::tests::run_test_with_tokio_runtime;
    use crate::tunnel::utils::rustls::dummy::verifier::DummyServerCertVerifier;
    use anyhow::Context;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x509_cert::{
        der::{Decode, Encode},
        Certificate,
    };

    // Test evidence intentionally is not a hardware proof. This fixture tests
    // HTTPS framing, certificate key continuity and safe protocol negotiation;
    // SNP evidence appraisal is qualified separately against the real guest.
    async fn request(layer: Arc<RatsTlsSecurityLayer>, protocols: Vec<Vec<u8>>) -> Result<Vec<u8>> {
        let (client, server) = tokio::io::duplex(131072);
        let server = async move {
            let (mut stream, _) = layer.handshake(server).await?;
            let mut request = [0u8; b"GET / HTTP/1.1\r\nHost: guest\r\n\r\n".len()];
            stream.read_exact(&mut request).await?;
            assert_eq!(&request, b"GET / HTTP/1.1\r\nHost: guest\r\n\r\n");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            stream.flush().await?;
            Ok::<(), anyhow::Error>(())
        };
        let client = async move {
            let mut config =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?))
                    .with_no_client_auth();
            config.alpn_protocols = protocols;
            let name = rustls::pki_types::ServerName::from(std::net::Ipv4Addr::LOCALHOST);
            let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, client)
                .await?;
            let cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .context("server certificate")?[0]
                .to_vec();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: guest\r\n\r\n")
                .await?;
            stream.flush().await?;
            let mut response = [0u8; 40];
            stream.read_exact(&mut response).await?;
            assert_eq!(&response, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            Ok::<_, anyhow::Error>(cert)
        };
        let (_, cert) = tokio::try_join!(server, client)?;
        Ok(cert)
    }

    #[tokio::test]
    async fn http1_accepts_browser_requests_and_retains_guest_key_across_evidence_refresh(
    ) -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let counter = Arc::new(AtomicUsize::new(0));
            let next = counter.clone();
            let router = axum::Router::new()
                .route("/info", axum::routing::get(|| async { axum::Json(serde_json::json!({"tee":"sample"})) }))
                .route("/aa/evidence", axum::routing::get(move || { let id = next.fetch_add(1, Ordering::SeqCst); async move { axum::Json(serde_json::json!({"test_generation":id})) } }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(async move { axum::serve(listener, router).await });
            let args: RaArgsUnchecked = serde_json::from_value(serde_json::json!({"attest": {"aa_provider":"coco_asr", "asr_addr":format!("http://{addr}"), "refresh_interval":0}}))?;
            let context = Arc::new(RaContext::from_ra_args(&args.into_checked()?).await?);
            let layer = Arc::new(RatsTlsSecurityLayer::new(context.clone(), runtime.clone(), false, true).await?);
            let a = request(layer.clone(), vec![b"h2".to_vec(), b"http/1.1".to_vec()]).await?;
            let b = request(layer.clone(), vec![b"rats-tls".to_vec()]).await?;
            let public_key = |der: &[u8]| -> Result<Vec<u8>> { Ok(Certificate::from_der(der)?.tbs_certificate.subject_public_key_info.to_der()?) };
            assert_eq!(public_key(&a)?, public_key(&b)?);
            assert_ne!(a, b, "new evidence must not silently reuse the prior report");
            assert!(counter.load(Ordering::SeqCst) >= 2);
            assert!(request(layer, vec![b"h2".to_vec()]).await.is_err(), "h2-only clients must not enter CONNECT mode");
            let replacement = Arc::new(RatsTlsSecurityLayer::new(context, runtime, false, true).await?);
            let c = request(replacement, vec![b"http/1.1".to_vec()]).await?;
            assert_ne!(public_key(&a)?, public_key(&c)?, "a replacement attester must have a new guest key");
            server.abort();
            Ok(())
        }).await
    }
}
