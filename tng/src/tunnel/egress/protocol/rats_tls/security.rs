use std::sync::Arc;

use crate::tunnel::{
    attestation_result::AttestationResult,
    ra_context::RaContext,
    stream::CommonStreamTrait,
    utils::{
        runtime::TokioRuntime,
        rustls::config::{alpn::Alpn, TlsConfigGenerator},
    },
};
use anyhow::Result;
use tracing::Instrument;

pub(super) struct RatsTlsSecurityLayer {
    tls_config_generator: TlsConfigGenerator,
    multiplex: bool,
}

impl RatsTlsSecurityLayer {
    pub async fn new(
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        multiplex: bool,
    ) -> Result<Self> {
        let tls_config_generator = TlsConfigGenerator::new(ra_context, runtime).await?;

        Ok(Self {
            tls_config_generator,
            multiplex,
        })
    }

    pub async fn handshake<T: CommonStreamTrait + std::marker::Sync>(
        &self,
        stream: T,
    ) -> Result<(
        tokio_rustls::server::TlsStream<T>,
        Option<AttestationResult>,
    )> {
        async {
            // Prepare TLS config
            let alpn = if self.multiplex {
                Alpn::Http2
            } else {
                Alpn::RatsTls
            };
            let tls_server_config = self
                .tls_config_generator
                .get_lazy_one_time_rustls_server_config(alpn)
                .await?;

            tracing::debug!("Start to estabilish rats-tls connection");

            let (security_layer_stream, attestation_result) =
                tls_server_config.handshake_with_stream(stream).await?;

            tracing::debug!("New rats-tls connection established");
            Ok((security_layer_stream, attestation_result))
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}
