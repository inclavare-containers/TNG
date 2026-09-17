use std::sync::Arc;

use anyhow::{Context as _, Result};
use rustls::ServerConfig;

#[cfg(unix)]
use crate::tunnel::utils::cert_manager::DynamicCertResolver;
use crate::tunnel::utils::rustls::{
    config::{alpn::Alpn, TlsConfigGenerator, TlsConfigGeneratorMode},
    dummy::RustlsDummyCert,
    early_data_prefix::EarlyDataPrefixStream,
};

/// Upper bound on accepted 0-RTT early data. The first proxied request should
/// fit; overflow is delivered as normal 1-RTT by the client write path.
const MAX_EARLY_DATA_SIZE: u32 = 1 << 17; // 128 KiB

impl TlsConfigGenerator {
    pub async fn get_lazy_one_time_rustls_server_config(
        &self,
        alpn: Alpn,
    ) -> Result<LazyOnetimeTlsServerConfig> {
        // The client-cert verifier is a shared Arc from the generator (built
        // once, not per handshake) so the verdict cache is shared across
        // connections. The server cert resolver (RustlsDummyCert /
        // DynamicCertResolver) does not gate resumption and stays per-handshake.
        let mut config = match &self.mode {
            TlsConfigGeneratorMode::NoRa => {
                let tls_server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(self.server_client_cert_verifier.clone())
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                LazyOnetimeTlsServerConfig(tls_server_config, None)
            }
            TlsConfigGeneratorMode::Verify(..) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(self.server_client_cert_verifier.clone())
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                LazyOnetimeTlsServerConfig(
                    tls_server_config,
                    self.server_lazy_client_verifier.clone(),
                )
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::Attest(cert_manager) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(self.server_client_cert_verifier.clone())
                        .with_cert_resolver(Arc::new(DynamicCertResolver::new(
                            cert_manager.clone(),
                        )));
                LazyOnetimeTlsServerConfig(tls_server_config, None)
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::AttestAndVerify(cert_manager, ..) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(self.server_client_cert_verifier.clone())
                        .with_cert_resolver(Arc::new(DynamicCertResolver::new(
                            cert_manager.clone(),
                        )));
                LazyOnetimeTlsServerConfig(
                    tls_server_config,
                    self.server_lazy_client_verifier.clone(),
                )
            }
        };
        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        // Enable TLS 1.3 0-RTT early data. rustls only accepts early data with
        // stateful resumption (the default ticketer); installing a real ticketer
        // (stateless tickets) silently disables 0-RTT, so do not add one.
        config.0.max_early_data_size = MAX_EARLY_DATA_SIZE;
        // Shared across handshakes: connection A stores the resumption secret
        // that connection B looks up to accept its 0-RTT.
        config.0.session_storage = self.server_session_store.clone();

        Ok(config)
    }
}

pub struct LazyOnetimeTlsServerConfig(
    pub rustls::ServerConfig,
    pub Option<Arc<crate::tunnel::utils::rustls::ra::client_cert_verifier::LazyClientCertVerifier>>,
);

impl LazyOnetimeTlsServerConfig {
    /// Perform TLS handshake then verify the peer certificate if a verifier was configured.
    pub async fn handshake_with_stream<S>(
        self,
        stream: S,
    ) -> Result<(
        EarlyDataPrefixStream<tokio_rustls::server::TlsStream<S>>,
        crate::tunnel::attestation_result::AttestationState,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        use std::io::Read as _;
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(self.0));
        let mut tls_stream = tls_acceptor
            .accept(stream)
            .await
            .context("Failed to accept TLS connection")?;

        // Drain accepted 0-RTT early data. tokio-rustls's server AsyncRead does
        // not deliver accepted early-data bytes, so without this the client's
        // early data would be stranded and lost. `handshake_kind()` is read
        // after the drain on purpose: it reflects handshake state set on
        // `accept()`, which the drain (consuming only the early-data buffer)
        // does not alter, so the value is identical before and after.
        let mut early = Vec::new();
        if let Some(mut rd) = tls_stream.get_mut().1.early_data() {
            // Unreachable in normal operation: early_data() yields a std::Read
            // backed by an in-memory buffer. Log instead of swallowing silently.
            if let Err(error) = rd.read_to_end(&mut early) {
                tracing::warn!(?error, "drain early data failed; accepted 0-RTT bytes lost");
            }
        }

        // RA modes (verifier present): full handshake freshly verifies the peer
        // cert fetched via peer_certificates(); resumed trusts the PSK binding.
        // No-ra / no-client-auth (no verifier) is always Unattested, even when
        // resumed, so its access-log bool stays false.
        let handshake_kind = tls_stream.get_mut().1.handshake_kind();
        let attestation_state = crate::tunnel::utils::rustls::ra::common::classify_attestation(
            self.1.as_ref().map(|v| v.lazy_verifier()),
            handshake_kind,
            tls_stream.get_mut().1.peer_certificates(),
        )
        .await?;

        Ok((
            EarlyDataPrefixStream::new(early, tls_stream),
            attestation_state,
        ))
    }
}

#[cfg(not(wasm))]
impl TlsConfigGenerator {
    pub async fn get_blocking_one_time_rustls_server_config(
        &self,
        alpn: Alpn,
    ) -> Result<BlockingOnetimeTlsServerConfig> {
        use crate::tunnel::utils::rustls::ra::client_cert_verifier::BlockingClientCertVerifier;

        let mut config = match &self.mode {
            TlsConfigGeneratorMode::NoRa => {
                let tls_server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            TlsConfigGeneratorMode::Verify(verify_ctx, cache) => {
                let verifier = Arc::new(BlockingClientCertVerifier::new(
                    verify_ctx.clone(),
                    cache.clone(),
                )?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::Attest(cert_manager) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(DynamicCertResolver::new(
                            cert_manager.clone(),
                        )));
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::AttestAndVerify(cert_manager, verify_ctx, cache) => {
                let verifier = Arc::new(BlockingClientCertVerifier::new(
                    verify_ctx.clone(),
                    cache.clone(),
                )?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(Arc::new(DynamicCertResolver::new(
                            cert_manager.clone(),
                        )));
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
        };
        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

#[cfg(not(wasm))]
pub struct BlockingOnetimeTlsServerConfig(pub rustls::ServerConfig);
