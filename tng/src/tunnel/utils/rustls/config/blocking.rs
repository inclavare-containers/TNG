//! Cert plumbing and config builders for the QUIC (blocking) handshake path.
//!
//! QUIC handshakes run inside the qproto driver where the cert resolver is
//! invoked synchronously and `block_in_place` is available, so the blocking
//! fetch here has a safe fallback under every `RefreshStrategy`. The lazy TCP
//! rats-tls path must instead await [`CertManager::get_latest_cert`] before
//! the handshake and install a snapshot resolver
//! ([`super::resolver`]); that is why [`SyncCertFetcher`] and
//! [`DynamicCertResolver`] are visibility-restricted to this module: code
//! outside it cannot construct the blocking fetcher at all.

use std::sync::Arc;

use anyhow::Result;
use rustls::ServerConfig;

#[cfg(unix)]
use crate::tunnel::utils::cert_manager::CertManager;
#[cfg(unix)]
use crate::tunnel::utils::maybe_cached::SyncGet;
use crate::tunnel::utils::rustls::{
    config::{alpn::Alpn, TlsConfigGenerator, TlsConfigGeneratorMode},
    dummy::{verifier::DummyServerCertVerifier, RustlsDummyCert},
};

/// A blocking cert fetcher over a [`CertManager`].
///
/// The only way to serve a sync cert fetch for `RefreshStrategy::Always`,
/// which has no resident value: the `NeedsBlocking` branch parks the caller
/// via `block_in_place` while the attestation round trip runs. On the lazy
/// TCP path that parking is exactly what must never happen, so construction
/// is restricted to this module (the QUIC config builders); the lazy builders
/// await the cert instead.
#[cfg(unix)]
#[derive(Debug)]
pub struct SyncCertFetcher(Arc<CertManager>);

#[cfg(unix)]
impl SyncCertFetcher {
    pub(in crate::tunnel::utils::rustls::config::blocking) fn new(
        cert_manager: Arc<CertManager>,
    ) -> Self {
        Self(cert_manager)
    }

    /// Blocking call to get the latest certificate.
    ///
    /// For `UpdatePeriodically` strategy, this is a cheap `watch::Receiver::borrow().clone()`
    /// that returns the most recently refreshed certificate without blocking.
    ///
    /// For `NoCache` strategy, other code running concurrently **in the same task** will be suspended
    ///
    /// # Note
    /// This method is called from within rustls's `ResolvesServerCert` / `ResolvesClientCert`
    /// trait implementations, which are synchronous and invoked during the TLS handshake.
    /// Only the `NeedsBlocking` fallback parks the caller with `block_in_place`, which tells the
    /// tokio runtime to move other tasks off the current worker thread before blocking, preventing
    /// the thread from being starved. The `Ready` fast path must not go through `block_in_place`:
    /// it detaches the worker core and makes tokio spawn a replacement thread per call, churning
    /// threads (and the glibc arenas they touch) once per full handshake under short-connection
    /// load, even though the value is already resident.
    pub(in crate::tunnel::utils::rustls::config::blocking) fn get_latest_cert_blocking(
        &self,
    ) -> Result<Arc<rustls::sign::CertifiedKey>> {
        match self.0.try_get_latest_cert() {
            SyncGet::Ready(cert) => Ok(cert),
            SyncGet::NeedsBlocking => tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(self.0.get_latest_cert())
            }),
        }
    }
}

/// A dynamic certificate resolver that always returns the latest certificate
/// from the [`SyncCertFetcher`]. Unlike [`super::resolver::SnapshotCertResolver`]
/// which captures a snapshot at creation time, this resolver queries the cert
/// manager on every handshake, ensuring attestation freshness — at the cost of
/// a possible `block_in_place`, so it is QUIC-path-only.
#[cfg(unix)]
#[derive(Debug)]
pub struct DynamicCertResolver {
    fetcher: SyncCertFetcher,
}

#[cfg(unix)]
impl DynamicCertResolver {
    pub(in crate::tunnel::utils::rustls::config::blocking) fn new(
        fetcher: SyncCertFetcher,
    ) -> Self {
        Self { fetcher }
    }
}

#[cfg(unix)]
impl rustls::server::ResolvesServerCert for DynamicCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        match self.fetcher.get_latest_cert_blocking() {
            Ok(v) => Some(v),
            Err(error) => {
                tracing::error!(?error, "DynamicCertResolver: failed to get server cert");
                None
            }
        }
    }
}

#[cfg(unix)]
impl rustls::client::ResolvesClientCert for DynamicCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        match self.fetcher.get_latest_cert_blocking() {
            Ok(v) => Some(v),
            Err(error) => {
                tracing::error!(?error, "DynamicCertResolver: failed to get client cert");
                None
            }
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// One-time server config for the blocking (QUIC/UDP) path, built per tunnel
/// by `get_blocking_one_time_rustls_server_config`.
pub struct BlockingOnetimeTlsServerConfig(pub rustls::ServerConfig);

/// One-time client config for the blocking (QUIC/UDP) path, built per tunnel
/// by `get_blocking_one_time_rustls_client_config`.
pub struct BlockingOnetimeTlsClientConfig(pub rustls::ClientConfig);

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
                            SyncCertFetcher::new(cert_manager.clone()),
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
                            SyncCertFetcher::new(cert_manager.clone()),
                        )));
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
        };
        // Same brotli-LRU rationale as the lazy path; the blocking builder
        // also assigns a fresh empty cache per config.
        config.0.cert_compression_cache = self.server_cert_compression_cache.clone();
        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }

    pub async fn get_blocking_one_time_rustls_client_config(
        &self,
        alpn: Alpn,
    ) -> Result<BlockingOnetimeTlsClientConfig> {
        use crate::tunnel::utils::rustls::ra::server_cert_verifier::BlockingServerCertVerifier;

        let mut config = match &self.mode {
            TlsConfigGeneratorMode::NoRa => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth();

                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                BlockingOnetimeTlsClientConfig(tls_client_config)
            }
            TlsConfigGeneratorMode::Verify(verify_ctx, cache) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth();

                let verifier: Arc<BlockingServerCertVerifier> = Arc::new(
                    BlockingServerCertVerifier::new(verify_ctx.clone(), cache.clone())?,
                );
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                BlockingOnetimeTlsClientConfig(tls_client_config)
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::Attest(cert_manager) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        DynamicCertResolver::new(SyncCertFetcher::new(cert_manager.clone())),
                    ));
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                BlockingOnetimeTlsClientConfig(tls_client_config)
            }
            #[cfg(unix)]
            TlsConfigGeneratorMode::AttestAndVerify(cert_manager, verify_ctx, cache) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        DynamicCertResolver::new(SyncCertFetcher::new(cert_manager.clone())),
                    ));

                let verifier: Arc<BlockingServerCertVerifier> = Arc::new(
                    BlockingServerCertVerifier::new(verify_ctx.clone(), cache.clone())?,
                );
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                BlockingOnetimeTlsClientConfig(tls_client_config)
            }
        };
        // Same brotli-LRU rationale as the lazy client path.
        config.0.cert_compression_cache = self.client_cert_compression_cache.clone();
        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use crate::{
        config::ra::{AttestArgs, AttesterArgs, CocoAttesterArgs},
        tests::run_test_with_tokio_runtime,
        tunnel::ra_context::AttestContext,
    };

    use super::*;

    /// Regression test for the per-handshake thread churn: on the periodic
    /// strategy the blocking getter must serve the watch snapshot without
    /// touching tokio's blocking machinery. `flavor = "current_thread"` is
    /// load-bearing — `block_in_place` panics on that runtime, so this test
    /// passing *is* proof the fast path does not go through it. A long
    /// refresh interval keeps the background refresh from racing the ptr_eq
    /// comparison.
    #[tokio::test(flavor = "current_thread")]
    async fn test_get_latest_cert_blocking_periodic_no_block_in_place() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let attest_ctx = AttestContext::from_attest_args(&AttestArgs::BackgroundCheck {
                attester: AttesterArgs::Coco(CocoAttesterArgs::Uds {
                    aa_addr:
                        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                            .to_owned(),
                }),
                refresh_interval: Some(600),
            }).await?;
            let fetcher = SyncCertFetcher::new(Arc::new(
                CertManager::new(Arc::new(attest_ctx), runtime).await?,
            ));

            let blocking_cert = fetcher.get_latest_cert_blocking()?;
            let async_cert = fetcher.0.get_latest_cert().await?;
            assert!(
                Arc::ptr_eq(&blocking_cert, &async_cert),
                "the sync fast path must return the same watch value as the async getter"
            );

            Ok(())
        })
        .await
    }

    /// The `Always` strategy reports `NeedsBlocking`, so the fetcher takes
    /// its `block_in_place` + `block_on` fallback and still returns a fresh
    /// cert — the QUIC path's contract under `refresh_interval: 0`. Needs a
    /// multi_thread runtime: `block_in_place` panics elsewhere, which is the
    /// very reason the lazy TCP path never calls this fetcher.
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_sync_cert_fetcher_always_fallback_returns_fresh_cert() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let attest_ctx = AttestContext::from_attest_args(&AttestArgs::BackgroundCheck {
                attester: AttesterArgs::Coco(CocoAttesterArgs::Uds {
                    aa_addr:
                        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                            .to_owned(),
                }),
                refresh_interval: Some(0),
            })
            .await?;
            let fetcher = SyncCertFetcher::new(Arc::new(
                CertManager::new(Arc::new(attest_ctx), runtime).await?,
            ));

            assert!(
                matches!(fetcher.0.try_get_latest_cert(), SyncGet::NeedsBlocking),
                "Always must reach the blocking fallback"
            );

            let first = fetcher.get_latest_cert_blocking()?;
            let second = fetcher.get_latest_cert_blocking()?;
            assert!(
                !Arc::ptr_eq(&first, &second),
                "the Always fallback must fetch a new cert per call, not reuse one"
            );

            Ok(())
        })
        .await
    }
}
