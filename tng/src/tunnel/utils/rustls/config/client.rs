#[cfg(not(wasm))]
use std::sync::Arc;

#[cfg(not(wasm))]
use anyhow::{Context as _, Result};
#[cfg(not(wasm))]
use rustls::RootCertStore;

#[cfg(all(unix, not(wasm)))]
use crate::tunnel::utils::rustls::config::TlsConfigGeneratorMode;
#[cfg(not(wasm))]
use crate::tunnel::utils::rustls::config::{alpn::Alpn, TlsConfigGenerator};

#[cfg(not(wasm))]
impl TlsConfigGenerator {
    pub async fn get_lazy_one_time_rustls_client_config(
        &self,
        alpn: Alpn,
    ) -> Result<LazyOnetimeTlsClientConfig> {
        // The verifier and resolver are shared Arcs from the generator (built
        // once, not per handshake) so rustls's resumption ptr-eq check passes.
        //
        // Attest modes present a cert and rustls calls `resolve()`
        // synchronously mid-handshake; the lazy TCP path must not block there
        // (the sync fetch is QUIC-only, see `super::blocking`), so the
        // freshest cert is awaited now and published into the shared
        // resolver. Under `RefreshStrategy::Always` this await is a real
        // attestation round trip. Concurrent handshakes may overwrite each
        // other's stored cert; under `Always` every stored value was just
        // fetched, so whichever one a `resolve()` sees is equally fresh.
        #[cfg(unix)]
        match &self.mode {
            TlsConfigGeneratorMode::Attest(cert_manager)
            | TlsConfigGeneratorMode::AttestAndVerify(cert_manager, ..) => {
                let cell = self.client_cert_cell.as_deref().context(
                    "attest modes must wire the swappable client cert resolver (build_shared_verifiers)",
                )?;
                cell.store(cert_manager.get_latest_cert().await?);
            }
            TlsConfigGeneratorMode::NoRa | TlsConfigGeneratorMode::Verify(..) => {}
        }

        let mut tls_client_config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(RootCertStore::empty())
                .with_client_cert_resolver(self.client_cert_resolver.clone());
        tls_client_config
            .dangerous()
            .set_certificate_verifier(self.client_server_cert_verifier.clone());

        // Carry the brotli LRU across handshakes for the client-presented
        // cert (Attest/AttestAndVerify). The builder assigns a fresh empty
        // cache per config, so overwrite with the generator-shared one.
        tls_client_config.cert_compression_cache = self.client_cert_compression_cache.clone();

        let mut config =
            LazyOnetimeTlsClientConfig(tls_client_config, self.client_lazy_server_verifier.clone());

        // Offer 0-RTT when a resumption ticket is available. The shared store
        // keeps tickets across handshakes so connection N+1 to the same server
        // can resume.
        config.0.resumption = rustls::client::Resumption::store(self.client_session_store.clone());
        config.0.enable_early_data = true;

        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

#[cfg(not(wasm))]
pub struct LazyOnetimeTlsClientConfig(
    pub rustls::ClientConfig,
    Option<Arc<crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier>>,
);

#[cfg(not(wasm))]
impl LazyOnetimeTlsClientConfig {
    /// Perform the TLS handshake then classify attestation from the negotiated
    /// handshake kind, mirroring the non-multiplex `connect_early` +
    /// `forward_stream` path.
    ///
    /// The verifier is a no-op during the handshake (stateless, so it can be
    /// shared across handshakes for resumption). After `connect().await` the
    /// handshake is complete, so `handshake_kind()` is valid here (unlike the
    /// 0-RTT path, which must prime first). On a full handshake the peer cert is
    /// fetched via `peer_certificates()` and RA-verified with `verify_cert`; on
    /// a resumed handshake rustls presents no peer cert, so verify is skipped
    /// and the PSK binding is trusted (`Resumed`). Multiplex reuses one
    /// long-lived connection, but a reconnect can resume if a ticket is cached,
    /// so the branch is kept for consistency with the non-multiplex path.
    ///
    /// Takes the peer as an `EndpointAddr` rather than a pre-formatted string so that
    /// IPv4 addresses become `ServerName::IpAddress` directly (no allocation) and
    /// domains become `ServerName::DnsName` from the borrowed string.
    pub async fn handshake_with_stream<S>(
        self,
        server_name: &crate::tunnel::endpoint::EndpointAddr,
        stream: S,
    ) -> Result<(
        tokio_rustls::client::TlsStream<S>,
        crate::tunnel::attestation_result::AttestationState,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        use rustls::pki_types::{DnsName, IpAddr, ServerName};

        // Build the borrowing `ServerName` from the structured address: IPv4 →
        // `IpAddress` (no string allocation), domain → `DnsName` from the
        // borrowed string. `to_owned()` then lifts it to `ServerName<'static>`
        // (a cheap IpAddr copy for IPv4; an owned copy of the DNS name for
        // domains, which is unavoidable for the async connect future).
        let server_name = match server_name {
            crate::tunnel::endpoint::EndpointAddr::Ipv4(ip) => {
                ServerName::IpAddress(IpAddr::V4((*ip).into()))
            }
            crate::tunnel::endpoint::EndpointAddr::Domain(d) => ServerName::DnsName(
                DnsName::try_from(d.as_str())
                    .with_context(|| format!("Invalid server name for TLS handshake ({d})"))?,
            ),
        };

        let tls_stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(self.0))
            .connect(server_name.to_owned(), stream)
            .await
            .context("Failed to establish TLS connection")?;

        // After `connect().await` the handshake is complete, so `handshake_kind()`
        // is valid here (unlike the 0-RTT path, which must prime first).
        let attestation_state = crate::tunnel::utils::rustls::ra::common::classify_attestation(
            self.1.as_ref().map(|v| v.lazy_verifier()),
            tls_stream.get_ref().1.handshake_kind(),
            tls_stream.get_ref().1.peer_certificates(),
        )
        .await?;

        Ok((tls_stream, attestation_state))
    }

    /// Start a client TLS connection that may carry 0-RTT early data.
    ///
    /// With a resumption ticket, `connect()` returns immediately in tokio-rustls's
    /// `EarlyData` state: the handshake is NOT complete. The caller must perform
    /// the first write (the early-data chunk) to drive the handshake; tokio-rustls
    /// replays the chunk as 1-RTT if the server rejects 0-RTT. Without a ticket,
    /// `connect()` completes a normal 1-RTT handshake before returning.
    ///
    /// Returns the shared lazy verifier handle; the caller primes the handshake,
    /// reads `handshake_kind()` off the stream, and verifies the peer cert
    /// (fetched via `peer_certificates()`) only on a full handshake. On a resumed
    /// handshake rustls presents no fresh cert, so the verifier must be skipped
    /// and the PSK binding trusted instead.
    pub async fn connect_early<S>(
        self,
        server_name: &crate::tunnel::endpoint::EndpointAddr,
        stream: S,
    ) -> Result<(
        tokio_rustls::client::TlsStream<S>,
        Option<Arc<crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier>>,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        use rustls::pki_types::{DnsName, IpAddr, ServerName};

        let server_name = match server_name {
            crate::tunnel::endpoint::EndpointAddr::Ipv4(ip) => {
                ServerName::IpAddress(IpAddr::V4((*ip).into()))
            }
            crate::tunnel::endpoint::EndpointAddr::Domain(d) => ServerName::DnsName(
                DnsName::try_from(d.as_str())
                    .with_context(|| format!("Invalid server name for TLS handshake ({d})"))?,
            ),
        };

        // early_data(true) gates the 0-RTT attempt; only this path sets it so
        // the multiplex handshake_with_stream path stays plain 1-RTT.
        let connector =
            tokio_rustls::TlsConnector::from(std::sync::Arc::new(self.0)).early_data(true);
        let tls_stream = connector
            .connect(server_name.to_owned(), stream)
            .await
            .context("Failed to establish TLS connection")?;

        Ok((tls_stream, self.1))
    }
}
