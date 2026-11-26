use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing::Instrument;

use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::{
    config::egress::{OHttpArgs, OHttpTlsArgs},
    tunnel::{
        connection_fault::{classify_boxed_failure, ConnectionFault, DownstreamSetupError},
        egress::protocol::ohttp::security::{context::TngStreamContext, server::OhttpServer},
        ra_context::RaContext,
        stream::FirstByteReadTimeoutStream,
        upstream::UpstreamConnector,
    },
    CommonStreamTrait, TokioRuntime,
};

mod api;
pub mod context;
pub mod cors_fallback;
#[allow(dead_code)]
pub mod key_manager;
pub mod server;

/// Timeout before receiving the first TLS handshake byte from downstream.
const OHTTP_TLS_HANDSHAKE_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);

/// Load the PEM server certificate chain and private key from `tls` and build
/// a `tokio_rustls::TlsAcceptor` for the egress OHTTP listener.
fn build_ohttp_tls_acceptor(tls: &OHttpTlsArgs) -> Result<TlsAcceptor> {
    if tls.cert_file.trim().is_empty() {
        bail!("Egress OHTTP TLS `cert_file` must not be empty");
    }
    if tls.key_file.trim().is_empty() {
        bail!("Egress OHTTP TLS `key_file` must not be empty");
    }

    let cert_bytes = std::fs::read(&tls.cert_file)
        .with_context(|| format!("Failed to read egress OHTTP TLS cert file: {}", tls.cert_file))?;
    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!("Failed to parse egress OHTTP TLS cert PEM: {}", tls.cert_file)
        })?;
    if certs.is_empty() {
        bail!(
            "No certificates found in egress OHTTP TLS cert file: {}",
            tls.cert_file
        );
    }

    let key_bytes = std::fs::read(&tls.key_file)
        .with_context(|| format!("Failed to read egress OHTTP TLS key file: {}", tls.key_file))?;
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .with_context(|| format!("Failed to parse egress OHTTP TLS key PEM: {}", tls.key_file))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No private key found in egress OHTTP TLS key file: {}",
                tls.key_file
            )
        })?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            anyhow::Error::from(e).context(format!(
                "Failed to build egress OHTTP TLS ServerConfig from {} and {}",
                tls.cert_file, tls.key_file
            ))
        })?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Hyper reports an incomplete message when a request was only partially read.
/// That verdict has no io source of its own, so it belongs at this boundary
/// where hyper's error type is in scope.
fn incomplete_message_fault(error: &(dyn std::error::Error + 'static)) -> Option<ConnectionFault> {
    let mut node = Some(error);
    while let Some(current) = node {
        if let Some(hyper_error) = current.downcast_ref::<hyper::Error>() {
            if hyper_error.is_incomplete_message() {
                return Some(ConnectionFault::PeerVanished);
            }
        }
        node = current.source();
    }
    None
}

pub struct OHttpSecurityLayer {
    runtime: TokioRuntime,
    ohttp_server: OhttpServer,
    tls_acceptor: Option<TlsAcceptor>,
}

impl OHttpSecurityLayer {
    pub async fn new(
        ra_context: Arc<RaContext>,
        ohttp_args: OHttpArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let tls_acceptor = ohttp_args
            .tls
            .as_ref()
            .map(build_ohttp_tls_acceptor)
            .transpose()?;
        if let Some(tls) = &ohttp_args.tls {
            tracing::info!(
                cert_file = %tls.cert_file,
                "Egress OHTTP native TLS listener enabled"
            );
        }
        Ok(Self {
            runtime: runtime.clone(),
            ohttp_server: OhttpServer::new(ra_context, ohttp_args, runtime).await?,
            tls_acceptor,
        })
    }

    /// Returns `true` when native TLS termination is enabled on this egress.
    pub(crate) fn has_tls(&self) -> bool {
        self.tls_acceptor.is_some()
    }

    /// Terminate TLS on the accepted TCP stream if native TLS is configured.
    pub(crate) async fn accept_tls(
        &self,
        stream: Box<dyn CommonStreamTrait + Sync>,
    ) -> Result<Box<dyn CommonStreamTrait + Sync>> {
        let Some(acceptor) = &self.tls_acceptor else {
            return Ok(stream);
        };
        let timed = Box::pin(FirstByteReadTimeoutStream::new(
            stream,
            OHTTP_TLS_HANDSHAKE_FIRST_BYTE_TIMEOUT,
        ));
        let tls_stream = acceptor.accept(timed).await.map_err(|e| {
            DownstreamSetupError::tag(
                anyhow::Error::from(e).context("Failed to accept egress OHTTP TLS connection"),
            )
        })?;
        Ok(Box::new(tls_stream))
    }

    pub async fn handle_http_stream(
        &self,
        stream: impl CommonStreamTrait,
        connector: Arc<UpstreamConnector>,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<()> {
        async {
            let access_connector = Arc::clone(&connector);
            let state = TngStreamContext {
                runtime: self.runtime.clone(),
                connector,
                peer_addr: peer,
                backend: Arc::default(),
            };
            let app = self
                .ohttp_server
                .create_routes(state.clone())
                .with_state(state);

            let hyper_service = hyper::service::service_fn(
                move |request: axum::extract::Request<hyper::body::Incoming>| {
                    app.clone().call(request)
                },
            );

            hyper_util::server::conn::auto::Builder::new(self.runtime.clone())
                .serve_connection_with_upgrades(TokioIo::new(stream), hyper_service)
                .await
                .map_err(|error| {
                    // Keep the boxed chain so the log shows the underlying
                    // cause. Hyper's own verdict is not visible to the generic
                    // io walk, so it is added here before tagging.
                    let fault = incomplete_message_fault(&*error)
                        .unwrap_or_else(|| classify_boxed_failure(&*error));
                    DownstreamSetupError::tag_boxed_with_fault(fault, error)
                        .context("failed to serve egress OHTTP security layer connection")
                })?;

            // The HTTP connection ended normally. That covers an idle close, a
            // key-config request, and a completed exchange; hyper reports Ok
            // for all of them. Record it as a per-connection event so the
            // access-log line stays at debug. A connection that dialled a
            // backend has already emitted its own access-log line, so this
            // fault no longer prints.
            access_connector
                .record_fault(ConnectionFault::PeerVanished)
                .await;

            Ok(())
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}

#[async_trait]
impl StatusProvider for OHttpSecurityLayer {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        self.ohttp_server.query_status(path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ra::RaArgs;
    use crate::tunnel::access_log::{AccessAccepted, EgressAccessMode};
    use crate::tunnel::endpoint::TngEndpoint;
    use crate::tunnel::service_metrics::ServiceMetricsCreator;
    use http::{Method, StatusCode};
    use hyper_util::server::conn::auto::Builder as HyperAutoBuilder;
    use indexmap::IndexMap;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    // Self-signed CA + server cert (SANs include 127.0.0.1 and localhost) + PKCS#8 private key.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIUEsAXd1ToLzGHTGdqammdyAsqJT8wDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVVE5HIFRlc3QgT0hUVFAgVExTIENBMB4XDTI2MDcxNDAz
MjYxOVoXDTM2MDcxMTAzMjYxOVowIDEeMBwGA1UEAwwVVE5HIFRlc3QgT0hUVFAg
VExTIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmRJ2TgQ18bHT
qMRrSVL7erjDdWcX/3xDQxVfQjKAX6JAdAPMcXgZgkq0BqEGjprb5G2uYzIlt/52
PKaZGoVl3mhY0gHEdyyX+ebRz9CVujNxJ44qXGKbybJemy/YeQee13gw3SVvzzTs
c2FXcW5GkkcryRCmP9GrqS2ryBRxywv0/o/zEPU2h2b/Tp7gA/bePhP5KhVvbrOx
LH6Y26FcH6HsRvAHIvlOxavnKNuxJp+3wZwZqcrEIkyQNuOC7l5iBNcG98jrHxdU
5v7l+lvzSmLeqVmBFyJm4pG6TGhK0hsZV5DlwQWkQzF8gMjsTmc2qUav1QD+wc7i
nWS4//FMwQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
hjAdBgNVHQ4EFgQUXbBOl4YFai2wa48MfhCT+BbsT1YwHwYDVR0jBBgwFoAUXbBO
l4YFai2wa48MfhCT+BbsT1YwDQYJKoZIhvcNAQELBQADggEBAG5R4bwlheWrZKGY
iPQeFYKwLMSTYKqhB6E5O6IzK1h6mpv8DWSr15Al/KIJDzufsm19G1ILtJmpRUkx
lwD24s/lMuK/ZGnM5rjQl6SGlK6lPowIwoateFEgQ+etUxm6Rytmt3JxAMzLUIqH
xny8Sa0tgH0iTidjTPp/y7FxH5Oy3Q9avNIvPDlzc0uwKg1w16Jmn/WfjmIgFK+Z
WvhTpXETb+WAf2hCxDYOtUy595MhcUKhyV46GseFr+xUMNhLg+dkO7r+BYD5DPXV
W39KadJMXmq0w8WODC8qdcjnbQvAqt0wuB80fdba8E7TGjRIoNZWEbcJv3F+WWIg
XNGNEe0=
-----END CERTIFICATE-----
";

    const TEST_SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDbjCCAlagAwIBAgIUFDdi7UCCeQJRPdHD3TtEZk8+ESYwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVVE5HIFRlc3QgT0hUVFAgVExTIENBMB4XDTI2MDcxNDAz
MjYxOVoXDTM2MDcxMTAzMjYxOVowITEfMB0GA1UEAwwWdG5nLXRlc3Qtb2h0dHAt
Z2F0ZXdheTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMUHwa4YC8F0
TnjVUiVUTh4+s+NLQHeype4LN+FF5ZkMbNQMc5hMCbEMsNRBYE4BHH8GAqpw7AGX
QgUjDxMzUx3pEzFuKF9k5syDVlf9/eb38c12CANsBcfTV+rE/lHl/BREt+0vDJYI
r8JTLsKf+hQqY5+867TL8AkBdo6OrRXACAR3y1iBuuiG+81nFmB7Z4lDi/Z4DUfR
EAlpl1vdxKaxRmUAtSbpcAi8dXGT5iifvIrnJRO8ZU39fgB7faK2GnUUpm+eKFDr
xeslFwIbroIsUmmyR8vFi7sISMNJKtYwLS3U8DbliArBe2GtydcmAdjBahHvKb8O
8MlQ7p7lavECAwEAAaOBnjCBmzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUHpXANNMmD16HM7/W7j58
UpSMcYowHwYDVR0jBBgwFoAUXbBOl4YFai2wa48MfhCT+BbsT1YwJgYDVR0RBB8w
HYcEwKgBAYcEwKgB/IcEfwAAAYIJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IB
AQAmDIz7EMBy3RpWwxYP+t3ifD6p3kL8BHiCOkd2u5eaoM91UVQj3UQps0cpqO0V
yld19XogVMv5UacTUbYerqSTie36p1k2MWbdDufcs2UNQKyUqo+z0hOSerSiIhuL
8fFSGoPQLH/eC61X6CyFjbH8eRwXRFQlGP/OcZZerG4OdefA0h3oeNbFntk3TLPh
eLzm7NfUo636KkltJRQFMjTD2FWbPs/n1xNecSWSaUnK4Vec9CmsSnVfMOYpyoe5
MDBvL9KrboS3GpKN7eEiimj5+iEh6zvvSEiSZrW4UwE2YQ42m71OuUIcQ2BFBlFI
m1PN0+oGwGtCGQPVtmkRLPBe
-----END CERTIFICATE-----
";

    const TEST_SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFB8GuGAvBdE54
1VIlVE4ePrPjS0B3sqXuCzfhReWZDGzUDHOYTAmxDLDUQWBOARx/BgKqcOwBl0IF
Iw8TM1Md6RMxbihfZObMg1ZX/f3m9/HNdggDbAXH01fqxP5R5fwURLftLwyWCK/C
Uy7Cn/oUKmOfvOu0y/AJAXaOjq0VwAgEd8tYgbrohvvNZxZge2eJQ4v2eA1H0RAJ
aZdb3cSmsUZlALUm6XAIvHVxk+Yon7yK5yUTvGVN/X4Ae32ithp1FKZvnihQ68Xr
JRcCG66CLFJpskfLxYu7CEjDSSrWMC0t1PA25YgKwXthrcnXJgHYwWoR7ym/DvDJ
UO6e5WrxAgMBAAECggEBAImOx8a/HP38MIkmDcroF/3/suG+eQzYmgYeqO3LOefn
h9dnthCfDakhfhdCaXUsS3PXg2bxnaPisYIanvy9uYrJXdAF44PuU0B3dYHLX0ew
1Y2nmSKieUqwn9HVpOUS1zJjY7HhRj09ZVAbeSsCO7t2eMVeRYWdWEFBVz9iFy91
/Y5yIryuL5r0J/Eu5EiHUszek+eFtrBsVpIaJOQQ4mV7baAnRZ15hsNRMspD+jPw
oJopcV/rqFwWv5/cQkSmEfOtFv4QPCGjTcaqNH6jyxckiyl/pJwXW94PBtV6PuGd
BDuOSWUhry9AkGcuBUhRTYzrvsI6m6Pe9j/QvRtK4tECgYEA/QWW/V1WPJQwRriF
u2SJAJvt0a6cLSKC0gucy1/u0vPMfPBMqbRs6sygmZlj5NdMJf9mqpefBqQgFYFA
G+XdLs0beypTW1oB2lnF4T4WVdVbt7WVrvMPUS2u9FclVQlUkqREQgtPNn8rvxOV
KrrJbNqenfQiUzPhO8YY1YkgOzUCgYEAx1lztkJgy6yXGdn88oolfQJxWI69G33G
HYyNh0VB4GFTLn43JJH8Tb/47x9QC5F2kKj/oLgZRcz6hUqIfGpNWuXPKGwFBisu
Eh4hpxrWT4LCWLRad1V4PePZNzavS2cVxTOmmKezdKM2zR6ZA21z2jf24NRNTOXh
r9mAtHg8rE0CgYBW+Jfo6S9eTVW2yXB2dF0/T1nUzF80iHtNNd6kbYpLCrBMddD0
OGeD4eiGQ5p5q6OqH/srQkjQYJQCsFXYARAhKTF8CZVzfiHK6zbAcLX+tQL8x7b2
1ud58OkFZfsYGsfuS/aGeRq2Uco4uMN6V5ArEY6aHrO5w8h04mfg5mykzQKBgF5N
KHm9aMCwgkIOZqPtSdKbBzdXPon0s3Vi+chVsNYN9CV4O2mnTW0SNRYY/+qZAzdn
WpWSwRHN52yKV4pTVwh60cZTYwUKBB859b1w6pRuTLVdi7YLzneogyalTcMjnp7M
0jBAlJnGY7Qgl02Rx04hTz4H8BFCZcKj50h34Gu5AoGBALgGRmcM96wX1gVCSWI8
NtGfozayLcNOHiL1YSYSfAm9UFSHobyUPOjlyuIXGEhN04hUsQKd2Oy+UCvgC6/+
OTV43/3HqttFufj8/bdDFFQ2v8DHHXLsr96bXAxpPepqPtIbReqTLnhyCqsybmJ/
JEQQxVoms/nCE6mTyDNazvHk
-----END PRIVATE KEY-----
";

    #[test]
    fn build_tls_acceptor_valid_pem_succeeds() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cert_path = dir.path().join("egress.crt");
        let key_path = dir.path().join("egress.key");
        std::fs::write(&cert_path, TEST_SERVER_CERT_PEM)?;
        std::fs::write(&key_path, TEST_SERVER_KEY_PEM)?;

        let tls = OHttpTlsArgs {
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
        };
        let _acceptor = build_ohttp_tls_acceptor(&tls)?;
        Ok(())
    }

    #[test]
    fn build_tls_acceptor_rejects_empty_or_missing_or_invalid_files() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cert_path = dir.path().join("egress.crt");
        let key_path = dir.path().join("egress.key");
        std::fs::write(&cert_path, TEST_SERVER_CERT_PEM)?;
        std::fs::write(&key_path, TEST_SERVER_KEY_PEM)?;

        // Empty paths
        assert!(build_ohttp_tls_acceptor(&OHttpTlsArgs {
            cert_file: "  ".to_string(),
            key_file: key_path.to_string_lossy().to_string(),
        })
        .is_err());
        assert!(build_ohttp_tls_acceptor(&OHttpTlsArgs {
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: "".to_string(),
        })
        .is_err());

        // Non-existent cert file
        let err = build_ohttp_tls_acceptor(&OHttpTlsArgs {
            cert_file: "/definitely/missing/egress.crt".to_string(),
            key_file: key_path.to_string_lossy().to_string(),
        })
        .err()
        .unwrap();
        assert!(format!("{err:#}").contains("/definitely/missing/egress.crt"));

        // Non-existent key file
        let err = build_ohttp_tls_acceptor(&OHttpTlsArgs {
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: "/definitely/missing/egress.key".to_string(),
        })
        .err()
        .unwrap();
        assert!(format!("{err:#}").contains("/definitely/missing/egress.key"));

        // Empty cert PEM
        let empty_cert = dir.path().join("empty.crt");
        std::fs::write(&empty_cert, "not a certificate
")?;
        assert!(build_ohttp_tls_acceptor(&OHttpTlsArgs {
            cert_file: empty_cert.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
        })
        .is_err());

        // Empty key PEM
        let empty_key = dir.path().join("empty.key");
        std::fs::write(&empty_key, "not a private key
")?;
        assert!(build_ohttp_tls_acceptor(&OHttpTlsArgs {
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: empty_key.to_string_lossy().to_string(),
        })
        .is_err());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn egress_native_tls_serves_ohttp_and_forwards_direct_peer_ip() -> Result<()> {
        crate::tests::run_test_with_tokio_runtime(|runtime| async move {
            let dir = tempfile::tempdir()?;
            let cert_path = dir.path().join("egress.crt");
            let key_path = dir.path().join("egress.key");
            let ca_path = dir.path().join("ca.pem");
            std::fs::write(&cert_path, TEST_SERVER_CERT_PEM)?;
            std::fs::write(&key_path, TEST_SERVER_KEY_PEM)?;
            std::fs::write(&ca_path, TEST_CA_PEM)?;

            // Start an upstream HTTP server recording X-Real-IP and X-Forwarded-For headers.
            let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
            let backend_addr = backend_listener.local_addr()?;
            let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<(String, String)>();
            let seen_tx = Arc::new(tokio::sync::Mutex::new(Some(seen_tx)));
            let backend_rt = runtime.clone();
            runtime.spawn_supervised_task(async move {
                if let Ok((stream, _)) = backend_listener.accept().await {
                    let seen_tx = Arc::clone(&seen_tx);
                    let svc = hyper::service::service_fn(
                        move |req: http::Request<hyper::body::Incoming>| {
                            let seen_tx = Arc::clone(&seen_tx);
                            async move {
                                let real_ip = req
                                    .headers()
                                    .get("x-real-ip")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let xff = req
                                    .headers()
                                    .get("x-forwarded-for")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                if let Some(tx) = seen_tx.lock().await.take() {
                                    let _ = tx.send((real_ip, xff));
                                }
                                Ok::<_, std::convert::Infallible>(
                                    http::Response::builder()
                                        .status(StatusCode::OK)
                                        .body(http_body_util::Full::new(bytes::Bytes::from_static(
                                            b"ok",
                                        )))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let _ = HyperAutoBuilder::new(backend_rt)
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                }
            });

            // Build egress OHttpSecurityLayer with native TLS enabled.
            let egress_ra = Arc::new(RaContext::from_ra_args(&RaArgs::NoRa).await?);
            let egress_ohttp_args: OHttpArgs = serde_json::from_value(serde_json::json!({
                "tls": {
                    "cert_file": cert_path.to_string_lossy().as_ref(),
                    "key_file": key_path.to_string_lossy().as_ref(),
                }
            }))?;
            let egress_layer = Arc::new(
                OHttpSecurityLayer::new(egress_ra, egress_ohttp_args, runtime.clone()).await?,
            );
            assert!(egress_layer.has_tls());

            let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
            let egress_addr = egress_listener.local_addr()?;
            let metrics = ServiceMetricsCreator::new_creator(Arc::new(
                opentelemetry::metrics::noop::NoopMeterProvider::new(),
            ))
            .new_service_metrics(IndexMap::new());
            let egress_layer_srv = Arc::clone(&egress_layer);
            let srv_rt = runtime.clone();
            runtime.spawn_supervised_task(async move {
                loop {
                    let Ok((tcp, peer)) = egress_listener.accept().await else {
                        break;
                    };
                    let layer = Arc::clone(&egress_layer_srv);
                    let connector = Arc::new(UpstreamConnector::new(
                        Arc::new(TngEndpoint::new(
                            backend_addr.ip().to_string(),
                            backend_addr.port(),
                        )),
                        metrics.clone(),
                        AccessAccepted::new_egress(
                            peer,
                            egress_addr,
                            EgressAccessMode::Mapping,
                        ),
                        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                        None,
                    ));
                    srv_rt.spawn_supervised_task(async move {
                        let tls_stream = layer.accept_tls(Box::new(tcp)).await?;
                        layer
                            .handle_http_stream(tls_stream, connector, Some(peer))
                            .await
                    });
                }
            });

            // Plain HTTP to the TLS-enabled egress must fail cleanly at TLS accept.
            let mut plain_conn = tokio::net::TcpStream::connect(egress_addr).await?;
            plain_conn.write_all(b"GET / HTTP/1.1

").await?;
            drop(plain_conn);

            // Build ingress OHttpSecurityLayer with tls=true and tls_ca_certs=[ca_path].
            let ingress_ra = Arc::new(RaContext::from_ra_args(&RaArgs::NoRa).await?);
            let ingress_ohttp_args = crate::config::ingress::OHttpArgs {
                tls: Some(true),
                tls_ca_certs: vec![ca_path.to_string_lossy().to_string()],
                ..Default::default()
            };
            let ingress_layer =
                crate::tunnel::ingress::protocol::ohttp::security::OHttpSecurityLayer::new(
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    None,
                    &ingress_ohttp_args,
                    ingress_ra,
                    runtime.clone(),
                )
                .await?;

            let req = http::Request::builder()
                .method(Method::GET)
                .uri(format!("http://127.0.0.1:{}/native-tls", egress_addr.port()))
                .header(http::header::HOST, "example.com")
                .body(axum::body::Body::empty())?;

            let resp = ingress_layer
                .forward_http_request(&TngEndpoint::new("127.0.0.1", egress_addr.port()), req)
                .await?;
            assert_eq!(resp.0.status(), StatusCode::OK);

            let (real_ip, xff) = seen_rx.await?;
            assert_eq!(real_ip, "127.0.0.1");
            assert_eq!(xff, "127.0.0.1");
            Ok(())
        })
        .await
    }
}
