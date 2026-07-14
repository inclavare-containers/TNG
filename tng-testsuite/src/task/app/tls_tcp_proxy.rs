use anyhow::{Context as _, Result};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

/// Launch a TLS-terminating raw-TCP proxy: accept TLS on `listen_port`,
/// decrypt, and copy the stream bidirectionally to `upstream_host:upstream_port`.
///
/// This models a TLS-terminating gateway in front of a TNG egress: the gateway
/// terminates TLS, then forwards the raw OHTTP-over-HTTP bytes to the egress.
pub async fn launch_tls_tcp_proxy(
    token: CancellationToken,
    listen_port: u16,
    upstream_host: &str,
    upstream_port: u16,
    cert_pem: &str,
    key_pem: &str,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let cert = certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse gateway TLS cert PEM")?;
    let key = pkcs8_private_keys(&mut key_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("No PKCS#8 key found in gateway key PEM"))?
        .context("Failed to parse gateway TLS key PEM")?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, rustls::pki_types::PrivateKeyDer::Pkcs8(key))
        .map_err(|e| anyhow::Error::from(e).context("Failed to build rustls ServerConfig"))?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind TLS proxy on :{listen_port}"))?;
    tracing::info!(%listen_port, upstream_host, upstream_port, "TLS TCP proxy listening");

    let upstream_host = upstream_host.to_owned();
    let handle = tokio::task::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                accept = listener.accept() => {
                    let (tcp_stream, _peer) = match accept {
                        Ok(s) => s,
                        Err(error) => {
                            tracing::warn!(?error, "TLS proxy: accept failed");
                            continue;
                        }
                    };
                    let acceptor = acceptor.clone();
                    let host = upstream_host.clone();
                    tokio::spawn(async move {
                        // Terminate TLS, then forward the decrypted stream.
                        let tls_stream = match acceptor.accept(tcp_stream).await {
                            Ok(s) => s,
                            Err(error) => {
                                tracing::warn!(?error, "TLS proxy: TLS handshake failed");
                                return;
                            }
                        };
                        let upstream = match tokio::net::TcpStream::connect((host.as_str(), upstream_port)).await {
                            Ok(s) => s,
                            Err(error) => {
                                tracing::error!(?error, "TLS proxy: upstream connect failed");
                                return;
                            }
                        };
                        // Bidirectional copy: decrypted client <-> upstream.
                        let (mut ri, mut wi) = tokio::io::split(tls_stream);
                        let (mut ro, mut wo) = tokio::io::split(upstream);
                        let c2u = tokio::io::copy(&mut ri, &mut wo);
                        let u2c = tokio::io::copy(&mut ro, &mut wi);
                        match tokio::join!(c2u, u2c) {
                            (Err(error), _) | (_, Err(error)) => {
                                tracing::warn!(?error, "TLS proxy: copy failed");
                            }
                            _ => {}
                        }
                    });
                }
            }
        }
        Ok(())
    });

    Ok(handle)
}
