use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    response::{IntoResponse as _, Response},
};
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

use crate::executor::envoy::confgen::{ENVOY_DUMMY_CERT, ENVOY_DUMMY_KEY};

async fn terminate_http_connect_svc(req: Request<Incoming>) -> Result<Response> {
    let req = req.map(Body::new);

    if req.method() == Method::CONNECT {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                {
                    // TODO: use the upgraded stream
                    return Ok(Response::new(Body::empty()).into_response());
                };
            }
            Err(e) => tracing::warn!("Failed to upgrade to HTTP CONNECT: {e:#}"),
        };
    }

    Ok((
        StatusCode::BAD_REQUEST,
        "Protocol Error: may not be a valid client",
    )
        .into_response())
}

pub async fn work_on_stream<
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite,
>(
    remote_addr: impl AsRef<str>,
    in_stream: S1,
) -> Result<S2> {
    let mut cert = ENVOY_DUMMY_CERT.as_bytes();
    let mut privkey = ENVOY_DUMMY_KEY.as_bytes();

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        // TODO: with_client_cert_verifier() and ClientCertVerifierBuilder
        .with_single_cert(
            rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?,
            rustls_pemfile::private_key(&mut privkey).map(|key| key.unwrap())?,
        )?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let tls_stream = tls_acceptor.accept(in_stream).await.with_context(|| {
        format!(
            "Failed to perform rats-tls handshake with '{}'",
            remote_addr.as_ref()
        )
    })?;

    let svc = tower::service_fn(terminate_http_connect_svc);
    let svc = TowerToHyperService::new(svc);

    if let Err(err) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls_stream), svc)
        .await
    {
        tracing::warn!("Failed to serve connection: {err:#}");
    }

    todo!()
}
