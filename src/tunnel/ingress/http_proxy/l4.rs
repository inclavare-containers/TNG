use anyhow::{Context, Result};

use axum::{
    body::Body,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};

use http::{HeaderValue, Request};
use hyper::body::Incoming;
use tokio::net::TcpListener;

use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use tower::ServiceBuilder;
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};

use crate::config::{attest::AttestArgs, ingress::EndpointFilter, verify::VerifyArgs};

async fn l4_svc(req: Request<Incoming>) -> Result<Response> {
    let mut req = req.map(Body::new);

    async fn tunnel<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin>(
        host_addr: impl AsRef<str>,
        mut stream: S,
    ) -> Result<()> {
        let mut server = TokioIo::new(
            crate::tunnel::ingress::core::client::get_stream_for_addr(&host_addr)
                .await
                .with_context(|| {
                    format!(
                        "Failed to get stream for target host '{}'",
                        host_addr.as_ref(),
                    )
                })?,
        );

        let (from_client, from_server) = tokio::io::copy_bidirectional(&mut stream, &mut server)
            .await
            .with_context(|| {
                format!(
                    "Failed during copy streams bidirectionally between input and target host '{}'",
                    host_addr.as_ref(),
                )
            })?;
        tracing::debug!(
            "Finished tunneling stream to target host '{}'. (tx: {} bytes, rx: {} bytes)",
            host_addr.as_ref(),
            from_client,
            from_server
        );

        Ok(())
    }

    if req.method() == Method::CONNECT {
        if let Some(host_addr) = req.uri().authority().map(|auth| auth.to_string()) {
            tracing::debug!("Got CONNECT request, waiting for upgrading");
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(host_addr, TokioIo::new(upgraded)).await {
                            tracing::warn!("{e:#}");
                        }
                    }
                    Err(e) => tracing::warn!("upgrade error: {e:#}"),
                };
            });
            Ok(Response::new(Body::empty()).into_response())
        } else {
            tracing::warn!("CONNECT uri contains no host addr: {:?}", req.uri());
            Ok((StatusCode::BAD_REQUEST, "CONNECT uri contains no host addr").into_response())
        }
    } else {
        match req.headers().get(http::header::HOST) {
            Some(host_addr) => {
                let host_addr = host_addr
                    .to_str()
                    .context("No valid 'HOST' value in request header")?
                    .to_owned();

                let (s1, s2) = tokio::io::duplex(4 * 1024);
                tokio::task::spawn(async move {
                    if let Err(e) = tunnel(&host_addr, s2).await {
                        tracing::warn!("{e:#}");
                    }
                });

                // TODO: support both http1 and http2 payload
                let (mut sender, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(s1)).await?;
                tokio::task::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::warn!("HTTP connection is broken: {e:#}");
                    }
                });

                let mut parts = req.uri().clone().into_parts();
                parts.authority = None;
                parts.scheme = None;
                *req.uri_mut() = http::Uri::from_parts(parts)
                    .with_context(|| format!("Failed to convert URI '{}'", req.uri()))?;

                Ok(sender
                    .send_request(req)
                    .await
                    .map(|res| res.into_response())
                    .context("Failed to forawrd HTTP request")?)
            }
            None => {
                Ok((StatusCode::BAD_REQUEST, "No 'HOST' header in http request").into_response())
            }
        }
    }
}

pub async fn run(
    id: usize,
    proxy_listen_addr: &str,
    proxy_listen_port: u16,
    dst_filters: &[EndpointFilter],
    no_ra: bool,
    attest: &Option<AttestArgs>,
    verify: &Option<VerifyArgs>,
) -> Result<()> {
    let svc = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::overriding(
            http::header::SERVER,
            HeaderValue::from_static("tng"),
        ))
        .service(tower::service_fn(l4_svc));
    let svc = TowerToHyperService::new(svc);

    let addr = format!("{proxy_listen_addr}:{proxy_listen_port}");
    tracing::debug!("Add listener on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    // TODO: ENVOY_LISTENER_SOCKET_OPTIONS

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let svc = svc.clone();
        tokio::task::spawn(async move {
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, svc)
                .await
            {
                tracing::warn!("Failed to serve connection: {e:#}");
            }
        });
    }
}
