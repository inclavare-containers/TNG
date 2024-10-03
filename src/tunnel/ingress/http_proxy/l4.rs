use std::sync::Arc;

use anyhow::anyhow;
use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use http::{uri::Scheme, HeaderValue, Request, Uri};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};

use crate::tunnel::ingress::core::client::stream::manager::StreamManager;
use crate::{
    config::{attest::AttestArgs, ingress::EndpointFilter, verify::VerifyArgs},
    tunnel::ingress::core::TngEndpoint,
};

async fn tunnel<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin>(
    stream_manager: Arc<StreamManager>,
    endpoint: TngEndpoint,
    mut stream: S,
) -> Result<()> {
    let mut server = TokioIo::new(
        stream_manager
            .new_stream(&endpoint)
            .await
            .with_context(|| format!("Failed to get stream for '{}'", endpoint))?,
    );

    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut stream, &mut server)
        .await
        .with_context(|| {
            format!(
                "Failed during copy streams bidirectionally between input and '{}'",
                endpoint,
            )
        })?;
    tracing::debug!(
        "Finished tunneling stream to '{}'. (tx: {} bytes, rx: {} bytes)",
        endpoint,
        from_client,
        from_server
    );

    Ok(())
}

async fn l4_svc(req: Request<Incoming>, stream_manager: Arc<StreamManager>) -> Result<Response> {
    let mut req = req.map(Body::new);

    if req.method() == Method::CONNECT {
        if let Some(authority) = req.uri().authority() {
            tracing::debug!("Got CONNECT request, waiting for upgrading");
            let endpoint = TngEndpoint::new(
                authority.host(),
                authority.port_u16().unwrap_or_else(|| {
                    if req.uri().scheme() == Some(&Scheme::HTTPS) {
                        443u16
                    } else {
                        80u16
                    }
                }),
            ); // TODO: handle support for something else like ftp ...

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) =
                            tunnel(stream_manager, endpoint, TokioIo::new(upgraded)).await
                        {
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
            Some(host) => {
                // Determine the host and port of endpoint
                let host = host
                    .to_str()
                    .context("No valid 'HOST' value in request header")?
                    .to_owned();

                let authority = host
                    .parse::<Uri>()
                    .map_err(|e| anyhow!(e))
                    .and_then(|uri| {
                        uri.into_parts()
                            .authority
                            .ok_or(anyhow!("The authority is empty"))
                    })
                    .context("The 'HOST' value in request header is not a valid host")?;

                let endpoint = TngEndpoint::new(
                    authority.host(),
                    authority.port_u16().unwrap_or_else(|| {
                        if req.uri().scheme() == Some(&Scheme::HTTPS) {
                            443u16
                        } else {
                            80u16
                        }
                    }),
                );

                // TODO: optimize this mem copy
                let (s1, s2) = tokio::io::duplex(4 * 1024);
                tokio::task::spawn(async move {
                    if let Err(e) = tunnel(stream_manager, endpoint, s2).await {
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
    let stream_manager = Arc::new(StreamManager::new());

    let svc = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::overriding(
            http::header::SERVER,
            HeaderValue::from_static("tng"),
        ))
        .service(tower::service_fn(move |req| {
            l4_svc(req, stream_manager.clone())
        }));
    let svc = TowerToHyperService::new(svc);

    let ingress_addr = format!("{proxy_listen_addr}:{proxy_listen_port}");
    tracing::debug!("Add listener (ingress {id}) on {}", ingress_addr);

    let listener = TcpListener::bind(ingress_addr).await.unwrap();
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
