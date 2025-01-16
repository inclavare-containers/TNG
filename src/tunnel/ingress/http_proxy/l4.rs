use std::sync::Arc;

use anyhow::anyhow;
use anyhow::{Context, Result};
use auto_enums::auto_enum;
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
use tracing::Instrument;

use crate::tunnel::ingress::core::client::stream_manager::StreamManager as _;
use crate::tunnel::ingress::core::client::trusted::TrustedStreamManager;
use crate::tunnel::ingress::core::client::unprotected::UnprotectedStreamManager;
use crate::{
    config::{attest::AttestArgs, ingress::EndpointFilter, verify::VerifyArgs},
    tunnel::ingress::core::TngEndpoint,
};

use super::endpoint_matcher::RegexEndpointMatcher;

async fn forward_stream(
    mut upstream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    mut input: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
) -> Result<()> {
    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut input, &mut upstream)
        .await
        .context("Failed during copy streams bidirectionally between downstream and upstream")?;
    tracing::debug!(
        tx_bytes = from_client,
        rx_bytes = from_server,
        "Finished transmit stream to upstream",
    );

    Ok(())
}

struct HttpProxyHandler {
    req: Request<Body>,
}

impl HttpProxyHandler {
    pub fn from_request(req: Request<Incoming>) -> Self {
        Self {
            req: req.map(Body::new),
        }
    }

    pub fn get_dst(&self) -> Result<TngEndpoint> {
        if self.req.method() == Method::CONNECT {
            tracing::debug!("Got CONNECT request, waiting for upgrading");
            if let Some(authority) = self.req.uri().authority() {
                let endpoint = TngEndpoint::new(
                    authority.host(),
                    authority.port_u16().unwrap_or_else(|| {
                        if self.req.uri().scheme() == Some(&Scheme::HTTPS) {
                            443u16
                        } else {
                            80u16
                        }
                    }),
                ); // TODO: handle support for something else like ftp ...

                Ok(endpoint)
            } else {
                return Err(anyhow!("No authority in HTTP CONNECT request URI"));
            }
        } else {
            match self.req.headers().get(http::header::HOST) {
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
                            if self.req.uri().scheme() == Some(&Scheme::HTTPS) {
                                443u16
                            } else {
                                80u16
                            }
                        }),
                    );

                    Ok(endpoint)
                }
                None => return Err(anyhow!("No 'HOST' header in http request")),
            }
        }
    }

    pub async fn forward_to_upstream_in_background(
        mut self,
        dst: TngEndpoint,
        upstream: impl tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + std::marker::Unpin
            + Send
            + 'static,
    ) -> Response {
        let span = tracing::info_span!("forward");

        let stream = if self.req.method() == Method::CONNECT {
            tracing::debug!(
                proxy_type = "http-connect",
                "Preparing stream with downstream"
            );

            tokio::task::spawn(async move {
                match hyper::upgrade::on(self.req).await {
                    Ok(upgraded) => {
                        tracing::debug!("Stream with downstream is ready and keeping forwarding to upstream now");

                        if let Err(e) = forward_stream( upstream, TokioIo::new(upgraded)).await
                        {
                            tracing::warn!("{e:#}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed during http connect upgrade: {e}");
                    }
                }
            }.instrument(span));
            Response::new(Body::empty()).into_response()
        } else {
            tracing::debug!(
                proxy_type = "http-reverse-proxy",
                "Preparing stream with downstream"
            );

            // TODO: optimize this mem copy
            let (s1, s2) = tokio::io::duplex(4 * 1024);

            tokio::task::spawn(
                async move {
                    if let Err(e) = forward_stream(s2, upstream).await {
                        tracing::warn!("{e:#}");
                    }
                }
                .instrument(span),
            );

            // TODO: support send both http1 and http2 payload
            let (mut sender, conn) =
                match hyper::client::conn::http1::handshake(TokioIo::new(s1)).await {
                    Ok(v) => v,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("Failed during http handshake with upstream: {e}"),
                        )
                            .into_response()
                    }
                };

            let span = tracing::info_span!("http_conn");
            tokio::task::spawn(
                async move {
                    if let Err(e) = conn.await {
                        tracing::warn!(?e, "The HTTP connection with upstream is broken");
                    }
                }
                .instrument(span),
            );

            let mut parts = self.req.uri().clone().into_parts();
            parts.authority = None;
            parts.scheme = None;
            *self.req.uri_mut() = match http::Uri::from_parts(parts) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!(
                            "Failed convert uri {} for forwarding http request to upstream: {e}",
                            self.req.uri()
                        ),
                    )
                        .into_response()
                }
            };

            tracing::debug!("Forwarding HTTP request to upstream now");
            match sender
                .send_request(self.req)
                .await
                .map(|res| res.into_response())
            {
                Ok(resp) => resp,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to forawrd http request to upstream: {e}"),
                    )
                        .into_response()
                }
            }
        };

        stream
    }
}

#[auto_enum]
async fn l4_svc(req: Request<Incoming>, tunnel_context: Arc<TunnelContext>) -> Response {
    let handler = HttpProxyHandler::from_request(req);
    let dst = match handler.get_dst() {
        Ok(dst) => dst,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    // Check if need to send via tng tunnel, and get stream to the upstream
    let via_tunnel = tunnel_context.endpoint_matcher.matches(&dst);
    tracing::debug!(%dst, via_tunnel, "Acquire connection to upstream");

    #[auto_enum(tokio1::AsyncRead, tokio1::AsyncWrite)]
    let upstream = if !via_tunnel {
        // Forward via unprotected tcp
        match tunnel_context
            .unprotected_stream_manager
            .new_stream(&dst)
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to connect to upstream {dst} via unprotected tcp: {e}"),
                )
                    .into_response()
            }
        }
    } else {
        // Forward via trusted tunnel
        match tunnel_context.trusted_stream_manager.new_stream(&dst).await {
            Ok(stream) => stream,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to connect to upstream {dst} via trusted tunnel: {e}"),
                )
                    .into_response()
            }
        }
    };

    handler
        .forward_to_upstream_in_background(dst, upstream)
        .await
}

struct TunnelContext {
    pub trusted_stream_manager: TrustedStreamManager,
    pub unprotected_stream_manager: UnprotectedStreamManager,
    pub endpoint_matcher: RegexEndpointMatcher,
}

pub async fn run(
    _id: usize,
    proxy_listen_addr: &str,
    proxy_listen_port: u16,
    dst_filters: &[EndpointFilter],
    no_ra: bool,
    attest: &Option<AttestArgs>,
    verify: &Option<VerifyArgs>,
) -> Result<()> {
    let tunnel_context = Arc::new(TunnelContext {
        trusted_stream_manager: TrustedStreamManager::new(),
        unprotected_stream_manager: UnprotectedStreamManager::new(),
        endpoint_matcher: RegexEndpointMatcher::new(dst_filters)?,
    });

    let svc = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::overriding(
            http::header::SERVER,
            HeaderValue::from_static("tng"),
        ))
        .service(tower::service_fn(move |req| {
            let tunnel_context = tunnel_context.clone();
            async { Result::<_, String>::Ok(l4_svc(req, tunnel_context).await) }
        }));
    let svc = TowerToHyperService::new(svc);

    let ingress_addr = format!("{proxy_listen_addr}:{proxy_listen_port}");
    tracing::debug!("Add TCP listener on {}", ingress_addr);

    let listener = TcpListener::bind(ingress_addr).await.unwrap();
    // TODO: ENVOY_LISTENER_SOCKET_OPTIONS

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let peer_addr = stream.peer_addr().unwrap();
        let io = TokioIo::new(stream);
        let svc = svc.clone();
        tokio::task::spawn({
            let fut = async {
                tracing::debug!("Start serving connection from client");

                if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, svc)
                    .await
                {
                    tracing::warn!("Failed to serve connection: {e:#}");
                }
            };

            fut.instrument(tracing::info_span!("serve", client=?peer_addr))
        });
    }
}
