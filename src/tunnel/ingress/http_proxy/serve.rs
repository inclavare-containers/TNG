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

use crate::config::ingress::{CommonArgs, HttpProxyArgs};
use crate::tunnel::ingress::core::client::stream_manager::StreamManager as _;
use crate::tunnel::ingress::core::client::trusted::TrustedStreamManager;
use crate::tunnel::ingress::core::client::unprotected::UnprotectedStreamManager;
use crate::tunnel::ingress::core::TngEndpoint;
use crate::tunnel::ingress::utils::endpoint_matcher::RegexEndpointMatcher;
use crate::tunnel::ingress::utils::forward_stream;

fn error_response(code: StatusCode, msg: String) -> Response {
    tracing::error!(?code, ?msg, "responding errors to client");
    (code, msg).into_response()
}

struct RequestHelper {
    req: Request<Body>,
}

impl RequestHelper {
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
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            format!("Failed during http handshake with upstream: {e:#}"),
                        )
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
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "Failed convert uri {} for forwarding http request to upstream: {e:#}",
                            self.req.uri()
                        ),
                    )
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
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("Failed to forawrd http request to upstream: {e:#}"),
                    )
                }
            }
        };

        stream
    }
}

struct StreamRouter {
    trusted_stream_manager: TrustedStreamManager,
    unprotected_stream_manager: UnprotectedStreamManager,
    endpoint_matcher: RegexEndpointMatcher,
}

impl StreamRouter {
    #[auto_enum]
    async fn route(&self, req: Request<Incoming>) -> Response {
        let helper = RequestHelper::from_request(req);
        let dst = match helper.get_dst() {
            Ok(dst) => dst,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };

        // Check if need to send via tng tunnel, and get stream to the upstream
        let via_tunnel = self.endpoint_matcher.matches(&dst);
        tracing::debug!(%dst, via_tunnel, "Acquire connection to upstream");

        #[auto_enum(tokio1::AsyncRead, tokio1::AsyncWrite)]
        let upstream = if !via_tunnel {
            // Forward via unprotected tcp
            match self.unprotected_stream_manager.new_stream(&dst).await {
                Ok(stream) => stream,
                Err(e) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("Failed to connect to upstream {dst} via unprotected tcp: {e:#}"),
                    )
                }
            }
        } else {
            // Forward via trusted tunnel
            match self.trusted_stream_manager.new_stream(&dst).await {
                Ok(stream) => stream,
                Err(e) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("Failed to connect to upstream {dst} via trusted tunnel: {e:#}"),
                    )
                }
            }
        };

        helper.forward_to_upstream_in_background(upstream).await
    }
}

pub struct HttpProxyIngress {
    listen_addr: String,
    listen_port: u16,
    stream_router: Arc<StreamRouter>,
}

impl HttpProxyIngress {
    pub fn new(http_proxy_args: &HttpProxyArgs, common_args: &CommonArgs) -> Result<Self> {
        let listen_addr = http_proxy_args
            .proxy_listen
            .host
            .as_deref()
            .unwrap_or("0.0.0.0");
        let listen_port = http_proxy_args.proxy_listen.port;

        Ok(Self {
            listen_addr: listen_addr.to_owned(),
            listen_port,
            stream_router: Arc::new(StreamRouter {
                trusted_stream_manager: TrustedStreamManager::new(common_args)?,
                unprotected_stream_manager: UnprotectedStreamManager::new(),
                endpoint_matcher: RegexEndpointMatcher::new(&http_proxy_args.dst_filters)?,
            }),
        })
    }

    pub async fn serve(&self) -> Result<()> {
        let ingress_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", ingress_addr);

        let listener = TcpListener::bind(ingress_addr).await.unwrap();
        // TODO: ENVOY_LISTENER_SOCKET_OPTIONS

        let stream_router = self.stream_router.clone();

        let svc = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(SetResponseHeaderLayer::overriding(
                http::header::SERVER,
                HeaderValue::from_static("tng"),
            ))
            .service(tower::service_fn(move |req| {
                let stream_router = stream_router.clone();
                async move { Result::<_, String>::Ok(stream_router.route(req).await) }
            }));
        let svc = TowerToHyperService::new(svc);

        loop {
            let (downstream, _) = listener.accept().await.unwrap();
            let peer_addr = downstream.peer_addr().unwrap();
            let svc = svc.clone();
            tokio::task::spawn({
                let fut = async {
                    tracing::debug!("Start serving connection from client");

                    let io = TokioIo::new(downstream);

                    if let Err(e) =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
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
}
