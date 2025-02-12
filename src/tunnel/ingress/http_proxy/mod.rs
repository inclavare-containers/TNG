use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::{Context, Result};
use async_trait::async_trait;
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
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;
use tower::ServiceBuilder;
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use tracing::Instrument;

use crate::config::ingress::{CommonArgs, EndpointFilter, IngressHttpProxyArgs};
use crate::tunnel::access_log::AccessLog;
use crate::tunnel::ingress::core::stream_manager::trusted::TrustedStreamManager;
use crate::tunnel::ingress::core::stream_manager::unprotected::UnprotectedStreamManager;
use crate::tunnel::ingress::core::stream_manager::StreamManager as _;
use crate::tunnel::ingress::core::TngEndpoint;
use crate::tunnel::utils::endpoint_matcher::RegexEndpointMatcher;
use crate::tunnel::{utils, RegistedService};

fn error_response(code: StatusCode, msg: String) -> Response {
    tracing::error!(?code, ?msg, "responding errors to downstream");
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
        shutdown_guard: ShutdownGuard,
    ) -> Response {
        let span = tracing::info_span!("forward");

        let stream = if self.req.method() == Method::CONNECT {
            tracing::debug!(
                proxy_type = "http-connect",
                "Setting up stream from http-proxy downstream"
            );

            shutdown_guard.spawn_task(async move {
                match hyper::upgrade::on(self.req).await {
                    Ok(upgraded) => {
                        tracing::debug!("Stream from downstream is ready, keeping forwarding to upstream now");

                        if let Err(e) = utils::forward_stream( upstream, TokioIo::new(upgraded)).await
                        {
                            tracing::error!("{e:#}");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed during http connect upgrade: {e:#}");
                    }
                }
            }.instrument(span));
            Response::new(Body::empty()).into_response()
        } else {
            tracing::debug!(
                proxy_type = "http-reverse-proxy",
                "Setting up stream from http-proxy downstream"
            );

            // TODO: optimize this mem copy
            let (s1, s2) = tokio::io::duplex(4 * 1024);

            shutdown_guard.spawn_task(
                async move {
                    if let Err(e) = utils::forward_stream(upstream, s2).await {
                        tracing::error!("{e:#}");
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
            shutdown_guard.spawn_task(
                async move {
                    if let Err(e) = conn.await {
                        tracing::error!(?e, "The HTTP connection with upstream is broken");
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
    async fn route(
        &self,
        req: Request<Incoming>,
        peer_addr: SocketAddr,
        shutdown_guard: ShutdownGuard,
    ) -> Response {
        let helper = RequestHelper::from_request(req);
        let dst = match helper.get_dst() {
            Ok(dst) => dst,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };

        // Check if need to send via tng tunnel, and get stream to the upstream
        let via_tunnel = self.endpoint_matcher.matches(&dst);
        tracing::debug!(%dst, via_tunnel, "Acquire connection to upstream");

        let attestation_result;
        #[auto_enum(tokio1::AsyncRead, tokio1::AsyncWrite)]
        let upstream = if !via_tunnel {
            // Forward via unprotected tcp
            match self.unprotected_stream_manager.new_stream(&dst).await {
                Ok((stream, att)) => {
                    attestation_result = att;
                    stream
                }
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
                Ok((stream, att)) => {
                    attestation_result = att;
                    stream
                }
                Err(e) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("Failed to connect to upstream {dst} via trusted tunnel: {e:#}"),
                    )
                }
            }
        };

        // Print access log
        let access_log = AccessLog {
            downstream: peer_addr,
            upstream: dst,
            to_trusted_tunnel: via_tunnel,
            peer_attested: attestation_result,
        };
        tracing::info!(?access_log);

        helper
            .forward_to_upstream_in_background(upstream, shutdown_guard)
            .await
    }
}

pub struct HttpProxyIngress {
    listen_addr: String,
    listen_port: u16,
    dst_filters: Vec<EndpointFilter>,
    common_args: CommonArgs,
}

impl HttpProxyIngress {
    pub fn new(http_proxy_args: &IngressHttpProxyArgs, common_args: &CommonArgs) -> Result<Self> {
        let listen_addr = http_proxy_args
            .proxy_listen
            .host
            .as_deref()
            .unwrap_or("0.0.0.0");
        let listen_port = http_proxy_args.proxy_listen.port;

        Ok(Self {
            listen_addr: listen_addr.to_owned(),
            listen_port,
            dst_filters: http_proxy_args.dst_filters.clone(),
            common_args: common_args.clone(),
        })
    }
}

#[async_trait]
impl RegistedService for HttpProxyIngress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        let stream_router = Arc::new(StreamRouter {
            trusted_stream_manager: TrustedStreamManager::new(
                &self.common_args,
                shutdown_guard.clone(),
            )
            .await?,
            unprotected_stream_manager: UnprotectedStreamManager::new(),
            endpoint_matcher: RegexEndpointMatcher::new(&self.dst_filters)?,
        });

        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await.unwrap();
        // TODO: ENVOY_LISTENER_SOCKET_OPTIONS
        ready.send(()).await?;

        loop {
            let (downstream, _) = tokio::select! {
                res = listener.accept() => res.unwrap(),
                _ = shutdown_guard.cancelled() => {
                    tracing::debug!("Shutdown signal received, stop accepting new connections");
                    break;
                }
            };

            let peer_addr = downstream.peer_addr().unwrap();
            let stream_router = stream_router.clone();
            let span = tracing::info_span!("serve", client=?peer_addr);

            shutdown_guard.spawn_task_fn(move |shutdown_guard| {
                let fut = async move {
                    tracing::debug!("Start serving new connection from client");

                    let svc = {
                        ServiceBuilder::new()
                            .layer(TraceLayer::new_for_http())
                            .layer(SetResponseHeaderLayer::overriding(
                                http::header::SERVER,
                                HeaderValue::from_static("tng"),
                            ))
                            .service(tower::service_fn(move |req| {
                                let stream_router = stream_router.clone();
                                let shutdown_guard = shutdown_guard.clone();
                                async move {
                                    Result::<_, String>::Ok(
                                        stream_router.route(req, peer_addr, shutdown_guard).await,
                                    )
                                }
                            }))
                    };
                    let svc = TowerToHyperService::new(svc);

                    let io = TokioIo::new(downstream);

                    if let Err(e) =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection_with_upgrades(io, svc)
                            .await
                    {
                        tracing::error!("Failed to serve connection: {e:?}");
                    }
                };

                fut.instrument(span)
            });
        }

        Ok(())
    }
}
