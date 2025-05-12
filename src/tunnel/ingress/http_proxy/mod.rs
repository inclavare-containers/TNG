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
use opentelemetry::metrics::MeterProvider;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::Instrument;

use crate::config::ingress::{CommonArgs, IngressHttpProxyArgs};
use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt;
use crate::service::RegistedService;
use crate::tunnel::access_log::AccessLog;
use crate::tunnel::ingress::core::stream_manager::trusted::TrustedStreamManager;
use crate::tunnel::ingress::core::stream_manager::unprotected::UnprotectedStreamManager;
use crate::tunnel::ingress::core::stream_manager::StreamManager as _;
use crate::tunnel::ingress::core::TngEndpoint;
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::utils::endpoint_matcher::EndpointMatcher;
use crate::tunnel::utils::socket::{SetListenerSockOpts, TCP_CONNECT_SO_MARK_DEFAULT};

pub enum RouteResult {
    // At least in this time, we got no error, and this request should be handled in background.
    HandleInBackgroud,
    // There is an error during routing and we failed. No background task is remained.
    Error(/*code*/ StatusCode, /* msg */ String),
    // We got a response to send to the client from upstream. No background task is remained.
    UpstreamResponse(Response),
}

impl Into<Response> for RouteResult {
    fn into(self) -> Response {
        match self {
            RouteResult::HandleInBackgroud => Response::new(Body::empty()).into_response(),
            RouteResult::Error(code, msg) => {
                tracing::error!(?code, ?msg, "responding errors to downstream");
                (code, msg).into_response()
            }
            RouteResult::UpstreamResponse(response) => response,
        }
    }
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

    pub async fn handle(
        self,
        stream_router: Arc<StreamRouter>,
        shutdown_guard: ShutdownGuard,
        metrics: ServiceMetrics,
        peer_addr: SocketAddr,
    ) -> RouteResult {
        let dst = match self.get_dst() {
            Ok(dst) => dst,
            Err(e) => return RouteResult::Error(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };

        if self.req.method() == Method::CONNECT {
            tracing::debug!(
                proxy_type = "http-connect",
                "Setting up stream from http-proxy downstream"
            );

            // Spawn a background task to handle the upgraded stream.
            let metrics_cloned = metrics.clone();
            let upgrade_span = tracing::info_span!("http-connect-upgrade");
            let task = shutdown_guard.spawn_task_fn_with_span(
                upgrade_span.clone(),
                move |shutdown_guard| async move {
                    let fut = async {
                        let upgraded = hyper::upgrade::on(self.req)
                            .await
                            .context("Failed during http connect upgrade")?;

                        stream_router
                            .forward_to_upstream(
                                dst,
                                TokioIo::new(upgraded),
                                shutdown_guard,
                                metrics_cloned,
                                peer_addr,
                            )
                            .await
                    };

                    if let Err(e) = fut.await {
                        tracing::error!(error=?e, "Failed handling http connect request");
                    }
                },
            );

            // Spawn a task to trace the connection status.
            shutdown_guard.spawn_task_with_span(upgrade_span.clone(), async move {
                if !matches!(task.await, Ok(())) {
                    metrics.cx_failed.add(1);
                }
                metrics.cx_active.add(-1);
            });

            RouteResult::HandleInBackgroud
        } else {
            tracing::debug!(
                proxy_type = "http-reverse-proxy",
                "Setting up stream from http-proxy downstream"
            );

            let forward_span = tracing::info_span!("http-proxy-forward");
            async {
                let (s1, s2) = tokio::io::duplex(4096);

                let forward_task = async {
                    if let Err(e) = stream_router
                        .forward_to_upstream(dst, s2, shutdown_guard.clone(), metrics, peer_addr)
                        .await
                    {
                        tracing::error!(error=?e);
                        Err(e)
                    } else {
                        Ok(())
                    }
                };

                let send_task = async {
                    // TODO: support send both http1 and http2 payload
                    let (mut sender, conn) =
                        hyper::client::conn::http1::handshake(TokioIo::new(s1))
                            .await
                            .context("Failed during http handshake with upstream")?;

                    let http_conn_span = tracing::info_span!("http_conn");
                    shutdown_guard.spawn_task_with_span(http_conn_span, async move {
                        if let Err(e) = conn.await {
                            tracing::error!(?e, "The HTTP connection with upstream is broken");
                        }
                    });

                    tracing::debug!("Forwarding HTTP request to upstream now");
                    sender
                        .send_request(self.req)
                        .await
                        .map(|res| res.into_response())
                        .context("Failed to send http request to upstream")
                };

                match tokio::join!(forward_task, send_task) {
                    // If there are errors during the forwarding, we report it to the downstream.
                    (Err(e), _) => RouteResult::Error(StatusCode::BAD_REQUEST, format!("{e:#}")),
                    (Ok(_), Ok(response)) => RouteResult::UpstreamResponse(response),
                    (Ok(_), Err(e)) => {
                        RouteResult::Error(StatusCode::BAD_REQUEST, format!("{e:#}"))
                    }
                }
            }
            .instrument(forward_span)
            .await
        }
    }
}

struct StreamRouter {
    trusted_stream_manager: TrustedStreamManager,
    unprotected_stream_manager: UnprotectedStreamManager,
    endpoint_matcher: EndpointMatcher,
}

impl StreamRouter {
    pub async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()> {
        self.trusted_stream_manager
            .prepare(shutdown_guard.clone())
            .await?;
        self.unprotected_stream_manager
            .prepare(shutdown_guard.clone())
            .await?;
        Ok(())
    }

    #[auto_enum]
    pub async fn forward_to_upstream(
        &self,
        dst: TngEndpoint,
        downstream: impl tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + std::marker::Unpin
            + std::marker::Send
            + 'static,
        shutdown_guard: ShutdownGuard,
        metrics: ServiceMetrics,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        tracing::debug!("Stream from downstream is ready, keeping forwarding to upstream now");

        // Check if need to send via tng tunnel, and get stream to the upstream
        let via_tunnel = self.endpoint_matcher.matches(&dst);
        tracing::debug!(%dst, via_tunnel, "Acquire connection to upstream");

        let attestation_result;
        #[auto_enum(Future)]
        let forward_stream_task = if !via_tunnel {
            // Forward via unprotected tcp
            let (forward_stream_task, att) = self
                .unprotected_stream_manager
                .forward_stream(&dst, downstream, shutdown_guard.clone(), metrics)
                .await
                .with_context(|| {
                    format!("Failed to connect to upstream {dst} via unprotected tcp")
                })?;

            attestation_result = att;
            forward_stream_task
        } else {
            // Forward via trusted tunnel
            let (forward_stream_task, att) = self
                .trusted_stream_manager
                .forward_stream(&dst, downstream, shutdown_guard.clone(), metrics)
                .await
                .with_context(|| {
                    format!("Failed to connect to upstream {dst} via trusted tunnel")
                })?;

            attestation_result = att;
            forward_stream_task
        };

        // Print access log
        let access_log = AccessLog {
            downstream: peer_addr,
            upstream: &dst,
            to_trusted_tunnel: via_tunnel,
            peer_attested: attestation_result,
        };
        tracing::info!(?access_log);

        shutdown_guard.spawn_task_with_span(tracing::info_span!("forward"), async move {
            if let Err(e) = forward_stream_task.await {
                let error = format!("{e:#}");
                tracing::error!(
                    %dst,
                    error,
                    "Failed during forwarding to upstream"
                );
            }
        });

        Ok(())
    }
}

pub struct HttpProxyIngress {
    listen_addr: String,
    listen_port: u16,
    metrics: ServiceMetrics,
    stream_router: Arc<StreamRouter>,
}

impl HttpProxyIngress {
    pub async fn new(
        id: usize,
        http_proxy_args: &IngressHttpProxyArgs,
        common_args: &CommonArgs,
        meter_provider: Arc<dyn MeterProvider + Send + Sync>,
    ) -> Result<Self> {
        let listen_addr = http_proxy_args
            .proxy_listen
            .host
            .as_deref()
            .unwrap_or("0.0.0.0")
            .to_owned();
        let listen_port = http_proxy_args.proxy_listen.port;

        // ingress_type=http_proxy,ingress_id={id},ingress_proxy_listen={proxy_listen.host}:{proxy_listen.port}
        let metrics = ServiceMetrics::new(
            meter_provider,
            [
                ("ingress_type".to_owned(), "http_proxy".to_owned()),
                ("ingress_id".to_owned(), id.to_string()),
                (
                    "ingress_proxy_listen".to_owned(),
                    format!("{}:{}", listen_addr, listen_port),
                ),
            ],
        );

        let stream_router = Arc::new(StreamRouter {
            trusted_stream_manager: TrustedStreamManager::new(
                &common_args,
                TCP_CONNECT_SO_MARK_DEFAULT,
            )
            .await?,
            unprotected_stream_manager: UnprotectedStreamManager::new(),
            endpoint_matcher: EndpointMatcher::new(&http_proxy_args.dst_filters)?,
        });

        Ok(Self {
            listen_addr,
            listen_port,
            metrics,
            stream_router,
        })
    }
}

#[async_trait]
impl RegistedService for HttpProxyIngress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        self.stream_router.prepare(shutdown_guard.clone()).await?;

        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        ready.send(()).await?;

        let loop_task = async {
            loop {
                async {
                    let (downstream, peer_addr) = listener.accept().await?;

                    let stream_router = self.stream_router.clone();
                    let metrics = self.metrics.clone();

                    shutdown_guard.spawn_task_fn_with_span(
                        tracing::info_span!("serve", client=?peer_addr),
                        move |shutdown_guard| async move {
                            tracing::debug!("Start serving new connection from client");

                            let svc = {
                                ServiceBuilder::new()
                                    .layer(SetResponseHeaderLayer::overriding(
                                        http::header::SERVER,
                                        HeaderValue::from_static("tng"),
                                    ))
                                    .service(tower::service_fn(move |req| {
                                        let stream_router = stream_router.clone();
                                        let shutdown_guard = shutdown_guard.clone();
                                        let metrics = metrics.clone();

                                        async move {
                                            metrics.cx_total.add(1);
                                            metrics.cx_active.add(1);

                                            let route_result = RequestHelper::from_request(req)
                                                .handle(
                                                    stream_router,
                                                    shutdown_guard,
                                                    metrics.clone(),
                                                    peer_addr,
                                                )
                                                .await;

                                            if matches!(route_result, RouteResult::Error(..))
                                                || matches!(
                                                    route_result,
                                                    RouteResult::UpstreamResponse(..)
                                                )
                                            {
                                                if matches!(route_result, RouteResult::Error(..)) {
                                                    metrics.cx_failed.add(1);
                                                }
                                                metrics.cx_active.add(-1);
                                            }

                                            Result::<_, String>::Ok(route_result.into())
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
                        },
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error=?e, "Failed to serve incoming connection from client");
                })
            }
        };

        tokio::select! {
            () = loop_task => {/* should not be here */},
            _ = shutdown_guard.cancelled() => {
                tracing::debug!("Shutdown signal received, stop accepting new connections");
            }
        };

        Ok(())
    }
}
