use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::{Context, Result};
use async_stream::stream;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use futures::StreamExt as _;
use http::{uri::Scheme, HeaderValue, Request, Uri};
use hyper::body::Incoming;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use indexmap::IndexMap;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio_graceful::ShutdownGuard;
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::Instrument;

use crate::config::ingress::IngressHttpProxyArgs;
use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::ingress::flow::stream_router::StreamRouter;
use crate::tunnel::utils::endpoint_matcher::EndpointMatcher;
use crate::tunnel::utils::socket::SetListenerSockOpts;

use super::flow::{AcceptedStream, Incomming, IngressTrait};

const TNG_HTTP_FORWARD_HEADER: &str = "X-Tng-Http-Forward";

pub enum RouteResult {
    // At least in this time, we got no error, and this request should be handled in background.
    HandleInBackgroud,
    // There is an error during routing and we failed. No background task is remained.
    Error(/*code*/ StatusCode, /* msg */ String),
    // We got a response to send to the client from upstream. No background task is remained.
    UpstreamResponse(Response),
}

impl From<RouteResult> for Response {
    fn from(val: RouteResult) -> Self {
        match val {
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
                Err(anyhow!("No authority in HTTP CONNECT request URI"))
            }
        } else {
            match self.req.headers().get(http::header::HOST) {
                Some(host) => {
                    let authority = host
                        .to_str()
                        .map_err(|e: http::header::ToStrError| anyhow!(e))
                        .and_then(|host| host.parse::<Uri>().map_err(|e| anyhow!(e)))
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
                None => Err(anyhow!("No 'HOST' header in http request")),
            }
        }
    }

    pub async fn handle(
        self,
        stream_router: Arc<StreamRouter>,
        shutdown_guard: ShutdownGuard,
        peer_addr: SocketAddr,
        sender: UnboundedSender<AcceptedStream>,
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
            let upgrade_span = tracing::info_span!("http-connect-upgrade");

            shutdown_guard.spawn_supervised_task_with_span(upgrade_span.clone(), async move {
                let fut = async {
                    let upgraded = hyper::upgrade::on(self.req)
                        .await
                        .context("Failed during http connect upgrade")?;

                    let via_tunnel = stream_router.should_forward_via_tunnel(&dst);
                    sender
                        .send(AcceptedStream {
                            stream: Box::new(TokioIo::new(upgraded)),
                            src: peer_addr,
                            dst,
                            via_tunnel,
                        })
                        .map_err(|e| anyhow!("{e:?}"))?;

                    Ok::<_, anyhow::Error>(())
                };

                if let Err(e) = fut.await {
                    tracing::error!(error=?e, "Failed handling http connect request");
                }
            });

            RouteResult::HandleInBackgroud
        } else {
            tracing::debug!(
                proxy_type = "http-reverse-proxy",
                "Setting up stream from http-proxy downstream"
            );

            let forward_span = tracing::info_span!("http-reverse-proxy-forward");
            async {

                if self.req.headers().get(TNG_HTTP_FORWARD_HEADER).is_some() {
                    tracing::debug!("Got header \"{TNG_HTTP_FORWARD_HEADER}\" in http request, recursion is detected");
                    return RouteResult::Error(StatusCode::BAD_REQUEST, "recursion is detected".to_string())
                }

                let (s1, s2) = tokio::io::duplex(4096);

                let send_accepted_stream = async {
                    let via_tunnel = stream_router.should_forward_via_tunnel(&dst);
                    sender.send(AcceptedStream { stream: Box::new(s2), src: peer_addr, dst, via_tunnel })
                };

                let send_task = async {
                    // TODO: support send both http1 and http2 payload
                    let (mut sender, conn) =
                        hyper::client::conn::http1::handshake(TokioIo::new(s1))
                            .await
                            .context("Failed during http handshake with upstream")?;

                    let http_conn_span = tracing::info_span!("http_conn");
                    shutdown_guard.spawn_supervised_task_with_span(http_conn_span, async move {
                        if let Err(e) = conn.await {
                            tracing::error!(?e, "The HTTP connection with upstream is broken");
                        }
                    });

                    let mut req = self.req;

                    // Remove scheme and authority, but keep path and query in the request URI.
                    let mut parts = req.uri().clone().into_parts();
                    parts.authority = None;
                    parts.scheme = None;
                    *req.uri_mut() = http::Uri::from_parts(parts).with_context(|| {
                        format!(
                            "Failed convert uri {} for forwarding http request to upstream",
                            req.uri()
                        )
                    })?;

                    // Add a header to detect recursion
                    req.headers_mut().remove(TNG_HTTP_FORWARD_HEADER);
                    req.headers_mut().insert(TNG_HTTP_FORWARD_HEADER, HeaderValue::from_static("true"));

                    tracing::debug!("Forwarding HTTP request to upstream now");
                    sender
                        .send_request(req)
                        .await
                        .map(|res| res.into_response())
                        .context("Failed to send http request to upstream")
                };

                match tokio::join!(send_accepted_stream, send_task) {
                    // TODO: send_accepted_stream is just send a accpted stream to IngressFlow, we need a better way to get error propagated back to here, so that we can get errors raised during the forwarding, and then report it to the downstream.
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

pub struct HttpProxyIngress {
    id: usize,
    listen_addr: String,
    listen_port: u16,
    stream_router: Arc<StreamRouter>,
}

impl HttpProxyIngress {
    pub async fn new(id: usize, http_proxy_args: &IngressHttpProxyArgs) -> Result<Self> {
        let listen_addr = http_proxy_args
            .proxy_listen
            .host
            .as_deref()
            .unwrap_or("0.0.0.0")
            .to_owned();
        let listen_port = http_proxy_args.proxy_listen.port;

        let stream_router = Arc::new(StreamRouter::with_endpoint_matcher(EndpointMatcher::new(
            &http_proxy_args.dst_filters,
        )?));

        Ok(Self {
            id,
            listen_addr,
            listen_port,
            stream_router,
        })
    }
}

#[async_trait]
impl IngressTrait for HttpProxyIngress {
    /// ingress_type=http_proxy,ingress_id={id},ingress_proxy_listen={proxy_listen.host}:{proxy_listen.port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("ingress_type".to_owned(), "http_proxy".to_owned()),
            ("ingress_id".to_owned(), self.id.to_string()),
            (
                "ingress_proxy_listen".to_owned(),
                format!("{}:{}", self.listen_addr, self.listen_port),
            ),
        ]
        .into()
    }

    fn transport_so_mark(&self) -> Option<u32> {
        None
    }

    async fn accept(&self, shutdown_guard: ShutdownGuard) -> Result<Incomming> {
        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;
        Ok(Box::new(
            stream! {
                loop {
                    yield listener.accept().await
                }
            }.flat_map_unordered(
                None, // Unlimited concurrency of http proxy session
                move |res| {
                    let shutdown_guard = shutdown_guard.clone();
                    let stream_router = self.stream_router.clone();

                    Box::pin(stream! {
                        match res {
                            Ok((stream, peer_addr)) => {
                                // Run http proxy server in a separate task to add parallelism with multi-cpu
                                let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

                                shutdown_guard.spawn_supervised_task_fn_current_span(move |shutdown_guard| async move {
                                    serve_http_proxy_no_throw_error(stream, stream_router, shutdown_guard, peer_addr, sender)
                                        .await
                                });

                                while let Some(accepted_stream) = receiver.recv().await {
                                    yield Ok(accepted_stream)
                                }
                            }
                            Err(e) => Err(anyhow!(e))?,
                        }
                    })
                }
            )
        ))
    }
}

async fn serve_http_proxy_no_throw_error(
    in_stream: TcpStream,
    stream_router: Arc<StreamRouter>,
    shutdown_guard: ShutdownGuard,
    peer_addr: SocketAddr,
    sender: UnboundedSender<AcceptedStream>,
) {
    let shutdown_guard_cloned = shutdown_guard.clone();

    let svc = {
        ServiceBuilder::new()
            .layer(SetResponseHeaderLayer::overriding(
                http::header::SERVER,
                HeaderValue::from_static("tng"),
            ))
            .service(tower::service_fn(move |req| {
                let stream_router = stream_router.clone();
                let shutdown_guard = shutdown_guard.clone();
                let sender = sender.clone();

                async move {
                    let route_result = RequestHelper::from_request(req)
                        .handle(stream_router, shutdown_guard, peer_addr, sender)
                        .await;

                    Result::<_, String>::Ok(route_result.into())
                }
            }))
    };
    let svc = TowerToHyperService::new(svc);

    if let Err(error) = hyper_util::server::conn::auto::Builder::new(
        shutdown_guard_cloned.as_hyper_executor(tokio::runtime::Handle::current()),
    )
    .serve_connection_with_upgrades(TokioIo::new(in_stream), svc)
    .await
    {
        tracing::error!(?error, "Failed to serve connection");
    }
}
