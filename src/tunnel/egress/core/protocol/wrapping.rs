use anyhow::Result;
use axum::{
    body::Body,
    response::{IntoResponse as _, Response},
};
use http::{HeaderValue, Method, Request, StatusCode};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use tokio_graceful::ShutdownGuard;
use tower::ServiceBuilder;
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use tracing::Instrument;

use super::super::stream_manager::{trusted::TrustedStreamManager, StreamManager};

fn error_response(code: StatusCode, msg: String) -> Response {
    tracing::error!(?code, ?msg, "responding errors to downstream");
    (code, msg).into_response()
}

pub struct WrappingLayer {}

impl WrappingLayer {
    pub async fn unwrap_stream(
        tls_stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
        channel: <TrustedStreamManager as StreamManager>::Sender,
        shutdown_guard: ShutdownGuard,
    ) -> Result<()> {
        let span = tracing::info_span!("wrapping");
        let svc = {
            let span = span.clone();
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(SetResponseHeaderLayer::overriding(
                    http::header::SERVER,
                    HeaderValue::from_static("tng"),
                ))
                .service(tower::service_fn(move |req| {
                    let channel = channel.clone();
                    let shutdown_guard = shutdown_guard.clone();
                    let span = span.clone();
                    async move {
                        Self::terminate_http_connect_svc(req, channel, shutdown_guard)
                            .instrument(span)
                            .await
                    }
                }))
        };

        let svc = TowerToHyperService::new(svc);

        if let Err(err) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls_stream), svc)
            .instrument(span)
            .await
        {
            tracing::warn!("Failed to serve connection: {err:#}");
        }
        Ok(())
    }

    async fn terminate_http_connect_svc(
        req: Request<Incoming>,
        channel: <TrustedStreamManager as StreamManager>::Sender,
        shutdown_guard: ShutdownGuard,
    ) -> Result<Response> {
        tracing::trace!("Handling new wrapping stream");

        let req = req.map(Body::new);

        if req.method() == Method::CONNECT {
            shutdown_guard.spawn_task(
                async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            tracing::debug!("Trusted tunnel established, now transporting application data stream.");

                            if let Err(e) = channel.send(upgraded) {
                                tracing::warn!("Failed to send stream via channel: {e:#}");
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed during http connect upgrade: {e:#}");
                        }
                    };
                }
                .in_current_span(),
            );
            Ok(Response::new(Body::empty()).into_response())
        } else {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                format!("Protocol Error: the method should be CONNECT, may be a invalid client"),
            ));
        }
    }
}
