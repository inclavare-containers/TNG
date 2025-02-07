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
    ) -> Result<()> {
        let svc = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(SetResponseHeaderLayer::overriding(
                http::header::SERVER,
                HeaderValue::from_static("tng"),
            ))
            .service(tower::service_fn(move |req| {
                let channel = channel.clone();
                async move { Self::terminate_http_connect_svc(req, channel).await }
            }));

        let svc = TowerToHyperService::new(svc);

        if let Err(err) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls_stream), svc)
            .instrument(tracing::info_span!("wrapping"))
            .await
        {
            tracing::warn!("Failed to serve connection: {err:#}");
        }
        Ok(())
    }

    async fn terminate_http_connect_svc(
        req: Request<Incoming>,
        channel: <TrustedStreamManager as StreamManager>::Sender,
    ) -> Result<Response> {
        tracing::debug!("handling inner stream");

        let req = req.map(Body::new);

        if req.method() == Method::CONNECT {
            tokio::task::spawn(
                async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = channel.send(upgraded) {
                                tracing::warn!("Failed to send stream via channel: {e:#}");
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed during http connect upgrade: {e:#}");
                        }
                    };
                }
                .instrument(tracing::info_span!("connect_upgrade")),
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
