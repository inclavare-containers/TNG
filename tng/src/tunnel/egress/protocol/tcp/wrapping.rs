use anyhow::Result;
use axum::{
    body::Body,
    response::{IntoResponse as _, Response},
};
use http::{HeaderValue, Method, Request, StatusCode};
use hyper::body::Incoming;
use hyper_util::service::TowerToHyperService;
use tower::ServiceBuilder;
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use tracing::Instrument;

use crate::tunnel::egress::stream_manager::{
    trusted::StreamType, trusted::TrustedStreamManager, StreamManager,
};
use crate::tunnel::{
    attestation_result::AttestationResult,
    utils::{runtime::TokioRuntime, tokio::TokioIo},
};

fn error_response(code: StatusCode, msg: String) -> Response {
    tracing::error!(?code, ?msg, "responding errors to downstream");
    (code, msg).into_response()
}

pub struct TcpWrappingLayer {}

impl TcpWrappingLayer {
    pub async fn unwrap_stream(
        tls_stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
        attestation_result: Option<AttestationResult>,
        channel: <TrustedStreamManager as StreamManager>::Sender,
        runtime: TokioRuntime,
    ) {
        let runtime_cloned = runtime.clone();

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
                    let runtime = runtime.clone();
                    let attestation_result = attestation_result.clone();
                    let span = span.clone();
                    async move {
                        Self::terminate_http_connect_svc(req, attestation_result, channel, runtime)
                            .instrument(span)
                            .await
                    }
                }))
        };

        let svc = TowerToHyperService::new(svc);

        if let Err(error) = hyper::server::conn::http2::Builder::new(runtime_cloned)
            // hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(tls_stream), svc)
            .instrument(span)
            .await
        {
            tracing::error!(?error, "Failed to serve connection");
        }
    }

    async fn terminate_http_connect_svc(
        req: Request<Incoming>,
        attestation_result: Option<AttestationResult>,
        channel: <TrustedStreamManager as StreamManager>::Sender,
        runtime: TokioRuntime,
    ) -> Result<Response> {
        tracing::trace!("Handling new wrapping stream");

        let req = req.map(Body::new);

        if req.method() == Method::CONNECT {
            runtime.spawn_supervised_task_current_span(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        tracing::debug!("Trusted tunnel established");

                        if let Err(e) = channel.send((
                            StreamType::SecuredStream(Box::new(TokioIo::new(upgraded))),
                            attestation_result,
                        )) {
                            tracing::error!("Failed to send stream via channel: {e:#}");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed during http connect upgrade: {e:#}");
                    }
                };
            });
            Ok(Response::new(Body::empty()).into_response())
        } else {
            Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Protocol Error: the method should be CONNECT, may be a invalid client".to_string(),
            ))
        }
    }
}
