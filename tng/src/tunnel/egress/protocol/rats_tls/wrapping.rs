use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use axum::{body::Body, response::IntoResponse as _};
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::service::TowerToHyperService;
use tower::ServiceBuilder;
use tracing::Instrument;

use crate::tunnel::{
    attestation_result::AttestationResult,
    utils::{self, runtime::TokioRuntime, tokio::TokioIo},
};
use crate::CommonStreamTrait;

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(0);

fn error_response(code: StatusCode, msg: String) -> Response<Body> {
    tracing::error!(?code, ?msg, "responding errors to downstream");
    (code, msg).into_response()
}

pub struct RatsTlsWrappingLayer {}

impl RatsTlsWrappingLayer {
    pub async fn unwrap_stream(
        tls_stream: impl CommonStreamTrait + Sync,
        attestation_result: Option<AttestationResult>,
        channel: tokio::sync::mpsc::UnboundedSender<(
            Box<dyn CommonStreamTrait + Sync>,
            Option<AttestationResult>,
        )>,
        runtime: TokioRuntime,
    ) {
        let runtime_cloned = runtime.clone();

        tracing::debug!("H2 server starting on TLS stream");

        let span = tracing::info_span!("wrapping");
        let svc = {
            let span = span.clone();
            ServiceBuilder::new().service(tower::service_fn(move |req| {
                let channel = channel.clone();
                let runtime = runtime.clone();
                let attestation_result = attestation_result.clone();
                let span = span.clone();
                let stream_id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
                async move {
                    tracing::debug!(stream_id, "H2 server received CONNECT request");
                    Self::terminate_http_connect_svc(
                        req,
                        stream_id,
                        attestation_result,
                        channel,
                        runtime,
                    )
                    .instrument(span)
                    .await
                }
            }))
        };

        let svc = TowerToHyperService::new(svc);

        if let Err(error) = hyper::server::conn::http2::Builder::new(runtime_cloned)
            .keep_alive_interval(None)
            .serve_connection(TokioIo::new(tls_stream), svc)
            .instrument(span)
            .await
        {
            tracing::error!(
                ?error,
                "H2 server on RATS-TLS wrapping layer terminated with error"
            );
        } else {
            tracing::debug!("H2 server on RATS-TLS wrapping layer exited cleanly");
        }
    }

    async fn terminate_http_connect_svc(
        req: Request<Incoming>,
        stream_id: u64,
        attestation_result: Option<AttestationResult>,
        channel: tokio::sync::mpsc::UnboundedSender<(
            Box<dyn CommonStreamTrait + Sync>,
            Option<AttestationResult>,
        )>,
        runtime: TokioRuntime,
    ) -> Result<Response<Body>> {
        tracing::trace!("Handling new wrapping stream");

        let req = req.map(Body::new);

        if req.method() == Method::CONNECT {
            runtime.spawn_supervised_task_current_span({
                let attestation_result = attestation_result.clone();
                async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            tracing::debug!(stream_id, "Trusted tunnel established (upgrade OK)");

                            let Ok(io) = utils::hyper::downcast_h2upgraded(upgraded) else {
                                tracing::error!(stream_id, "failed to downcast to inner stream");
                                return;
                            };

                            if let Err(e) = channel.send((Box::new(io), attestation_result)) {
                                tracing::error!(
                                    stream_id,
                                    "Failed to send stream via channel: {e:#}"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::error!(stream_id, "Failed during http connect upgrade: {e:#}");
                        }
                    };
                }
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
