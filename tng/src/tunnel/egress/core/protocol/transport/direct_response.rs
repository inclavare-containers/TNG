use anyhow::Result;
use http::StatusCode;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio_graceful::ShutdownGuard;

use std::convert::Infallible;

use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt;

const INVALID_HTTP_REQUEST_RESPONSE_BODY: &str = "This service is secured by TNG secure session and you must establish the connection via TNG.\n\nIf this is an unexpected behavior, add path matching rules to `decap_from_http.allow_non_tng_traffic_regexes` option.";

const READ_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub async fn send_http1_response_to_non_tng_client(
    shutdown_guard: ShutdownGuard,
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
) -> Result<()> {
    shutdown_guard.spawn_supervised_task_current_span(async move {
        if let Err(error) = hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .timer(TokioTimer::new())
            .header_read_timeout(READ_REQUEST_TIMEOUT)
            .serve_connection(TokioIo::new(stream), service_fn(hello))
            .await
        {
            tracing::error!(?error, "Failed to serve connection");
        }
    });

    Ok(())
}

async fn hello(_: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut response = Response::new(Full::new(Bytes::from(INVALID_HTTP_REQUEST_RESPONSE_BODY)));
    *response.status_mut() = StatusCode::IM_A_TEAPOT; // 418
    Ok(response)
}
