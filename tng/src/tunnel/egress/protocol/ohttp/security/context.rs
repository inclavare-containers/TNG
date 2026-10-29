use std::sync::Arc;

use axum::response::IntoResponse;

use crate::tunnel::ohttp::timing::{EgressLatency, Timer};
use crate::tunnel::upstream::UpstreamConnector;
use crate::{error::TngError, AttestationResult, TokioIo, TokioRuntime};

type DynSendBody =
    std::pin::Pin<Box<dyn http_body::Body<Data = bytes::Bytes, Error = axum::BoxError> + Send>>;

/// Boxed request body for the pooled backend connections: `Send` but not
/// `Sync`. `http_body_util::BoxBody` additionally requires `Sync`, which the
/// bhttp decoder's body stream is not; a pooled `SendRequest` only needs
/// `Send`.
pub struct SendBoxBody(DynSendBody);

impl http_body::Body for SendBoxBody {
    type Data = bytes::Bytes;
    type Error = axum::BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        // The only field is `Pin<Box<dyn Body>>`, which is `Unpin`; the inner
        // future stays pinned inside the box.
        self.get_mut().0.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }
}

type PooledSendRequest = hyper::client::conn::http1::SendRequest<SendBoxBody>;

/// One keep-alive backend connection, reused across the requests that arrive
/// on the same outer OHTTP connection. A single slot suffices: the mutex
/// serializes sends, the hyper connection pairs responses FIFO, and today's
/// ingress/relay legs are HTTP/1 (one in-flight request per outer connection).
/// A client that negotiated h2c on the outer connection would head-of-line
/// block on the slot instead of getting a dedicated backend connection.
/// A dead or not-ready slot is discarded and replaced by the next request;
/// a slot whose send failed is evicted on the spot, never handed to a later
/// request.
#[derive(Default)]
pub(crate) struct BackendSlot {
    send_request: tokio::sync::Mutex<Option<PooledSendRequest>>,
}

#[derive(Clone)]
pub struct TngStreamContext {
    pub runtime: TokioRuntime,
    /// Upstream dialing for this outer connection: the endpoint the egress
    /// capture mode resolved at accept time, the mode's `SO_MARK`, and the
    /// service accounting. Backend connections are dialed directly here;
    /// the flow no longer sees them.
    pub connector: Arc<UpstreamConnector>,
    /// Direct TCP peer of the OHTTP POST (the relay in the relay topology).
    /// Used to inject X-Real-IP / X-Forwarded-For on the inner request.
    pub peer_addr: Option<std::net::SocketAddr>,
    /// Shared by every request handler cloned from this connection's context.
    /// When the outer connection ends and the last clone drops, the pooled
    /// `SendRequest` is dropped, which tears down the backend connection and
    /// its hyper driver task.
    pub(crate) backend: Arc<BackendSlot>,
    /// Shared with the API handler; records the backend-wait segments of
    /// every forwarded request.
    pub(crate) latency: Arc<EgressLatency>,
}

impl TngStreamContext {
    /// Forwards the decrypted inner request to the backend. `attestation_result`
    /// only rides along when a fresh backend connection is established; on the
    /// reuse path the connection was already registered with it. Every caller
    /// passes `None` today (per-request attestation of the *client* is checked
    /// in the tunnel API, not carried here).
    pub async fn forward_request<B>(
        &self,
        req: http::Request<B>,
        attestation_result: Option<AttestationResult>,
    ) -> Result<axum::response::Response, TngError>
    where
        B: http_body::Body<Data = bytes::Bytes> + 'static,
        B: std::marker::Send,
        <B as http_body::Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // TODO: maybe adjust forward the request to the upstream server with reqwest?

        use http_body_util::BodyExt as _;
        let req = req.map(|body| -> DynSendBody { Box::pin(body.map_err(Into::into)) });
        let req = req.map(SendBoxBody);

        let lock_timer = Timer::start();
        let mut slot = self.backend.send_request.lock().await;
        self.latency.backend_slot_wait.record(lock_timer.elapsed());

        if let Some(send_request) = slot.as_mut() {
            // `ready()` waits if the connection is still streaming the
            // previous response and fails before a request is dispatched, so
            // replacing the connection after it cannot duplicate a request.
            // Once `send_request()` is used, an error is returned to the
            // caller rather than retried: the request may have reached the
            // backend.
            let ready_timer = Timer::start();
            let is_ready = send_request.ready().await.is_ok();
            self.latency.backend_ready.record(ready_timer.elapsed());
            if is_ready {
                let send_timer = Timer::start();
                let response = send_request.send_request(req).await;
                self.latency.backend_send.record(send_timer.elapsed());
                if response.is_err() {
                    // `ready()` can answer Ok while the connection is dying
                    // under a previous aborted response: the upstream close
                    // is still in flight and the send is what surfaces it.
                    // Evict the handle so the next request redials instead
                    // of inheriting the dying connection.
                    *slot = None;
                }
                return response
                    .map(axum::response::Response::into_response)
                    .map_err(TngError::HttpPlainTextForwardError);
            }
            *slot = None;
        }

        // Cold slot: dial the backend directly. A failure to reach the
        // backend surfaces here, before the request is dispatched.
        // `backend_redial` covers the whole fresh-connection setup: the
        // dial plus the HTTP handshake.
        let redial_timer = Timer::start();
        let connected = self
            .connector
            .connect(true, attestation_result.is_some())
            .await
            .map_err(TngError::ConnectUpstreamFailed)?;
        let (stream, active_cx) = connected.into_parts();
        let stream = self.connector.metrics().new_wrapped_backend_stream(stream);

        // TODO: support send both http1 and http2 payload
        let handshake = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await;
        let (mut send_request, conn) = match handshake {
            Ok(pair) => pair,
            Err(error) => {
                // The dial succeeded, so a connection that dies at the HTTP
                // layer is a teardown, not a failed connect.
                active_cx.mark_finished_successfully();
                return Err(TngError::HttpPlainTextForwardError(error));
            }
        };
        self.latency.backend_redial.record(redial_timer.elapsed());

        self.runtime.spawn_supervised_task_current_span(async move {
            if let Err(error) = conn.await {
                tracing::error!(?error, "The HTTP connection with upstream is broken");
            }
            active_cx.mark_finished_successfully();
        });

        tracing::debug!("Forwarding HTTP request to upstream now");
        let send_timer = Timer::start();
        let response = send_request.send_request(req).await;
        self.latency.backend_send_fresh.record(send_timer.elapsed());
        // Pool only on success: a handle whose very first send failed must
        // not be the connection a later request inherits.
        if response.is_ok() {
            *slot = Some(send_request);
        }

        response
            .map(axum::response::Response::into_response)
            .map_err(TngError::HttpPlainTextForwardError)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::Full;
    use indexmap::IndexMap;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    use crate::observability::metric::simple_exporter::noop::NoopMeterProvider;
    use crate::tests::run_test_with_tokio_runtime;
    use crate::tunnel::access_log::{AccessAccepted, EgressAccessMode};
    use crate::tunnel::endpoint::TngEndpoint;
    use crate::tunnel::service_metrics::{ServiceMetrics, ServiceMetricsCreator};

    fn test_metrics() -> ServiceMetrics {
        ServiceMetricsCreator::new_creator(Arc::new(NoopMeterProvider::new()))
            .new_service_metrics(IndexMap::new())
    }

    fn make_context(runtime: TokioRuntime, port: u16) -> TngStreamContext {
        let connector = UpstreamConnector::new(
            Arc::new(TngEndpoint::from_ipv4(Ipv4Addr::LOCALHOST, port)),
            test_metrics(),
            AccessAccepted::new_egress(
                "127.0.0.1:54321".parse().unwrap(),
                "127.0.0.1:8080".parse().unwrap(),
                EgressAccessMode::Netfilter,
            ),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
        );
        TngStreamContext {
            runtime,
            connector: Arc::new(connector),
            peer_addr: None,
            backend: Arc::default(),
            latency: Arc::new(EgressLatency::new()),
        }
    }

    /// Acts as the backend on a real TCP listener: every accepted connection
    /// carries raw HTTP/1 bytes; reply one tiny `200` per request head.
    /// Returns counters for connections served and requests answered, plus
    /// the listener port.
    #[allow(clippy::disallowed_methods)] // fake backend lives on the bare test runtime
    async fn spawn_fake_upstream(
        close_first_stream_after: Option<usize>,
    ) -> (Arc<AtomicUsize>, Arc<AtomicUsize>, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let streams = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (s, r) = (streams.clone(), requests.clone());
        tokio::spawn(async move {
            while let Ok((stream, _addr)) = listener.accept().await {
                s.fetch_add(1, Ordering::SeqCst);
                let r = r.clone();
                let cap = close_first_stream_after;
                tokio::spawn(async move {
                    let mut stream = stream;
                    let mut buf = Vec::new();
                    let mut on_stream = 0usize;
                    loop {
                        let mut byte = [0u8; 1];
                        match stream.read(&mut byte).await {
                            Ok(0) => break,
                            Ok(_) => buf.push(byte[0]),
                            Err(_) => break,
                        }
                        if buf.ends_with(b"\r\n\r\n") {
                            on_stream += 1;
                            r.fetch_add(1, Ordering::SeqCst);
                            let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi";
                            if stream.write_all(response).await.is_err() {
                                break;
                            }
                            let _ = stream.flush().await;
                            buf.clear();
                            if cap.is_some_and(|cap| on_stream >= cap) {
                                // Backend hung up, like a keep-alive idle
                                // timeout closing the connection between
                                // requests.
                                break;
                            }
                        }
                    }
                });
            }
        });
        (streams, requests, port)
    }

    async fn try_get(
        ctx: &TngStreamContext,
    ) -> Result<axum::response::Response, crate::error::TngError> {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri("/t")
            .header(http::header::HOST, "backend.invalid")
            .body(Full::new(bytes::Bytes::from_static(b"")))
            .unwrap();
        ctx.forward_request(req, None).await
    }

    async fn get(ctx: &TngStreamContext) -> (u16, String) {
        let resp = try_get(ctx).await.unwrap();
        let status = resp.status().as_u16();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes()
            .as_ref()
            .to_vec();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn backend_connection_is_reused_across_requests() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, requests, port) = spawn_fake_upstream(None).await;
            let ctx = make_context(runtime, port);

            for _ in 0..3 {
                let (status, body) = get(&ctx).await;
                assert_eq!(status, 200);
                assert_eq!(body, "hi");
            }

            assert_eq!(streams.load(Ordering::SeqCst), 1, "one pooled backend conn");
            assert_eq!(requests.load(Ordering::SeqCst), 3, "three requests on it");
            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dead_backend_connection_is_redialled_transparently() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, requests, port) = spawn_fake_upstream(Some(1)).await;
            let ctx = make_context(runtime, port);

            let (status, _) = get(&ctx).await;
            assert_eq!(status, 200);
            // Give the fake backend time to drop the connection and the
            // driver task to observe the closed connection.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let (status, _) = get(&ctx).await;
            assert_eq!(status, 200, "request survives a dead pooled connection");

            assert_eq!(streams.load(Ordering::SeqCst), 2, "redial after close");
            assert_eq!(requests.load(Ordering::SeqCst), 2);
            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn request_body_streams_through_send_box_body() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (_streams, _requests, port) = spawn_fake_upstream(None).await;
            let ctx = make_context(runtime, port);

            let body = Full::new(bytes::Bytes::from_static(b"payload=1"));
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri("/t")
                .header(http::header::HOST, "backend.invalid")
                .header(http::header::CONTENT_LENGTH, 9)
                .body(body)
                .unwrap();
            let resp = ctx.forward_request(req, None).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);
            Ok(())
        })
        .await
    }

    /// Fake backend where the first connection answers the first request and
    /// then hangs up without answering the second one: the close reaches the
    /// hyper driver only after the second request was dispatched, so
    /// `ready()` answers Ok and the send is what fails. Later connections
    /// answer every request. Returns a counter of connections served.
    #[allow(clippy::disallowed_methods)] // fake backend lives on the bare test runtime
    async fn spawn_hangup_racing_close() -> (Arc<AtomicUsize>, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let streams = Arc::new(AtomicUsize::new(0));
        let s = streams.clone();
        tokio::spawn(async move {
            let mut racing_conn = true;
            while let Ok((stream, _addr)) = listener.accept().await {
                s.fetch_add(1, Ordering::SeqCst);
                let race_close = std::mem::replace(&mut racing_conn, false);
                tokio::spawn(async move {
                    let mut stream = stream;
                    let mut buf = Vec::new();
                    loop {
                        let mut byte = [0u8; 1];
                        match stream.read(&mut byte).await {
                            Ok(0) => break,
                            Ok(_) => buf.push(byte[0]),
                            Err(_) => break,
                        }
                        if !buf.ends_with(b"\r\n\r\n") {
                            continue;
                        }
                        buf.clear();
                        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi";
                        if stream.write_all(response).await.is_err() {
                            break;
                        }
                        let _ = stream.flush().await;
                        if race_close {
                            // Read the next request, then drop the connection
                            // without answering it.
                            loop {
                                let mut byte = [0u8; 1];
                                match stream.read(&mut byte).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) => buf.push(byte[0]),
                                }
                                if buf.ends_with(b"\r\n\r\n") {
                                    break;
                                }
                            }
                            return;
                        }
                    }
                });
            }
        });
        (streams, port)
    }

    /// Integration repro in miniature: after an aborted response the pooled
    /// connection is dying, `ready()` cannot see it yet, and the send fails.
    /// The failed handle must leave the pool at that moment, so the next
    /// request redials instead of inheriting the dying connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_send_evicts_pooled_connection() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, port) = spawn_hangup_racing_close().await;
            let ctx = make_context(runtime, port);

            let (status, _) = get(&ctx).await;
            assert_eq!(status, 200, "first request on a fresh connection");

            assert!(
                try_get(&ctx).await.is_err(),
                "second request was dispatched before the close, must surface as an error"
            );
            assert!(
                ctx.backend.send_request.lock().await.is_none(),
                "a failed send must evict the pooled connection"
            );

            let (status, body) = get(&ctx).await;
            assert_eq!(status, 200, "third request redials");
            assert_eq!(body, "hi");
            assert_eq!(
                streams.load(Ordering::SeqCst),
                2,
                "exactly one redial after the failed send"
            );
            Ok(())
        })
        .await
    }

    /// A brand-new connection whose very first send fails must not enter the
    /// pool either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::disallowed_methods)] // fake backend lives on the bare test runtime
    async fn failed_first_send_does_not_pool_connection() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let streams = Arc::new(AtomicUsize::new(0));
            let s = streams.clone();
            tokio::spawn(async move {
                let mut first_conn = true;
                while let Ok((stream, _addr)) = listener.accept().await {
                    s.fetch_add(1, Ordering::SeqCst);
                    let hang_up = std::mem::replace(&mut first_conn, false);
                    tokio::spawn(async move {
                        let mut stream = stream;
                        let mut buf = Vec::new();
                        loop {
                            let mut byte = [0u8; 1];
                            match stream.read(&mut byte).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => buf.push(byte[0]),
                            }
                            if !buf.ends_with(b"\r\n\r\n") {
                                continue;
                            }
                            if hang_up {
                                // Hang up without ever answering.
                                return;
                            }
                            buf.clear();
                            let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi";
                            if stream.write_all(response).await.is_err() {
                                break;
                            }
                            let _ = stream.flush().await;
                        }
                    });
                }
            });
            let ctx = make_context(runtime, port);

            assert!(
                try_get(&ctx).await.is_err(),
                "first send on the hanging-up connection must fail"
            );
            assert!(
                ctx.backend.send_request.lock().await.is_none(),
                "a failed fresh connection must not enter the pool"
            );

            let (status, _) = get(&ctx).await;
            assert_eq!(status, 200, "next request redials successfully");
            assert_eq!(streams.load(Ordering::SeqCst), 2);
            Ok(())
        })
        .await
    }
}
