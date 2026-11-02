use std::sync::Arc;

use axum::response::IntoResponse;

use crate::tunnel::upstream::{ConnectedUpstream, UpstreamConnector};
use crate::tunnel::utils::runtime::supervised_task::SupervisedTaskResult;
use crate::{error::TngError, AttestationResult, TokioRuntime};

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

/// A backend dial started ahead of the rest of the request pipeline by
/// [`TngStreamContext::begin_backend_dial`], owned by the request that
/// started it. The handle is passed to `forward_request`, which reaps the
/// dial on the cold path; dropping it before then (a decapsulation error, a
/// client disconnect, a request that rode the pooled connection) closes the
/// dial off quietly instead of parking an already-connected, already-idling
/// socket for a later request to inherit. The dial task is supervised, so a
/// handle dropped at process teardown dies with shutdown rather than
/// lingering past the process exit.
#[must_use = "the handle tears down an unconsumed dial; hold it until it is passed to forward_request"]
pub(crate) struct BackendDial {
    runtime: TokioRuntime,
    /// `None` once `into_connection` has taken the task's verdict.
    handle: Option<
        tokio::task::JoinHandle<SupervisedTaskResult<Result<ConnectedUpstream, anyhow::Error>>>,
    >,
}

impl BackendDial {
    /// Await the dial's verdict: `Some(Ok(..))` for a connected socket,
    /// `Some(Err(..))` for a dial the backend refused, `None` when the dial
    /// task vanished (shutdown cancelled it, or it panicked) without ever
    /// answering. Consuming the handle makes the Drop teardown a no-op.
    async fn into_connection(mut self) -> Option<Result<ConnectedUpstream, anyhow::Error>> {
        let handle = self.handle.take()?;
        match handle.await {
            Ok(SupervisedTaskResult::Finished(connected)) => Some(connected),
            _ => None,
        }
    }
}

impl Drop for BackendDial {
    fn drop(&mut self) {
        // The common case is that forward_request already took the verdict;
        // the taken handle makes that a no-op without spawning anything.
        let Some(handle) = self.handle.take() else {
            return;
        };
        // Reap a dial nobody consumed. A dial that completed fine is marked
        // finished before the socket closes: an unused connection is not a
        // failed one. A dial error, or a dial cancelled by shutdown,
        // accounted itself when the dial future unwound inside the task, so
        // those outcomes need nothing here. Spawning the reaper (instead of
        // awaiting inline) keeps an abandoned request's error path from
        // waiting on a dial that is still running.
        self.runtime.spawn_supervised_task_current_span(async move {
            if let Ok(SupervisedTaskResult::Finished(Ok(connected))) = handle.await {
                let (_stream, active_cx) = connected.into_parts();
                active_cx.mark_finished_successfully();
            }
        });
    }
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
}

impl TngStreamContext {
    /// Start the backend dial for this request ahead of the rest of the
    /// pipeline, so the TCP connect overlaps the ohttp decapsulation (HPKE
    /// open, client attestation check, bhttp decode) instead of running
    /// serially after it. Call once the request has cleared the envelope
    /// gates: the content type check and a parseable metadata block are
    /// cheap proof of a genuine TNG request, so garbage traffic cannot
    /// spend backend connections.
    ///
    /// Only the TCP dial is pre-started: hyper's HTTP/1 handshake performs
    /// no wire I/O (it builds the connection state and resolves
    /// immediately), so there is nothing beyond the connect to overlap.
    ///
    /// Returns `None` (and dials nothing) when a pre-dial would be wasted:
    /// the pooled backend connection is present or in use. Hold the
    /// returned handle until `forward_request` consumes it; dropping it
    /// without forwarding closes the dial off quietly.
    pub(crate) fn begin_backend_dial(&self) -> Option<BackendDial> {
        // Peek, never wait: a locked slot means another request is
        // mid-forward on this outer connection and will fill (or has just
        // refilled) it.
        let warm = self
            .backend
            .send_request
            .try_lock()
            .map_or(true, |slot| slot.is_some());
        if warm {
            return None;
        }
        let connector = Arc::clone(&self.connector);
        // attested=false matches every `begin_backend_dial` caller today
        // (both forward paths pass no per-request attestation);
        // `forward_request` refuses to reuse the dial if that ever changes,
        // because the Established access line is stamped at dial time.
        let handle = self.runtime.spawn_supervised_task_current_span(async move {
            connector.connect(true, false).await
        });
        Some(BackendDial {
            runtime: self.runtime.clone(),
            handle: Some(handle),
        })
    }

    /// Forwards the decrypted inner request to the backend. `attestation_result`
    /// only rides along when a fresh backend connection is established; on the
    /// reuse path the connection was already registered with it. Every caller
    /// passes `None` today (per-request attestation of the *client* is checked
    /// in the tunnel API, not carried here). `dial` is the backend dial this
    /// request's pipeline pre-started, if any; a request that ends up riding
    /// the pooled connection leaves it unconsumed and its Drop closes the dial
    /// off.
    pub async fn forward_request<B>(
        &self,
        req: http::Request<B>,
        attestation_result: Option<AttestationResult>,
        dial: Option<BackendDial>,
    ) -> Result<axum::response::Response, TngError>
    where
        B: http_body::Body<Data = bytes::Bytes> + 'static,
        B: std::marker::Send,
        <B as http_body::Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        use http_body_util::BodyExt as _;
        let req = req.map(|body| -> DynSendBody { Box::pin(body.map_err(Into::into)) });
        let req = req.map(SendBoxBody);

        let mut slot = self.backend.send_request.lock().await;

        if let Some(send_request) = slot.as_mut() {
            // `ready()` waits if the connection is still streaming the
            // previous response and fails before a request is dispatched, so
            // replacing the connection after it cannot duplicate a request.
            // Once `send_request()` is used, an error is returned to the
            // caller rather than retried: the request may have reached the
            // backend.
            if send_request.ready().await.is_ok() {
                let response = send_request.send_request(req).await;
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

        // Cold slot: reap the dial this request's pipeline pre-started when
        // it brought one, else dial directly. A failure to reach the backend
        // surfaces here, before the request is dispatched.
        let attested = attestation_result.is_some();
        // An attested request never reuses a pre-dial: the Established
        // access line is stamped at dial time, and that dial is stamped
        // unattested. Dropping the handle closes the dial off quietly.
        let dial = if attested { None } else { dial };
        let mut send_request = match dial {
            Some(dial) => match dial.into_connection().await {
                Some(Ok(connected)) => {
                    connected
                        .into_http1_backend(&self.runtime, self.connector.metrics())
                        .await?
                }
                // The dial itself was refused: report it exactly like an
                // inline failure. Redialing here would charge the request
                // two cx_total for a backend that is down.
                Some(Err(error)) => return Err(TngError::ConnectUpstreamFailed(error)),
                // The dial task vanished (shutdown cancelled it, or it
                // panicked) without a verdict from the backend. Correctness
                // never depends on the dial, so fall back to the
                // inline dial; an attempt that got far enough to be
                // accounted was already charged when its task unwound.
                None => {
                    tracing::debug!(
                        "ohttp egress: pre-dial unavailable, dialling the backend inline"
                    );
                    self.connector
                        .connect_http1(&self.runtime, true, attested)
                        .await?
                }
            },
            None => {
                self.connector
                    .connect_http1(&self.runtime, true, attested)
                    .await?
            }
        };

        tracing::debug!("Forwarding HTTP request to upstream now");
        let response = send_request.send_request(req).await;
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
    use crate::tunnel::upstream::tests::Recorder;

    fn test_metrics() -> ServiceMetrics {
        ServiceMetricsCreator::new_creator(Arc::new(NoopMeterProvider::new()))
            .new_service_metrics(IndexMap::new())
    }

    fn make_context(runtime: TokioRuntime, port: u16) -> TngStreamContext {
        make_context_with_metrics(runtime, port, test_metrics())
    }

    /// The same context, but with a `ServiceMetrics` whose `cx_*` counters
    /// can be read back through the `Recorder`, for the dial accounting
    /// assertions.
    fn make_context_with_metrics(
        runtime: TokioRuntime,
        port: u16,
        metrics: ServiceMetrics,
    ) -> TngStreamContext {
        let connector = UpstreamConnector::new(
            Arc::new(TngEndpoint::from_ipv4(Ipv4Addr::LOCALHOST, port)),
            metrics,
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

    async fn try_get_with(
        ctx: &TngStreamContext,
        dial: Option<BackendDial>,
    ) -> Result<axum::response::Response, crate::error::TngError> {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri("/t")
            .header(http::header::HOST, "backend.invalid")
            .body(Full::new(bytes::Bytes::from_static(b"")))
            .unwrap();
        ctx.forward_request(req, None, dial).await
    }

    async fn try_get(
        ctx: &TngStreamContext,
    ) -> Result<axum::response::Response, crate::error::TngError> {
        try_get_with(ctx, None).await
    }

    async fn get_with(ctx: &TngStreamContext, dial: Option<BackendDial>) -> (u16, String) {
        let resp = try_get_with(ctx, dial).await.unwrap();
        let status = resp.status().as_u16();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes()
            .as_ref()
            .to_vec();
        (status, String::from_utf8_lossy(&body).into_owned())
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
            let resp = ctx.forward_request(req, None, None).await.unwrap();
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

    /// A fake backend that answers requests like `spawn_fake_upstream` but
    /// additionally counts connections the egress closed: used to watch an
    /// abandoned dial being torn down.
    #[allow(clippy::disallowed_methods)] // fake backend lives on the bare test runtime
    async fn spawn_observing_upstream() -> (Arc<AtomicUsize>, Arc<AtomicUsize>, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let conns = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let (c, d) = (conns.clone(), closed.clone());
        tokio::spawn(async move {
            while let Ok((stream, _addr)) = listener.accept().await {
                c.fetch_add(1, Ordering::SeqCst);
                let d = d.clone();
                tokio::spawn(async move {
                    let mut stream = stream;
                    let mut buf = Vec::new();
                    loop {
                        let mut byte = [0u8; 1];
                        match stream.read(&mut byte).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => buf.push(byte[0]),
                        }
                        if buf.ends_with(b"\r\n\r\n") {
                            buf.clear();
                            let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi";
                            if stream.write_all(response).await.is_err() {
                                break;
                            }
                            let _ = stream.flush().await;
                        }
                    }
                    d.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        (conns, closed, port)
    }

    async fn wait_until(counter: &AtomicUsize, expected: usize) -> bool {
        for _ in 0..100 {
            if counter.load(Ordering::SeqCst) >= expected {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        false
    }

    /// `begin_backend_dial` dials without any `forward_request` call, and the
    /// cold path reaps exactly that connection: one backend connection for
    /// the fresh request. Once the pool is warm, `begin_backend_dial` declines
    /// and the next request rides the pooled connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn backend_dial_starts_early_and_is_reaped_by_forward() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, requests, port) = spawn_fake_upstream(None).await;
            let ctx = make_context(runtime, port);

            let dial = ctx.begin_backend_dial().expect("cold slot pre-dials");
            assert!(
                wait_until(&streams, 1).await,
                "the dial reaches the backend before any forward_request"
            );

            let (status, body) = get_with(&ctx, Some(dial)).await;
            assert_eq!(status, 200);
            assert_eq!(body, "hi");
            assert_eq!(
                streams.load(Ordering::SeqCst),
                1,
                "the request rode the pre-dialed connection"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 1);

            let (status, _) = get(&ctx).await;
            assert_eq!(status, 200);
            assert!(
                ctx.begin_backend_dial().is_none(),
                "a warm backend slot must not pre-dial"
            );
            assert_eq!(
                streams.load(Ordering::SeqCst),
                1,
                "pooled connection reused"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 2);
            Ok(())
        })
        .await
    }

    /// A dial the backend refused surfaces as the same
    /// `ConnectUpstreamFailed` the inline path reports, and it is charged
    /// exactly one connection: the cold path must not redial inline after
    /// a failed dial, which would count the request twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_backend_dial_is_not_redialled() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let (metrics, rec) = Recorder::new();
            let ctx = make_context_with_metrics(runtime, port, metrics);

            let dial = ctx.begin_backend_dial().expect("cold slot pre-dials");
            let error = try_get_with(&ctx, Some(dial))
                .await
                .expect_err("a refused backend must fail the request");
            assert!(
                matches!(error, crate::error::TngError::ConnectUpstreamFailed(_)),
                "the dial error keeps its class: {error:?}"
            );
            assert_eq!(rec.counter_u64("cx_total"), 1, "one counted dial");
            assert_eq!(rec.counter_u64("cx_failed"), 1);
            assert_eq!(rec.counter_i64("cx_active"), 0);
            Ok(())
        })
        .await
    }

    /// A dial task that vanished without a verdict (here: cancelled
    /// before it ever ran) must not sink the request: the cold path falls
    /// back to the inline dial, and because the vanished task never started
    /// a connection the request is still charged exactly one cx_total.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn vanished_backend_dial_falls_back_to_inline_dial() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, _requests, port) = spawn_fake_upstream(None).await;
            let (metrics, rec) = Recorder::new();
            let ctx = make_context_with_metrics(runtime, port, metrics);

            // Stand in for a dial task cancelled by shutdown before
            // it dialled: a handle whose task is aborted, so awaiting it
            // yields a join error instead of a dial result.
            let handle = ctx
                .runtime
                .spawn_supervised_task_current_span(std::future::pending::<
                    Result<ConnectedUpstream, anyhow::Error>,
                >());
            handle.abort();
            let dial = BackendDial {
                runtime: ctx.runtime.clone(),
                handle: Some(handle),
            };

            let (status, body) = get_with(&ctx, Some(dial)).await;
            assert_eq!(status, 200, "the request survives via the inline dial");
            assert_eq!(body, "hi");
            assert_eq!(streams.load(Ordering::SeqCst), 1);
            assert_eq!(
                rec.counter_u64("cx_total"),
                1,
                "the vanished task never dialled; only the inline fallback counted"
            );
            assert_eq!(rec.counter_u64("cx_failed"), 0);
            Ok(())
        })
        .await
    }

    /// Dropping the handle without forwarding (the request died during
    /// decapsulation) closes the dial off: the backend sees the connection
    /// come and go, the cx accounting reads one finished connection with no
    /// failure, and nothing is left behind for a later request to inherit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn abandoned_backend_dial_closes_quietly() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (conns, closed, port) = spawn_observing_upstream().await;
            let (metrics, rec) = Recorder::new();
            let ctx = make_context_with_metrics(runtime, port, metrics);

            let dial = ctx.begin_backend_dial().expect("cold slot pre-dials");
            drop(dial);

            assert!(
                wait_until(&closed, 1).await,
                "the abandoned dial is closed, not leaked"
            );
            assert_eq!(
                conns.load(Ordering::SeqCst),
                1,
                "the dial reached the backend"
            );
            assert_eq!(rec.counter_u64("cx_total"), 1);
            assert_eq!(
                rec.counter_u64("cx_failed"),
                0,
                "an unused but successful dial is not a failure"
            );
            assert_eq!(rec.counter_i64("cx_active"), 0);

            // The context stays usable: the next cold request redials.
            let (status, _) = get(&ctx).await;
            assert_eq!(status, 200);
            assert_eq!(conns.load(Ordering::SeqCst), 2);
            assert_eq!(rec.counter_u64("cx_total"), 2);
            Ok(())
        })
        .await
    }
}
