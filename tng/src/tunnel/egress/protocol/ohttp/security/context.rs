use std::sync::Arc;

use axum::response::IntoResponse;
use futures::future::Either;

use crate::tunnel::ohttp::timing::{EgressLatency, PreconnectCounters, Timer};
use crate::tunnel::upstream::{ConnectedUpstream, UpstreamConnector};
use crate::tunnel::utils::runtime::supervised_task::SupervisedTaskResult;
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

/// How much request-body data the cold path may buffer while it waits for
/// the backend dial and the HTTP handshake. 128 KiB matches the relay pipe
/// the duplex bridge used before it was removed: bodies up to that size are
/// fully buffered, so the backend leg starts with the whole payload ready to
/// write; larger bodies keep streaming after the prefix. The buffer lives on
/// the handler task and is freed once hyper has written it to the backend.
const PREFIX_CAP: usize = 128 * 1024;

/// What a [`PrefixPull`] produced: the frames consumed from the body so far,
/// a captured stream error, and the body to continue from (`None` when the
/// body already ended).
struct Pulled {
    frames: Vec<http_body::Frame<bytes::Bytes>>,
    error: Option<axum::BoxError>,
    rest: Option<DynSendBody>,
}

/// Drains up to [`PREFIX_CAP`] bytes of the request body into memory. The
/// cold path of `forward_request` runs it concurrently with the backend dial
/// on the handler task, so the decode-chain work (pulling the sealed bytes
/// through the bhttp/HPKE body stream) overlaps the connect wait instead of
/// serializing behind it. It ends when the body ends, errors, or the buffer
/// cap is reached; each of those states is recorded so `JoinedBody` can
/// replay the exact frame sequence a live stream would have produced.
struct PrefixPull {
    body: Option<DynSendBody>,
    frames: Vec<http_body::Frame<bytes::Bytes>>,
    buffered: usize,
    error: Option<axum::BoxError>,
    ended: bool,
}

impl PrefixPull {
    fn new(body: DynSendBody) -> Self {
        Self {
            body: Some(body),
            frames: Vec::new(),
            buffered: 0,
            error: None,
            ended: false,
        }
    }

    fn finished(&self) -> bool {
        self.ended || self.error.is_some() || self.buffered >= PREFIX_CAP
    }

    /// Take the pull state out. Also used when the dial completes first: the
    /// frames buffered so far stay valid, the rest of the body keeps
    /// streaming live through the joined body.
    fn finish(&mut self) -> Pulled {
        let rest = if self.ended { None } else { self.body.take() };
        Pulled {
            frames: std::mem::take(&mut self.frames),
            error: self.error.take(),
            rest,
        }
    }
}

impl std::future::Future for PrefixPull {
    type Output = Pulled;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Pulled> {
        let this = self.as_mut().get_mut();
        loop {
            if this.finished() {
                return std::task::Poll::Ready(this.finish());
            }
            // Poll through a borrow that ends at the statement so the
            // handlers below can touch `this` again. `finish()` is the only
            // thing that clears the body, and `finished()` covers that case,
            // so the `None` arm cannot arise.
            let poll = match this.body.as_mut() {
                Some(body) => body.as_mut().poll_frame(cx),
                None => std::task::Poll::Ready(None),
            };
            match poll {
                std::task::Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        this.buffered += data.len();
                    }
                    this.frames.push(frame);
                }
                std::task::Poll::Ready(Some(Err(error))) => {
                    this.error = Some(error);
                }
                std::task::Poll::Ready(None) => this.ended = true,
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

/// The body `forward_request` hands hyper on the cold path: the frames the
/// [`PrefixPull`] already consumed, replayed in order, followed by whatever
/// the original body still produces (or the stream error the pull captured,
/// surfaced at send time so a body that breaks mid-prefix keeps today's
/// error visibility: the request head and the prefix reach the backend
/// before the failure appears on the wire).
struct JoinedBody {
    prefix: std::vec::IntoIter<http_body::Frame<bytes::Bytes>>,
    /// Data bytes still sitting in `prefix`, tracked so `size_hint` stays
    /// truthful while frames are handed out (`Frame` is not `Clone`, so the
    /// iterator cannot be rescanned).
    prefix_bytes: u64,
    error: Option<axum::BoxError>,
    rest: Option<DynSendBody>,
}

impl From<Pulled> for JoinedBody {
    fn from(pulled: Pulled) -> Self {
        let prefix_bytes = pulled
            .frames
            .iter()
            .filter_map(|frame| frame.data_ref())
            .map(|data| data.len() as u64)
            .sum();
        Self {
            prefix: pulled.frames.into_iter(),
            prefix_bytes,
            error: pulled.error,
            rest: pulled.rest,
        }
    }
}

impl http_body::Body for JoinedBody {
    type Data = bytes::Bytes;
    type Error = axum::BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(frame) = this.prefix.next() {
            if let Some(data) = frame.data_ref() {
                this.prefix_bytes -= data.len() as u64;
            }
            return std::task::Poll::Ready(Some(Ok(frame)));
        }
        if let Some(error) = this.error.take() {
            return std::task::Poll::Ready(Some(Err(error)));
        }
        match this.rest.as_mut() {
            Some(body) => body.as_mut().poll_frame(cx),
            None => std::task::Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.len() == 0
            && self.error.is_none()
            && match &self.rest {
                Some(body) => body.is_end_stream(),
                None => true,
            }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = http_body::SizeHint::new();
        match self.rest.as_ref() {
            Some(body) => {
                let rest = body.size_hint();
                hint.set_lower(self.prefix_bytes + rest.lower());
                if let Some(upper) = rest.upper() {
                    hint.set_upper(self.prefix_bytes + upper);
                }
            }
            None => hint.set_exact(self.prefix_bytes),
        }
        hint
    }
}

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

/// A backend dial started ahead of the request pipeline by
/// [`TngStreamContext::start_preconnect`], pending in the context's
/// `preconnect` slot until the cold path of `forward_request` reaps it.
/// Supervised, so a dial nobody reaped dies with shutdown instead of
/// lingering past the process exit.
type PreconnectDial =
    tokio::task::JoinHandle<SupervisedTaskResult<Result<ConnectedUpstream, anyhow::Error>>>;

/// Scopes a preconnect to the request that started it: if that request
/// never reaches `forward_request` (decapsulation error, client disconnect),
/// dropping the guard closes the dial off instead of parking an
/// already-connected, already-idling socket in the slot for a later request
/// to inherit.
#[must_use = "the guard tears down an abandoned preconnect; drop it only by holding it until forward_request runs"]
pub(crate) struct PreconnectGuard {
    runtime: TokioRuntime,
    preconnect: Arc<tokio::sync::Mutex<Option<PreconnectDial>>>,
    counters: Arc<PreconnectCounters>,
}

impl Drop for PreconnectGuard {
    fn drop(&mut self) {
        // The common case is that forward_request already took the dial;
        // peek first so successful requests pay no task spawn. A slot that
        // is locked (another handler on this outer connection) counts as
        // something possibly pending and gets reaped below.
        if let Ok(slot) = self.preconnect.try_lock() {
            if slot.is_none() {
                return;
            }
        }
        let runtime = self.runtime.clone();
        let preconnect = Arc::clone(&self.preconnect);
        let counters = Arc::clone(&self.counters);
        runtime.spawn_supervised_task_current_span(async move {
            // Reap a dial nobody consumed. A dial that completed fine is
            // marked finished before the socket closes: an unused
            // connection is not a failed one. A dial error, or a dial
            // cancelled by shutdown, accounted itself when the dial future
            // unwound inside the task, so those outcomes need nothing here.
            let Some(handle) = preconnect.lock().await.take() else {
                return;
            };
            counters.record_abandoned();
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
    /// The one in-flight preconnect for this outer connection, started by
    /// [`TngStreamContext::start_preconnect`] and reaped by `forward_request`
    /// or by the guard of the request that started it. One slot matches the
    /// `BackendSlot` assumption that today's ingress legs carry a single
    /// in-flight request per outer connection.
    pub(crate) preconnect: Arc<tokio::sync::Mutex<Option<PreconnectDial>>>,
    /// Lifecycle counters for the preconnect slots above, served at
    /// `.../ohttp/preconnect` for diagnosing whether pre-dials are declined,
    /// started but late, or reaped.
    pub(crate) preconnect_counters: Arc<PreconnectCounters>,
    /// Shared with the API handler; records the backend-wait segments of
    /// every forwarded request.
    pub(crate) latency: Arc<EgressLatency>,
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
    /// Returns `None` (and dials nothing) when a pre-dial would be wasted:
    /// the pooled backend connection is present or in use, or a preconnect
    /// is already pending. Hold the returned guard until `forward_request`
    /// runs; dropping it without forwarding closes the dial off quietly.
    pub(crate) fn start_preconnect(&self) -> Option<PreconnectGuard> {
        // Peek, never wait: a locked slot means another request is
        // mid-forward on this outer connection and will fill (or has just
        // refilled) it.
        let warm = self
            .backend
            .send_request
            .try_lock()
            .map_or(true, |slot| slot.is_some());
        if warm {
            self.preconnect_counters.record_declined_warm();
            return None;
        }
        let mut pending = self.preconnect.try_lock().ok()?;
        if pending.is_some() {
            return None;
        }
        let connector = Arc::clone(&self.connector);
        // attested=false matches every preconnect-eligible caller today
        // (both forward paths pass no per-request attestation);
        // `forward_request` refuses to reuse the dial if that ever changes,
        // because the Established access line is stamped at dial time.
        *pending = Some(self.runtime.spawn_supervised_task_current_span(async move {
            connector.connect(true, false).await
        }));
        drop(pending);
        self.preconnect_counters.record_started();
        Some(PreconnectGuard {
            runtime: self.runtime.clone(),
            preconnect: Arc::clone(&self.preconnect),
            counters: Arc::clone(&self.preconnect_counters),
        })
    }

    /// Hand the cold path the pending pre-dial, if the request brought one.
    /// Attested requests never reuse it: that dial is stamped unattested.
    async fn take_preconnect(&self, attested: bool) -> Option<PreconnectDial> {
        if attested {
            return None;
        }
        let handle = self.preconnect.lock().await.take();
        if handle.is_some() {
            self.preconnect_counters.record_reaped();
        }
        handle
    }

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
                let response = send_request.send_request(req.map(SendBoxBody)).await;
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

        // Cold slot. Two futures run concurrently on this task: the backend
        // dial plus HTTP handshake, and the [`PrefixPull`] of the request
        // body. The body pump is what hid the dial wait in the removed
        // duplex-bridge design, and the starved dial task does not get
        // faster by being awaited sooner; what the overlap buys is that a
        // saturated runtime cannot hold up the decode-chain work behind the
        // dial's scheduling. The pull runs on this handler task (no spawn),
        // so its polls are guaranteed whenever the task runs, and by the
        // time the handshake completes the body prefix is already buffered
        // and the send starts with the payload in hand.
        let attested = attestation_result.is_some();
        let (head, body) = req.into_parts();
        let mut dial = std::pin::pin!(self.dial_backend(attested));
        let mut pull = PrefixPull::new(body);
        let outcome = tokio::select! {
            result = &mut dial => Either::Left(result),
            pulled = &mut pull => Either::Right(pulled),
        };
        let (mut send_request, pulled) = match outcome {
            Either::Left(result) => (result?, pull.finish()),
            Either::Right(pulled) => (dial.await?, pulled),
        };

        let req = http::Request::from_parts(head, SendBoxBody(Box::pin(JoinedBody::from(pulled))));

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

    /// Cold-path backend setup: reap the dial this request's pipeline
    /// pre-started when there is one, else dial directly, then bring the
    /// connection up to a pooled `SendRequest`. A failure to reach the
    /// backend surfaces here, before the request is dispatched.
    /// `backend_redial` covers the whole fresh-connection setup: the dial
    /// plus the HTTP handshake.
    async fn dial_backend(&self, attested: bool) -> Result<PooledSendRequest, TngError> {
        let redial_timer = Timer::start();
        let connected = match self.take_preconnect(attested).await {
            Some(handle) => match handle.await {
                Ok(SupervisedTaskResult::Finished(Ok(connected))) => connected,
                // The dial itself was refused: report it exactly like an
                // inline failure. Redialing here would charge the request
                // two cx_total for a backend that is down.
                Ok(SupervisedTaskResult::Finished(Err(error))) => {
                    return Err(TngError::ConnectUpstreamFailed(error))
                }
                // The dial task vanished (shutdown cancelled it, or it
                // panicked) without a verdict from the backend. Correctness
                // never depends on the preconnect, so fall back to the
                // inline dial; an attempt that got far enough to be
                // accounted was already charged when its task unwound.
                _ => {
                    tracing::debug!(
                        "ohttp egress: preconnect unavailable, dialling the backend inline"
                    );
                    self.connector
                        .connect(true, attested)
                        .await
                        .map_err(TngError::ConnectUpstreamFailed)?
                }
            },
            None => self
                .connector
                .connect(true, attested)
                .await
                .map_err(TngError::ConnectUpstreamFailed)?,
        };
        let (stream, active_cx) = connected.into_parts();
        let stream = self.connector.metrics().new_wrapped_backend_stream(stream);

        // TODO: support send both http1 and http2 payload
        let handshake = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await;
        let (send_request, conn) = match handshake {
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

        Ok(send_request)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body::Body as _;
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
    /// can be read back through the `Recorder`, for the preconnect
    /// accounting assertions.
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
            preconnect: Arc::default(),
            preconnect_counters: Arc::new(PreconnectCounters::default()),
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

    /// A fake backend that answers requests like `spawn_fake_upstream` but
    /// additionally counts connections the egress closed: used to watch an
    /// abandoned preconnect being torn down.
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

    /// The preconnect dials without any `forward_request` call, and the
    /// cold path reaps exactly that connection: one backend connection for
    /// the fresh request. Once the pool is warm, `start_preconnect` declines
    /// and the next request rides the pooled connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn preconnect_dials_early_and_is_reaped_by_forward() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, requests, port) = spawn_fake_upstream(None).await;
            let ctx = make_context(runtime, port);

            let _preconnect = ctx.start_preconnect().expect("cold slot pre-dials");
            assert!(
                ctx.preconnect.try_lock().unwrap().is_some(),
                "the dial stays in the slot until forward_request takes it"
            );
            assert!(
                wait_until(&streams, 1).await,
                "the dial reaches the backend before any forward_request"
            );

            let (status, body) = get(&ctx).await;
            assert_eq!(status, 200);
            assert_eq!(body, "hi");
            assert!(
                ctx.preconnect.lock().await.is_none(),
                "forward_request consumed the preconnect"
            );
            assert_eq!(
                streams.load(Ordering::SeqCst),
                1,
                "the request rode the pre-dialed connection"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 1);

            let (status, _) = get(&ctx).await;
            assert_eq!(status, 200);
            assert!(
                ctx.start_preconnect().is_none(),
                "a warm backend slot must not pre-dial"
            );
            assert!(ctx.preconnect.try_lock().unwrap().is_none());
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

    /// A preconnect whose dial was refused surfaces as the same
    /// `ConnectUpstreamFailed` the inline path reports, and it is charged
    /// exactly one connection: the cold path must not redial inline after
    /// a failed preconnect, which would count the request twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_preconnect_dial_is_not_redialled() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let (metrics, rec) = Recorder::new();
            let ctx = make_context_with_metrics(runtime, port, metrics);

            let _preconnect = ctx.start_preconnect().expect("cold slot pre-dials");
            let error = try_get(&ctx)
                .await
                .expect_err("a refused backend must fail the request");
            assert!(
                matches!(error, crate::error::TngError::ConnectUpstreamFailed(_)),
                "the dial error keeps its class: {error:?}"
            );
            assert_eq!(rec.counter_u64("cx_total"), 1, "one counted dial");
            assert_eq!(rec.counter_u64("cx_failed"), 1);
            assert_eq!(rec.counter_i64("cx_active"), 0);
            assert!(
                ctx.preconnect.lock().await.is_none(),
                "the failed dial was consumed, not left in the slot"
            );
            Ok(())
        })
        .await
    }

    /// A preconnect task that vanished without a verdict (here: cancelled
    /// before it ever ran) must not sink the request: the cold path falls
    /// back to the inline dial, and because the vanished task never started
    /// a connection the request is still charged exactly one cx_total.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn vanished_preconnect_falls_back_to_inline_dial() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, _requests, port) = spawn_fake_upstream(None).await;
            let (metrics, rec) = Recorder::new();
            let ctx = make_context_with_metrics(runtime, port, metrics);

            // Stand in for a preconnect task cancelled by shutdown before
            // it dialled: the slot holds a handle whose task is aborted,
            // so awaiting it yields a join error instead of a dial result.
            let handle = ctx
                .runtime
                .spawn_supervised_task_current_span(std::future::pending::<
                    Result<ConnectedUpstream, anyhow::Error>,
                >());
            handle.abort();
            *ctx.preconnect.lock().await = Some(handle);

            let (status, body) = get(&ctx).await;
            assert_eq!(status, 200, "the request survives via the inline dial");
            assert_eq!(body, "hi");
            assert!(ctx.preconnect.lock().await.is_none());
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

    /// Dropping the guard without forwarding (the request died during
    /// decapsulation) closes the dial off: the backend sees the connection
    /// come and go, the cx accounting reads one finished connection with no
    /// failure, and nothing is left in the slot for a later request to
    /// inherit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn abandoned_preconnect_closes_quietly() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (conns, closed, port) = spawn_observing_upstream().await;
            let (metrics, rec) = Recorder::new();
            let ctx = make_context_with_metrics(runtime, port, metrics);

            let preconnect = ctx.start_preconnect().expect("cold slot pre-dials");
            drop(preconnect);

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
            assert!(ctx.preconnect.lock().await.is_none());

            // The context stays usable: the next cold request redials.
            let (status, _) = get(&ctx).await;
            assert_eq!(status, 200);
            assert_eq!(conns.load(Ordering::SeqCst), 2);
            assert_eq!(rec.counter_u64("cx_total"), 2);
            Ok(())
        })
        .await
    }

    // ---------- prefix-overlap tests ----------

    use std::sync::atomic::AtomicBool;

    /// A scripted body: hands out the given data chunks one frame per poll,
    /// then optionally one error frame, then ends. Counts polls and records
    /// when the script ran out, so tests can observe whether (and how far)
    /// the prefix pull consumed the body.
    struct ScriptedBody {
        chunks: std::vec::IntoIter<bytes::Bytes>,
        then_error: bool,
        error_fired: bool,
        polls: Arc<AtomicUsize>,
        drained: Arc<AtomicBool>,
    }

    impl ScriptedBody {
        fn scripted(chunks: Vec<bytes::Bytes>) -> (Self, Arc<AtomicUsize>, Arc<AtomicBool>) {
            let polls = Arc::new(AtomicUsize::new(0));
            let drained = Arc::new(AtomicBool::new(false));
            (
                Self {
                    chunks: chunks.into_iter(),
                    then_error: false,
                    error_fired: false,
                    polls: Arc::clone(&polls),
                    drained: Arc::clone(&drained),
                },
                polls,
                drained,
            )
        }

        fn failing(chunks: Vec<bytes::Bytes>) -> Self {
            Self {
                chunks: chunks.into_iter(),
                then_error: true,
                error_fired: false,
                polls: Arc::new(AtomicUsize::new(0)),
                drained: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl http_body::Body for ScriptedBody {
        type Data = bytes::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            if let Some(chunk) = this.chunks.next() {
                return std::task::Poll::Ready(Some(Ok(http_body::Frame::data(chunk))));
            }
            if this.then_error && !this.error_fired {
                this.error_fired = true;
                return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "scripted body failure",
                ))));
            }
            this.drained.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(None)
        }
    }

    fn test_bytes(prefix: u8, len: usize) -> bytes::Bytes {
        let mut v = Vec::with_capacity(len);
        for i in 0..len {
            v.push(prefix.wrapping_add((i % 251) as u8));
        }
        bytes::Bytes::from(v)
    }

    /// A fake backend that answers each HTTP/1 request with an echo of the
    /// body it read: parses the request head, reads exactly the declared
    /// `content-length` bytes, then replies `200` with those bytes as the
    /// response body. Counts connections and completed requests.
    #[allow(clippy::disallowed_methods)] // fake backend lives on the bare test runtime
    async fn spawn_echo_upstream() -> (Arc<AtomicUsize>, Arc<AtomicUsize>, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let streams = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (s, r) = (streams.clone(), requests.clone());
        tokio::spawn(async move {
            while let Ok((stream, _addr)) = listener.accept().await {
                s.fetch_add(1, Ordering::SeqCst);
                let r = r.clone();
                tokio::spawn(async move {
                    let mut stream = stream;
                    // Keep-alive: serve requests on this connection until it
                    // closes.
                    loop {
                        let mut buf = Vec::new();
                        loop {
                            let mut byte = [0u8; 1];
                            match stream.read(&mut byte).await {
                                Ok(0) | Err(_) => return,
                                Ok(_) => buf.push(byte[0]),
                            }
                            if buf.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        let head_end = buf.len();
                        // The tests all declare a content-length; a head
                        // without one is treated as a bodyless request.
                        let mut content_length = 0usize;
                        for line in buf[..head_end].split(|b| *b == b'\n') {
                            let line = line.to_ascii_lowercase();
                            if let Some(rest) = line.strip_prefix(b"content-length:") {
                                let digits: Vec<u8> = rest
                                    .iter()
                                    .copied()
                                    .filter(|b| b.is_ascii_digit())
                                    .collect();
                                content_length = std::str::from_utf8(&digits)
                                    .ok()
                                    .and_then(|s| s.parse().ok())
                                    .unwrap_or(0);
                            }
                        }
                        let mut body = vec![0u8; content_length];
                        let mut filled = 0usize;
                        while filled < content_length {
                            let mut byte = [0u8; 1];
                            match stream.read(&mut byte).await {
                                Ok(0) | Err(_) => return,
                                Ok(_) => {
                                    body[filled] = byte[0];
                                    filled += 1;
                                }
                            }
                        }
                        r.fetch_add(1, Ordering::SeqCst);
                        let mut response =
                            format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len())
                                .into_bytes();
                        response.extend_from_slice(&body);
                        if stream.write_all(&response).await.is_err() {
                            return;
                        }
                        if stream.flush().await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (streams, requests, port)
    }

    async fn post_and_collect(
        ctx: &TngStreamContext,
        body: ScriptedBody,
        content_length: usize,
    ) -> Result<(u16, Vec<u8>), crate::error::TngError> {
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("/t")
            .header(http::header::HOST, "backend.invalid")
            .header(http::header::CONTENT_LENGTH, content_length)
            .body(body)
            .unwrap();
        let resp = ctx.forward_request(req, None).await?;
        let status = resp.status().as_u16();
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes()
            .as_ref()
            .to_vec();
        Ok((status, bytes))
    }

    async fn wait_flag(flag: &AtomicBool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 2).max(1) {
            if flag.load(Ordering::SeqCst) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        flag.load(Ordering::SeqCst)
    }

    /// The cold path pulls the request body while the dial is still pending:
    /// the body is fully consumed before the preconnect resolves, yet the
    /// backend has seen no request head at that moment (the head goes out
    /// only after the handshake). The eventual response carries the exact
    /// bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    // The forward task runs on the bare test runtime: the test needs its
    // awaitable JoinHandle, which the supervised spawn helper does not offer.
    #[allow(clippy::disallowed_methods)]
    async fn cold_path_prefix_pull_overlaps_the_backend_dial() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, requests, port) = spawn_echo_upstream().await;
            let ctx = Arc::new(make_context(runtime, port));
            let body_len = 64 * 1024;
            let (body, _polls, drained) = ScriptedBody::scripted(vec![test_bytes(7, body_len)]);

            // A preconnect whose dial resolves only after the body would
            // have been pulled: stand-in for the starved pre-dial on a
            // saturated runtime.
            let connector = Arc::clone(&ctx.connector);
            let handle = ctx.runtime.spawn_supervised_task_current_span(async move {
                let connected = connector.connect(true, false).await;
                tokio::time::sleep(std::time::Duration::from_millis(60)).await;
                connected
            });
            *ctx.preconnect.lock().await = Some(handle);

            let forward_ctx = Arc::clone(&ctx);
            let forward =
                tokio::spawn(async move { post_and_collect(&forward_ctx, body, body_len).await });

            assert!(
                wait_flag(&drained, 2000).await,
                "the body is pulled while the dial is still pending"
            );
            assert_eq!(
                requests.load(Ordering::SeqCst),
                0,
                "no request head at the backend yet: the pull ran before the send"
            );

            let (status, echoed) = forward.await.unwrap().unwrap();
            assert_eq!(status, 200);
            assert_eq!(echoed, test_bytes(7, body_len).as_ref());
            assert_eq!(streams.load(Ordering::SeqCst), 1, "the pre-dial was reaped");
            Ok(())
        })
        .await
    }

    /// A body smaller than the cap is fully buffered during the cold path
    /// and still forwards byte-exact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cold_path_small_body_forwards_byte_exact() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (_streams, _requests, port) = spawn_echo_upstream().await;
            let ctx = make_context(runtime, port);
            let chunks = vec![test_bytes(1, 1000), test_bytes(2, 21), test_bytes(3, 3000)];
            let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            let total = expected.len();
            let (body, polls, _drained) = ScriptedBody::scripted(chunks);

            let (status, echoed) = post_and_collect(&ctx, body, total).await.unwrap();
            assert_eq!(status, 200);
            assert_eq!(echoed, expected);
            assert!(polls.load(Ordering::SeqCst) >= 1, "the body was consumed");
            Ok(())
        })
        .await
    }

    /// A body larger than the cap forwards byte-exact too: the buffered
    /// prefix is spliced in front of the still-live remainder.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cold_path_body_beyond_prefix_cap_forwards_byte_exact() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (_streams, _requests, port) = spawn_echo_upstream().await;
            let ctx = make_context(runtime, port);
            let chunks = vec![
                test_bytes(1, 100 * 1024),
                test_bytes(2, 100 * 1024),
                test_bytes(3, 100 * 1024),
            ];
            let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            let total = expected.len();
            assert!(total > PREFIX_CAP);
            // Note: with the content-length satisfied hyper stops polling the
            // body at the last needed byte, so `drained` may stay false; the
            // byte-exact echo is the real proof the remainder streamed.
            let (body, _polls, _drained) = ScriptedBody::scripted(chunks);

            let (status, echoed) = post_and_collect(&ctx, body, total).await.unwrap();
            assert_eq!(status, 200);
            assert_eq!(echoed, expected);
            Ok(())
        })
        .await
    }

    /// A body that breaks mid-stream keeps today's error visibility: the
    /// captured stream error travels inside the joined body and surfaces
    /// when hyper sends it, as a `HttpPlainTextForwardError`, and the
    /// connection is not pooled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cold_path_body_error_surfaces_as_forward_error() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (_streams, requests, port) = spawn_echo_upstream().await;
            let ctx = make_context(runtime, port);
            // Declares 64 bytes but only carries 32 before the error.
            let body = ScriptedBody::failing(vec![test_bytes(9, 32)]);
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri("/t")
                .header(http::header::HOST, "backend.invalid")
                .header(http::header::CONTENT_LENGTH, 64usize)
                .body(body)
                .unwrap();

            let error = ctx
                .forward_request(req, None)
                .await
                .expect_err("a body that fails mid-stream must fail the request");
            assert!(
                matches!(error, crate::error::TngError::HttpPlainTextForwardError(_)),
                "the body error keeps its send-time class: {error:?}"
            );
            assert!(
                ctx.backend.send_request.lock().await.is_none(),
                "the connection whose body failed must not be pooled"
            );
            assert_eq!(
                requests.load(Ordering::SeqCst),
                0,
                "the backend never got a complete request"
            );
            Ok(())
        })
        .await
    }

    /// The dial failing after the prefix pull already consumed body bytes:
    /// the buffered frames are simply dropped, the request keeps the dial's
    /// own error class, and nothing panics.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_dial_after_prefix_pull_keeps_connect_error() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let ctx = make_context(runtime, port);
            let (body, _polls, drained) = ScriptedBody::scripted(vec![test_bytes(4, 4096)]);

            // A preconnect that only reports the failure after the body has
            // been pulled.
            let handle = ctx.runtime.spawn_supervised_task_current_span(async move {
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                Err(anyhow::anyhow!("backend is down"))
            });
            *ctx.preconnect.lock().await = Some(handle);

            let error = ctx
                .forward_request(
                    http::Request::builder()
                        .method(http::Method::POST)
                        .uri("/t")
                        .header(http::header::HOST, "backend.invalid")
                        .header(http::header::CONTENT_LENGTH, 4096usize)
                        .body(body)
                        .unwrap(),
                    None,
                )
                .await
                .expect_err("a refused pre-dial must fail the request");
            assert!(
                matches!(error, crate::error::TngError::ConnectUpstreamFailed(_)),
                "the dial error keeps its class: {error:?}"
            );
            assert!(
                drained.load(Ordering::SeqCst),
                "the prefix was pulled (and then discarded) before the dial verdict"
            );
            Ok(())
        })
        .await
    }

    /// The hot path (pooled slot hit) forwards through the reuse branch:
    /// the fresh-dial and prefix machinery is structurally below the reuse
    /// return, so the per-request phase counters must not move.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hot_path_skips_fresh_dial_and_prefix_phases() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (streams, requests, port) = spawn_echo_upstream().await;
            let ctx = make_context(runtime, port);

            // First request: cold path, one fresh dial, one fresh send.
            let (status, _) = post_and_collect(
                &ctx,
                {
                    let (body, _p, _d) = ScriptedBody::scripted(vec![test_bytes(5, 128)]);
                    body
                },
                128,
            )
            .await
            .unwrap();
            assert_eq!(status, 200);

            // Second request: hot path.
            let (body, _polls, _drained) = ScriptedBody::scripted(vec![test_bytes(6, 128)]);
            let (status, echoed) = post_and_collect(&ctx, body, 128).await.unwrap();
            assert_eq!(status, 200);
            assert_eq!(echoed, test_bytes(6, 128).as_ref());

            let snap = ctx.latency.snapshot();
            assert_eq!(snap["phases"]["backend_redial"]["count"], 1, "dialled once");
            assert_eq!(
                snap["phases"]["backend_send_fresh"]["count"], 1,
                "the fresh-send path ran once; the hot request must not touch it"
            );
            assert_eq!(
                snap["phases"]["backend_send"]["count"], 1,
                "reuse path once"
            );
            assert_eq!(streams.load(Ordering::SeqCst), 1);
            assert_eq!(requests.load(Ordering::SeqCst), 2);
            Ok(())
        })
        .await
    }

    // ---------- PrefixPull / JoinedBody unit tests ----------

    fn dyn_body(body: ScriptedBody) -> DynSendBody {
        use http_body_util::BodyExt as _;
        Box::pin(body.map_err(Into::into))
    }

    #[tokio::test]
    async fn prefix_pull_stops_at_cap_and_keeps_the_live_body() {
        let (body, _polls, drained) = ScriptedBody::scripted(vec![
            test_bytes(1, 100 * 1024),
            test_bytes(2, 100 * 1024),
            test_bytes(3, 100 * 1024),
        ]);
        let pulled = PrefixPull::new(dyn_body(body)).await;
        assert_eq!(pulled.frames.len(), 2, "stopped once the cap was covered");
        assert!(pulled.error.is_none());
        assert!(pulled.rest.is_some(), "the remainder keeps streaming");
        assert!(
            !drained.load(Ordering::SeqCst),
            "the body was not fully consumed"
        );

        let joined = JoinedBody::from(pulled);
        let got = http_body_util::BodyExt::collect(Box::pin(joined))
            .await
            .unwrap()
            .to_bytes();
        let mut expected = Vec::new();
        expected.extend(test_bytes(1, 100 * 1024));
        expected.extend(test_bytes(2, 100 * 1024));
        expected.extend(test_bytes(3, 100 * 1024));
        assert_eq!(got.as_ref(), expected.as_slice());

        // Exactly at the cap the pull stops before seeing the end marker,
        // so the live body stays in `rest`; the join still ends cleanly. A
        // one-frame 128 KiB body is what the hook-capture on-bin test posts.
        let (body, _polls, _drained) = ScriptedBody::scripted(vec![test_bytes(4, PREFIX_CAP)]);
        let pulled = PrefixPull::new(dyn_body(body)).await;
        assert_eq!(pulled.frames.len(), 1);
        assert!(
            pulled.rest.is_some(),
            "a body of exactly the cap stops before its end"
        );
        let joined = JoinedBody::from(pulled);
        let got = http_body_util::BodyExt::collect(Box::pin(joined))
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(got.as_ref(), test_bytes(4, PREFIX_CAP).as_ref());
    }

    #[tokio::test]
    async fn prefix_pull_captures_errors_and_ends() {
        let body = ScriptedBody::failing(vec![test_bytes(8, 16)]);
        let pulled = PrefixPull::new(dyn_body(body)).await;
        assert_eq!(pulled.frames.len(), 1);
        assert!(pulled.error.is_some(), "the stream error is captured");
        assert!(
            pulled.rest.is_some(),
            "a mid-stream error does not end the body"
        );

        // The ended cases: a drained body leaves no live remainder.
        let (body, _polls, _drained) = ScriptedBody::scripted(vec![test_bytes(9, 16)]);
        let pulled = PrefixPull::new(dyn_body(body)).await;
        assert!(pulled.rest.is_none(), "an ended body must not be re-polled");

        let mut joined = JoinedBody::from(pulled);
        assert!(
            !joined.is_end_stream(),
            "the unreplayed prefix frame keeps the join non-empty"
        );
        assert_eq!(
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut joined).poll_frame(cx))
                .await
                .expect("frame")
                .expect("ok")
                .into_data()
                .unwrap()
                .len(),
            16
        );
        assert!(
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut joined).poll_frame(cx))
                .await
                .is_none(),
            "after the prefix, the ended body ends the join"
        );

        // A zero-frame end is an end stream up front (the empty-body case
        // that today's `Full::new(b"")` requests rely on).
        let (body, _polls, _drained) = ScriptedBody::scripted(vec![]);
        let pulled = PrefixPull::new(dyn_body(body)).await;
        assert!(pulled.frames.is_empty() && pulled.rest.is_none());
        assert!(JoinedBody::from(pulled).is_end_stream());
    }

    #[tokio::test]
    async fn joined_body_replays_frames_then_error_in_order() {
        let a = http_body::Frame::data(test_bytes(1, 8));
        let mut trailers = http::HeaderMap::new();
        trailers.append("x-checksum", http::HeaderValue::from_static("1234"));
        let t = http_body::Frame::trailers(trailers);
        let joined = JoinedBody::from(Pulled {
            frames: vec![a, t],
            error: Some(axum::BoxError::from("boom")),
            rest: None,
        });
        assert_eq!(
            joined.size_hint().lower(),
            8,
            "data bytes count, trailers do not"
        );
        assert!(
            !joined.is_end_stream(),
            "a captured error is not an end of stream"
        );

        let mut joined = joined;
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut joined).poll_frame(cx))
            .await
            .expect("frame")
            .expect("ok");
        assert_eq!(frame.into_data().unwrap().len(), 8);
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut joined).poll_frame(cx))
            .await
            .expect("frame")
            .expect("ok");
        assert!(frame
            .into_trailers()
            .is_ok_and(|t| t.contains_key("x-checksum")));
        let error = std::future::poll_fn(|cx| std::pin::Pin::new(&mut joined).poll_frame(cx))
            .await
            .expect("frame")
            .expect_err("the stored error surfaces in order");
        assert!(error.to_string().contains("boom"));
        assert!(
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut joined).poll_frame(cx))
                .await
                .is_none(),
            "polls past the error end the stream"
        );
    }

    async fn wait_counter(ctx: &TngStreamContext, key: &str, expected: u64) -> bool {
        for _ in 0..100 {
            if ctx.preconnect_counters.snapshot()[key] == serde_json::json!(expected) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        ctx.preconnect_counters.snapshot()[key] == serde_json::json!(expected)
    }

    /// The counters track each preconnect outcome: a started dial that its
    /// request reaps, a warm-slot decline, and a guard dropped without
    /// forwarding abandoning its dial.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn preconnect_counters_track_dial_lifecycle() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(async |runtime| {
            let (_streams, _requests, port) = spawn_fake_upstream(None).await;
            let ctx = make_context(runtime.clone(), port);

            let snap = ctx.preconnect_counters.snapshot();
            assert_eq!(snap["preconnect_started"], 0);
            assert_eq!(snap["preconnect_declined_warm"], 0);
            assert_eq!(snap["preconnect_reaped"], 0);
            assert_eq!(snap["preconnect_abandoned"], 0);

            let _preconnect = ctx.start_preconnect().expect("cold slot pre-dials");
            assert_eq!(ctx.preconnect_counters.snapshot()["preconnect_started"], 1);

            let (status, _body) = get(&ctx).await;
            assert_eq!(status, 200);
            let snap = ctx.preconnect_counters.snapshot();
            assert_eq!(
                snap["preconnect_reaped"], 1,
                "forward_request consumed the dial"
            );
            assert_eq!(snap["preconnect_abandoned"], 0);

            // The pool is warm now: the next peek declines.
            assert!(ctx.start_preconnect().is_none());
            assert_eq!(
                ctx.preconnect_counters.snapshot()["preconnect_declined_warm"],
                1,
                "a warm slot decline is counted"
            );

            // A second context: a guard dropped without forwarding abandons
            // its dial (the teardown runs on its own task).
            let ctx2 = make_context(runtime.clone(), port);
            let preconnect = ctx2.start_preconnect().expect("cold slot pre-dials");
            drop(preconnect);
            assert!(
                wait_counter(&ctx2, "preconnect_abandoned", 1).await,
                "the abandoned dial is counted: {:?}",
                ctx2.preconnect_counters.snapshot()
            );
            assert_eq!(ctx2.preconnect_counters.snapshot()["preconnect_started"], 1);
            assert_eq!(ctx2.preconnect_counters.snapshot()["preconnect_reaped"], 0);
            Ok(())
        })
        .await
    }
}
