//! The seal pump fuses ohttp sealing into the HTTP body stream it feeds.
//! Data flow: bhttp plaintext is written through the ohttp seal writer, the
//! seal appends its AEAD chunks to an always-ready sink, and the pump drains
//! that sink into frames of at most `SEALED_FRAME_SIZE` for the body.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{io::BufReader, AsyncBufRead, AsyncRead, AsyncWrite, Stream, StreamExt};
use parking_lot::Mutex;

use crate::tunnel::ohttp::{SEALED_FRAME_SIZE, SEAL_CHUNK_SIZE};

/// The always-ready in-memory destination that collects a seal stream's
/// sealed bytes. The seal writer's `poll_write` then never parks and never
/// buffers internally beyond one AEAD chunk: every accepted byte lands here.
/// That is the precondition for running the seal synchronously inside the
/// body stream's poll instead of a task of its own behind a
/// `tokio::io::duplex`.
///
/// Clone to hand one copy to `encapsulate_response`/`encapsulate_stream` and
/// keep the other to drain sealed bytes. Both clones are only touched by the
/// single task polling the pump, so there is no real contention; `parking_lot`
/// additionally keeps the mutex panic-proof across the lock boundary.
#[derive(Clone)]
pub(crate) struct SealedBytesSink(Arc<Mutex<BytesMut>>);

impl SealedBytesSink {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(BytesMut::new())))
    }

    /// Move the sealed bytes accumulated since the last drain into `out`.
    fn drain_into(&self, out: &mut BytesMut) {
        let sealed = std::mem::take(&mut *self.0.lock());
        if !sealed.is_empty() {
            out.extend_from_slice(&sealed);
        }
    }
}

impl AsyncWrite for SealedBytesSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PumpState {
    /// Reading plaintext and writing it through the seal.
    Running,
    /// Plaintext exhausted: flushing and closing the seal, which emits the
    /// final ohttp chunk.
    Closing,
    /// Seal closed (or failed): handing over the sealed bytes still buffered.
    Draining,
    /// Everything handed over; the stream ends.
    Done,
}

/// Push the current fill -- the plaintext window `poll_fill_buf` returned --
/// through the seal, returning the byte count it accepted and, if it stopped
/// early, why.  Free-standing so the `fill` borrow (which pins the reader)
/// ends when this returns and the caller can `consume` on the reader and
/// drain the sink without an overlapping mutable borrow.
fn write_fill(
    seal: &mut Pin<Box<dyn AsyncWrite + Send + 'static>>,
    cx: &mut Context<'_>,
    fill: &[u8],
) -> (usize, Option<io::Error>) {
    let mut offset = 0usize;
    while offset < fill.len() {
        match seal.as_mut().poll_write(cx, &fill[offset..]) {
            Poll::Ready(Ok(0)) => {
                return (
                    offset,
                    Some(io::Error::other("seal stream accepted no bytes")),
                );
            }
            Poll::Ready(Ok(n)) => offset += n,
            Poll::Ready(Err(error)) => return (offset, Some(error)),
            Poll::Pending => break,
        }
    }
    (offset, None)
}

/// Sealed ohttp body frames driven from a plaintext reader plus an ohttp
/// seal stream, on one task and with no intermediate pipe.
///
/// The sequence replays what the removed `spawn + duplex + copy_buf +
/// close()` relay did: read through a `BufReader` sized to the protocol's
/// 16 KiB max chunk so the plaintext chunk sizes, and therefore the sealed
/// framing, match what `copy_buf` produced; hand each fill to the seal
/// writer, draining the sink after every write so it holds at most one
/// chunk; flush and close the seal exactly once at EOF (the fork emits the
/// final `FINAL_CHUNK_AAD` chunk during close, so drain after it); end the
/// stream once the buffered output is handed over. Output frames are
/// coalesced to `SEALED_FRAME_SIZE`, the granularity of the `ReaderStream`s
/// that were removed.
///
/// Source or seal errors are logged under the construction-time span (the
/// request span captured where the old supervised task was spawned) and the
/// stream then ends cleanly, as before: the task path logged the error and
/// dropped its pipe writer, the outer body finished at that byte offset,
/// and the peer's `ChunkReader` reported `ohttp::Error::Truncated`.
/// Yielding an error item instead would change the outer transport's
/// failure mode, so truncation remains the observable.
///
/// The seal objects (`ohttp`'s `StreamClient` / `ServerResponse`) are
/// `pin_project` types that are not `Unpin` and cannot be named from
/// outside the crate, so reader and seal are boxed at construction; the
/// pump itself is `Unpin` and polled by the body without an extra pin.
struct SealPump {
    /// The bhttp plaintext to seal, buffered at `SEAL_CHUNK_SIZE` (one AEAD
    /// chunk) so chunk boundaries match the removed relay.
    plaintext: Pin<Box<dyn AsyncBufRead + Send + 'static>>,
    /// The seal writer fed by `plaintext`; its AEAD chunks land in `sink`.
    seal: Pin<Box<dyn AsyncWrite + Send + 'static>>,
    /// The seal's write destination; drained into `unsent` after every step
    /// so it never holds more than the chunk just written.
    sink: SealedBytesSink,
    /// Sealed bytes not yet handed over as body frames.
    unsent: BytesMut,
    state: PumpState,
    /// Plaintext bytes consumed, for the completion log.
    plain_bytes: u64,
    /// Log line emitted on a source or seal failure.
    error_msg: &'static str,
    /// Log line emitted when the pump finishes cleanly, if the caller wants
    /// one.
    done_msg: Option<&'static str>,
    /// The request span captured where the removed relay task was spawned;
    /// pump logs enter it so they keep the same context.
    span: tracing::Span,
}

impl SealPump {
    fn new<R, S>(plaintext: R, seal: S, sink: SealedBytesSink, error_msg: &'static str) -> Self
    where
        R: AsyncRead + Send + 'static,
        S: AsyncWrite + Send + 'static,
    {
        Self {
            plaintext: Box::pin(BufReader::with_capacity(SEAL_CHUNK_SIZE, plaintext)),
            seal: Box::pin(seal),
            sink,
            unsent: BytesMut::new(),
            state: PumpState::Running,
            plain_bytes: 0,
            error_msg,
            done_msg: None,
            span: tracing::Span::current(),
        }
    }

    /// Wind down after a source or seal failure: log it, hand over the
    /// sealed bytes produced so far, and end the stream without an error
    /// item, leaving the peer to report truncation (see the struct doc for
    /// why this matches the removed relay).
    fn fail(&mut self, error: &dyn std::fmt::Debug) {
        tracing::error!(?error, "{}", self.error_msg);
        self.sink.drain_into(&mut self.unsent);
        self.state = PumpState::Draining;
    }
}

impl Stream for SealPump {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // Enter a cloned span: the enter guard would borrow the pump
        // immutably and block the field-wise mutations below.
        let span = this.span.clone();
        let _guard = span.enter();
        loop {
            // Hand over accumulated sealed bytes before doing more work.
            if this.unsent.len() >= SEALED_FRAME_SIZE {
                let frame = this.unsent.split_to(SEALED_FRAME_SIZE).freeze();
                return Poll::Ready(Some(Ok(frame)));
            }
            match this.state {
                PumpState::Done => return Poll::Ready(None),
                PumpState::Running => {
                    let mut park = false;
                    let mut failed: Option<io::Error> = None;
                    match this.plaintext.as_mut().poll_fill_buf(cx) {
                        Poll::Ready(Ok([])) => {
                            this.state = PumpState::Closing;
                        }
                        Poll::Ready(Ok(fill)) => {
                            let len = fill.len();
                            let (consumed, error) = write_fill(&mut this.seal, cx, fill);
                            if consumed > 0 {
                                this.plaintext.as_mut().consume(consumed);
                                this.plain_bytes += consumed as u64;
                            }
                            this.sink.drain_into(&mut this.unsent);
                            failed = error;
                            park = failed.is_none() && consumed < len;
                        }
                        Poll::Ready(Err(error)) => failed = Some(error),
                        Poll::Pending => park = true,
                    }
                    if let Some(error) = failed {
                        this.fail(&error);
                        continue;
                    }
                    if park {
                        if this.unsent.is_empty() {
                            return Poll::Pending;
                        }
                        let frame = std::mem::take(&mut this.unsent).freeze();
                        return Poll::Ready(Some(Ok(frame)));
                    }
                }
                PumpState::Closing => {
                    // `ChunkWriter::poll_close` flushes pending bytes, emits
                    // the final chunk, and flushes again before closing the
                    // destination; with the always-ready sink one close pass
                    // captures everything, but handle Pending defensively.
                    if let Poll::Ready(Err(error)) = this.seal.as_mut().poll_flush(cx) {
                        this.fail(&error);
                        continue;
                    }
                    match this.seal.as_mut().poll_close(cx) {
                        Poll::Ready(Ok(())) => {
                            this.sink.drain_into(&mut this.unsent);
                            this.state = PumpState::Draining;
                        }
                        Poll::Ready(Err(error)) => {
                            this.sink.drain_into(&mut this.unsent);
                            this.fail(&error);
                        }
                        Poll::Pending => {
                            this.sink.drain_into(&mut this.unsent);
                            if this.unsent.is_empty() {
                                return Poll::Pending;
                            }
                            let frame = std::mem::take(&mut this.unsent).freeze();
                            return Poll::Ready(Some(Ok(frame)));
                        }
                    }
                }
                PumpState::Draining => {
                    if this.unsent.is_empty() {
                        if let Some(msg) = this.done_msg {
                            tracing::debug!(bytes_copied = this.plain_bytes, "{msg}");
                        }
                        this.state = PumpState::Done;
                    } else {
                        let take = this.unsent.len().min(SEALED_FRAME_SIZE);
                        let frame = this.unsent.split_to(take).freeze();
                        return Poll::Ready(Some(Ok(frame)));
                    }
                }
            }
        }
    }
}

/// Sealed ohttp response body over an `encapsulate_response` stream: the
/// pump seals `plaintext` through `seal` and yields its frames, taking
/// sealed bytes out of `sink` (the seal's write destination).
pub(crate) fn sealed_response_body<R, S>(
    plaintext: R,
    seal: S,
    sink: SealedBytesSink,
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static
where
    R: AsyncRead + Send + 'static,
    S: AsyncWrite + Send + 'static,
{
    SealPump::new(plaintext, seal, sink, "Error when encrypting response")
}

/// Sealed ohttp request body for the outer POST: the prost metadata buffer
/// as the first frame, then the sealed inner request pumped from `plaintext`
/// through `seal`, exactly as in [`sealed_response_body`].
pub(crate) fn sealed_request_body<R, S>(
    metadata: Bytes,
    plaintext: R,
    seal: S,
    sink: SealedBytesSink,
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static
where
    R: AsyncRead + Send + 'static,
    S: AsyncWrite + Send + 'static,
{
    let mut pump = SealPump::new(plaintext, seal, sink, "Error when encrypting request");
    // Preserve the relay path's completion debug line (level unchanged).
    pump.done_msg = Some("BHTTP request encoded and encrypted");
    futures::stream::once(async move { Ok(metadata) }).chain(pump)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use ohttp::hpke::{Aead, Kdf, Kem};

    fn aes128_config() -> ohttp::KeyConfig {
        ohttp::KeyConfig::new(
            7,
            Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
        )
        .expect("key config")
    }

    /// Read an `AsyncRead` that is not `Unpin` to completion without
    /// combinator bounds: pin it into a box and drive `poll_read`.
    async fn read_all_pinned<R: AsyncRead>(r: R) -> io::Result<Vec<u8>> {
        let mut r = Box::pin(r);
        let mut out = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = futures::future::poll_fn(|cx| r.as_mut().poll_read(cx, &mut buf)).await?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    async fn collect<S: Stream<Item = io::Result<Bytes>> + Unpin>(stream: S) -> Vec<u8> {
        let mut out = Vec::new();
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            out.extend_from_slice(&item.expect("ok frame"));
        }
        out
    }

    async fn open_request(sealed: Vec<u8>, kc: ohttp::KeyConfig) -> Vec<u8> {
        open_request_result(sealed, kc)
            .await
            .expect("open sealed stream")
    }

    /// The ChunkReader only returns EOF after the final chunk; a missing
    /// close surfaces as an error through this `Result`.
    async fn open_request_result(sealed: Vec<u8>, kc: ohttp::KeyConfig) -> io::Result<Vec<u8>> {
        let header = ohttp::Server::decode_header(futures::io::Cursor::new(sealed))
            .await
            .map_err(io::Error::other)?;
        let server_request = header.into_server_request(kc);
        read_all_pinned(server_request).await
    }

    /// Seal `plaintext` through the pump and open it with the stock
    /// `ChunkReader`, returning both byte vectors.
    async fn pump_and_open(plaintext: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut kc = aes128_config();
        let client = ohttp::ClientRequest::from_config(&mut kc).expect("client");
        let sink = SealedBytesSink::new();
        let seal = client
            .encapsulate_stream(sink.clone())
            .expect("encapsulate");
        let sealed = collect(SealPump::new(
            futures::io::Cursor::new(plaintext.clone()),
            seal,
            sink,
            "test error",
        ))
        .await;
        let recovered = open_request(sealed.clone(), kc).await;
        (sealed, recovered)
    }

    #[tokio::test]
    async fn roundtrip_boundary_sizes() {
        for size in [
            0usize,
            1,
            7,
            16 * 1024 - 1,
            16 * 1024,
            16 * 1024 + 1,
            64 * 1024,
            256 * 1024,
        ] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (_sealed, recovered) = pump_and_open(plaintext.clone()).await;
            assert_eq!(recovered, plaintext, "size {size}");
        }
    }

    #[tokio::test]
    async fn frames_bounded_by_sealed_frame_size() {
        let plaintext = vec![9u8; 1024 * 1024];
        let mut kc = aes128_config();
        let client = ohttp::ClientRequest::from_config(&mut kc).expect("client");
        let sink = SealedBytesSink::new();
        let seal = client
            .encapsulate_stream(sink.clone())
            .expect("encapsulate");
        let pump = SealPump::new(
            futures::io::Cursor::new(plaintext),
            seal,
            sink,
            "test error",
        );
        futures::pin_mut!(pump);
        let mut frames = 0usize;
        while let Some(item) = pump.next().await {
            let frame = item.expect("ok frame");
            assert!(
                frame.len() <= SEALED_FRAME_SIZE,
                "frame {} exceeds relay cap {}",
                frame.len(),
                SEALED_FRAME_SIZE
            );
            frames += 1;
        }
        assert!(frames >= 2, "expected multiple frames, got {frames}");
    }

    /// The removed relay (duplex + `copy_buf` + `close()`) must produce the
    /// same framing as the pump: for identical plaintext the total sealed
    /// length is equal (chunk boundaries depend only on read sizes, and both
    /// paths read through a 16 KiB `BufReader`). Values differ per run (the
    /// HPKE context is randomized), so length is the parity invariant.
    // The legacy side of this differential test reconstructs the removed
    // relay task, which spawned on the default runtime; test-only usage.
    #[allow(clippy::disallowed_methods)]
    #[tokio::test]
    async fn legacy_path_framing_parity() {
        use tokio_util::compat::{FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt};
        for size in [1usize, 16 * 1024, 16 * 1024 + 1, 64 * 1024] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

            // Pump path.
            let (pump_sealed, _) = pump_and_open(plaintext.clone()).await;

            // Legacy path, composed exactly like the old egress/ingress task:
            // duplex + BufReader(SEAL_CHUNK_SIZE) + copy_buf + close.
            let mut kc = aes128_config();
            let client = ohttp::ClientRequest::from_config(&mut kc).expect("client");
            let (mut read_half, write_half) =
                tokio::io::duplex(crate::tunnel::ohttp::RELAY_PIPE_SIZE);
            let seal = client
                .encapsulate_stream(write_half.compat())
                .expect("encapsulate");
            let task = {
                let plaintext_inner = plaintext.clone();
                tokio::spawn(async move {
                    use tokio_util::compat::FuturesAsyncReadCompatExt;
                    let mut seal = seal.compat_write();
                    let mut reader = tokio::io::BufReader::with_capacity(
                        SEAL_CHUNK_SIZE,
                        futures::io::Cursor::new(plaintext_inner).compat(),
                    );
                    tokio::io::copy_buf(&mut reader, &mut seal).await?;
                    let mut seal = seal.into_inner();
                    futures::AsyncWriteExt::close(&mut seal).await?;
                    Ok::<_, anyhow::Error>(())
                })
            };
            let mut legacy_sealed = Vec::new();
            while let Some(chunk) = futures::StreamExt::next(
                &mut tokio_util::io::ReaderStream::with_capacity(&mut read_half, SEALED_FRAME_SIZE),
            )
            .await
            {
                let chunk = chunk.expect("legacy frame");
                legacy_sealed.extend_from_slice(&chunk[..]);
            }
            task.await.expect("legacy task").expect("legacy seal");
            assert_eq!(
                legacy_sealed.len(),
                pump_sealed.len(),
                "framing length differs at size {size}"
            );
        }
    }

    #[tokio::test]
    async fn seal_error_ends_cleanly_and_peer_detects_truncation() {
        // Reader that yields data then fails.
        struct FailAfter {
            data: Bytes,
            sent: usize,
            fail_at: usize,
        }
        impl AsyncRead for FailAfter {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                if self.sent >= self.fail_at {
                    return Poll::Ready(Err(io::Error::other("boom")));
                }
                let n = (buf.len()).min(self.data.len() - self.sent);
                buf[..n].copy_from_slice(&self.data[self.sent..self.sent + n]);
                self.sent += n;
                Poll::Ready(Ok(n))
            }
        }
        let mut kc = aes128_config();
        let client = ohttp::ClientRequest::from_config(&mut kc).expect("client");
        let sink = SealedBytesSink::new();
        let seal = client
            .encapsulate_stream(sink.clone())
            .expect("encapsulate");
        let fail_at = SEAL_CHUNK_SIZE * 2 + 100;
        let data = Bytes::from(vec![3u8; fail_at + 1000]);
        let pump = SealPump::new(
            FailAfter {
                data,
                sent: 0,
                fail_at,
            },
            seal,
            sink,
            "test error",
        );
        let sealed = collect(pump).await; // collect asserts every frame Ok: clean end
        assert!(!sealed.is_empty());
        // The peer sees a truncated message, exactly like the old behavior.
        let res = open_request_result(sealed, kc).await;
        assert!(
            res.is_err(),
            "truncated sealed stream must not open cleanly"
        );
    }

    #[tokio::test]
    async fn close_emits_final_chunk_with_no_body() {
        let (_sealed, recovered) = pump_and_open(vec![]).await;
        assert!(recovered.is_empty());
    }

    #[tokio::test]
    async fn metadata_frame_precedes_sealed_bytes() {
        let metadata = Bytes::from_static(b"\x00\x00\x00\x05METAD");
        let mut kc = aes128_config();
        let client = ohttp::ClientRequest::from_config(&mut kc).expect("client");
        let sink = SealedBytesSink::new();
        let seal = client
            .encapsulate_stream(sink.clone())
            .expect("encapsulate");
        let stream = sealed_request_body(
            metadata.clone(),
            futures::io::Cursor::new(vec![1u8; 10]),
            seal,
            sink,
        );
        futures::pin_mut!(stream);
        let first = stream.next().await.expect("frame").expect("ok");
        assert_eq!(first, metadata, "first frame must be the metadata buffer");
        let rest: Vec<Bytes> = stream.map(|f| f.expect("ok")).collect().await;
        let joined: Vec<u8> = rest.iter().flat_map(|b| b.iter().copied()).collect();
        // `metadata` was the first frame already; the remainder is the
        // pure ohttp stream (u32 length + metadata prefix excluded).
        let recovered = open_request(joined, kc).await;
        assert_eq!(recovered, vec![1u8; 10]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stalling_reader_delivers_everything() {
        // Reader that returns Pending on alternating polls: a lost wakeup or
        // dropped bytes would hang or under-deliver this test.
        struct Stall {
            data: Vec<u8>,
            sent: usize,
            stall_next: bool,
        }
        impl AsyncRead for Stall {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                if self.stall_next {
                    self.stall_next = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.stall_next = true;
                if self.sent == self.data.len() {
                    return Poll::Ready(Ok(0));
                }
                let n = 31usize.min(buf.len()).min(self.data.len() - self.sent);
                buf[..n].copy_from_slice(&self.data[self.sent..self.sent + n]);
                self.sent += n;
                Poll::Ready(Ok(n))
            }
        }
        let plaintext: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let mut kc = aes128_config();
        let client = ohttp::ClientRequest::from_config(&mut kc).expect("client");
        let sink = SealedBytesSink::new();
        let seal = client
            .encapsulate_stream(sink.clone())
            .expect("encapsulate");
        let sealed = collect(SealPump::new(
            Stall {
                data: plaintext.clone(),
                sent: 0,
                stall_next: false,
            },
            seal,
            sink,
            "test error",
        ))
        .await;
        let recovered = open_request(sealed, kc).await;
        assert_eq!(recovered, plaintext);
    }

    /// Wrapper that counts `poll_close` calls passed through to the seal.
    /// The inner seal is boxed because the fork's stream types are !Unpin.
    struct CountSeal {
        inner: Pin<Box<dyn AsyncWrite + Send>>,
        closes: Arc<Mutex<usize>>,
    }
    impl AsyncWrite for CountSeal {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.inner.as_mut().poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.inner.as_mut().poll_flush(cx)
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            *self.closes.lock() += 1;
            self.inner.as_mut().poll_close(cx)
        }
    }

    #[tokio::test]
    async fn seal_closed_exactly_once() {
        let closes = Arc::new(Mutex::new(0usize));
        let mut kc = aes128_config();
        let client = ohttp::ClientRequest::from_config(&mut kc).expect("client");
        let sink = SealedBytesSink::new();
        let seal = client
            .encapsulate_stream(sink.clone())
            .expect("encapsulate");
        let counted = CountSeal {
            inner: Box::pin(seal),
            closes: closes.clone(),
        };
        let sealed = collect(SealPump::new(
            futures::io::Cursor::new(vec![7u8; 40]),
            counted,
            sink,
            "test error",
        ))
        .await;
        open_request(sealed, kc).await;
        assert_eq!(*closes.lock(), 1, "seal poll_close must run exactly once");
    }

    /// A seal that parks mid-write must not drop or double-consume the
    /// plaintext: the pump re-polls with the same waker registration and
    /// delivers every byte.
    #[tokio::test(flavor = "multi_thread")]
    async fn stalling_seal_delivers_everything() {
        struct StallSeal {
            inner: SealedBytesSink,
            stall_next: bool,
        }
        impl AsyncWrite for StallSeal {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.stall_next {
                    self.stall_next = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.stall_next = true;
                // Accept at most 1000 bytes per call to force multi-step writes.
                let n = buf.len().min(1000);
                self.inner.0.lock().extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let plaintext: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let sink = SealedBytesSink::new();
        let stall = StallSeal {
            inner: sink.clone(),
            stall_next: false,
        };
        let sealed = collect(SealPump::new(
            futures::io::Cursor::new(plaintext.clone()),
            stall,
            sink,
            "test error",
        ))
        .await;
        assert_eq!(sealed, plaintext);
    }
}
