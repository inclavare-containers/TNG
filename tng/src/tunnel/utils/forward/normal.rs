use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// This module provides a custom bidirectional stream forwarding implementation
// instead of using `tokio::io::copy_bidirectional`. We intentionally avoid the
// tokio built-in because:
// 1. Our `ForwardError` enum captures direction-aware error context (which stream
//    and which side failed), making production debugging much easier.
// 2. We use 512 KB buffers instead of tokio's 8 KB default for better throughput.
// Do NOT replace this with `tokio::io::copy_bidirectional` — the loss of error
// directionality would make it very hard to diagnose forwarding failures.

/// Error that captures the direction and read/write side of a forward failure,
/// while preserving the original `io::Error` as the source.
#[derive(Error, Debug)]
pub enum ForwardError {
    #[error("read on downstream failed")]
    ReadDownstream(#[source] io::Error),
    #[error("write on upstream failed")]
    WriteUpstream(#[source] io::Error),
    #[error("read on upstream failed")]
    ReadUpstream(#[source] io::Error),
    #[error("write on downstream failed")]
    WriteDownstream(#[source] io::Error),
    #[error("write zero byte into writer")]
    WriteZero,
}

// The default buffer size used in tokio::io::copy_bidirectional is 8 KB, here we increase it to 512 KB to improve the performance.
const FORWARD_BUF_SIZE: usize = 512 * 1024;

/// Buffer used for copying data between streams.
struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    fn new(buf_size: usize) -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; buf_size].into_boxed_slice(),
        }
    }

    fn poll_copy<R, W, RE, WE>(
        &mut self,
        cx: &mut TaskContext<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        read_err: RE,
        write_err: WE,
    ) -> Poll<Result<u64, ForwardError>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
        RE: Fn(io::Error) -> ForwardError,
        WE: Fn(io::Error) -> ForwardError,
    {
        loop {
            if self.cap < self.buf.len() && !self.read_done {
                match self.poll_fill_buf(cx, reader.as_mut()) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(read_err(err))),
                    Poll::Pending => {
                        if self.pos == self.cap {
                            if self.need_flush {
                                match writer.as_mut().poll_flush(cx) {
                                    Poll::Ready(Ok(())) => {
                                        self.need_flush = false;
                                    }
                                    Poll::Ready(Err(err)) => {
                                        return Poll::Ready(Err(write_err(err)));
                                    }
                                    Poll::Pending => return Poll::Pending,
                                }
                            }
                            return Poll::Pending;
                        }
                    }
                }
            }

            while self.pos < self.cap {
                match self.poll_write_buf(cx, reader.as_mut(), writer.as_mut()) {
                    Poll::Ready(Ok(i)) => {
                        if i == 0 {
                            return Poll::Ready(Err(ForwardError::WriteZero));
                        } else {
                            self.pos += i;
                            self.amt += i as u64;
                            self.need_flush = true;
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(write_err(err))),
                    Poll::Pending => {
                        if !self.read_done && self.cap < self.buf.len() {
                            match self.poll_fill_buf(cx, reader.as_mut()) {
                                Poll::Ready(Ok(())) => {}
                                Poll::Ready(Err(err)) => return Poll::Ready(Err(read_err(err))),
                                Poll::Pending => return Poll::Pending,
                            }
                        } else {
                            return Poll::Pending;
                        }
                    }
                }
            }

            self.pos = 0;
            self.cap = 0;

            if self.read_done {
                match writer.as_mut().poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {
                        return Poll::Ready(Ok(self.amt));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(write_err(err))),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    fn poll_fill_buf<R>(
        &mut self,
        cx: &mut TaskContext<'_>,
        reader: Pin<&mut R>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
    {
        let me = &mut *self;
        let mut buf = ReadBuf::new(&mut me.buf);
        buf.set_filled(me.cap);
        let res = reader.poll_read(cx, &mut buf);
        if let Poll::Ready(Ok(())) = res {
            let filled_len = buf.filled().len();
            me.read_done = me.cap == filled_len;
            me.cap = filled_len;
        }
        res
    }

    fn poll_write_buf<R, W>(
        &mut self,
        cx: &mut TaskContext<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<usize>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        let me = &mut *self;
        match writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]) {
            Poll::Pending => {
                if !me.read_done && me.cap < me.buf.len() {
                    match me.poll_fill_buf(cx, reader.as_mut()) {
                        Poll::Ready(Ok(())) => {}
                        other => return other.map(|_| Ok(0)),
                    }
                }
                Poll::Pending
            }
            res => res,
        }
    }
}

/// State of a transfer direction.
enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done(u64),
}

/// Transfers data in one direction between two streams.
fn transfer_one_direction<A, B, RE, WE>(
    cx: &mut TaskContext<'_>,
    state: &mut TransferState,
    r: &mut A,
    w: &mut B,
    read_err: RE,
    write_err: WE,
) -> Poll<Result<u64, (u64, u64, ForwardError)>>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    RE: Fn(io::Error) -> ForwardError,
    WE: Fn(io::Error) -> ForwardError,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);
    loop {
        match state {
            TransferState::Running(buf) => {
                let result = buf.poll_copy(cx, r.as_mut(), w.as_mut(), &read_err, &write_err);
                let count = match result {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => {
                        let sent = buf.amt;
                        let remain = (buf.cap.saturating_sub(buf.pos)) as u64;
                        return Poll::Ready(Err((sent, remain, e)));
                    }
                    Poll::Pending => return Poll::Pending,
                };
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => match w.as_mut().poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    let c = *count;
                    *state = TransferState::Done(c);
                }
                Poll::Ready(Err(err)) => {
                    let sent = *count;
                    return Poll::Ready(Err((sent, 0, write_err(err))));
                }
                Poll::Pending => return Poll::Pending,
            },
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

/// Copies data bidirectionally between two streams with specified buffer sizes.
///
/// Returns `(a_to_b_bytes, b_to_a_bytes)`.  Errors in either direction are
/// logged as debug-level events and treated as that direction completing
/// with zero bytes — they never bubble up to the caller.
async fn copy_bidirectional_impl<A, B>(
    a: &mut A,
    b: &mut B,
    a_to_b_buffer_size: usize,
    b_to_a_buffer_size: usize,
) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut a_to_b = TransferState::Running(CopyBuffer::new(a_to_b_buffer_size));
    let mut b_to_a = TransferState::Running(CopyBuffer::new(b_to_a_buffer_size));

    poll_fn(|cx| {
        // Transfer from a to b (downstream -> upstream)
        let a_to_b_result = transfer_one_direction(
            cx,
            &mut a_to_b,
            a,
            b,
            ForwardError::ReadDownstream,
            ForwardError::WriteUpstream,
        );
        // Transfer from b to a (upstream -> downstream)
        let b_to_a_result = transfer_one_direction(
            cx,
            &mut b_to_a,
            b,
            a,
            ForwardError::ReadUpstream,
            ForwardError::WriteDownstream,
        );

        // Each direction completes independently — errors are logged and
        // treated as "direction finished with N bytes transferred".  This
        // prevents the classic teardown race: one side EOFs → the other
        // side's write hits ECONNRESET/EPIPE → we return Ok because the
        // EOF direction completed legitimately.
        let a_to_b_done = match a_to_b_result {
            Poll::Ready(Ok(n)) => Some(n),
            Poll::Ready(Err((sent, remain, error))) => {
                if remain > 0 {
                    tracing::error!(
                        ?error,
                        sent,
                        remain,
                        "downstream to upstream transfer lost data"
                    );
                } else {
                    tracing::debug!(
                        ?error,
                        sent,
                        "downstream to upstream transfer completed with error"
                    );
                }
                Some(sent)
            }
            Poll::Pending => None,
        };
        let b_to_a_done = match b_to_a_result {
            Poll::Ready(Ok(n)) => Some(n),
            Poll::Ready(Err((sent, remain, error))) => {
                if remain > 0 {
                    tracing::error!(
                        ?error,
                        sent,
                        remain,
                        "upstream to downstream transfer lost data"
                    );
                } else {
                    tracing::debug!(
                        ?error,
                        sent,
                        "upstream to downstream transfer completed with error"
                    );
                }
                Some(sent)
            }
            Poll::Pending => None,
        };

        // Only return when both directions have finished (success or error).
        match (a_to_b_done, b_to_a_done) {
            (Some(a), Some(b)) => Poll::Ready((a, b)),
            _ => Poll::Pending,
        }
    })
    .await
}

pub async fn forward_stream(
    mut upstream: impl AsyncRead + AsyncWrite + Unpin,
    mut downstream: impl AsyncRead + AsyncWrite + Unpin,
) {
    tracing::debug!("Starting to transmit application data");
    // downstream corresponds to 'a', upstream corresponds to 'b'
    // a_to_b is downstream -> upstream (tx/from_client)
    // b_to_a is upstream -> downstream (rx/from_server)
    let (from_client, from_server) = copy_bidirectional_impl(
        &mut downstream,
        &mut upstream,
        FORWARD_BUF_SIZE,
        FORWARD_BUF_SIZE,
    )
    .await;
    tracing::debug!(
        tx_bytes = from_client,
        rx_bytes = from_server,
        "Finished transmit application data",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // =====================================================================
    // MockStream: a single, independent stream endpoint
    // =====================================================================
    // In production, forward_stream bridges two physically independent TCP
    // connections.  Each MockStream controls its own read/write behaviour
    // independently — there is NO shared pipe between them.  The only data
    // channel is the CopyBuffer inside forward_stream itself.

    /// Mutable inner state of a single MockStream.
    struct MockStreamInner {
        /// Data returned by the next poll_read call(s).
        read_data: Vec<u8>,
        /// If set, the next poll_read returns this error instead of data/EOF.
        read_err: Option<io::ErrorKind>,
        /// If set, the next poll_write returns this error instead of accepting data.
        write_err: Option<io::ErrorKind>,
        /// If set, poll_write succeeds until this many bytes are written, then returns the error.
        write_err_after: Option<(io::ErrorKind, u32)>,
        /// Whether the stream has been "read-closed" — poll_read returns EOF.
        read_eof: bool,
        /// Bytes written to this stream (for assertions).
        written: Vec<u8>,
    }

    impl MockStreamInner {
        fn new() -> Self {
            Self {
                read_data: Vec::new(),
                read_err: None,
                write_err: None,
                write_err_after: None,
                read_eof: false,
                written: Vec::new(),
            }
        }

        fn inject_read_data(&mut self, data: &[u8]) {
            self.read_data.extend_from_slice(data);
        }

        fn set_read_err(&mut self, kind: io::ErrorKind) {
            self.read_err = Some(kind);
        }

        fn set_write_err(&mut self, kind: io::ErrorKind) {
            self.write_err = Some(kind);
        }

        /// Make poll_write fail after `bytes` bytes are written.
        fn set_write_err_after(&mut self, kind: io::ErrorKind, bytes: u32) {
            self.write_err_after = Some((kind, bytes));
        }

        fn close_read(&mut self) {
            self.read_eof = true;
        }
    }

    /// A single mock stream endpoint.  Two instances are completely independent.
    struct MockStream {
        inner: Arc<Mutex<MockStreamInner>>,
    }

    impl MockStream {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(MockStreamInner::new())),
            }
        }

        /// Inject data that will be returned on the next poll_read.
        fn inject_read_data(&self, data: &[u8]) {
            self.inner.lock().unwrap().inject_read_data(data);
        }

        /// Make the next poll_read return this error.
        fn set_read_err(&self, kind: io::ErrorKind) {
            self.inner.lock().unwrap().set_read_err(kind);
        }

        /// Make the next poll_write return this error.
        fn set_write_err(&self, kind: io::ErrorKind) {
            self.inner.lock().unwrap().set_write_err(kind);
        }

        /// Make poll_write fail after `bytes` bytes are written.
        fn set_write_err_after(&self, kind: io::ErrorKind, bytes: u32) {
            self.inner.lock().unwrap().set_write_err_after(kind, bytes);
        }

        /// Make poll_read return EOF immediately (no data).
        fn close_read(&self) {
            self.inner.lock().unwrap().close_read();
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut inner = self.inner.lock().unwrap();

            // Priority: injected error
            if let Some(kind) = inner.read_err.take() {
                return Poll::Ready(Err(io::Error::from(kind)));
            }

            // Then: available data
            if inner.read_data.is_empty() {
                // No data left. If the read end has been "closed", signal EOF
                // (like a real TCP FIN after all buffered data is consumed).
                if inner.read_eof {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending
            } else {
                let n = std::cmp::min(inner.read_data.len(), buf.remaining());
                buf.put_slice(&inner.read_data[..n]);
                inner.read_data.drain(..n);
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut inner = self.inner.lock().unwrap();

            if let Some(kind) = inner.write_err.take() {
                return Poll::Ready(Err(io::Error::from(kind)));
            }

            if let Some((kind, remaining)) = &mut inner.write_err_after {
                let len = buf.len() as u32;
                if *remaining == 0 {
                    return Poll::Ready(Err(io::Error::from(*kind)));
                }
                if len > *remaining {
                    // Partial write: accept up to the threshold, next call errors.
                    let partial = *remaining as usize;
                    *remaining = 0;
                    inner.written.extend_from_slice(&buf[..partial]);
                    return Poll::Ready(Ok(partial));
                }
                *remaining -= len;
            }

            inner.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn reset() -> io::ErrorKind {
        io::ErrorKind::ConnectionReset
    }

    fn broken_pipe() -> io::ErrorKind {
        io::ErrorKind::BrokenPipe
    }

    /// Runs `copy_bidirectional_impl` and returns `(downstream→upstream, upstream→downstream)` byte counts.
    async fn run_copy(downstream: &mut MockStream, upstream: &mut MockStream) -> (u64, u64) {
        copy_bidirectional_impl(downstream, upstream, FORWARD_BUF_SIZE, FORWARD_BUF_SIZE).await
    }

    // =====================================================================
    // Test scenarios — each pair of MockStreams is physically independent
    // =====================================================================

    /// Scenario 1: Both sides have data to read, then both close (EOF).
    ///
    /// downstream reads "client data" → EOF
    /// upstream  reads "server data" → EOF
    /// The CopyBuffer carries data between them.
    #[tokio::test]
    async fn test_both_sides_data_then_eof() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.inject_read_data(b"hello from client");
        downstream.close_read();

        upstream.inject_read_data(b"hello from server");
        upstream.close_read();

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(ds_to_us, 17, "downstream→upstream: 17 bytes expected");
        assert_eq!(us_to_ds, 17, "upstream→downstream: 17 bytes expected");
    }

    /// Scenario 2: Both sides immediately get a read error.
    ///
    /// After fix: both directions error → logged → returns (0, 0).
    #[tokio::test]
    async fn test_both_sides_read_error() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.set_read_err(reset());
        upstream.set_read_err(reset());

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(ds_to_us, 0, "a→b read error → 0 bytes");
        assert_eq!(us_to_ds, 0, "b→a read error → 0 bytes");
    }

    /// Scenario 3: **The key scenario from the iperf3 logs.**
    ///
    /// downstream reads "server response" → EOF (server closed normally with FIN)
    /// upstream has a write error (when proxy tries to write back to the client,
    /// the connection is already torn down → ECONNRESET)
    ///
    /// This maps to the egress side: egress reads data from iperf3 server (EOF),
    /// then tries to write to the downstream tunnel → but the tunnel is already
    /// being torn down, so write fails.
    ///
    /// After fix: a→b reads 20 bytes but write fails → 0 counted;
    /// b→a EOFs with 0 bytes.
    #[tokio::test]
    async fn test_one_side_eof_other_side_write_error() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.inject_read_data(b"server response data");
        downstream.close_read();

        upstream.close_read();
        upstream.set_write_err(reset());

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(
            ds_to_us, 0,
            "a→b: read 20 bytes but write failed → 0 counted"
        );
        assert_eq!(us_to_ds, 0, "b→a: EOF immediately → 0 bytes");
    }

    /// Scenario 4: One side immediately gets a read error, the other side
    /// has normal data.
    ///
    /// After fix: a→b errors (0 bytes), b→a transfers data successfully.
    #[tokio::test]
    async fn test_one_side_read_error_other_normal() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.set_read_err(reset());
        upstream.inject_read_data(b"upstream has data");
        upstream.close_read();

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(ds_to_us, 0, "a→b read error → 0 bytes");
        assert_eq!(us_to_ds, 17, "b→a: 17 bytes transferred");
    }

    /// Scenario 5: One side immediately EOFs (no data), the other side
    /// has data then closes normally.
    ///
    /// This simulates a client that only receives (no data to send).
    #[tokio::test]
    async fn test_one_side_eof_other_side_data() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.close_read();

        upstream.inject_read_data(b"response from server");
        upstream.close_read();

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(ds_to_us, 0, "a→b: EOF immediately → 0 bytes");
        assert_eq!(us_to_ds, 20, "b→a: 20 bytes transferred");
    }

    /// Scenario 6: One side EOFs immediately, the other side write errors
    /// immediately. Both directions fail simultaneously.
    ///
    /// After fix: both directions complete → (0, 0).
    #[tokio::test]
    async fn test_one_side_eof_other_side_immediate_write_error() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.close_read();
        upstream.close_read();
        upstream.set_write_err(broken_pipe());

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(ds_to_us, 0, "a→b: EOF immediately → 0 bytes");
        assert_eq!(us_to_ds, 0, "b→a: write error → 0 bytes");
    }

    /// Scenario 7: upstream reads data then EOF, downstream write errors.
    ///
    /// This maps to the ingress side: ingress reads from the rats-tls tunnel
    /// (upstream), the tunnel closes normally (EOF). But when ingress tries
    /// to write to downstream, it gets EPIPE (Broken pipe).
    #[tokio::test]
    async fn test_upstream_eof_downstream_write_error() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        upstream.inject_read_data(b"tunnel data");
        upstream.close_read();

        downstream.close_read();
        downstream.set_write_err(broken_pipe());

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(ds_to_us, 0, "a→b: EOF immediately → 0 bytes");
        assert_eq!(us_to_ds, 0, "b→a: read data but write failed → 0 counted");
    }

    /// Scenario 9: Partial write success then write error.
    ///
    /// downstream has 1024 bytes → EOF, read in one go.
    /// upstream accepts the first 512 bytes, then fails on the remainder.
    ///
    /// After fix: a→b logs ERROR with sent=512 and remain=512, b→a gets 0.
    #[tokio::test]
    async fn test_partial_write_then_error() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        // 1024 bytes total.
        let data = vec![0xABu8; 1024];
        downstream.inject_read_data(&data);
        downstream.close_read();

        upstream.close_read();

        // upstream accepts 512 bytes, then fails with ConnectionReset.
        upstream.set_write_err_after(reset(), 512);

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;

        // First 512 bytes written, second batch of 512 failed.
        assert_eq!(
            ds_to_us, 512,
            "a→b: first 512 bytes written, second batch failed, sent=512"
        );
        assert_eq!(us_to_ds, 0, "b→a: EOF immediately → 0 bytes");
    }

    /// Scenario 10: Real TCP pipe via tokio::io::duplex.
    /// Validates that EOF propagates correctly through real pipes.
    /// Both pipes have data written, then writers are dropped.
    /// The forwarder reads from both and shuts down cleanly.
    #[tokio::test]
    async fn test_duplex_both_write_then_drop() {
        let (mut ds_a, mut ds_b) = tokio::io::duplex(64);
        let (mut us_a, mut us_b) = tokio::io::duplex(64);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Write data into both pipes from the B ends, then drop writers
        ds_b.write_all(b"hello").await.unwrap();
        drop(ds_b);
        us_b.write_all(b"world").await.unwrap();
        drop(us_b);

        // Read from both ends to verify data arrived, then test forwarding
        let mut buf = [0u8; 5];
        ds_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        us_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        // After consuming all data, both sides see EOF → forward_stream returns Ok
        let result =
            copy_bidirectional_impl(&mut ds_a, &mut us_a, FORWARD_BUF_SIZE, FORWARD_BUF_SIZE).await;
        assert_eq!(
            result,
            (0, 0),
            "both sides already EOF, no more data to transfer"
        );
    }
}
