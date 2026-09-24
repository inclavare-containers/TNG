//! Bidirectional stream forwarding between two sockets.
//!
//! Custom implementation instead of `tokio::io::copy_bidirectional`:
//! - `ForwardError` captures direction-aware context (which stream and which
//!   side failed), which makes production debugging much easier.
//! - 512 KB buffers instead of tokio's 8 KB default, for throughput.
//!
//! Do not replace it with `tokio::io::copy_bidirectional`: the loss of error
//! directionality would make forwarding failures hard to diagnose.
//!
//! # Model
//!
//! Two endpoints, two directions sharing them:
//! - `D` downstream (client-facing), `U` upstream (server-facing).
//! - Dir1 = `D.read -> U.write` (client to server).
//! - Dir2 = `U.read -> D.write` (server to client).
//!
//! A TCP endpoint's read and write halves are independent (half-close). A TLS
//! session corruption (`PeerMisbehaved`) or a TCP RST makes that endpoint's
//! read AND write halves unusable. That asymmetry drives the close rules.
//!
//! # Close rules
//!
//! A direction that ends with a clean read EOF is a cooperative half-close:
//! it flushes and shuts down the peer's write half, and the other direction is
//! left to drain its in-flight data (the classic teardown race).
//!
//! A direction that ends with an error must not leave the other direction
//! pending forever. `classify_error` sorts the error and `apply_abort` finishes
//! the other direction accordingly.
//!
//! ## Read anomalies (on a direction's read; the other direction is symmetric)
//!
//! | case | meaning | endpoint state | action |
//! |------|--------|-----------------|--------|
//! | R1 | `Ok(0)` clean EOF | peer cleanly FIN'd its write half | cooperative half-close; let the other direction drain |
//! | R2 | `Err(UnexpectedEof)` (TLS close without close_notify) | peer gone | fatal: force-finish the other direction now |
//! | R3 | `Err(InvalidData)` incl. TLS `PeerMisbehaved` (e.g. `TooManyKeyUpdateRequests`) | session corrupt, both halves dead | fatal |
//! | R4 | `Err(ConnectionReset/ConnectionAborted)` (TCP RST) | endpoint dead | fatal |
//! | R5 | `Err(other)` (TimedOut, etc.) | unrecoverable | fatal (conservative) |
//!
//! Any non-EOF read error is fatal: the source endpoint can no longer produce
//! trusted data, and if it is TLS-corrupt or RST its write half (the other
//! direction's sink) is dead too, so draining is impossible. The forward
//! returns promptly so the owning task drops both sockets and the application
//! sees the connection close instead of hanging.
//!
//! ## Write anomalies (on a direction's write)
//!
//! | case | meaning | other direction | action |
//! |------|--------|-----------------|--------|
//! | W1 | benign kind (`BrokenPipe`/`ConnectionReset`/`ConnectionAborted`) + other already done | done | soft: both done, return (teardown race) |
//! | W2 | benign kind + other still active (buffered/in-flight data, write blocked) | draining | soft: let it drain; force-finish once idle |
//! | W3 | `WriteZero` | as W2 | soft |
//! | W4 | non-benign kind (e.g. `PermissionDenied`) | any | fatal: discard the other direction's in-flight data, return |
//!
//! A benign write error means the peer closed its read half; the same
//! endpoint's read half (the other direction's source) may still be sending
//! valid data, so the other direction is allowed to drain. A non-benign write
//! error is treated as a broken connection and force-finishes the other
//! direction.
//!
//! `ForwardError::WriteZero` and write errors whose `io::ErrorKind` is in
//! {BrokenPipe, ConnectionReset, ConnectionAborted, WriteZero, NotConnected}
//! are benign; all other write errors are fatal. Every read error is fatal.
//!
//! A failed direction is parked as `Done(sent)` on error (see
//! `transfer_one_direction`) so it is not re-driven on the next poll, which
//! would otherwise stall the forward when the other direction is still active.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
                match result {
                    Poll::Ready(Ok(count)) => {
                        *state = TransferState::ShuttingDown(count);
                    }
                    Poll::Ready(Err(e)) => {
                        let sent = buf.amt;
                        let remain = (buf.cap.saturating_sub(buf.pos)) as u64;
                        // Make the error sticky: a direction that failed (TLS
                        // corruption, RST, EPIPE) cannot reliably make more
                        // progress, so park it as Done(sent) instead of
                        // re-polling it on the next iteration. Without this a
                        // write error leaves the buffer's unwritten bytes
                        // stranded and the direction re-enters poll_fill_buf,
                        // stalling the whole forward when the other direction
                        // is still active.
                        *state = TransferState::Done(sent);
                        return Poll::Ready(Err((sent, remain, e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            TransferState::ShuttingDown(count) => match w.as_mut().poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    let c = *count;
                    *state = TransferState::Done(c);
                }
                Poll::Ready(Err(err)) => {
                    let sent = *count;
                    *state = TransferState::Done(sent);
                    return Poll::Ready(Err((sent, 0, write_err(err))));
                }
                Poll::Pending => return Poll::Pending,
            },
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

// How a direction's failure should affect the other direction inside
// `copy_bidirectional_impl`. The asymmetry is deliberate: a read error means
// the source endpoint is dead, and because TLS corruption or a TCP RST makes
// that endpoint's write half unusable too, the other direction (whose sink is
// that endpoint) cannot deliver anything more, so it is force-finished now. A
// benign write error means only that the peer stopped accepting our data; its
// read half may still be sending valid response bytes, so the other direction
// is allowed to drain its in-flight data and is force-finished only once it
// goes idle. Without this, a read error on one direction left the other
// direction pending forever: the peer had nothing to send and never EOFed, so
// the forward never returned and the TCP connection stayed open.
#[derive(Clone, Copy)]
enum AbortKind {
    None,
    // Read error, or an unrecoverable write error: force the other direction to
    // finish immediately, discarding any unwritten buffered data.
    Fatal,
    // Benign write error (peer closed its read side): let the other direction
    // drain buffered/in-flight data; force it only once it is idle.
    Soft,
}

fn is_benign_write_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::WriteZero
            | io::ErrorKind::NotConnected
    )
}

fn classify_error(error: &ForwardError) -> AbortKind {
    match error {
        // A read that returns an error (non-EOF) means the source endpoint can
        // no longer produce trusted data: TLS PeerMisbehaved/InvalidData
        // (including TooManyKeyUpdateRequests), UnexpectedEof, ConnectionReset,
        // etc. The endpoint's write half is unusable too, so the other
        // direction cannot deliver anything more.
        ForwardError::ReadDownstream(_) | ForwardError::ReadUpstream(_) => AbortKind::Fatal,
        ForwardError::WriteZero => AbortKind::Soft,
        ForwardError::WriteUpstream(e) | ForwardError::WriteDownstream(e) => {
            if is_benign_write_kind(e.kind()) {
                AbortKind::Soft
            } else {
                AbortKind::Fatal
            }
        }
    }
}

fn state_amt_remain(state: &TransferState) -> (u64, u64) {
    match state {
        TransferState::Running(buf) => {
            let remain = (buf.cap.saturating_sub(buf.pos)) as u64;
            (buf.amt, remain)
        }
        TransferState::ShuttingDown(n) | TransferState::Done(n) => (*n, 0),
    }
}

/// Records a per-direction error and lifts `abort` to the strongest kind seen
/// so far (`Fatal` wins over `Soft`).
fn record_error(
    abort: &mut AbortKind,
    error: ForwardError,
    sent: u64,
    remain: u64,
    dir: &'static str,
) {
    match classify_error(&error) {
        AbortKind::Fatal => {
            tracing::error!(
                ?error,
                sent,
                remain,
                direction = dir,
                "fatal forward error, aborting bidirectional transfer"
            );
            *abort = AbortKind::Fatal;
        }
        AbortKind::Soft => {
            if remain > 0 {
                tracing::error!(?error, sent, remain, direction = dir, "transfer lost data");
            } else {
                tracing::debug!(
                    ?error,
                    sent,
                    direction = dir,
                    "transfer completed with error"
                );
            }
            if matches!(*abort, AbortKind::None) {
                *abort = AbortKind::Soft;
            }
        }
        AbortKind::None => {}
    }
}

/// Finishes the other direction once one direction has failed, so the forward
/// never waits forever for a peer that has nothing more to send.
fn apply_abort(abort: AbortKind, state: &TransferState, done: &mut Option<u64>, dir: &'static str) {
    if done.is_some() {
        return;
    }
    let (sent, remain) = state_amt_remain(state);
    match abort {
        AbortKind::None => {}
        AbortKind::Fatal => {
            if remain > 0 {
                tracing::error!(
                    sent,
                    remain,
                    direction = dir,
                    "discarding unwritten data: fatal error on the other direction"
                );
            }
            *done = Some(sent);
        }
        AbortKind::Soft => {
            // Let in-flight buffered data drain on a subsequent poll; only
            // force once the buffer is empty so we don't hang on an idle peer.
            if remain == 0 {
                *done = Some(sent);
            }
        }
    }
}

/// Copies data bidirectionally between two streams with specified buffer sizes.
///
/// Returns `(a_to_b_bytes, b_to_a_bytes)`. A direction that ends with a clean
/// read EOF is a cooperative half-close: that direction flushes and shuts down
/// the peer's write half, and the other direction is left to drain its
/// in-flight data (the classic teardown race, handled as before).
///
/// A direction that ends with an error does not leave the other direction
/// pending forever. A read error is fatal (the source endpoint is dead, so the
/// other direction's sink is dead too) and force-finishes the other direction
/// in the same poll. A benign write error (peer closed its read half) lets the
/// other direction drain its buffered data and force-finishes it once idle.
/// Either way the forward returns promptly so the owning task drops both
/// sockets and the application sees the connection close instead of hanging.
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

    // Set when one direction fails; persists across polls until the forward
    // returns so the other direction is handled consistently.
    let mut abort = AbortKind::None;

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

        let mut a_to_b_done = match a_to_b_result {
            Poll::Ready(Ok(n)) => Some(n),
            Poll::Ready(Err((sent, remain, error))) => {
                record_error(&mut abort, error, sent, remain, "downstream to upstream");
                Some(sent)
            }
            Poll::Pending => None,
        };
        let mut b_to_a_done = match b_to_a_result {
            Poll::Ready(Ok(n)) => Some(n),
            Poll::Ready(Err((sent, remain, error))) => {
                record_error(&mut abort, error, sent, remain, "upstream to downstream");
                Some(sent)
            }
            Poll::Pending => None,
        };

        apply_abort(abort, &a_to_b, &mut a_to_b_done, "downstream to upstream");
        apply_abort(abort, &b_to_a, &mut b_to_a_done, "upstream to downstream");

        // Return once both directions have finished: cleanly, by error, or by
        // force-finish from a fatal/soft abort.
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
    use std::time::Duration;

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
        /// If set, poll_write returns Ok(0) (writer reports zero capacity),
        /// which the copy loop turns into ForwardError::WriteZero.
        write_zero: bool,
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
                write_zero: false,
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

        fn set_write_zero(&mut self) {
            self.write_zero = true;
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

        /// Make poll_write return Ok(0) (WriteZero).
        fn set_write_zero(&self) {
            self.inner.lock().unwrap().set_write_zero();
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

            if inner.write_zero {
                return Poll::Ready(Ok(0));
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

    /// Scenario 11: one side read-errors (e.g. TLS `PeerMisbehaved`), the other
    /// side is idle with no data and no EOF. The idle direction would never
    /// produce data and never EOF, so the forward would hang forever.
    ///
    /// After fix: fatal read error force-finishes the idle direction in the
    /// same poll, the forward returns promptly instead of hanging.
    #[tokio::test]
    async fn test_read_error_other_side_idle_does_not_hang() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();
        upstream.set_read_err(reset());

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            run_copy(&mut downstream, &mut upstream),
        )
        .await;
        assert!(
            result.is_ok(),
            "forward must not hang when one direction read-errors and the other is idle"
        );
        let (ds_to_us, us_to_ds) = result.unwrap();
        assert_eq!(ds_to_us, 0, "downstream had nothing to send");
        assert_eq!(us_to_ds, 0, "upstream read errored before any data");
    }

    /// Scenario 12: a benign write error on one direction (peer closed its read
    /// side) must NOT abort in-flight response data on the other direction.
    ///
    /// downstream sends a request then EOF; upstream rejects our write
    /// (ConnectionReset, benign) but still has a response to deliver back.
    /// The response must still reach downstream.
    #[tokio::test]
    async fn test_benign_write_error_other_side_data_delivered() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.inject_read_data(b"client request");
        downstream.close_read();

        upstream.set_write_err(reset());
        upstream.inject_read_data(b"server response");
        upstream.close_read();

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(
            ds_to_us, 0,
            "write to upstream failed immediately, nothing delivered upstream"
        );
        assert_eq!(
            us_to_ds, 15,
            "server response (15 bytes) must still be delivered to downstream"
        );
    }

    /// Scenario 13: a benign write error on one direction while the other
    /// direction is idle (no data, no EOF) must not hang. The peer stopped
    /// accepting our data and has no response coming, so waiting would block
    /// forever. After fix: the idle direction is force-finished once it is
    /// empty, and the forward returns.
    #[tokio::test]
    async fn test_benign_write_error_other_side_idle_does_not_hang() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.inject_read_data(b"client request");
        downstream.close_read();

        upstream.set_write_err(reset());
        // upstream: no data, never EOFs -> the other direction is idle.

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            run_copy(&mut downstream, &mut upstream),
        )
        .await;
        assert!(
            result.is_ok(),
            "forward must not hang after a benign write error when the other direction is idle"
        );
        let (ds_to_us, us_to_ds) = result.unwrap();
        assert_eq!(ds_to_us, 0, "write to upstream failed, nothing delivered");
        assert_eq!(us_to_ds, 0, "upstream had nothing to send back");
    }

    // =====================================================================
    // Coverage for the close-rule matrix (R1-R5 read, W1-W4 write).
    // Already covered by earlier scenarios:
    //   R1 clean EOF drains ............ test_one_side_eof_other_side_data
    //   R4 read ConnectionReset ........ test_read_error_other_side_idle_does_not_hang
    //   W1 benign write + other done ... test_one_side_eof_other_side_write_error,
    //                                    test_upstream_eof_downstream_write_error
    //   W2a benign write + other data .. test_benign_write_error_other_side_data_delivered
    //   W2b benign write + other idle .. test_benign_write_error_other_side_idle_does_not_hang
    // Below: the remaining cases (R2, R3, R5, W3, W4) plus the Fatal-vs-Soft
    // distinction for in-flight data blocked from being written out.
    // =====================================================================

    /// R2/R3/R5: any non-EOF read error is fatal regardless of io::ErrorKind.
    /// With the other direction idle, the forward must force-finish it and
    /// return promptly instead of hanging.
    async fn read_error_on_idle_aborts(kind: io::ErrorKind) {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();
        upstream.set_read_err(kind);

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            run_copy(&mut downstream, &mut upstream),
        )
        .await;
        assert!(
            result.is_ok(),
            "read error {:?} must not hang the forward",
            kind
        );
        let (ds_to_us, us_to_ds) = result.unwrap();
        assert_eq!(ds_to_us, 0, "downstream had nothing to send");
        assert_eq!(us_to_ds, 0, "upstream read errored before any data");
    }

    /// R2: TLS peer closed TCP without close_notify, surfaced as UnexpectedEof.
    #[tokio::test]
    async fn test_r2_read_unexpected_eof_aborts() {
        read_error_on_idle_aborts(io::ErrorKind::UnexpectedEof).await;
    }

    /// R3: TLS PeerMisbehaved (e.g. TooManyKeyUpdateRequests) is mapped by
    /// tokio-rustls to io::Error(InvalidData, ..) on the read path.
    #[tokio::test]
    async fn test_r3_read_invalid_data_aborts() {
        read_error_on_idle_aborts(io::ErrorKind::InvalidData).await;
    }

    /// R5: any other read error kind is fatal (conservative).
    #[tokio::test]
    async fn test_r5_read_other_error_aborts() {
        read_error_on_idle_aborts(io::ErrorKind::TimedOut).await;
    }

    /// W3: WriteZero is classified as Soft, so the other direction's in-flight
    /// response is still delivered.
    #[tokio::test]
    async fn test_w3_write_zero_other_side_data_delivered() {
        let mut downstream = MockStream::new();
        let mut upstream = MockStream::new();

        downstream.inject_read_data(b"client request");
        downstream.close_read();

        upstream.set_write_zero();
        upstream.inject_read_data(b"server response");
        upstream.close_read();

        let (ds_to_us, us_to_ds) = run_copy(&mut downstream, &mut upstream).await;
        assert_eq!(
            ds_to_us, 0,
            "upstream write returned zero, nothing delivered upstream"
        );
        assert_eq!(
            us_to_ds, 15,
            "server response (15 bytes) still delivered (WriteZero is soft)"
        );
    }

    /// W4: a non-benign write error is Fatal. The other direction has a large
    /// response in flight whose write to the downstream sink is blocked (tiny
    /// duplex buffer, not drained). Fatal must force-finish it and discard the
    /// buffered remainder instead of waiting for a peer that will never drain.
    #[tokio::test]
    async fn test_w4_fatal_write_error_discards_blocked_inflight() {
        use tokio::io::AsyncWriteExt;

        let (mut ds_a, mut ds_b) = tokio::io::duplex(8);
        // Prime Dir1's read so it reaches the failing upstream write.
        ds_b.write_all(b"req").await.unwrap();
        // ds_b stays alive but is never drained, so Dir2's writes to ds_a block
        // once the 8-byte buffer fills.
        let mut upstream = MockStream::new();
        let resp: &[u8] = b"server response payload that exceeds the tiny duplex buffer";
        upstream.inject_read_data(resp);
        upstream.close_read();
        upstream.set_write_err(io::ErrorKind::PermissionDenied);

        let (ds_to_us, us_to_ds) =
            copy_bidirectional_impl(&mut ds_a, &mut upstream, FORWARD_BUF_SIZE, FORWARD_BUF_SIZE)
                .await;
        assert_eq!(ds_to_us, 0, "write to upstream failed immediately");
        assert!(
            us_to_ds < resp.len() as u64,
            "Fatal abort must discard the blocked in-flight response (got {} of {})",
            us_to_ds,
            resp.len()
        );
        drop(ds_b);
    }

    /// W2 contrast: a benign write error is Soft, so the other direction is
    /// allowed to drain its in-flight response to completion once the
    /// downstream sink is drained. This is the dual of the W4 test above and
    /// is what makes Fatal-vs-Soft observable.
    #[tokio::test]
    async fn test_w2_soft_write_error_drains_blocked_inflight() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut ds_a, mut ds_b) = tokio::io::duplex(8);
        ds_b.write_all(b"req").await.unwrap();
        let mut upstream = MockStream::new();
        let resp: &[u8] = b"server response payload that exceeds the tiny duplex buffer";
        upstream.inject_read_data(resp);
        upstream.close_read();
        upstream.set_write_err(broken_pipe());

        // Drive run_copy and drain ds_b concurrently in one task (no spawn):
        // Dir2's writes to ds_a only progress while ds_b is being read.
        let copy_fut =
            copy_bidirectional_impl(&mut ds_a, &mut upstream, FORWARD_BUF_SIZE, FORWARD_BUF_SIZE);
        let drain_fut = async {
            let mut got = Vec::new();
            let mut buf = [0u8; 64];
            loop {
                match ds_b.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            got
        };
        let ((ds_to_us, us_to_ds), got) = tokio::join!(copy_fut, drain_fut);

        assert_eq!(ds_to_us, 0, "write to upstream failed immediately");
        assert_eq!(
            us_to_ds,
            resp.len() as u64,
            "Soft must let the other direction drain all in-flight data (got {} of {})",
            us_to_ds,
            resp.len()
        );
        assert_eq!(got, resp, "drained bytes must equal the full response");
    }
}
