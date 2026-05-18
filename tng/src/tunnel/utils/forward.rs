use anyhow::{Context, Result};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context as TaskContext, Poll};
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
#[derive(Debug)]
pub enum ForwardError {
    ReadDownstream { source: io::Error },
    WriteUpstream { source: io::Error },
    ReadUpstream { source: io::Error },
    WriteDownstream { source: io::Error },
    WriteZero,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::ReadDownstream { source } => {
                write!(f, "read on downstream failed: {:?}", source)
            }
            ForwardError::WriteUpstream { source } => {
                write!(f, "write on upstream failed: {:?}", source)
            }
            ForwardError::ReadUpstream { source } => {
                write!(f, "read on upstream failed: {:?}", source)
            }
            ForwardError::WriteDownstream { source } => {
                write!(f, "write on downstream failed: {:?}", source)
            }
            ForwardError::WriteZero => {
                write!(f, "write zero byte into writer")
            }
        }
    }
}

impl std::error::Error for ForwardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ForwardError::ReadDownstream { source }
            | ForwardError::WriteUpstream { source }
            | ForwardError::ReadUpstream { source }
            | ForwardError::WriteDownstream { source } => Some(source),
            ForwardError::WriteZero => None,
        }
    }
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
) -> Poll<Result<u64, ForwardError>>
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
                let count =
                    ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut(), &read_err, &write_err))?;
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => match w.as_mut().poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    let c = *count;
                    *state = TransferState::Done(c);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(write_err(err))),
                Poll::Pending => return Poll::Pending,
            },
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

/// Copies data bidirectionally between two streams with specified buffer sizes.
///
/// Returns `(a_to_b_bytes, b_to_a_bytes)` on success, or an error with direction context on failure.
async fn copy_bidirectional_impl<A, B>(
    a: &mut A,
    b: &mut B,
    a_to_b_buffer_size: usize,
    b_to_a_buffer_size: usize,
) -> Result<(u64, u64), ForwardError>
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
            |e| ForwardError::ReadDownstream { source: e },
            |e| ForwardError::WriteUpstream { source: e },
        );
        // Transfer from b to a (upstream -> downstream)
        let b_to_a_result = transfer_one_direction(
            cx,
            &mut b_to_a,
            b,
            a,
            |e| ForwardError::ReadUpstream { source: e },
            |e| ForwardError::WriteDownstream { source: e },
        );

        // Wait for both directions
        let a_to_b_bytes = match ready!(a_to_b_result) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };

        let b_to_a_bytes = match ready!(b_to_a_result) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };

        Poll::Ready(Ok((a_to_b_bytes, b_to_a_bytes)))
    })
    .await
}

pub async fn forward_stream(
    mut upstream: impl AsyncRead + AsyncWrite + Unpin,
    mut downstream: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<()> {
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
    .await
    .context("Failed during bidirectional stream copy")?;
    tracing::debug!(
        tx_bytes = from_client,
        rx_bytes = from_server,
        "Finished transmit application data",
    );

    Ok(())
}
