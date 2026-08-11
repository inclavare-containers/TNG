use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::anyhow;
#[cfg(not(wasm))]
use tokio::time as tokio_time;
#[cfg(wasm)]
use tokio_with_wasm::alias::time as tokio_time;

#[cfg_attr(wasm, allow(unused))]
pub struct FirstByteReadTimeoutStream<
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
> {
    inner: T,
    timeout: Duration,
    state: State,
}

#[allow(clippy::enum_variant_names)]
#[cfg_attr(wasm, allow(unused))]
enum State {
    BeforeFirstRead,
    // The `Sleep` is boxed and pinned on the heap. `Pin<Box<Sleep>>` is itself
    // `Unpin` (a `Box` pointer is always `Unpin`, and `Pin<P>` is `Unpin` when
    // `P: Unpin`), so this variant does not make `State` (and therefore the
    // whole stream) `!Unpin`, while still preserving the pinning guarantee the
    // `tokio_time::Sleep` future requires to be polled safely.
    InFirstRead(Pin<Box<tokio_time::Sleep>>),
    AfterFirstRead,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>
    FirstByteReadTimeoutStream<T>
{
    pub fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            state: State::BeforeFirstRead,
        }
    }

    /// Consumes this wrapper and returns the inner stream.
    ///
    /// # Warning
    ///
    /// The caller **must** ensure that the first byte read has logically
    /// completed before calling this method. Blindly unwrapping the stream
    /// before the first byte is read will bypass the timeout check.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Returns a reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// The caller **must** ensure that the first byte read has logically
    /// completed before calling this method. Blindly unwrapping the stream
    /// before the first byte is read will bypass the timeout check.
    #[cfg_attr(not(target_os = "linux"), allow(unused))]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> tokio::io::AsyncRead
    for FirstByteReadTimeoutStream<T>
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Every field is `Unpin` (`T: Unpin` by bound, `Duration`
        // is `Unpin`, and `State` is `Unpin` since its only non-trivial variant
        // holds a `Pin<Box<Sleep>>` which is `Unpin`), so the whole struct is
        // `Unpin` and we can recover a `&mut Self` from the pinned reference
        // without `unsafe` (and without needing `pin_project`).
        let this = self.get_mut();

        // Check if we have not read any bytes yet
        if matches!(this.state, State::BeforeFirstRead) {
            // Change the state to reading and install the timeout.
            this.state = State::InFirstRead(Box::pin(tokio_time::sleep(this.timeout)));
        }

        // If we are in the first read state, check if we are timeouted.
        if let State::InFirstRead(sleep) = &mut this.state {
            match Future::poll(sleep.as_mut(), cx) {
                std::task::Poll::Ready(()) => {
                    // Timeout expired.
                    return std::task::Poll::Ready(Err(std::io::Error::other(anyhow!(
                        "first byte read timeout"
                    ))));
                }
                std::task::Poll::Pending => { /* The timeout is not expired, let's continue. */ }
            }
        }

        // If there is no timeout happened, just delegate to the inner stream.
        // `T: Unpin`, so pinning a `&mut T` reference is safe via `Pin::new`.
        let poll_res = Pin::new(&mut this.inner).poll_read(cx, buf);
        match poll_res {
            std::task::Poll::Ready(_) => {
                /* We got result from the inner stream, so we can cancel the timeout. */
                this.state = State::AfterFirstRead;
                poll_res
            }
            std::task::Poll::Pending => {
                /* The inner stream is not ready, let's continue. */
                poll_res
            }
        }
    }
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> tokio::io::AsyncWrite
    for FirstByteReadTimeoutStream<T>
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Compile-time proof that the wrapper stays `Unpin` even though it wraps a
    // `tokio_time::Sleep` (which is `!Unpin`). Boxing+pinning the `Sleep` keeps
    // the pinning guarantee without leaking `!Unpin` into the enclosing struct.
    #[test]
    fn stream_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<FirstByteReadTimeoutStream<tokio::io::DuplexStream>>();
    }

    #[tokio::test]
    async fn first_read_within_timeout_succeeds() {
        let (mut server, client) = tokio::io::duplex(64);
        server.write_all(b"hello").await.unwrap();
        let mut stream = FirstByteReadTimeoutStream::new(client, Duration::from_millis(100));
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn first_read_times_out_when_no_data() {
        let (_server, client) = tokio::io::duplex(64);
        let mut stream = FirstByteReadTimeoutStream::new(client, Duration::from_millis(100));
        let mut buf = [0u8; 8];
        // Nobody ever writes to the client half, so the first read arms the
        // 100ms timeout and then blocks on the inner stream until it fires.
        let err = stream.read(&mut buf).await.unwrap_err();
        assert!(
            err.to_string().contains("first byte read timeout"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn no_timeout_after_first_byte() {
        let (mut server, client) = tokio::io::duplex(64);
        let mut stream = FirstByteReadTimeoutStream::new(client, Duration::from_millis(100));

        // First byte arrives well within the deadline.
        server.write_all(b"a").await.unwrap();
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"a");

        // After the first byte the timeout is cancelled. A later read with no
        // data must stay pending (not error out) even past the original
        // deadline: `tokio_time::timeout` returning `Err` means the wrapped
        // read never completed, i.e. it was still pending rather than timed out.
        let mut buf2 = [0u8; 1];
        let pending = tokio_time::timeout(Duration::from_millis(300), stream.read(&mut buf2))
            .await
            .is_err();
        assert!(pending, "second read should remain pending, not time out");

        // Providing data afterwards still flows through like the bare inner stream.
        server.write_all(b"b").await.unwrap();
        let mut buf3 = [0u8; 1];
        stream.read_exact(&mut buf3).await.unwrap();
        assert_eq!(&buf3, b"b");
    }

    #[tokio::test]
    async fn write_is_delegated_to_inner() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = FirstByteReadTimeoutStream::new(client, Duration::from_millis(100));
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn into_inner_returns_inner_stream() {
        let (mut server, client) = tokio::io::duplex(64);
        server.write_all(b"x").await.unwrap();
        let stream = FirstByteReadTimeoutStream::new(client, Duration::from_millis(100));
        let mut inner = stream.into_inner();
        let mut buf = [0u8; 1];
        inner.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"x");
    }
}
