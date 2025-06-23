use std::future::Future;

use pin_project::pin_project;

#[pin_project]
pub struct FirstByteReadTimeoutStream<
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
> {
    #[pin]
    inner: T,
    timeout: tokio::time::Duration,
    #[pin]
    state: State,
}

#[pin_project(project = StateProj)]
enum State {
    BeforeFirstRead,
    InFirstRead(#[pin] tokio::time::Sleep),
    AfterFirstRead,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>
    FirstByteReadTimeoutStream<T>
{
    pub fn new(inner: T, timeout: tokio::time::Duration) -> Self {
        Self {
            inner,
            timeout,
            state: State::BeforeFirstRead,
        }
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
        let mut this = self.project();

        // Check if we have not read any bytes yet
        {
            let state = this.state.as_mut().project();
            if matches!(state, StateProj::BeforeFirstRead) {
                // Change the state to reading and install the timeout.
                this.state
                    .as_mut()
                    .set(State::InFirstRead(tokio::time::sleep(this.timeout.clone())));
            }
        }

        // If we are in the first read state, check if we are timeouted.
        {
            let state = this.state.as_mut().project();
            if let StateProj::InFirstRead(sleep) = state {
                match sleep.poll(cx) {
                    std::task::Poll::Ready(()) => {
                        // Timeout expired.
                        return std::task::Poll::Ready(Err(std::io::Error::from(
                            std::io::ErrorKind::TimedOut,
                        )));
                    }
                    std::task::Poll::Pending => { /* The timeout is not expired, let's continue. */
                    }
                }
            }
        }

        // If there is no timeout happened, just delegate to the inner stream.
        let poll_res = this.inner.poll_read(cx, buf);
        match poll_res {
            std::task::Poll::Ready(_) => {
                /* We got result from the inner stream, so we can cancel the timeout. */
                this.state.as_mut().set(State::AfterFirstRead);
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
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
