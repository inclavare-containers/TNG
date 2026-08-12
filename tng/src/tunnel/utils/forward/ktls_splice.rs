//! kTLS splice data plane: one `TcpStream` + one `Mutex<Context>`.
//!
//! The kernel-TLS socket is driven by `tokio_splice2::copy_bidirectional`. Both
//! directions share the single `TcpStream` mio registration — no `dup`, no
//! `into_raw`, no second `AsyncFd`, no hand-rolled cmsg parsing. When splice
//! returns `EIO` because a non-data TLS control record (`NewSessionTicket`,
//! `close_notify`) is pending, `Context::handle_io_error` drains the record via
//! a kernel cmsg and the adapter returns `WouldBlock` so the splice loop
//! retries. Shutdown emits `close_notify` via `Context::shutdown` before the TCP
//! half-close. kTLS itself is only engaged on Linux kernels >= 5.16 (TNG's
//! existing `EnvCheckedKtls` probe); older kernels fall back to the user-space
//! rustls data plane.
//!
//! `Mutex<Context>` (rather than `RefCell<Context>`) is required because the
//! `Send` future that calls `copy_bidirectional` holds `&mut KtlsSpliceStream`
//! across await points, and `&mut T: Send` requires `T: Sync`. The lock is only
//! ever contended between the single task's read and write halves, so it is
//! effectively a single-threaded borrow with `Sync` shape.

use std::os::fd::AsFd;
use std::sync::Mutex;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_splice2::{AsyncReadFd, AsyncWriteFd, IsNotFile};

use ktls_core::{tls::Peer, Error, ProtocolVersion, TlsCryptoInfoRx, TlsCryptoInfoTx, TlsSession};

use crate::observability::metric::stream::PendingCounter;

/// Minimal `TlsSession` for the kTLS splice data plane (A2).
///
/// Holds only the negotiated protocol version + peer side; the kernel owns
/// AEAD. `handle_new_session_ticket` MUST return `Ok(())` (ignore) — a
/// returning-`Err` impl aborts every TLS 1.3 connection whose peer sends an
/// NST, because the NST arrives as a control record that `EIO`-drives
/// `handle_tls_control_message` -> `handle_new_session_ticket` (spec §5.1).
/// Key updates are unsupported (parity with the official `ktls` v6 crate); the
/// proxy never initiates one.
pub(crate) struct Session {
    peer: Peer,
    version: ProtocolVersion,
}

impl Session {
    pub(crate) fn new_client(conn: &rustls::ClientConnection) -> Self {
        Self {
            peer: Peer::Client,
            version: conn
                .protocol_version()
                .unwrap_or(rustls::ProtocolVersion::TLSv1_2)
                .into(),
        }
    }

    pub(crate) fn new_server(conn: &rustls::ServerConnection) -> Self {
        Self {
            peer: Peer::Server,
            version: conn
                .protocol_version()
                .unwrap_or(rustls::ProtocolVersion::TLSv1_2)
                .into(),
        }
    }
}

impl TlsSession for Session {
    fn peer(&self) -> Peer {
        self.peer
    }

    fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    fn update_tx_secret(&mut self) -> Result<TlsCryptoInfoTx, Error> {
        Err(Error::KeyUpdateFailed(std::io::Error::other(
            "tng kTLS splice session does not support key updates",
        )))
    }

    fn update_rx_secret(&mut self) -> Result<TlsCryptoInfoRx, Error> {
        Err(Error::KeyUpdateFailed(std::io::Error::other(
            "tng kTLS splice session does not support key updates",
        )))
    }

    fn handle_new_session_ticket(&mut self, _payload: &[u8]) -> Result<(), Error> {
        // Ignore the ticket — do NOT abort. (TLS 1.3 NST post-handshake.)
        Ok(())
    }
}

/// `tokio_splice2`-compatible zero-copy adapter around an installed-kTLS
/// socket. Holds the single `TcpStream` (the kTLS socket; its mio registration
/// from the handshake drives BOTH directions — no `dup`, no second `AsyncFd`,
/// no `EEXIST`) and a `Mutex<Context>` (the state machine + cmsg `EIO` drain +
/// `close_notify` shutdown, owned by `ktls-core`).
///
/// `Mutex` (rather than `RefCell`) is required because the `Send` future that
/// calls `copy_bidirectional` holds `&mut KtlsSpliceStream` across await points,
/// and `&mut T: Send` requires `T: Sync`. The lock is only ever contended
/// between the single task's read and write halves, so it is effectively a
/// single-threaded borrow with `Sync` shape.
///
/// `ktls_stream::Stream` is NOT wrapped: its `inner` is private and its
/// `AsyncRead`/`AsyncWrite` are user-space `poll_read`/`poll_write`, the
/// opposite of what splice needs; but `ktls_core::Context` is public, so the
/// adapter holds `TcpStream + Context` directly (spec §3.1).
pub(crate) struct KtlsSpliceStream {
    tcp: TcpStream,
    ctx: Mutex<ktls_core::Context<Session>>,
}

impl KtlsSpliceStream {
    pub(crate) fn new(tcp: TcpStream, ctx: ktls_core::Context<Session>) -> Self {
        Self {
            tcp,
            ctx: Mutex::new(ctx),
        }
    }

    /// Borrow the `Context` (e.g. to drain the corked-tail buffer before the
    /// splice loop). The lock is never contended; callers must not hold the
    /// guard across await.
    fn ctx_mut(&self) -> std::sync::MutexGuard<'_, ktls_core::Context<Session>> {
        self.ctx.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl AsFd for KtlsSpliceStream {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.tcp.as_fd()
    }
}

impl AsyncReadFd for KtlsSpliceStream {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tcp.poll_read_ready(cx)
    }

    fn try_io_read<R>(&self, f: impl FnOnce() -> io::Result<R>) -> io::Result<R> {
        // EIO interception contract (spec §2.1): the splice closure must always
        // run. On EIO (a non-application TLS control record) we drain the record
        // via Context::handle_io_error and surface WouldBlock so
        // poll_splice_drain retries. All non-recoverable errors are forwarded.
        match f() {
            Ok(r) => Ok(r),
            Err(e) => match self.ctx_mut().handle_io_error(&self.tcp, e) {
                Ok(()) => Err(io::ErrorKind::WouldBlock.into()), // recovered -> retry
                Err(e) => Err(e),                                // unrecoverable -> Fault
            },
        }
    }
}

impl AsyncWriteFd for KtlsSpliceStream {
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tcp.poll_write_ready(cx)
    }

    fn try_io_write<R>(&self, f: impl FnOnce() -> io::Result<R>) -> io::Result<R> {
        // Symmetric with try_io_read: always run the closure; EIO from a control
        // record is recovered via Context::handle_io_error -> WouldBlock.
        match f() {
            Ok(r) => Ok(r),
            Err(e) => match self.ctx_mut().handle_io_error(&self.tcp, e) {
                Ok(()) => Err(io::ErrorKind::WouldBlock.into()),
                Err(e) => Err(e),
            },
        }
    }
}

impl IsNotFile for KtlsSpliceStream {}

impl AsyncRead for KtlsSpliceStream {
    // Not on the splice hot path (copy_bidirectional uses try_io_read); serves
    // only any out-of-band user-space read. Delegates to the Context buffer
    // then the TcpStream, mirroring ktls_stream::Stream::poll_read.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut ctx = this.ctx_mut();
        if ctx.state().is_read_closed() {
            return Poll::Ready(Ok(()));
        }
        // Serve any buffered corked-tail bytes first.
        let read_from_buffer = ctx.buffer_mut().read(|data| {
            let amt = buf.remaining().min(data.len());
            buf.put_slice(&data[..amt]);
            amt
        });
        if read_from_buffer.is_some() {
            return Poll::Ready(Ok(()));
        }
        drop(ctx);
        Pin::new(&mut this.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for KtlsSpliceStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ctx_mut().state().is_write_closed() {
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut this.tcp).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Emit close_notify (Context::shutdown -> send_tls_control_message
        // ALERT close_notify) then TCP half-close. Replaces the hand-rolled
        // send_close_notify. Best-effort: a failure here is no worse than a
        // bare FIN.
        this.ctx_mut().shutdown(&this.tcp);
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}

/// Bidirectional zero-copy forward for an installed-kTLS upstream.
///
/// Both directions run through a single `tokio_splice2::copy_bidirectional`
/// over the kTLS socket (`KtlsSpliceStream`, one mio registration, no `dup`)
/// and the downstream `TcpStream`. kTLS control records (TLS 1.3
/// `NewSessionTicket`, `close_notify`) make splice return `EIO`; that is
/// intercepted in `KtlsSpliceStream::try_io_read` via
/// `Context::handle_io_error` (the cmsg drain lives in `ktls-core`, not
/// here) and surfaced as `WouldBlock` so `copy_bidirectional`'s drain loop
/// retries — the bulk path stays zero-copy. `close_notify` on teardown is
/// emitted by `KtlsSpliceStream::poll_shutdown` -> `Context::shutdown`.
pub async fn forward_ktls_stream_bi(
    ktls: KtlsSpliceStream,
    mut tcp: TcpStream,
    tcp_prelude: Option<bytes::Bytes>,
    mut tcp_to_ktls: PendingCounter,
    mut ktls_to_tcp: PendingCounter,
) {
    use tokio::io::AsyncWriteExt;

    let mut ktls = ktls;

    // Flush any user-space prelude (HTTP inspector over-read) into the kTLS TX
    // fd before splicing — splice cannot see user-space bytes; a plain write(2)
    // on the kTLS fd is encrypted by the kernel TX path.
    if let Some(prelude) = tcp_prelude {
        if !prelude.is_empty() {
            if let Err(error) = ktls.write_all(&prelude).await {
                tracing::warn!(
                    ?error,
                    "kTLS forward: prelude flush failed; continuing with splice"
                );
            } else {
                tcp_to_ktls.add(prelude.len() as u64);
            }
        }
    }

    // Drain the corked-tail buffer (early data / prelude folded in at setup)
    // straight to downstream — a one-time user-space write; the bulk path below
    // is zero-copy splice. The guard from ctx_mut() is dropped before the
    // await.
    let tail = ktls.ctx_mut().buffer_mut().drain();
    if let Some(tail) = tail {
        if !tail.is_empty() {
            if let Err(error) = tcp.write_all(&tail).await {
                tracing::debug!(?error, "kTLS recv: flush corked tail failed");
                return;
            } else {
                ktls_to_tcp.add(tail.len() as u64);
            }
        }
    }

    // copy_bidirectional drives both directions over single stream values; the
    // kTLS side's EIO/ shutdown are handled inside KtlsSpliceStream.
    //
    // TrafficResult semantics from tokio_splice2::copy_bidirectional(sl, sr):
    //   tx = bytes sl -> sr
    //   rx = bytes sr -> sl
    // Here sl = ktls, sr = tcp, so tx is kTLS -> downstream (recv) and rx is
    // downstream -> kTLS (send).
    let result = tokio_splice2::copy_bidirectional(&mut ktls, &mut tcp).await;
    match result {
        Ok(traffic) => {
            if traffic.tx > 0 {
                ktls_to_tcp.add(traffic.tx as u64);
            }
            if traffic.rx > 0 {
                tcp_to_ktls.add(traffic.rx as u64);
            }
            tracing::debug!(
                tx = traffic.tx,
                rx = traffic.rx,
                "kTLS forward (splice) finished"
            );
        }
        Err(error) => {
            tracing::debug!(?error, "kTLS forward (splice) finished with error");
        }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use ktls_core::{tls::Peer, TlsSession};

    #[test]
    fn new_session_ticket_is_ignored_not_aborted() {
        // A TLS 1.3 peer sends a NewSessionTicket post-handshake. If this
        // returned Err, the connection would abort (the NST arrives as a
        // control record -> EIO -> handle_tls_control_message -> Handshake ->
        // handle_new_session_ticket). MUST be Ok (ignore). See spec §5.1.
        let mut s = Session {
            peer: Peer::Client,
            version: ktls_core::ProtocolVersion::TLSv1_3,
        };
        assert!(s.handle_new_session_ticket(&[]).is_ok());
    }

    #[test]
    fn key_update_is_unsupported_without_aborting_state() {
        // Proxy does not initiate TLS 1.3 key updates (parity with official
        // ktls v6). Returns Err but does not mutate state.
        let mut s = Session {
            peer: Peer::Client,
            version: ktls_core::ProtocolVersion::TLSv1_3,
        };
        assert!(s.update_tx_secret().is_err());
        assert!(s.update_rx_secret().is_err());
    }
}
