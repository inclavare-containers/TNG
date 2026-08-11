use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{unix::AsyncFd, AsyncWrite};
use tokio::net::TcpStream;
use tokio_splice2::{AsyncWriteFd, IsNotFile};

use crate::observability::metric::stream::PendingCounter;

/// Duplicate a fd into a fresh `tokio::net::TcpStream`.
///
/// `dup(2)` produces a new file descriptor number referring to the same open
/// file description (so a kTLS ULP and its installed keys are shared) while
/// keeping a distinct mio registration — registering the *same* fd number
/// twice fails with `EEXIST`, which is why the send and recv loops each need
/// their own `TcpStream` value built off a separately dup'd fd.
///
/// File *status* flags (`O_NONBLOCK`) live on the open file description, so
/// they are shared with the original tokio socket; `set_nonblocking(true)` is
/// re-asserted only for robustness and is a no-op on a socket tokio already
/// set nonblocking. The `OwnedFd` returned by `dup` owns nothing from the
/// borrowed input fd, so the original stream can move into its own copy loop
/// once this returns.
fn dup_to_tokio_tcp<F: AsFd>(fd: F) -> io::Result<TcpStream> {
    let owned = nix::unistd::dup(fd).map_err(io::Error::from)?;
    let std_stream = std::net::TcpStream::from(owned);
    std_stream.set_nonblocking(true)?;
    TcpStream::from_std(std_stream)
}

/// Send a TLS `close_notify` alert on a kTLS transmit socket.
///
/// This mirrors the `ktls` crate's private `ffi::send_close_notify` (the `ffi`
/// module is not re-exported): a `sendmsg` carrying the `TLS_SET_RECORD_TYPE`
/// control message set to `ALERT`, with a 2-byte plaintext alert payload
/// `[Warning(1), close_notify(0)]`. The kernel wraps and encrypts it as a TLS
/// record on the TX path. Emitted on send-direction teardown so the peer gets a
/// clean `close_notify` instead of a bare TCP FIN — which is what a
/// `splice`-driven send (writing through a `dup`'d plain `TcpStream`) would
/// otherwise emit, tripping the peer's "closed without close_notify" warning.
///
/// Best-effort: a failure here only means the alert did not go out, which is no
/// worse than the previous FIN-only teardown. Callers log the result at debug.
fn send_close_notify(fd: RawFd) -> io::Result<()> {
    // Constants from <linux/tls.h> (matching the `ktls` crate's `ffi` module).
    const SOL_TLS: nix::libc::c_int = 282;
    const TLS_SET_RECORD_TYPE: nix::libc::c_int = 1;
    const TLS_RECORD_TYPE_ALERT: u8 = 0x15;
    const ALERT_LEVEL_WARNING: u8 = 1;
    const ALERT_DESC_CLOSE_NOTIFY: u8 = 0;

    // Plaintext alert payload: [level, description]. The kTLS TX path encrypts
    // these two bytes into a full TLS alert record.
    let mut payload: [u8; 2] = [ALERT_LEVEL_WARNING, ALERT_DESC_CLOSE_NOTIFY];

    // cmsg buffer: a `cmsghdr` immediately followed by the 1-byte record type.
    // `cmsg_len` is the header size plus the data length (no trailing padding),
    // matching the `ktls` crate's `Cmsg::new` computation.
    #[repr(C)]
    struct CmsgHdr {
        hdr: nix::libc::cmsghdr,
        data: [u8; 1],
    }
    let mut cmsg = CmsgHdr {
        hdr: nix::libc::cmsghdr {
            cmsg_len: (std::mem::size_of::<nix::libc::cmsghdr>() + 1) as _,
            cmsg_level: SOL_TLS,
            cmsg_type: TLS_SET_RECORD_TYPE,
        },
        data: [TLS_RECORD_TYPE_ALERT],
    };

    let mut iov = nix::libc::iovec {
        iov_base: payload.as_mut_ptr() as _,
        iov_len: payload.len(),
    };
    let msg = nix::libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov as *mut _ as _,
        msg_iovlen: 1,
        msg_control: &mut cmsg as *mut _ as _,
        msg_controllen: cmsg.hdr.cmsg_len as _,
        msg_flags: 0,
    };

    // SAFETY: `fd` is an open kTLS TX socket (installed via `config_ktls_*`),
    // and the msghdr/iov/cmsg buffers are valid for the duration of the call.
    let ret = unsafe { nix::libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A `tokio_splice2`-compatible writer around the `dup`'d kTLS send fd whose
/// `poll_shutdown` emits a TLS `close_notify` *before* the TCP half-close.
///
/// `tokio_splice2::copy` calls `W::poll_shutdown` once the read side reaches EOF
/// (its `Terminating` state). On a bare `TcpStream` that `poll_shutdown` is a
/// `SHUT_WR` (a TCP FIN) with no TLS alert, so the peer sees an abrupt
/// `close_notify`-less teardown. Wrapping the kTLS send fd here lets that same
/// shutdown path emit the `close_notify` alert first (via [`send_close_notify`])
/// and then fall through to the normal TCP half-close — restoring the clean
/// teardown `KtlsStream::poll_shutdown` would have produced on the recv side.
///
/// Every method other than `poll_shutdown` forwards to the inner `TcpStream`
/// verbatim so splice keeps its zero-copy semantics.
struct KtlsSendStream(TcpStream);

impl KtlsSendStream {
    fn new(stream: TcpStream) -> Self {
        Self(stream)
    }
}

impl AsFd for KtlsSendStream {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for KtlsSendStream {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsyncWrite for KtlsSendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Emit the TLS close_notify alert first so the peer gets a clean
        // teardown; only then half-close the TCP side. A failure to send the
        // alert is non-fatal — fall through to the TCP shutdown regardless.
        if let Err(error) = send_close_notify(this.0.as_raw_fd()) {
            tracing::debug!(?error, "kTLS: send_close_notify on send teardown failed");
        }
        Pin::new(&mut this.0).poll_shutdown(cx)
    }
}

impl AsyncWriteFd for KtlsSendStream {
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_write_ready(cx)
    }

    fn try_io_write<R>(&self, f: impl FnOnce() -> io::Result<R>) -> io::Result<R> {
        self.0.try_io_write(f)
    }
}

impl IsNotFile for KtlsSendStream {}

/// Move up to `len` bytes `fd_in -> fd_out` via `splice(2)`.
///
/// Both ends must be non-blocking (sockets carry `O_NONBLOCK` on their open
/// file description; the relay pipe is created with `pipe2(O_NONBLOCK)`).
/// Offsets are `NULL` — `splice` does not support offsets on sockets or pipes.
/// Returns the number of bytes moved (`0` only when `fd_in` hits EOF), or the
/// last OS error on failure. Flag choice is documented at the `FLAGS` const.
fn do_splice(fd_in: RawFd, fd_out: RawFd, len: usize) -> io::Result<usize> {
    // SPLICE_F_MOVE is a no-op for socket<->pipe (pages are only movable from
    // page-backed pipe buffers, not from socket receive queues), so it is not
    // set. SPLICE_F_MORE is intentionally NOT set either: it coalesces the
    // peer's TCP sends, which adds latency to short/request traffic. Only
    // SPLICE_F_NONBLOCK is set so a full/empty peer surfaces as `EAGAIN`
    // rather than blocking the executor.
    const FLAGS: nix::libc::c_uint = nix::libc::SPLICE_F_NONBLOCK;
    // SAFETY: both fds are open and non-blocking; NULL offsets are required for
    // sockets and pipes (splice rejects non-NULL offsets on non-regular files).
    let r = unsafe {
        nix::libc::splice(
            fd_in,
            std::ptr::null_mut(),
            fd_out,
            std::ptr::null_mut(),
            len,
            FLAGS,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

/// Outcome of draining one non-application kTLS RX record via `recvmsg`.
enum ControlDrain {
    /// Drained a non-terminal control record (TLS 1.3 `NewSessionTicket`, or a
    /// non-close alert). Application data (or `EAGAIN`) is now the next record
    /// — the splice loop should resume.
    Resume,
    /// Drained a `close_notify` (peer half-closed its send side) — the recv
    /// direction is finished.
    Close,
    /// `recvmsg` failed with a real I/O error (not `EAGAIN`).
    Failed(io::Error),
}

/// Drain a single non-application TLS record from a kTLS RX socket.
///
/// `splice(2)` on a kTLS RX socket returns `EIO` (errno 5) when the next record
/// is a *control* record — a TLS 1.3 `NewSessionTicket` lands right after the
/// handshake, and `close_notify` lands at teardown — because splice moves bytes
/// only and has no way to surface the `TLS_GET_RECORD_TYPE` control message that
/// identifies the record, so the kernel refuses to splice it. This mirrors the
/// `read`→`EIO`→`recvmsg` recovery the `ktls` crate's `KtlsStream::poll_read`
/// performs: a single `recvmsg` carrying that cmsg drains exactly the one
/// control record, after which splice sees application data again. Control
/// records are rare (one `NewSessionTicket`, one `close_notify` per
/// connection), so this escape hatch is negligible against the zero-copy bulk
/// splice — it is *not* a per-byte user-space copy.
///
/// Implemented directly on `libc::recvmsg` (rather than `nix::recvmsg`) to
/// sidestep `nix`'s `SockaddrIn` peer-address parsing — the peer address is
/// irrelevant here and parsing it as IPv4 would break on an IPv6 connection.
fn drain_ktls_control_record(fd: RawFd) -> ControlDrain {
    // <linux/tls.h>: SOL_TLS = 282; TLS_SET_RECORD_TYPE = 1; TLS_GET_RECORD_TYPE = 2.
    const SOL_TLS: nix::libc::c_int = 282;
    const TLS_GET_RECORD_TYPE: nix::libc::c_int = 2;
    const TLS_RECORD_TYPE_ALERT: u8 = 0x15; // 21
    const TLS_RECORD_TYPE_HANDSHAKE: u8 = 0x16; // 22
    const ALERT_DESC_CLOSE_NOTIFY: u8 = 0;

    // cmsg space must hold CMSG_SPACE(1 byte); 64 bytes is ample on any ABI.
    let mut cmsgspace = [0u8; 64];
    // Control records are tiny (close_notify = 2 bytes, NewSessionTicket ≲
    // 256 bytes), but allow headroom for a larger handshake record.
    let mut buf = [0u8; 8192];
    let mut iov = nix::libc::iovec {
        iov_base: buf.as_mut_ptr() as _,
        iov_len: buf.len(),
    };
    // SAFETY: a zeroed `msghdr` is the idiomatic init; only the set fields are read by recvmsg.
    let mut msg: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut _ as _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgspace.as_mut_ptr() as _;
    msg.msg_controllen = cmsgspace.len() as _;

    // SAFETY: fd is an open kTLS RX socket; msghdr/iov/cmsg buffers are valid
    // for the call. The socket is non-blocking, so this returns immediately;
    // the splice loop only calls here after splice returned EIO, so a control
    // record is genuinely pending.
    let ret = unsafe { nix::libc::recvmsg(fd, &mut msg, 0) };
    if ret < 0 {
        let error = io::Error::last_os_error();
        // EAGAIN: the control record vanished between the splice EIO and this
        // recvmsg (or was already drained). Resuming is harmless — splice will
        // re-report EIO if the record reappears.
        if error.raw_os_error() == Some(nix::libc::EAGAIN) {
            return ControlDrain::Resume;
        }
        return ControlDrain::Failed(error);
    }
    if ret == 0 {
        // EOF on the socket — treat as a clean close.
        return ControlDrain::Close;
    }

    // Walk the cmsg buffer for TLS_GET_RECORD_TYPE (the record type is one byte).
    let mut record_type: Option<u8> = None;
    unsafe {
        let mut cmsg = nix::libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == SOL_TLS && hdr.cmsg_type == TLS_GET_RECORD_TYPE {
                let data = nix::libc::CMSG_DATA(cmsg);
                record_type = Some(*(data as *const u8));
                break;
            }
            cmsg = nix::libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    match record_type {
        Some(TLS_RECORD_TYPE_ALERT) => {
            // Alert payload is [level, description]; description == 0 is close_notify.
            let desc = buf.get(1).copied().unwrap_or(0);
            if desc == ALERT_DESC_CLOSE_NOTIFY {
                ControlDrain::Close
            } else {
                // Non-close alert (warning or fatal). A fatal alert ends the
                // session; the splice loop will hit EOF/err on the next splice.
                // Treat as resume and let the next splice surface the failure.
                ControlDrain::Resume
            }
        }
        Some(TLS_RECORD_TYPE_HANDSHAKE) => {
            // TLS 1.3 NewSessionTicket (post-handshake) — ignore and keep
            // draining application data.
            ControlDrain::Resume
        }
        _ => {
            // ChangeCipherSpec / Unknown / unexpected ApplicationData: resume
            // and let the splice loop re-evaluate. ApplicationData via recvmsg
            // is unreachable per the ktls crate, but resume is the safe move.
            ControlDrain::Resume
        }
    }
}

/// Recv direction (`kTLS RX -> downstream`): zero-copy `splice(2)` relay.
///
/// The kTLS RX socket is spliced into a pipe, and the pipe into the downstream
/// TCP socket — neither direction crosses into user space for bulk data. The
/// only user-space touch is [`drain_ktls_control_record`] on the rare
/// `splice`→`EIO` (a control record the kernel refuses to splice because
/// `splice` cannot surface the `TLS_GET_RECORD_TYPE` cmsg).
///
/// Readiness is driven by two `AsyncFd`s — the kTLS RX socket (readable) and
/// the downstream socket (writable) — each backed by a separately `dup`'d fd
/// (registering an already-mio-registered fd with `AsyncFd` fails with
/// `EEXIST`, the same reason the send direction dups). The relay pipe is
/// unregistered: it is a bounded internal buffer tracked by `pipe_fill`, and
/// the produce/consume `try_io` calls only run when there is room / data, so
/// `EAGAIN` on a splice always means "the registered end is not ready"
/// (correctly clearing that end's readiness), never a spurious pipe-full that
/// would clear the kTLS readiness and stall the relay.
async fn ktls_recv_splice(
    ktls: ktls::KtlsStream<TcpStream>,
    mut tcp: TcpStream,
    mut ktls_to_tcp: PendingCounter,
) {
    // 1. Recover the raw kTLS RX socket + any already-decrypted bytes the ktls
    //    crate drained from rustls before installing kTLS (the "corked tail").
    let (drained, ktls_tcp) = ktls.into_raw();

    // 2. Flush the corked tail straight to downstream. This is a one-time,
    //    tiny user-space write (typically empty for a server-side recv); the
    //    bulk path below is zero-copy splice.
    if let Some(bytes) = drained {
        if !bytes.is_empty() {
            use tokio::io::AsyncWriteExt;
            if let Err(error) = tcp.write_all(&bytes).await {
                tracing::debug!(?error, "kTLS recv (splice): flush corked tail failed");
                return;
            } else {
                // The corked tail is a user-space write (not splice), so it
                // bypasses the recv-direction splice count below — attribute
                // it here so these bytes are counted in `rx_bytes_total`.
                ktls_to_tcp.add(bytes.len() as u64);
            }
        }
    }

    // 3. dup both fds into fresh OwnedFds for AsyncFd (separate mio
    //    registrations — the originals stay alive in this scope and close on
    //    return; the dups keep the socket open until the relay finishes).
    let ktls_owned = match nix::unistd::dup(ktls_tcp.as_fd()) {
        Ok(fd) => fd,
        Err(error) => {
            tracing::error!(?error, "kTLS recv (splice): dup kTLS fd failed");
            return;
        }
    };
    let down_owned = match nix::unistd::dup(tcp.as_fd()) {
        Ok(fd) => fd,
        Err(error) => {
            tracing::error!(?error, "kTLS recv (splice): dup downstream fd failed");
            return;
        }
    };
    let ktls_afd = match AsyncFd::new(ktls_owned) {
        Ok(a) => a,
        Err(error) => {
            tracing::error!(?error, "kTLS recv (splice): AsyncFd::new kTLS failed");
            return;
        }
    };
    let down_afd = match AsyncFd::new(down_owned) {
        Ok(a) => a,
        Err(error) => {
            tracing::error!(?error, "kTLS recv (splice): AsyncFd::new downstream failed");
            return;
        }
    };

    // 4. Relay pipe (non-blocking). splice is socket->pipe then pipe->socket.
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe_fds is a valid 2-element array; O_NONBLOCK makes both ends
    // non-blocking (shared status flag on the open file description).
    if unsafe { nix::libc::pipe2(pipe_fds.as_mut_ptr(), nix::libc::O_NONBLOCK) } != 0 {
        let error = io::Error::last_os_error();
        tracing::error!(?error, "kTLS recv (splice): pipe2 failed");
        return;
    }
    // SAFETY: pipe2 just filled these; take ownership so they close on drop.
    let pipe_rx = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
    let pipe_tx = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
    let pipe_rx_fd = pipe_rx.as_raw_fd();
    let pipe_tx_fd = pipe_tx.as_raw_fd();
    let ktls_fd = ktls_afd.get_ref().as_raw_fd();
    let down_fd = down_afd.get_ref().as_raw_fd();
    // Pipe capacity bounds `pipe_fill`; splice self-limits to the real free
    // space, so an over-estimate is harmless.
    let pipe_cap_raw = unsafe { nix::libc::fcntl(pipe_rx_fd, nix::libc::F_GETPIPE_SZ) };
    let pipe_cap = if pipe_cap_raw > 0 {
        pipe_cap_raw as usize
    } else {
        64 * 1024
    };

    let mut pipe_fill: usize = 0;
    std::future::poll_fn(|cx| -> Poll<()> {
        loop {
            let mut progress = false;

            // Consume: pipe -> downstream (only when the pipe has data).
            if pipe_fill > 0 {
                if let Poll::Ready(Ok(mut guard)) = down_afd.poll_write_ready(cx) {
                    match guard.try_io(|_| do_splice(pipe_rx_fd, down_fd, pipe_fill)) {
                        Ok(Ok(0)) => return Poll::Ready(()), // downstream closed
                        Ok(Ok(n)) => {
                            // Attribute the bytes actually delivered to the
                            // downstream to `rx_bytes_total`. Only this
                            // pipe_rx->down consume splice is counted — the
                            // ktls->pipe produce splice below is an
                            // intermediate move into the pipe buffer whose
                            // bytes are later delivered (and counted) here, so
                            // counting it too would double-count.
                            if n > 0 {
                                ktls_to_tcp.add(n as u64);
                            }
                            pipe_fill -= n;
                            progress = true;
                        }
                        Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Ok(Err(e)) => {
                            tracing::debug!(?e, "kTLS recv (splice): pipe->downstream error");
                            return Poll::Ready(());
                        }
                        Err(_wouldblock_cleared) => {}
                    }
                }
            }

            // Produce: kTLS RX -> pipe (only when the pipe has room).
            if pipe_fill < pipe_cap {
                if let Poll::Ready(Ok(mut guard)) = ktls_afd.poll_read_ready(cx) {
                    match guard.try_io(|_| do_splice(ktls_fd, pipe_tx_fd, pipe_cap - pipe_fill)) {
                        Ok(Ok(0)) => return Poll::Ready(()), // kTLS RX EOF
                        Ok(Ok(n)) => {
                            pipe_fill += n;
                            progress = true;
                        }
                        Ok(Err(e))
                            if e.raw_os_error() == Some(nix::libc::EIO)
                                || e.raw_os_error() == Some(nix::libc::EINVAL) =>
                        {
                            // A non-application TLS control record is next on
                            // the kTLS RX socket, and the kernel refuses to
                            // splice it — splice moves bytes only and cannot
                            // surface the `TLS_GET_RECORD_TYPE` cmsg that
                            // identifies the record. Draining the one record
                            // via `recvmsg`+cmsg above lets splice deliver the
                            // application data that follows. Some kernels
                            // report this as `EINVAL`, others as `EIO`; both
                            // are handled here.
                            drop(guard);
                            match drain_ktls_control_record(ktls_fd) {
                                ControlDrain::Close => return Poll::Ready(()),
                                ControlDrain::Resume => progress = true,
                                ControlDrain::Failed(e) => {
                                    tracing::debug!(
                                        ?e,
                                        "kTLS recv (splice): control-record drain error"
                                    );
                                    return Poll::Ready(());
                                }
                            }
                        }
                        Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Ok(Err(e)) => {
                            tracing::debug!(?e, "kTLS RX -> pipe splice error");
                            return Poll::Ready(());
                        }
                        Err(_wouldblock_cleared) => {}
                    }
                }
            }

            if !progress {
                return Poll::Pending;
            }
        }
    })
    .await;
    tracing::debug!("kTLS recv (splice) direction finished");
}

/// Bidirectional zero-copy forward for an installed-kTLS upstream.
///
/// Send (`downstream -> ktls`): `splice(2)` into the kTLS TX path — the kernel
/// encrypts the pipe pages, off the per-connection rustls task. Recv
/// (`ktls -> downstream`): `splice(2)` relay through a pipe (see
/// [`ktls_recv_splice`]). The two loops run concurrently (`tokio::join!`) over
/// separately `dup`'d `TcpStream` values — see [`dup_to_tokio_tcp`] for why
/// neither direction can share the other's stream. Errors in either direction
/// are logged at debug and treated as that direction finishing, so a half-close
/// on one side does not abort the other's in-flight transfer (mirroring
/// [`forward_stream`](crate::tunnel::utils::forward::normal::forward_stream)).
pub async fn forward_ktls_stream_bi(
    ktls: ktls::KtlsStream<TcpStream>,
    tcp: TcpStream,
    // Bytes the HTTP inspector over-read past the request headers — they live
    // in user space, so splice cannot see them. Flush them to the kTLS send
    // writer BEFORE the splice loop. `None` on the netfilter path (no
    // inspection, hence no over-read).
    tcp_prelude: Option<bytes::Bytes>,
    // Clones of the tx/rx byte counters. The splice data plane bypasses
    // `new_wrapped_stream` (which would need to interpose on the spliced fds),
    // so the loops add per-syscall byte counts themselves to keep kTLS traffic
    // visible in `tx_bytes_total`/`rx_bytes_total`.
    mut tcp_to_ktls: PendingCounter,
    ktls_to_tcp: PendingCounter,
) {
    // Borrow each socket's fd just long enough to dup it; the returned
    // `OwnedFd` owns nothing from the borrow, so the originals can then move
    // into their respective copy loops below.
    let mut ktls_send = match dup_to_tokio_tcp(ktls.get_ref()) {
        Ok(s) => s,
        Err(error) => {
            tracing::error!(?error, "kTLS forward: dup kTLS fd failed");
            return;
        }
    };
    let downstream_send = match dup_to_tokio_tcp(&tcp) {
        Ok(s) => s,
        Err(error) => {
            tracing::error!(?error, "kTLS forward: dup downstream fd failed");
            return;
        }
    };

    // Flush any user-space prelude into the kTLS send direction before splicing.
    // splice(2) only moves kernel-buffer bytes and cannot see hyper's user-space
    // over-read; a plain write(2) on the kTLS fd encrypts via the kernel TX path.
    // None on the netfilter path (no prelude).
    if let Some(prelude) = tcp_prelude {
        use tokio::io::AsyncWriteExt;
        if let Err(error) = ktls_send.write_all(&prelude).await {
            tracing::warn!(
                ?error,
                "kTLS forward: prelude flush failed; continuing with splice"
            );
        } else {
            // The prelude is a user-space write (not splice), so it bypasses
            // the send-direction splice count below — attribute it here so the
            // ClientHello bytes are counted in `tx_bytes_total`.
            tcp_to_ktls.add(prelude.len() as u64);
        }
    }

    // Send: downstream -> kTLS (zero-copy splice into the kTLS TX path). The
    // writer is wrapped in [`KtlsSendStream`] so `tokio_splice2::copy`'s
    // built-in EOF shutdown emits a TLS `close_notify` before the TCP FIN
    // (a bare `TcpStream` shutdown would only send the FIN, leaving the peer
    // with an abrupt close_notify-less teardown).
    let send = async move {
        let mut r = downstream_send;
        let mut w = KtlsSendStream::new(ktls_send);
        match tokio_splice2::copy(&mut r, &mut w).await {
            Ok(result) => {
                // `tokio_splice2::copy` returns a `TrafficResult` whose `tx`
                // is the bytes moved a->b (downstream -> kTLS TX path = the
                // send-direction transfer). Attribute those to
                // `tx_bytes_total`; `rx` (b->a) is zero for a one-way copy.
                if result.tx > 0 {
                    tcp_to_ktls.add(result.tx as u64);
                }
                tracing::debug!("kTLS send (splice) direction finished");
            }
            Err(error) => {
                tracing::debug!(?error, "kTLS send (splice) direction finished with error")
            }
        }
    };

    // Recv: kTLS -> downstream (zero-copy splice relay); see [`ktls_recv_splice`]
    // for the control-record drain that splice cannot surface on its own.
    let recv = async move {
        ktls_recv_splice(ktls, tcp, ktls_to_tcp).await;
    };

    // Both directions complete independently; the join returns once each has
    // finished (success or error), so a half-close on one side lets the other
    // drain its in-flight data before tearing down.
    tokio::join!(send, recv);
}
