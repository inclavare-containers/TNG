//! TPROXY receive-side helpers — create the interception socket and recover the
//! original destination (`IP_ORIGDSTADDR`) via `recvmsg`.
//!
//! Linux only. Both `netfilter_udp` ingress and egress receive through
//! [`TproxyRecvSocket`]: ingress via the async [`recv`](TproxyRecvSocket::recv)
//! (it drives its own recv loop); the egress via the synchronous
//! [`poll_recv`](TproxyRecvSocket::poll_recv), because quinn's
//! `AsyncUdpSocket::poll_recv` is a sync `Poll` fn (tokio's `AsyncFd` exposes
//! `poll_read_ready` for exactly this case). `create_tproxy_udp_socket` /
//! `recvmsg_once` below are the lower-level building blocks `TproxyRecvSocket`
//! is built on.
//!
//! Uses raw libc calls since nix 0.23's recvmsg API doesn't expose `msghdr`
//! for manual construction.

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use libc::{cmsghdr, iovec, msghdr, sockaddr_storage, socklen_t};
use tokio::io::unix::AsyncFd;

/// The Linux socket option for receiving the original destination address.
pub const IP_RECVORIGDSTADDR: libc::c_int = 20;

/// A single received TPROXY datagram: byte count, the client source address,
/// and the original destination the client dialed (from `IP_ORIGDSTADDR`).
///
/// Named (rather than a positional tuple) so call sites cannot swap the two
/// addresses by mistake.
pub(crate) struct RecvPacket {
    /// Number of payload bytes read.
    pub len: usize,
    /// The client that sent the datagram.
    pub peer: SocketAddr,
    /// The original destination the client dialed (`IP_ORIGDSTADDR`).
    pub orig_dst: SocketAddr,
}

/// Perform a single `recvmsg()` call on a TPROXY-configured UDP socket.
pub(crate) fn recvmsg_once(
    fd: RawFd,
    buf: &mut [u8],
) -> std::result::Result<RecvPacket, std::io::Error> {
    let mut storage: MaybeUninit<sockaddr_storage> = MaybeUninit::uninit();
    let mut iov = [iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    }];

    // Control message buffer
    let mut cmsg_buf = [0u8; 256];

    let mut msg: msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = mem::size_of::<sockaddr_storage>() as socklen_t;
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iov.len() as _;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    let bytes = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if bytes < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let bytes = bytes as usize;

    // Parse client source address
    let storage = unsafe { storage.assume_init() };
    let client_src = sockaddr_to_addr(&storage, msg.msg_namelen)?;

    // Parse control messages for IP_ORIGDSTADDR
    let mut original_dst = None;
    let mut cmsg_ptr = msg.msg_control as *mut cmsghdr;
    while !cmsg_ptr.is_null() {
        let cmsg = unsafe { &*cmsg_ptr };
        if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == IP_RECVORIGDSTADDR {
            // On Linux, IP_ORIGDSTADDR uses the same constant as IP_RECVORIGDSTADDR
            // The data is a sockaddr_in
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg_ptr) };
            let orig = unsafe { &*(data_ptr as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(orig.sin_addr.s_addr));
            let port = u16::from_be(orig.sin_port);
            original_dst = Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
        }
        cmsg_ptr = unsafe { libc::CMSG_NXTHDR(&msg, cmsg_ptr) };
    }

    let original_dst = original_dst.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "recvmsg did not return IP_ORIGDSTADDR — packet may not have come through TPROXY",
        )
    })?;

    Ok(RecvPacket {
        len: bytes,
        peer: client_src,
        orig_dst: original_dst,
    })
}

fn sockaddr_to_addr(
    storage: &sockaddr_storage,
    _len: libc::socklen_t,
) -> std::result::Result<SocketAddr, std::io::Error> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr: &libc::sockaddr_in =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let addr: &libc::sockaddr_in6 =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown socket address family",
        )),
    }
}

/// Create and configure a UDP socket for TPROXY interception.
pub(crate) fn create_tproxy_udp_socket(bind_addr: std::net::SocketAddr) -> Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_ip_transparent(true)?;

    let fd = socket.as_raw_fd();
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_RECVORIGDSTADDR,
            &val as *const _ as *const libc::c_void,
            mem::size_of_val(&val) as socklen_t,
        )
    };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setsockopt IP_RECVORIGDSTADDR failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;

    Ok(socket)
}

/// A TPROXY interception socket wrapped in an `AsyncFd`, providing both an
/// async [`recv`](Self::recv) (for ingress, which drives its own recv loop)
/// and a synchronous [`poll_recv`](Self::poll_recv) (for the egress, whose recv
/// is driven by quinn's `AsyncUdpSocket::poll_recv` — a sync `Poll` fn). Both
/// drain via `recvmsg` and `clear_ready()` on `WouldBlock`.
///
/// The `AsyncFd` + `clear_ready()` is required because tokio's own
/// `UdpSocket::readable()` readiness flag is only cleared by tokio's own
/// `recv`/`try_recv` (not raw `recvmsg`) — without `clear_ready()` the flag is
/// never cleared and the loop busy-spins forever.
pub(crate) struct TproxyRecvSocket {
    inner: AsyncFd<socket2::Socket>,
    local_addr: SocketAddr,
}

impl TproxyRecvSocket {
    /// Create a TPROXY socket bound to `bind_addr` (IP_TRANSPARENT +
    /// IP_RECVORIGDSTADDR, nonblocking) and register it with tokio's I/O
    /// driver via `AsyncFd`.
    pub(crate) fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = create_tproxy_udp_socket(bind_addr)?;
        let local_addr = socket
            .local_addr()
            .context("Failed to get TPROXY listener local addr")?
            .as_socket()
            .context("TPROXY listener addr is not an IP socket")?;
        let inner = AsyncFd::new(socket)?;
        Ok(Self { inner, local_addr })
    }

    /// The local address the listener is bound to.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Receive one datagram, blocking (async) until a packet arrives.
    ///
    /// Spurious readiness (the socket is empty) is cleared with
    /// `clear_ready()` so the next wait actually blocks instead of
    /// busy-looping.
    pub(crate) async fn recv(&self, buf: &mut [u8]) -> Result<RecvPacket> {
        loop {
            let mut readable_guard = self
                .inner
                .readable()
                .await
                .context("TPROXY socket readable failed")?;
            match recvmsg_once(self.inner.get_ref().as_raw_fd(), buf) {
                Ok(packet) => return Ok(packet),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // Spurious readiness — the socket is empty. Clear it so the
                    // next `readable()` actually blocks instead of busy-looping.
                    readable_guard.clear_ready();
                    continue;
                }
                Err(error) => {
                    readable_guard.clear_ready();
                    return Err(anyhow::Error::from(error).context("recvmsg_once failed"));
                }
            }
        }
    }

    /// Poll for one datagram (synchronous), for callers that drive their own
    /// poll loop — the egress, whose recv is driven by quinn's
    /// `AsyncUdpSocket::poll_recv`. Returns `Pending` until a packet is ready;
    /// spurious readiness is cleared with `clear_ready()` so the next poll does
    /// not busy-loop.
    pub(crate) fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<RecvPacket>> {
        use std::task::ready;
        loop {
            let mut guard = match ready!(self.inner.poll_read_ready(cx)) {
                Ok(g) => g,
                Err(error) => return Poll::Ready(Err(error)),
            };
            match recvmsg_once(self.inner.get_ref().as_raw_fd(), buf) {
                Ok(packet) => return Poll::Ready(Ok(packet)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(error) => {
                    guard.clear_ready();
                    return Poll::Ready(Err(error));
                }
            }
        }
    }

    /// Poll for write readiness — used by the egress quinn `UdpPoller`'s
    /// `poll_writable` as a proxy for "ok to attempt `try_send`". (The actual
    /// reply send goes through the separate `SOCK_RAW` reply socket, which is
    /// virtually always writable; this checks the TPROXY socket's
    /// write-readiness as a stand-in so quinn does not busy-loop if
    /// `try_send` would block. Preserves the pre-unification behavior.)
    pub(crate) fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.poll_write_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(_guard)) => Poll::Ready(Ok(())),
        }
    }
}
