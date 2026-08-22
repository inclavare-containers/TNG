//! Bridge between quinn and the netfilter `TPROXY` interception socket.
//!
//! [`QuinnTproxyBridgeSocket`] implements quinn's `AsyncUdpSocket` trait over a
//! TPROXY-configured UDP socket so quinn can run its QUIC endpoint directly on
//! the intercepted traffic. It is the egress's **downstream** (tunnel-facing)
//! socket — the one the remote ingress QUIC client connects to — *not* the
//! upstream (backend-facing) socket (backend-bound forwarding lives in
//! `datagram_flow`).
//!
//! The bridge does two TPROXY-specific things quinn's default UDP socket
//! cannot:
//!   - **receive**: `recvmsg` with `IP_ORIGDSTADDR` to recover the original
//!     destination (`orig_dst` = the backend the client dialed) of each
//!     TPROXY-redirected packet;
//!   - **send**: reply toward the ingress (downstream) with the IPv4 source
//!     spoofed to `orig_dst:port` via a `SOCK_RAW` + `IP_HDRINCL` socket, so
//!     the downstream's connected QUIC socket accepts the reply (quinn rejects
//!     replies from any other source port).

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::{AsyncUdpSocket, UdpPoller};

use crate::tunnel::utils::udp::tproxy_recv::TproxyRecvSocket;
use crate::tunnel::utils::udp::tproxy_send::RawUdpSender;

use super::DownstreamOrigDstMap;

/// The egress's downstream (tunnel-facing) QUIC listener, exposed to quinn as
/// a custom `AsyncUdpSocket` and bridged onto a netfilter `TPROXY`
/// interception socket.
///
/// The egress is the *server* end of the encrypted QUIC tunnel; this is its
/// **downstream** (tunnel-facing) socket — the one the remote ingress QUIC
/// client connects to. It is *not* the **upstream** (backend-facing) socket:
/// backend-bound forwarding uses a separate normal UDP socket in
/// `datagram_flow`. Do not conflate the two.
///
/// It is a TPROXY interception socket. iptables marks the ingress's QUIC
/// packets — which are addressed to the *backend* `orig_dst:port` the client
/// dialed — and routes them here via policy routing. We `recvmsg` them to
/// recover that original destination (`IP_ORIGDSTADDR`), which is the real
/// backend (upstream) address to forward to, and we send QUIC replies back
/// toward the ingress (downstream) with the IPv4 source spoofed to
/// `orig_dst:port` so the downstream's connected QUIC socket accepts them
/// (quinn rejects replies from any other source port).
pub(crate) struct QuinnTproxyBridgeSocket {
    /// The downstream (tunnel-facing) TPROXY/QUIC listener socket, wrapped as a
    /// [`TproxyRecvSocket`] (`AsyncFd` + `clear_ready`). quinn drives receive
    /// readiness through it and reads `local_addr` from it. It is **not** used
    /// for the actual send syscall — replies go out through
    /// `downstream_reply_sender`; the only data this socket carries is the
    /// *receive* path, which `TproxyRecvSocket::poll_recv` drives via `recvmsg`
    /// to extract `IP_ORIGDSTADDR` (tokio's `UdpSocket` does not expose
    /// `recvmsg` with ancillary data). (Wrapped in `Arc` so the `UdpPoller` can
    /// share it.)
    downstream_recv: Arc<TproxyRecvSocket>,
    /// The downstream (tunnel-facing) reply socket — a `SOCK_RAW` +
    /// `IP_HDRINCL` socket that sends QUIC replies back toward the ingress
    /// (downstream) with the IPv4 source spoofed to `orig_dst:port` — no
    /// `bind`, so a co-located backend on that port need not set
    /// `SO_REUSEADDR`. Cached once: quinn calls `try_send` per packet.
    downstream_reply_sender: RawUdpSender,
    /// Downstream → `orig_dst` correspondence, populated by `poll_recv` and
    /// read by `try_send` to look up the spoofed source (`orig_dst:port`) for
    /// each downstream reply. See [`DownstreamOrigDstMap`] for why this map
    /// exists (a quinn-interface ↔ business-requirement bridge).
    downstream_orig_dst_map: Arc<DownstreamOrigDstMap>,
}

impl QuinnTproxyBridgeSocket {
    pub(crate) fn new(
        bind_addr: SocketAddr,
        downstream_orig_dst_map: Arc<DownstreamOrigDstMap>,
    ) -> anyhow::Result<Self> {
        // Create the downstream TPROXY interception socket (IP_TRANSPARENT +
        // IP_RECVORIGDSTADDR, bound, nonblocking) and register it with tokio's
        // I/O driver, all inside `TproxyRecvSocket::new`. The `IP_TRANSPARENT`
        // serves the *receive* side (accepting TPROXY-redirected packets
        // addressed to the backend `orig_dst:port`) — it is unrelated to the
        // `SOCK_RAW` `downstream_reply_sender` created below for the *send*
        // (reply) side.
        let downstream_recv = Arc::new(TproxyRecvSocket::new(bind_addr)?);

        // No SO_MARK on the egress reply socket: its destination is the ingress
        // (downstream) (never a `capture_dst`), so it is never re-captured, and marking
        // it with the TPROXY fwmark would risk routing it back into the local
        // TPROXY table.
        let downstream_reply_sender = RawUdpSender::new(None)?;

        Ok(Self {
            downstream_recv,
            downstream_orig_dst_map,
            downstream_reply_sender,
        })
    }
}

impl std::fmt::Debug for QuinnTproxyBridgeSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuinnTproxyBridgeSocket")
            .field("downstream_recv_addr", &self.downstream_recv.local_addr())
            .finish()
    }
}

/// `UdpPoller` implementation for [`QuinnTproxyBridgeSocket`].
struct QuinnTproxyBridgePoller {
    downstream_recv: Arc<TproxyRecvSocket>,
}

impl std::fmt::Debug for QuinnTproxyBridgePoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuinnTproxyBridgePoller").finish()
    }
}

impl UdpPoller for QuinnTproxyBridgePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Proxy write-readiness for the quinn `UdpPoller` — see
        // `TproxyRecvSocket::poll_write_ready`. (The actual reply send goes
        // through the separate `SOCK_RAW` reply socket.)
        self.downstream_recv.poll_write_ready(cx)
    }
}

impl AsyncUdpSocket for QuinnTproxyBridgeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(QuinnTproxyBridgePoller {
            downstream_recv: Arc::clone(&self.downstream_recv),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        // Reply from orig_dst (the address the ingress QUIC client dialed) so
        // quinn accepts the response: it rejects replies from a port other than
        // the one it dialed (verified — a reply from the TPROXY listen port
        // never completes the handshake). We send via the cached `SOCK_RAW` +
        // `IP_HDRINCL` socket (`downstream_reply_sender`), which hand-builds
        // the IPv4+UDP header with the spoofed source. Unlike the previous
        // `IP_TRANSPARENT` + `bind(orig_dst:port)` approach, this never binds,
        // so a co-located backend on `orig_dst:port` need not set
        // `SO_REUSEADDR` — that topology is now supported.
        let orig_dst = self
            .downstream_orig_dst_map
            .get(&transmit.destination)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "no orig_dst mapping for downstream {} — the packet may have arrived before TPROXY interception populated the map, or the connection was established via a different path",
                        transmit.destination
                    ),
                )
            })?;

        self.downstream_reply_sender
            .send(transmit.contents, orig_dst, transmit.destination)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Defensive: this impl fills exactly one slot (`bufs[0]` / `meta[0`]);
        // reject empty / mismatched slices with an error instead of panicking on
        // the index. (quinn normally passes equal-length non-empty slices.)
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "poll_recv called with empty bufs/meta",
            )));
        }

        // Drive the receive via `TproxyRecvSocket::poll_recv` (shared with the
        // ingress), which polls `AsyncFd` read-readiness and `recvmsg`s with
        // `clear_ready()` on `WouldBlock`.
        let buf: &mut [u8] = &mut bufs[0];
        let packet = std::task::ready!(self.downstream_recv.poll_recv(cx, buf))?;
        let downstream_addr = packet.peer;
        let orig_dst = packet.orig_dst;

        // Record the downstream → orig_dst mapping for later use in try_send
        // (reply source spoofing) and accept (backend addr).
        self.downstream_orig_dst_map
            .insert(downstream_addr, orig_dst);

        // Populate RecvMeta with the original destination
        meta[0] = quinn::udp::RecvMeta {
            addr: downstream_addr,
            len: packet.len,
            stride: packet.len,
            ecn: None,
            dst_ip: Some(orig_dst.ip()),
            dst_addr: Some(orig_dst),
        };

        // One datagram read into `bufs[0]` / `meta[0]`; quinn's `poll_recv`
        // contract returns the number of packets filled.
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.downstream_recv.local_addr())
    }
}
