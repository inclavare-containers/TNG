//! Spoofed-source UDP send — a `SOCK_RAW` + `IP_HDRINCL` socket that hand-builds
//! the IPv4 + UDP header so a datagram can be sent from an arbitrary source
//! address (the `orig_dst:port` the client dialed) without `bind`.
//!
//! Used by both `netfilter_udp` reply paths (ingress + egress). The sender is
//! typically cached by the caller (per listener) rather than created per
//! packet.

use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd};

use libc::socklen_t;

/// A `SOCK_RAW` + `IP_HDRINCL` socket that sends UDP datagrams with a fully
/// spoofed IPv4 source address (`src_ip:src_port`) without `bind`.
///
/// The netfilter_udp ingress and egress reply paths must send from
/// `orig_dst:port` (the address the QUIC peer dialed) so the connected peer
/// accepts the reply. Doing this with a normal DGRAM socket requires
/// `bind(orig_dst:port)`, which collides (`EADDRINUSE`) with a co-located real
/// backend unless that backend sets `SO_REUSEADDR`. A raw socket hand-builds
/// the IPv4 + UDP header instead — no `bind`, no `SO_REUSEADDR` dependency, and
/// co-located / single-node deployments work. Requires `CAP_NET_RAW` (TNG
/// already runs privileged for iptables/TPROXY).
pub struct RawUdpSender {
    sock: socket2::Socket,
}

impl RawUdpSender {
    /// Create a raw socket. `so_mark`, if set, marks the outgoing skb so it
    /// bypasses this node's own mangle `OUTPUT` capture (the
    /// `--mark so_mark -j RETURN` escape) — used by the ingress reply path.
    /// The egress reply passes `None`: its destination is the ingress peer
    /// (never a `capture_dst`), so it is never re-captured, and marking it with
    /// the TPROXY fwmark would risk routing it back into the local TPROXY
    /// table.
    pub fn new(so_mark: Option<u32>) -> std::io::Result<Self> {
        // IPPROTO_RAW (255) implies IP_HDRINCL (we supply the IP header); set
        // IP_HDRINCL explicitly too for clarity. SOCK_RAW needs CAP_NET_RAW.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sock = unsafe { socket2::Socket::from_raw_fd(fd) };

        let val: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &val as *const _ as *const libc::c_void,
                mem::size_of_val(&val) as socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if let Some(mark) = so_mark {
            sock.set_mark(mark)?;
        }
        sock.set_nonblocking(true)?;
        Ok(Self { sock })
    }

    /// Send `payload` as a UDP datagram from `src` to `dst`, both IPv4. The
    /// IPv4 header checksum is filled by the kernel under `IP_HDRINCL`; the UDP
    /// checksum is computed here so the packet is indistinguishable from a
    /// normal UDP datagram.
    pub fn send(
        &self,
        payload: &[u8],
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        let src_ip = match src.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "RawUdpSender does not support IPv6 source",
                ));
            }
        };
        let dst_ip = match dst.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "RawUdpSender does not support IPv6 destination",
                ));
            }
        };

        const IP_HDR_LEN: usize = 20;
        const UDP_HDR_LEN: usize = 8;
        let total_len = IP_HDR_LEN + UDP_HDR_LEN + payload.len();

        let mut packet = vec![0u8; total_len];

        // --- IPv4 header (20 bytes, network byte order) ---
        packet[0] = 0x45; // version 4, IHL 5 (20-byte header)
        packet[1] = 0; // DSCP/ECN (tos)
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes()); // total length
        packet[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
        packet[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + fragment offset (no DF)
        packet[8] = 64; // TTL
        packet[9] = libc::IPPROTO_UDP as u8; // protocol
                                             // Header checksum: 0 here — the kernel fills it under IP_HDRINCL.
        packet[10..12].copy_from_slice(&0u16.to_be_bytes());
        packet[12..16].copy_from_slice(&src_ip.octets()); // source IP
        packet[16..20].copy_from_slice(&dst_ip.octets()); // destination IP

        // --- UDP header (8 bytes) ---
        packet[IP_HDR_LEN..IP_HDR_LEN + 2].copy_from_slice(&src.port().to_be_bytes());
        packet[IP_HDR_LEN + 2..IP_HDR_LEN + 4].copy_from_slice(&dst.port().to_be_bytes());
        let udp_len = (UDP_HDR_LEN + payload.len()) as u16;
        packet[IP_HDR_LEN + 4..IP_HDR_LEN + 6].copy_from_slice(&udp_len.to_be_bytes());
        // UDP checksum at [IP_HDR_LEN+6 .. IP_HDR_LEN+8] filled below (0 now).

        // --- payload ---
        packet[IP_HDR_LEN + UDP_HDR_LEN..].copy_from_slice(payload);

        // Compute the UDP checksum over the UDP header (check=0) + payload,
        // using the IPv4 pseudo-header.
        let udp_segment = &packet[IP_HDR_LEN..];
        let cksum = udp_checksum(src_ip, dst_ip, udp_segment);
        packet[IP_HDR_LEN + 6..IP_HDR_LEN + 8].copy_from_slice(&cksum.to_be_bytes());

        // send_to: the sockaddr's port is ignored by raw sockets — the IP
        // header carries the destination. They are kept consistent.
        self.sock.send_to(&packet, &socket2::SockAddr::from(dst))?;
        Ok(())
    }
}

/// Compute the IPv4 UDP checksum (RFC 768) over the IPv4 pseudo-header plus the
/// UDP segment (UDP header with its `check` field zeroed + payload). Returns
/// the one's-complement sum; a computed zero is mapped to `0xFFFF` (a UDP
/// checksum of `0` means "not computed").
fn udp_checksum(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let s = src.octets();
    let d = dst.octets();
    // Pseudo-header: source IP, destination IP, zero, protocol (UDP=17),
    // and UDP length (header + payload).
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += libc::IPPROTO_UDP as u32;
    sum += segment.len() as u32;

    let len = segment.len();
    let mut i = 0;
    while i + 1 < len {
        sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
        i += 2;
    }
    if i < len {
        // Odd length: pad the final byte with a zero byte (network order).
        sum += (segment[i] as u32) << 8;
    }
    // Fold the 32-bit sum into 16 bits, adding carries back.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    if cksum == 0 {
        0xFFFF
    } else {
        cksum
    }
}
