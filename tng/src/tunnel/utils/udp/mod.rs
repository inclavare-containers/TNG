//! TPROXY UDP plumbing shared by the `netfilter_udp` ingress and egress.
//!
//! Two disjoint concerns live here:
//!   - [`tproxy_recv`] — creating a TPROXY interception socket and recovering
//!     the original destination (`IP_ORIGDSTADDR`) via `recvmsg`;
//!   - [`tproxy_send`] — sending UDP datagrams with a fully spoofed IPv4
//!     source via a `SOCK_RAW` + `IP_HDRINCL` socket (no `bind`).

pub mod tproxy_recv;
pub mod tproxy_send;
