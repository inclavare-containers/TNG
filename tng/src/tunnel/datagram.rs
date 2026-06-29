use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;

use anyhow::Result;

/// Core trait for datagram I/O, analogous to `CommonStreamTrait` for streams.
///
/// Key differences from stream-based traits:
/// - Uses `Bytes` for payloads (atomic, no splitting)
/// - Returns `(Bytes, SocketAddr)` from `recv_from` (datagrams carry source info)
/// - No `AsyncRead`/`AsyncWrite` — datagrams are discrete units
#[allow(dead_code)]
pub trait CommonDatagramTrait: Unpin + Send + 'static {
    /// Send a datagram to the specified address.
    fn send_to(
        &mut self,
        buf: Bytes,
        target: SocketAddr,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Receive a datagram, returning (payload, source_address).
    fn recv_from(&mut self) -> impl Future<Output = Result<(Bytes, SocketAddr)>> + Send;
}
