use std::net::SocketAddr;
use std::sync::Arc;

use crate::{
    error::TngError,
    status::{StatusProvider, StatusQueryResult},
    tunnel::{
        endpoint::TngEndpoint,
        ingress::protocol::{
            rats_tls::security::RatsTlsSecurityLayer, ProtocolStreamForwarder,
            ProtocolStreamForwarderOutput,
        },
        ra_context::RaContext,
        utils,
    },
    AttestationState, CommonStreamTrait, ContextualStream, TokioRuntime,
};

use anyhow::{Context as _, Result};
use async_trait::async_trait;

mod security;
mod transport;
mod wrapping;

pub struct RatsTlsStreamForwarder {
    security_layer: RatsTlsSecurityLayer,
}

impl RatsTlsStreamForwarder {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        multiplex: bool,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                transport_so_mark,
                ra_context,
                runtime,
                multiplex,
            )
            .await?,
        })
    }

    pub async fn connect(
        &self,
        endpoint: TngEndpoint,
    ) -> Result<(
        Box<dyn CommonStreamTrait + Sync>,
        /* local_addr */ Option<SocketAddr>,
        AttestationState,
        /* session_id */ u64,
    )> {
        let (stream, local_addr, attestation_state, session_id) = self
            .security_layer
            .allocate_secured_stream(endpoint)
            .await?;
        Ok((
            Box::new(ContextualStream::new(stream, "ingress-rats-tls")),
            local_addr,
            attestation_state,
            session_id,
        ))
    }
}

#[async_trait]
impl ProtocolStreamForwarder for RatsTlsStreamForwarder {
    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        mut downstream: Box<dyn CommonStreamTrait + 'static>,
    ) -> Result<ProtocolStreamForwarderOutput> {
        if !self.security_layer.is_multiplex() {
            // Non-multiplex: send the first downstream chunk as 0-RTT early
            // data, complete the handshake, then classify attestation from the
            // negotiated handshake kind. The handshake completes during
            // prime's first write/flush, so handshake_kind() is only valid
            // after prime; reading it before would report the unfinished
            // EarlyData state. On a resumed handshake rustls skips cert
            // verification, so a fresh RA result is neither produced nor
            // needed; trust the PSK binding (Resumed) instead of erroring.
            let (mut tls_stream, verifier_opt, local_addr) =
                self.security_layer.connect_0rtt(endpoint).await?;
            prime_0rtt(&mut tls_stream, &mut downstream).await?;
            let handshake_kind = tls_stream.get_mut().1.handshake_kind();
            let attestation_state = match (verifier_opt, handshake_kind) {
                (Some(_), Some(rustls::HandshakeKind::Resumed)) => AttestationState::Resumed,
                (Some(v), _) => {
                    // Full handshake: fetch the peer cert the verifier could
                    // not inspect during the (no-op) handshake callback and
                    // verify it now. peer_certificates() returns the end-entity
                    // cert rustls validated; on a full RA handshake it is present.
                    let peer_cert = crate::tunnel::utils::rustls::ra::common::take_end_entity_cert(
                        tls_stream.get_mut().1.peer_certificates(),
                    )?;
                    AttestationState::Fresh(v.verify_cert(peer_cert).await?)
                }
                (None, _) => AttestationState::Unattested,
            };
            let upstream: Box<dyn CommonStreamTrait + Sync> =
                Box::new(ContextualStream::new(tls_stream, "ingress-rats-tls-0rtt"));
            Ok((
                Box::pin(async move {
                    let _: () = utils::forward::forward_stream(upstream, downstream).await;
                    Ok(())
                }),
                attestation_state,
                local_addr,
            ))
        } else {
            // Multiplex: single long-lived TLS connection; 0-RTT does not apply.
            let (upstream, local_addr, attestation_state, _session_id) =
                self.connect(endpoint.clone()).await?;
            Ok((
                Box::pin(async move {
                    let _: () = utils::forward::forward_stream(upstream, downstream).await;
                    Ok(())
                }),
                attestation_state,
                local_addr,
            ))
        }
    }
}

/// Max bytes attempted as 0-RTT early data from the first downstream read.
/// Capped below the server's MAX_EARLY_DATA_SIZE so the whole first chunk
/// qualifies as 0-RTT; the forward loop handles the rest as 1-RTT.
const EARLY_DATA_PRIME_BUF: usize = 64 * 1024;

/// Race the first downstream read against an upstream flush.
///
/// In tokio-rustls's EarlyData state (a resumption ticket was available),
/// `connect_0rtt` returned before the handshake completed; the first write
/// drives the 0-RTT send and completes the handshake (rejected 0-RTT is
/// auto-replayed as 1-RTT by tokio-rustls). If the downstream has no data
/// ready, the flush branch completes the handshake as plain 1-RTT so the
/// connection cannot hang waiting on a write.
///
/// Generic over the upstream so it can drive the raw `TlsStream` (the caller
/// must read `handshake_kind()` off it after this returns, which requires the
/// unboxed stream).
async fn prime_0rtt<U: CommonStreamTrait>(
    upstream: &mut U,
    downstream: &mut Box<dyn CommonStreamTrait>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut buf = vec![0u8; EARLY_DATA_PRIME_BUF];
    tokio::select! {
        biased; // prefer sending downstream data as 0-RTT when it is ready
        r = downstream.read(&mut buf) => {
            match r.context("read downstream for 0-RTT prime")? {
                0 => upstream.flush().await.context("flush upstream (downstream EOF)")?,
                n => {
                    upstream
                        .write_all(&buf[..n])
                        .await
                        .context("write upstream 0-RTT prime")?;
                    upstream.flush().await.context("flush upstream 0-RTT prime")?;
                }
            }
        }
        _ = upstream.flush() => {
            // No downstream data ready in time: complete the handshake as 1-RTT.
        }
    }
    Ok(())
}

#[async_trait]
impl StatusProvider for RatsTlsStreamForwarder {
    async fn query_status(&self, _path: &[&str]) -> Result<StatusQueryResult, TngError> {
        Err(TngError::StatusPathNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::task::{Context, Poll};
    use std::{io, pin::Pin};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// Upstream mock: records bytes written and counts `poll_flush` calls.
    /// `poll_flush` returns `Ready(Ok(()))` immediately so the flush branch of
    /// `prime_0rtt` can complete the handshake without a real TLS layer.
    struct MockUpstream {
        written: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<AtomicUsize>,
    }

    impl MockUpstream {
        fn new() -> Self {
            Self {
                written: Arc::new(Mutex::new(Vec::new())),
                flushes: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl AsyncRead for MockUpstream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // prime_0rtt never reads from upstream; yield empty reads if asked.
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockUpstream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Downstream mock that never yields: `poll_read` returns `Pending` and
    /// never wakes, simulating a client that connected but sent nothing.
    struct PendingDownstream;

    impl AsyncRead for PendingDownstream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingDownstream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Downstream mock that yields a fixed chunk then EOF (0-byte read).
    struct DataDownstream {
        data: Vec<u8>,
        pos: usize,
    }

    impl DataDownstream {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl AsyncRead for DataDownstream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.pos >= this.data.len() {
                return Poll::Ready(Ok(())); // EOF
            }
            let n = std::cmp::min(buf.remaining(), this.data.len() - this.pos);
            buf.put_slice(&this.data[this.pos..this.pos + n]);
            this.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DataDownstream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn prime_0rtt_no_downstream_data_flush_wins_no_hang() {
        // Downstream stays pending; the upstream flush branch must complete the
        // handshake. If it hung, this test would never return.
        let upstream_mock = MockUpstream::new();
        let flushes = upstream_mock.flushes.clone();
        let written = upstream_mock.written.clone();
        let mut upstream: Box<dyn CommonStreamTrait + Sync> = Box::new(upstream_mock);
        let mut downstream: Box<dyn CommonStreamTrait> = Box::new(PendingDownstream);

        prime_0rtt(&mut upstream, &mut downstream)
            .await
            .expect("prime_0rtt should complete via the flush branch");

        assert_eq!(
            flushes.load(Ordering::SeqCst),
            1,
            "upstream flush must be invoked to complete the handshake"
        );
        assert!(
            written.lock().unwrap().is_empty(),
            "no downstream data should have been forwarded"
        );
    }

    #[tokio::test]
    async fn prime_0rtt_downstream_data_ready_writes_and_flushes() {
        let upstream_mock = MockUpstream::new();
        let flushes = upstream_mock.flushes.clone();
        let written = upstream_mock.written.clone();
        let mut upstream: Box<dyn CommonStreamTrait + Sync> = Box::new(upstream_mock);
        let mut downstream: Box<dyn CommonStreamTrait> =
            Box::new(DataDownstream::new(b"HELLO".to_vec()));

        prime_0rtt(&mut upstream, &mut downstream)
            .await
            .expect("prime_0rtt should forward the ready chunk");

        assert_eq!(written.lock().unwrap().as_slice(), b"HELLO");
        assert_eq!(
            flushes.load(Ordering::SeqCst),
            1,
            "upstream flush must follow the 0-RTT write"
        );
    }

    #[tokio::test]
    async fn prime_0rtt_downstream_eof_flushes() {
        let upstream_mock = MockUpstream::new();
        let flushes = upstream_mock.flushes.clone();
        let mut upstream: Box<dyn CommonStreamTrait + Sync> = Box::new(upstream_mock);
        let mut downstream: Box<dyn CommonStreamTrait> = Box::new(DataDownstream::new(Vec::new()));

        prime_0rtt(&mut upstream, &mut downstream)
            .await
            .expect("prime_0rtt should treat downstream EOF as a flush trigger");

        assert_eq!(
            flushes.load(Ordering::SeqCst),
            1,
            "upstream flush must be invoked on downstream EOF"
        );
    }
}
