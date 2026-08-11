//! kTLS handshake helper + outcome types for the ingress client and egress
//! server paths.
//!
//! Wraps the official `ktls` crate: CorkStream-wraps a `TcpStream`, runs the
//! tokio_rustls handshake (reusing
//! `LazyOnetimeTlsClientConfig`/`LazyOnetimeTlsServerConfig::handshake_with_stream`,
//! which also runs lazy attestation via `verity_pending_cert`), probes the
//! negotiated cipher against the kernel's kTLS support set (cached
//! `CompatibleCiphers`), and on success calls `ktls::config_ktls_client`/
//! `config_ktls_server` to install the kTLS keys in-kernel. On an infeasible
//! cipher (or a failed probe) it transparently falls back to a boxed rustls
//! `TlsStream`, so the existing `forward_stream` data plane handles it.
//!
//! # Data plane
//!
//! Once kTLS is installed, [`forward_ktls_stream_bi`] forwards both directions
//! with zero-copy `splice(2)`: send splices into the kTLS TX socket (the kernel
//! encrypts the pipe pages), recv relays the kTLS RX socket through a pipe (see
//! [`ktls_recv_splice`]). Non-application TLS records (`NewSessionTicket`,
//! `close_notify`) make splice return an error because it cannot surface the
//! `TLS_GET_RECORD_TYPE` cmsg; the relay drains each via `recvmsg`+cmsg (see
//! [`drain_ktls_control_record`]) and resumes — these are rare, so the bulk
//! path stays zero-copy.
//!
//! The send and recv loops cannot share a `TcpStream` value:
//! - the send direction drives its `TcpStream` through `tokio_splice2` (which
//!   impls `AsyncWriteFd` only for whole `TcpStream` values), while the recv
//!   direction drives its own `dup`'d fds through `AsyncFd` directly — each
//!   direction owns separately `dup`'d fds so neither shares a mio
//!   registration with the other (registering the same fd twice fails with
//!   `EEXIST`).
//! - `dup(2)` yields a fresh fd number referring to the same kTLS socket, so
//!   splice into a `dup`'d fd is encrypted in-kernel exactly as the original
//!   would be, and a `dup`'d kTLS RX fd decrypts in-kernel exactly as the
//!   original would.
//!
//! # Performance
//!
//! kTLS is the enabler for zero-copy, not a crypto speedup: a user-space
//! rustls stream cannot be spliced, but once the TLS record layer moves into
//! the kernel the socket can be spliced end-to-end with no user-space copy.
//! With hardware TLS acceleration, in-kernel and user-space AEAD run at the
//! same rate, so moving the record layer into the kernel buys nothing on its
//! own — the win is the zero-copy data movement. H2 multiplexing is excluded
//! for the same reason: under multiplexing the splice pipe's far end is
//! application demux logic rather than a TCP socket, so splice (and thus
//! zero-copy kTLS) is not possible there, and kTLS is not engaged.
//!
//! The kTLS RX splice path needs kernel ≥ v5.16: on 5.10.y,
//! `tls_sw_splice_read` does not advance the read pointer (re-delivers the
//! first record), fixed in v5.16 by `e062fe99cccd` and never backported. The
//! `best-effort` policy probes the kernel at setup and falls back to rustls on
//! an older kernel (so a 5.10 dev box cannot exercise the splice path — it
//! transparently uses the rustls data plane instead); `required` fails setup.
//! A separately transparent rustls fallback covers an infeasible cipher for
//! `best-effort` (and a hard failure for `required`).
//!
//! The close_notify alert on send-direction teardown (see [`KtlsSendStream`])
//! is a correctness fix independent of throughput — a `splice`-driven send
//! would otherwise emit a bare TCP FIN, tripping the peer's
//! "closed without close_notify" warning.
// The whole module is gated on Linux by `config/mod.rs`
// (`#[cfg(target_os = "linux")] pub mod ktls;`); an inner `#![cfg]` would be a
// duplicated attribute (clippy::duplicated_attributes).

use std::format;
use std::os::fd::{AsRawFd, RawFd};
use std::{
    io,
    task::{Context, Poll},
};

use anyhow::{Context as _, Result};
use tokio::net::TcpStream;

use crate::config::ktls::{EnvCheckedKtls, FallbackDecision, KtlsConnUnavailable, Side};
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::endpoint::EndpointAddr;
use crate::tunnel::stream::PreludedStream;
use crate::tunnel::stream::{CommonStreamTrait, FirstByteReadTimeoutStream};
#[cfg(target_os = "linux")]
use crate::tunnel::utils::rustls::TlsOutcome;

use super::client::LazyOnetimeTlsClientConfig;
use super::server::LazyOnetimeTlsServerConfig;

/// kTLS kernel-capability probe, cached for the process lifetime.
///
/// `CompatibleCiphers::default()` (all `false`) on probe failure → every
/// `is_compatible` returns `false` → all connections transparently fall back
/// to rustls. Probed lazily on the first kTLS connection (no startup wiring),
/// and a probe failure never crashes TNG over this optimization layer.
static COMPATIBLE_CIPHERS: tokio::sync::OnceCell<ktls::CompatibleCiphers> =
    tokio::sync::OnceCell::const_new();

async fn compatible_ciphers() -> &'static ktls::CompatibleCiphers {
    COMPATIBLE_CIPHERS
        .get_or_init(|| async {
            match ktls::CompatibleCiphers::new().await {
                Ok(c) => c,
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "kTLS: CompatibleCiphers probe failed; will use rustls fallback"
                    );
                    ktls::CompatibleCiphers::default()
                }
            }
        })
        .await
}
/// Trait unifying the ingress client config (`LazyOnetimeTlsClientConfig`,
/// which needs the peer `EndpointAddr` as the rustls `ServerName`) and the
/// egress server config (`LazyOnetimeTlsServerConfig`, which has no peer name).
///
/// Each side is represented by a dedicated struct implementing this trait,
/// so callers cannot pass a mismatched `Side`/config pair. The `Side` is
/// reported by [`KtlsHandshakeConfig::side`]; the rustls handshake is run by
/// [`KtlsHandshakeConfig::handshake_with_stream`], which lifts the concrete
/// `client::TlsStream` / `server::TlsStream` into the side-tagged
/// [`KtlsTlsStream`] so the rest of the handshake is side-neutral.
#[async_trait::async_trait]
pub trait KtlsHandshakeConfig {
    fn side(&self) -> Side;

    /// CorkStream-wrap is done by the caller; this runs the rustls handshake
    /// (reusing `LazyOnetimeTls{Client,Server}Config::handshake_with_stream`,
    /// which also runs lazy attestation via `verity_pending_cert`) and lifts the
    /// concrete `client::TlsStream` / `server::TlsStream` into the side-tagged
    /// [`KtlsTlsStream`].
    async fn handshake_with_stream<IO: StreamForKtls>(
        self,
        corked: ktls::CorkStream<IO>,
    ) -> Result<(KtlsTlsStream<IO>, Option<AttestationResult>)>;
}

/// Client-side kTLS handshake config.
///
/// Carries the peer `EndpointAddr` as the rustls `ServerName`.
pub struct KtlsClientHandshakeConfig<'a> {
    config: LazyOnetimeTlsClientConfig,
    server_name: &'a EndpointAddr,
}

impl<'a> KtlsClientHandshakeConfig<'a> {
    pub fn new(config: LazyOnetimeTlsClientConfig, server_name: &'a EndpointAddr) -> Self {
        Self {
            config,
            server_name,
        }
    }
}

#[async_trait::async_trait]
impl<'a> KtlsHandshakeConfig for KtlsClientHandshakeConfig<'a> {
    fn side(&self) -> Side {
        Side::Client
    }

    async fn handshake_with_stream<IO: StreamForKtls>(
        self,
        corked: ktls::CorkStream<IO>,
    ) -> Result<(KtlsTlsStream<IO>, Option<AttestationResult>)> {
        let (tls_stream, attestation_result) = self
            .config
            .handshake_with_stream(self.server_name, corked)
            .await?;
        Ok((KtlsTlsStream::Client(tls_stream), attestation_result))
    }
}

/// Server-side kTLS handshake config.
///
/// Accepts the incoming TLS client connection; no peer name is required.
pub struct KtlsServerHandshakeConfig {
    config: LazyOnetimeTlsServerConfig,
}

impl KtlsServerHandshakeConfig {
    pub fn new(config: LazyOnetimeTlsServerConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl KtlsHandshakeConfig for KtlsServerHandshakeConfig {
    fn side(&self) -> Side {
        Side::Server
    }

    async fn handshake_with_stream<IO: StreamForKtls>(
        self,
        corked: ktls::CorkStream<IO>,
    ) -> Result<(KtlsTlsStream<IO>, Option<AttestationResult>)> {
        let (tls_stream, attestation_result) = self.config.handshake_with_stream(corked).await?;
        Ok((KtlsTlsStream::Server(tls_stream), attestation_result))
    }
}

/// Side-tagged negotiated-but-not-yet-kTLS-installed rustls `TlsStream`.
///
/// `tokio_rustls::client::TlsStream` and `server::TlsStream` are distinct
/// concrete types (they wrap `rustls::ClientConnection` vs `ServerConnection`),
/// so a single side-neutral handshake cannot return one concrete stream type.
/// This enum wraps either and exposes the three operations the handshake needs
/// — read the negotiated cipher, box the stream as the rustls fallback, and
/// install kTLS in-kernel — each as a one-line match dispatch, so the
/// `.get_ref().1` incantation lives in exactly one place instead of being
/// mirrored across the client and server fns.
pub enum KtlsTlsStream<IO: StreamForKtls> {
    Client(tokio_rustls::client::TlsStream<ktls::CorkStream<IO>>),
    Server(tokio_rustls::server::TlsStream<ktls::CorkStream<IO>>),
}

impl<IO: StreamForKtls + 'static> KtlsTlsStream<IO> {
    /// Read the negotiated cipher from the underlying rustls `Connection`.
    fn negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
        match self {
            Self::Client(s) => s.get_ref().1.negotiated_cipher_suite(),
            Self::Server(s) => s.get_ref().1.negotiated_cipher_suite(),
        }
    }

    /// Box the stream as the rustls fallback. Both `client::TlsStream` and
    /// `server::TlsStream<CorkStream<TcpStream>>` blanket-impl
    /// `CommonStreamTrait`, so the existing boxed `forward_stream` data plane
    /// handles it uniformly.
    fn into_rustls_fallback(self) -> Box<dyn CommonStreamTrait + Sync> {
        match self {
            Self::Client(s) => Box::new(s),
            Self::Server(s) => Box::new(s),
        }
    }

    /// Install the kTLS keys in-kernel (`config_ktls_client`/`config_ktls_server`
    /// consume the stream). On failure the stream is gone — see
    /// [`install_failed_bail`].
    async fn config_ktls(self) -> Result<ktls::KtlsStream<TcpStream>> {
        Ok(match self {
            Self::Client(s) => StreamForKtls::config_ktls_client(s).await?,
            Self::Server(s) => StreamForKtls::config_ktls_server(s).await?,
        })
    }
}

#[async_trait::async_trait]
pub trait StreamForKtls:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Sync + Send + Sized
{
    async fn config_ktls_client(
        this: tokio_rustls::client::TlsStream<ktls::CorkStream<Self>>,
    ) -> Result<ktls::KtlsStream<TcpStream>>;

    async fn config_ktls_server(
        this: tokio_rustls::server::TlsStream<ktls::CorkStream<Self>>,
    ) -> Result<ktls::KtlsStream<TcpStream>>;
}

#[async_trait::async_trait]
impl StreamForKtls for TcpStream {
    async fn config_ktls_client(
        this: tokio_rustls::client::TlsStream<ktls::CorkStream<Self>>,
    ) -> Result<ktls::KtlsStream<TcpStream>> {
        // Just call the ktls::config_ktls_* function.
        Ok(ktls::config_ktls_client(this).await?)
    }

    async fn config_ktls_server(
        this: tokio_rustls::server::TlsStream<ktls::CorkStream<Self>>,
    ) -> Result<ktls::KtlsStream<TcpStream>> {
        // Just call the ktls::config_ktls_* function.
        Ok(ktls::config_ktls_server(this).await?)
    }
}

/// Shared body of [`StreamForKtls::config_ktls_client`] /
/// [`StreamForKtls::config_ktls_server`] on `PreludedStream<TcpStream>`:
/// drain the rustls prelude, call the side-specific `ktls::config_ktls_*`, then
/// prepend the drained bytes to the resulting `KtlsStream`. The two side methods
/// differ only in which `ktls::config_ktls_*` function installs the kTLS keys,
/// passed here as `$config_fn`; everything else (prelude drain, raw-stream
/// recovery, drained-bytes prepend) is identical.
macro_rules! preluded_config_ktls_body {
    ($this:ident, $config_fn:path) => {{
        // 1. drain Tcp stream until prelude is empty, save the drained bytes on stack.
        //
        // The prelude is the over-read buffered in the `prelude` field of the
        // `PreludedStream`. After the handshake it usually holds at most a
        // few post-handshake records the peer sent before the HTTP inspector
        // stopped reading (early data, a `NewSessionTicket` echo, etc.); once it
        // is exhausted every further read goes straight to the `TcpStream`. We
        // drive rustls reads until the prelude is fully consumed, collecting the
        // decrypted bytes locally so step 3 can prepend them to the `KtlsStream`
        // — the kTLS RX path cannot surface these user-space bytes itself, so
        // they must be drained through rustls here.
        use tokio::io::AsyncReadExt as _;
        let mut this = $this;
        let mut drained: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            // Stop once the prelude has been fully consumed by rustls.
            let is_prelude_consumed = this.get_ref().0.io.prelude_consumed();
            if is_prelude_consumed {
                break;
            }
            // The prelude still holds bytes, so this read is served from the
            // `prelude` buffer rather than the underlying `TcpStream` — but
            // that is a side effect, not the goal. The purpose of this loop is
            // to reach exactly the state where the prelude has been fully
            // consumed by rustls, so that step 3 can hand kTLS a clean stream
            // with no residual user-space bytes.
            let n = this.read(&mut buf).await?;
            if n == 0 {
                // rustls returned no decrypted bytes while the prelude is not
                // yet fully consumed. Because this read is served from the
                // prelude buffer, a 0-byte return here means we cannot make
                // further progress toward the "prelude exactly consumed"
                // state this loop exists to reach — surface the error instead
                // of silently stopping with a half-drained prelude.
                return Err(anyhow::anyhow!(
                    "kTLS: prelude drain stalled: rustls returned 0 bytes before \
                     the prelude was fully consumed ({} bytes drained so far)",
                    drained.len()
                ));
            }
            drained.extend_from_slice(&buf[..n]);
        }
        if !drained.is_empty() {
            tracing::trace!(drained_len = drained.len(), "kTLS: drained prelude bytes");
        }

        // 2. call the ktls::config_ktls_* function.
        let ktls_stream = $config_fn(this).await?;

        // 3. prepend the drained bytes to the ktls::KtlsStream
        let (drained_part2, io) = ktls_stream.into_raw();
        let PreludedStream { stream, .. } = io; // It is safe to unwrap the PreludedStream here because we have made sure the prelude is drained.
        let drained = if let Some(drained_part2) = drained_part2 {
            [drained, drained_part2].concat()
        } else {
            drained
        };
        Ok(ktls::KtlsStream::new(stream, Some(drained)))
    }};
}

#[async_trait::async_trait]
impl StreamForKtls for PreludedStream<TcpStream> {
    async fn config_ktls_client(
        this: tokio_rustls::client::TlsStream<ktls::CorkStream<Self>>,
    ) -> Result<ktls::KtlsStream<TcpStream>> {
        preluded_config_ktls_body!(this, ktls::config_ktls_client)
    }

    async fn config_ktls_server(
        this: tokio_rustls::server::TlsStream<ktls::CorkStream<Self>>,
    ) -> Result<ktls::KtlsStream<TcpStream>> {
        preluded_config_ktls_body!(this, ktls::config_ktls_server)
    }
}

impl AsRawFd for PreludedStream<TcpStream> {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

// `ktls::config_ktls_server` (and `KtlsStream<IO>::AsyncRead`) carry a
// `IO: AsyncReadReady` bound that the body never actually exercises — see the
// analysis in `preluded_config_ktls_body!`. TNG immediately `.into_raw()`s the
// resulting `KtlsStream`, so this impl exists to satisfy the bound, not to be
// driven on the hot path. It is still correct: while the prelude holds
// unread user-space bytes a read returns immediately, so report readiness
// without polling the socket; once the prelude is exhausted defer to the
// inner `TcpStream`'s readiness.
impl ktls::AsyncReadReady for PreludedStream<TcpStream> {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.prelude_consumed() {
            return Poll::Ready(Ok(()));
        }
        ktls::AsyncReadReady::poll_read_ready(&self.stream, cx)
    }
}

// Same redundant bound-satisfier as above for the egress/server side. The
// first-byte timeout is enforced in `poll_read`, not at readiness time, so
// `poll_read_ready` simply reports the inner socket's readability.
impl ktls::AsyncReadReady for FirstByteReadTimeoutStream<TcpStream> {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ktls::AsyncReadReady::poll_read_ready(self.get_ref(), cx)
    }
}

/// `FirstByteReadTimeoutStream` wrapper for kTLS install.
///
/// The rustls handshake has already completed by the time we reach this
/// point, so the first-byte read timeout has fired and the inner
/// `TcpStream` can be safely unwrapped.
#[async_trait::async_trait]
impl StreamForKtls for FirstByteReadTimeoutStream<TcpStream> {
    async fn config_ktls_client(
        this: tokio_rustls::client::TlsStream<ktls::CorkStream<Self>>,
    ) -> Result<ktls::KtlsStream<TcpStream>> {
        let ktls_stream = ktls::config_ktls_client(this).await?;
        let (drained, io) = ktls_stream.into_raw();
        Ok(ktls::KtlsStream::new(io.into_inner(), drained))
    }

    async fn config_ktls_server(
        this: tokio_rustls::server::TlsStream<ktls::CorkStream<Self>>,
    ) -> Result<ktls::KtlsStream<TcpStream>> {
        let ktls_stream = ktls::config_ktls_server(this).await?;
        let (drained, io) = ktls_stream.into_raw();
        Ok(ktls::KtlsStream::new(io.into_inner(), drained))
    }
}
impl AsRawFd for FirstByteReadTimeoutStream<TcpStream> {
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().as_raw_fd()
    }
}

/// Perform the TLS handshake, then install kTLS when feasible.
///
/// Shared by the ingress client side (`KtlsHandshakeConfig::Client`, carrying
/// the peer `EndpointAddr` as the rustls `ServerName`) and the egress server
/// side (`KtlsHandshakeConfig::Server`, accepting the incoming TLS client
/// connection). Steps when the caller routes a connection here (i.e. `ktls`
/// config on):
/// 1. CorkStream-wrap the `TcpStream` (required by `config_ktls_*`).
/// 2. Handshake → `client::TlsStream<CorkStream<TcpStream>>` (client) or
///    `server::TlsStream<CorkStream<TcpStream>>` (server) + attestation.
///    Reuses `LazyOnetimeTlsClientConfig`/`LazyOnetimeTlsServerConfig::handshake_with_stream`
///    (which also runs lazy attestation via `verity_pending_cert`).
/// 3. Read the negotiated cipher from the rustls `Connection` and probe the
///    cached `CompatibleCiphers`.
/// 4. Feasible → `config_ktls_*` (consumes the stream) → `KtlsStream`.
///    Infeasible → box the `TlsStream<CorkStream<TcpStream>>` (blanket-impls
///    `CommonStreamTrait`) as the rustls fallback.
///
/// Returns the outcome plus the attestation result (always available — the
/// handshake ran regardless of the kTLS decision).
#[cfg(target_os = "linux")]
pub async fn handshake_ktls<IO: StreamForKtls + 'static, C: KtlsHandshakeConfig>(
    config: C,
    tcp: IO,
    ktls: EnvCheckedKtls,
) -> Result<(TlsOutcome, Option<AttestationResult>)> {
    let side = config.side();
    // 1. CorkStream-wrap BEFORE the tokio_rustls handshake (config_ktls_*
    //    requires `TlsStream<CorkStream<IO>>`).
    let corked = ktls::CorkStream::new(tcp);
    let (tls_stream, attestation_result) = config.handshake_with_stream(corked).await?;

    // 2. Feasibility: read the negotiated cipher from the rustls
    //    Connection and probe the cached kernel kTLS support set.
    let supported = match tls_stream.negotiated_cipher_suite() {
        Some(suite) => compatible_ciphers().await.is_compatible(suite),
        None => false,
    };

    if !supported {
        let reason = match tls_stream.negotiated_cipher_suite() {
            Some(suite) => KtlsConnUnavailable::InfeasibleCipher {
                side,
                suite: format!("{suite:?}"),
            },
            None => KtlsConnUnavailable::NoCipherNegotiated { side },
        };
        match ktls.on_connection_unavailable(reason) {
            FallbackDecision::FallBack => {
                return Ok((
                    TlsOutcome::Rustls(tls_stream.into_rustls_fallback()),
                    attestation_result,
                ));
            }
            FallbackDecision::Bail(error) => return Err(error),
        }
    }

    // 3. config_ktls_* consumes the TlsStream<CorkStream<TcpStream>> and
    //    installs the kTLS keys in-kernel. On failure the stream is gone (no
    //    rustls fallback) — surface as a connection error.
    let ktls_stream = tls_stream.config_ktls().await.context(format!(
        "kTLS ({side}): config_ktls_* install failed (stream consumed, no rustls fallback possible)"
    ))?;

    tracing::info!("kTLS ({side}): installed in-kernel; forwarding via KtlsStream (kernel AEAD)");
    Ok((TlsOutcome::Ktls(ktls_stream), attestation_result))
}
