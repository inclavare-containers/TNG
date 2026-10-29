use std::sync::Arc;

use crate::{
    config::egress::RatsTlsArgs,
    error::TngError,
    status::{StatusProvider, StatusQueryResult},
    tunnel::{
        egress::{
            protocol::{
                common::transport::TngTransportStream,
                rats_tls::{security::RatsTlsSecurityLayer, wrapping::RatsTlsWrappingLayer},
            },
            stream_manager::{
                trusted::{ProtocolStreamDecoder, ProtocolStreamDecoderOutput},
                DecodedStream,
            },
        },
        ra_context::RaContext,
    },
    AttestationState, CommonStreamTrait, TokioRuntime,
};

use anyhow::Result;
use async_stream::stream;
use async_trait::async_trait;
use futures::StreamExt;

pub mod security;
pub mod wrapping;

pub struct RatsTlsStreamDecoder {
    security_layer: RatsTlsSecurityLayer,
    runtime: TokioRuntime,
    multiplex: bool,
}

impl RatsTlsStreamDecoder {
    pub async fn new(
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        rats_tls: &RatsTlsArgs,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(ra_context, runtime.clone(), rats_tls)
                .await?,
            runtime,
            multiplex: rats_tls.multiplex,
        })
    }

    /// Route a multiplexed (h2-configured) TLS stream: check the negotiated
    /// ALPN, spawn the HTTP/2 server on `h2`, otherwise fall back to direct
    /// TLS forwarding (a peer that ignores ALPN gets raw forwarding instead
    /// of a broken h2 server).
    fn decode_mux<T: CommonStreamTrait + Sync>(
        &self,
        tls_stream: crate::tunnel::utils::rustls::early_data_prefix::EarlyDataPrefixStream<
            tokio_rustls::server::TlsStream<T>,
        >,
        attestation_state: AttestationState,
    ) -> ProtocolStreamDecoderOutput {
        let (_, tls_session) = tls_stream.inner().get_ref();
        let negotiated_alpn = tls_session.alpn_protocol();
        tracing::debug!(?negotiated_alpn, "ALPN negotiated on egress TLS handshake");

        if negotiated_alpn == Some(b"h2") {
            // H2 mode (multiplex=true): spawn HTTP/2 server and yield streams from it
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
            let _runtime = self.runtime.clone();
            self.runtime
                .spawn_supervised_task_fn_current_span(move |runtime| async move {
                    RatsTlsWrappingLayer::unwrap_stream(
                        tls_stream,
                        attestation_state,
                        sender,
                        runtime,
                    )
                    .await;
                });

            stream! {
                while let Some((stream, attestation_state)) = receiver.recv().await {
                    yield Ok((DecodedStream::Opaque(stream), attestation_state));
                }
            }
            .boxed()
        } else {
            // Direct TLS mode fallback: return TLS stream directly
            stream! {
                yield Ok((DecodedStream::Opaque(Box::new(tls_stream)), attestation_state));
            }
            .boxed()
        }
    }
}

#[async_trait]
impl ProtocolStreamDecoder for RatsTlsStreamDecoder {
    async fn decode_stream(
        &self,
        input: TngTransportStream,
        _peer: Option<std::net::SocketAddr>,
    ) -> Result<ProtocolStreamDecoderOutput> {
        // rats_tls does raw byte forwarding; peer is unused.
        tracing::debug!("Start to estabilish rats-tls connection");

        let output = if self.multiplex {
            match input {
                TngTransportStream::Inspected(stream) => {
                    let (tls_stream, attestation_state) =
                        self.security_layer.handshake(stream).await?;
                    self.decode_mux(tls_stream, attestation_state)
                }
                TngTransportStream::Uninspected(stream) => {
                    let (tls_stream, attestation_state) =
                        self.security_layer.handshake(stream).await?;
                    self.decode_mux(tls_stream, attestation_state)
                }
            }
        } else {
            // Direct TLS mode (multiplex=false): return TLS stream directly
            #[cfg(target_os = "linux")]
            {
                use crate::tunnel::utils::rustls::TlsOutcome;

                let (tls_stream, attestation_state) =
                    self.security_layer.handshake_try_ktls(input).await?;

                let stream = match tls_stream {
                    TlsOutcome::Ktls(ktls_stream) => DecodedStream::Ktls(ktls_stream),
                    TlsOutcome::Rustls(common_stream_trait) => {
                        DecodedStream::Opaque(common_stream_trait)
                    }
                };

                stream! {
                    yield Ok((stream, attestation_state));
                }
                .boxed()
            }
            #[cfg(not(target_os = "linux"))]
            {
                let (tls_stream, attestation_state) =
                    self.security_layer.handshake_rustls(input).await?;
                stream! {
                    yield Ok((DecodedStream::Opaque(tls_stream), attestation_state));
                }
                .boxed()
            }
        };

        tracing::debug!("New rats-tls connection established");
        Ok(output)
    }
}

#[async_trait]
impl StatusProvider for RatsTlsStreamDecoder {
    async fn query_status(&self, _path: &[&str]) -> Result<StatusQueryResult, TngError> {
        Err(TngError::StatusPathNotFound)
    }
}
