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
    TokioRuntime,
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
}

#[async_trait]
impl ProtocolStreamDecoder for RatsTlsStreamDecoder {
    async fn decode_stream(
        &self,
        input: TngTransportStream,
    ) -> Result<ProtocolStreamDecoderOutput> {
        tracing::debug!("Start to estabilish rats-tls connection");

        let output = if self.multiplex {
            let (tls_stream, attestation_result) =
                self.security_layer.handshake_rustls(input).await?;

            // H2 mode (multiplex=true): spawn HTTP/2 server and yield streams from it
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
            let _runtime = self.runtime.clone();
            self.runtime
                .spawn_supervised_task_fn_current_span(move |runtime| async move {
                    RatsTlsWrappingLayer::unwrap_stream(
                        tls_stream,
                        attestation_result,
                        sender,
                        runtime,
                    )
                    .await;
                });

            stream! {
                while let Some((stream, attestation_result)) = receiver.recv().await {
                    yield Ok((DecodedStream::Opaque(stream), attestation_result));
                }
            }
            .boxed()
        } else {
            // Direct TLS mode (multiplex=false): return TLS stream directly
            #[cfg(target_os = "linux")]
            {
                use crate::tunnel::utils::rustls::TlsOutcome;

                let (tls_stream, attestation_result) =
                    self.security_layer.handshake_try_ktls(input).await?;

                let stream = match tls_stream {
                    TlsOutcome::Ktls(ktls_stream) => DecodedStream::Ktls(ktls_stream),
                    TlsOutcome::Rustls(common_stream_trait) => {
                        DecodedStream::Opaque(common_stream_trait)
                    }
                };

                stream! {
                    yield Ok((stream, attestation_result));
                }
                .boxed()
            }
            #[cfg(not(target_os = "linux"))]
            {
                let (tls_stream, attestation_result) =
                    self.security_layer.handshake_rustls(input).await?;
                stream! {
                    yield Ok((DecodedStream::Opaque(tls_stream), attestation_result));
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
