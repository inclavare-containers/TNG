use std::sync::Arc;

use crate::{
    error::TngError,
    status::{StatusProvider, StatusQueryResult},
    tunnel::{
        egress::{
            protocol::rats_tls::{security::RatsTlsSecurityLayer, wrapping::RatsTlsWrappingLayer},
            stream_manager::trusted::{ProtocolStreamDecoder, ProtocolStreamDecoderOutput},
        },
        ra_context::RaContext,
    },
    CommonStreamTrait, TokioRuntime,
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
}

impl RatsTlsStreamDecoder {
    pub async fn new(
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        multiplex: bool,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(ra_context, runtime.clone(), multiplex)
                .await?,
            runtime,
        })
    }
}

#[async_trait]
impl ProtocolStreamDecoder for RatsTlsStreamDecoder {
    async fn decode_stream(
        &self,
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
    ) -> Result<ProtocolStreamDecoderOutput> {
        let (tls_stream, attestation_result) = self.security_layer.handshake(input).await?;

        // Check negotiated ALPN protocol
        let (_, tls_session) = tls_stream.get_ref();
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
                        attestation_result,
                        sender,
                        runtime,
                    )
                    .await;
                });

            Ok(stream! {
                while let Some(value) = receiver.recv().await {
                    yield Ok(value);
                }
            }
            .boxed())
        } else {
            // Direct TLS mode (multiplex=false): return TLS stream directly
            Ok(stream! {
                yield Ok((Box::new(tls_stream) as Box<dyn CommonStreamTrait + Sync>, attestation_result));
            }
            .boxed())
        }
    }
}

#[async_trait]
impl StatusProvider for RatsTlsStreamDecoder {
    async fn query_status(&self, _path: &[&str]) -> Result<StatusQueryResult, TngError> {
        Err(TngError::StatusPathNotFound)
    }
}
