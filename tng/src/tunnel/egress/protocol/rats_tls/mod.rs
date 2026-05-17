use std::sync::Arc;

use crate::{
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
        raw_tls: bool,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(ra_context, runtime.clone(), raw_tls).await?,
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
        let is_raw_tls = tls_session.alpn_protocol() == Some(b"raw-tls");

        if is_raw_tls {
            // Raw-TLS mode: return TLS stream directly, no HTTP/2 server
            Ok(stream! {
                yield Ok((Box::new(tls_stream) as Box<dyn CommonStreamTrait + Sync>, attestation_result));
            }
            .boxed())
        } else {
            // H2 mode: spawn HTTP/2 server and yield streams from it
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
        }
    }
}
