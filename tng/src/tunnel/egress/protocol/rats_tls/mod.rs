use std::sync::Arc;

use crate::{
    error::TngError,
    status::{StatusProvider, StatusQueryResult},
    tunnel::{
        egress::protocol::rats_tls::{
            security::RatsTlsSecurityLayer, wrapping::RatsTlsWrappingLayer,
        },
        ra_context::RaContext,
        upstream::UpstreamConnector,
    },
    CommonStreamTrait, TokioRuntime,
};

use anyhow::Result;
use async_trait::async_trait;

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
        http1: bool,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(
                ra_context,
                runtime.clone(),
                multiplex,
                http1,
            )
            .await?,
            runtime,
        })
    }

    /// Claims an accepted connection for its whole lifetime: the TLS
    /// handshake runs on the calling task, every decoded byte leg is
    /// forwarded to the backend from a per-leg task spawned on
    /// `forward_runtime` through the connection's `UpstreamConnector`, and
    /// the call returns when the decoded-stream source is exhausted.
    ///
    /// Decrypted legs are tunnel traffic, so each backend connection is
    /// registered with encrypted=true and the `attested` flag derived from
    /// the leg's attestation state; the wrapping layer's per-leg
    /// `AttestationState` carries the connection-level result. `peer` is
    /// unused because rats_tls does raw byte forwarding.
    pub async fn handle_stream(
        &self,
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
        _peer: Option<std::net::SocketAddr>,
        connector: Arc<UpstreamConnector>,
        forward_runtime: TokioRuntime,
    ) -> Result<()> {
        let (tls_stream, attestation_state) = self.security_layer.handshake(input).await?;

        // Check negotiated ALPN protocol
        let (_, tls_session) = tls_stream.inner().get_ref();
        let negotiated_alpn = tls_session.alpn_protocol();
        tracing::debug!(?negotiated_alpn, "ALPN negotiated on egress TLS handshake");

        if negotiated_alpn == Some(b"h2") {
            // H2 mode (multiplex=true): spawn HTTP/2 server and forward each
            // accepted CONNECT stream on its own backend connection.
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
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

            while let Some((downstream, attestation_state)) = receiver.recv().await {
                forward_runtime.spawn_supervised_task_current_span({
                    let connector = Arc::clone(&connector);
                    async move {
                        let attested = attestation_state.is_attested();
                        if let Err(error) = connector
                            .connect_and_forward_bytes(downstream, true, attested)
                            .await
                        {
                            tracing::error!(?error, "Failed to forward stream");
                        }
                    }
                });
            }
            Ok(())
        } else {
            // Direct TLS mode (multiplex=false): one backend connection for
            // the TLS stream itself.
            forward_runtime.spawn_supervised_task_current_span(async move {
                let attested = attestation_state.is_attested();
                let downstream = Box::new(tls_stream) as Box<dyn CommonStreamTrait>;
                if let Err(error) = connector
                    .connect_and_forward_bytes(downstream, true, attested)
                    .await
                {
                    tracing::error!(?error, "Failed to forward stream");
                }
            });
            Ok(())
        }
    }
}

#[async_trait]
impl StatusProvider for RatsTlsStreamDecoder {
    async fn query_status(&self, _path: &[&str]) -> Result<StatusQueryResult, TngError> {
        Err(TngError::StatusPathNotFound)
    }
}
