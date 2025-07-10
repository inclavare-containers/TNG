use std::sync::Arc;

use crate::{
    config::egress::CommonArgs,
    observability::trace::shutdown_guard_ext::ShutdownGuardExt,
    tunnel::{
        attestation_result::AttestationResult,
        egress::core::protocol::{
            security::SecurityLayer,
            transport::{DecodeResult, TransportLayer},
            wrapping::WrappingLayer,
        },
        stream::CommonStreamTrait,
        utils::runtime::TokioRuntime,
    },
};
use anyhow::Context;
use anyhow::{bail, Result};
use tokio::sync::mpsc;
use tokio_graceful::ShutdownGuard;

use super::StreamManager;

pub struct TrustedStreamManager {
    transport_layer: TransportLayer,
    security_layer: Arc<SecurityLayer>,
    // A standalone tokio runtime to run tasks related to the protocol module
    rt: Arc<TokioRuntime>,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs) -> Result<Self> {
        Ok(Self {
            transport_layer: TransportLayer::new(
                common_args.direct_forward.clone(),
                common_args.decap_from_http.clone(),
            )?,
            security_layer: Arc::new(SecurityLayer::new(&common_args.ra_args).await?),
            #[cfg(feature = "unix")]
            rt: TokioRuntime::new_multi_thread()?.into_shared(),
            #[cfg(not(feature = "unix"))]
            rt: TokioRuntime::wasm_main_thread().into_shared()?,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    type Sender = mpsc::UnboundedSender<(StreamType, Option<AttestationResult>)>;

    async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()> {
        self.security_layer.prepare(shutdown_guard).await
    }

    async fn consume_stream(
        &self,
        in_stream: Box<(dyn CommonStreamTrait + std::marker::Send + 'static)>,
        sender: Self::Sender,
        shutdown_guard: ShutdownGuard,
    ) -> Result<()> {
        let decode_result = self
            .transport_layer
            .decode(in_stream, shutdown_guard.clone())
            .await
            .context("Failed to decode stream")?;

        match decode_result {
            DecodeResult::ContinueAsTngTraffic(stream) => {
                let security_layer = self.security_layer.clone();
                let channel = sender.clone();

                {
                    // Run in the standalone tokio runtime
                    let _guard = self.rt.tokio_rt_handle().enter();
                    let rt_cloned = self.rt.clone();
                    shutdown_guard.spawn_supervised_task_fn_current_span(
                        |shutdown_guard| async move {
                            let (tls_stream, attestation_result) = match security_layer
                                .handshake(stream)
                                .await
                            {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::error!(%e, "Failed to enstablish security session");
                                    return;
                                }
                            };

                            WrappingLayer::unwrap_stream(
                                tls_stream,
                                attestation_result,
                                channel,
                                shutdown_guard,
                                rt_cloned,
                            )
                            .await
                        },
                    );
                }
            }
            DecodeResult::DirectlyForward(stream) => {
                if let Err(e) =
                    sender.send((StreamType::DirectlyForwardStream(Box::new(stream)), None))
                {
                    bail!("Got a directly forward stream but failed to send via channel: {e:#}");
                }
            }
        }

        Ok(())
    }
}

pub enum StreamType {
    SecuredStream(Box<dyn CommonStreamTrait>),
    DirectlyForwardStream(Box<dyn CommonStreamTrait>),
}

impl StreamType {
    pub fn is_secured(&self) -> bool {
        match self {
            StreamType::SecuredStream(_) => true,
            StreamType::DirectlyForwardStream(_) => false,
        }
    }

    pub fn into_stream(self) -> Box<dyn CommonStreamTrait> {
        match self {
            StreamType::SecuredStream(stream) => stream,
            StreamType::DirectlyForwardStream(stream) => stream,
        }
    }
}
