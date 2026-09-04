use std::sync::Arc;

use crate::tunnel::ingress::protocol::rats_tls::security::AllocatedSecuredStream;
use crate::{
    config::ingress::RatsTlsArgs,
    error::TngError,
    status::{StatusProvider, StatusQueryResult},
    tunnel::{
        endpoint::TngEndpoint,
        ingress::{
            flow::IncomingStream,
            protocol::{
                rats_tls::security::RatsTlsSecurityLayer, ForwardTask, ProtocolStreamForwarder,
                ProtocolStreamForwarderOutput,
            },
        },
        ra_context::RaContext,
        service_metrics::ServiceMetrics,
        stream::PreludedStream,
        utils::{self, rustls::TlsOutcome},
    },
    ContextualStream, TokioRuntime,
};

use anyhow::Result;
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
        rats_tls: &RatsTlsArgs,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                transport_so_mark,
                ra_context,
                runtime,
                rats_tls,
            )
            .await?,
        })
    }
}

#[async_trait]
impl ProtocolStreamForwarder for RatsTlsStreamForwarder {
    async fn forward_stream(
        &self,
        endpoint: &TngEndpoint,
        downstream: IncomingStream,
        metrics: Arc<ServiceMetrics>,
    ) -> Result<ProtocolStreamForwarderOutput> {
        match downstream {
            IncomingStream::Opaque(opaque) => {
                // When downstream is Opaque, it is not possible to use KTLS
                // (kTLS installs on a raw fd, which an erased stream has no
                // access to). Apply the policy: `required` bails the connection;
                // `best-effort`/`disabled` fall back to the rustls data plane.
                #[cfg(target_os = "linux")]
                self.security_layer.check_opaque_downstream()?;

                let (upstream, local_addr, attestation_result) = self
                    .security_layer
                    .allocate_secured_stream_rustls(endpoint.clone())
                    .await?;

                let upstream = ContextualStream::new(upstream, "ingress-rats-tls");
                let task: ForwardTask = Box::pin(async move {
                    let opaque = metrics.new_wrapped_stream(opaque); // for counting bytes
                    let _: () = utils::forward::normal::forward_stream(upstream, opaque).await;
                    Ok(())
                });

                Ok((task, attestation_result, local_addr))
            }
            IncomingStream::Raw(tcp, prelude) => {
                // When downstream is Raw, we can try to use KTLS
                let (upstream, local_addr, attestation_result) = self
                    .security_layer
                    .allocate_secured_stream_try_ktls(endpoint.clone())
                    .await?;

                // Check if KTLS was used
                let task: ForwardTask = match upstream {
                    #[cfg(target_os = "linux")]
                    AllocatedSecuredStream::Raw(TlsOutcome::Ktls(upstream)) => {
                        Box::pin(async move {
                            use crate::tunnel::service_metrics::ByteCounters;

                            let ByteCounters { tx, rx } = metrics.new_byte_counter();
                            let _: () = utils::forward::ktls_splice::forward_ktls_stream_bi(
                                upstream, tcp, prelude, tx, rx,
                            )
                            .await;
                            Ok(())
                        })
                    }
                    AllocatedSecuredStream::Raw(TlsOutcome::Rustls(upstream))
                    | AllocatedSecuredStream::Multiplexed(upstream) => {
                        let upstream = ContextualStream::new(upstream, "ingress-rats-tls");
                        Box::pin(async move {
                            let downstream = PreludedStream {
                                prelude: prelude.unwrap_or_default(),
                                prelude_pos: 0,
                                stream: tcp,
                            };
                            let downstream = metrics.new_wrapped_stream(downstream); // for counting bytes
                            let _: () =
                                utils::forward::normal::forward_stream(upstream, downstream).await;
                            Ok(())
                        })
                    }
                };

                Ok((task, attestation_result, local_addr))
            }
        }
    }
}

#[async_trait]
impl StatusProvider for RatsTlsStreamForwarder {
    async fn query_status(&self, _path: &[&str]) -> Result<StatusQueryResult, TngError> {
        Err(TngError::StatusPathNotFound)
    }
}
