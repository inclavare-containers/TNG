pub mod trusted;
pub mod unprotected;

use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use crate::tunnel::{
    attestation_result::AttestationState, endpoint::TngEndpoint, ingress::flow::IncomingStream,
    service_metrics::ServiceMetrics,
};
use anyhow::Result;

/// Return tuple shared by both forward methods: the task driving the data
/// plane, the attestation state carried out of the handshake, and the
/// upstream local address.
pub type StreamManagerOutput = (
    /* forward_stream_task */
    Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
    AttestationState,
    /* upstream_local */ Option<SocketAddr>,
);

#[allow(async_fn_in_trait)]
pub(super) trait StreamManager {
    async fn forward_stream(
        &self,
        endpoint: &TngEndpoint,
        downstream: IncomingStream,
        metrics: Arc<ServiceMetrics>,
    ) -> Result<StreamManagerOutput>;
}
