pub mod trusted;
pub mod unprotected;

use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use crate::tunnel::{
    attestation_result::AttestationResult, endpoint::TngEndpoint, ingress::flow::IncomingStream,
    service_metrics::ServiceMetrics,
};
use anyhow::Result;

/// Return tuple shared by both forward methods: the task driving the data
/// plane, the attestation result (if the handshake ran), and the upstream
/// local address.
pub type StreamManagerOutput = (
    /* forward_stream_task */
    Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
    Option<AttestationResult>,
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
