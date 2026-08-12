pub mod ohttp;

#[cfg(not(wasm))]
pub mod rats_tls;

use std::{future::Future, net::SocketAddr, pin::Pin};

use anyhow::Result;

#[cfg(not(wasm))]
use crate::status::StatusProvider;
#[cfg(not(wasm))]
use crate::tunnel::endpoint::TngEndpoint;
#[cfg(not(wasm))]
use crate::tunnel::ingress::flow::IncomingStream;
#[cfg(not(wasm))]
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::AttestationResult;
#[cfg(not(wasm))]
use async_trait::async_trait;

pub type ForwardTask = Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>;

pub type ProtocolStreamForwarderOutput = (
    ForwardTask,
    Option<AttestationResult>,
    /* upstream_local */ Option<SocketAddr>,
);

#[cfg(not(wasm))]
#[async_trait]
pub(super) trait ProtocolStreamForwarder: StatusProvider {
    async fn forward_stream(
        &self,
        endpoint: &TngEndpoint,
        downstream: IncomingStream,
        metrics: std::sync::Arc<ServiceMetrics>,
    ) -> Result<ProtocolStreamForwarderOutput>;
}
