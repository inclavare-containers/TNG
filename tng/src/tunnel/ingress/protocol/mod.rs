pub mod ohttp;

#[cfg(not(wasm))]
pub mod rats_tls;

use std::{future::Future, net::SocketAddr, pin::Pin};

use anyhow::Result;
use async_trait::async_trait;

use crate::{tunnel::endpoint::TngEndpoint, AttestationResult, CommonStreamTrait};

pub type ForwardTask = Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>;

pub type ProtocolStreamForwarderOutput = (
    ForwardTask,
    Option<AttestationResult>,
    /* upstream_local */ Option<SocketAddr>,
);

#[async_trait]
pub trait ProtocolStreamForwarder {
    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: Box<dyn CommonStreamTrait + 'static>,
    ) -> Result<ProtocolStreamForwarderOutput>;
}
