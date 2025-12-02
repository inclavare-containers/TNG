pub mod ohttp;

#[cfg(unix)]
pub mod rats_tls;

#[cfg(unix)]
pub use unix_specific_module::*;
#[cfg(unix)]
mod unix_specific_module {
    use std::{future::Future, pin::Pin};

    use anyhow::Result;
    use async_trait::async_trait;

    use crate::{tunnel::endpoint::TngEndpoint, AttestationResult, CommonStreamTrait};

    pub type ForwardTask = Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>;

    pub type ProtocolStreamForwarderOutput = (ForwardTask, Option<AttestationResult>);

    #[async_trait]
    pub trait ProtocolStreamForwarder {
        async fn forward_stream<'a>(
            &self,
            endpoint: &'a TngEndpoint,
            downstream: Box<dyn CommonStreamTrait + 'static>,
        ) -> Result<ProtocolStreamForwarderOutput>;
    }
}
