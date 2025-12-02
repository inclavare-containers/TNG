pub mod trusted;
#[cfg(unix)]
pub mod unprotected;

use std::{future::Future, pin::Pin};

use crate::{
    tunnel::{attestation_result::AttestationResult, endpoint::TngEndpoint},
    CommonStreamTrait,
};
use anyhow::Result;

#[allow(async_fn_in_trait)]
pub trait StreamManager {
    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: Box<dyn CommonStreamTrait + 'static>,
    ) -> Result<(
        /* forward_stream_task */
        Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
        Option<AttestationResult>,
    )>;
}
