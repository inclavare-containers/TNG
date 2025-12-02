use anyhow::Result;
use futures::stream::BoxStream;

use crate::{tunnel::stream::CommonStreamTrait, AttestationResult};

pub mod trusted;

pub trait StreamManager {
    async fn consume_stream(
        &self,
        stream: Box<dyn CommonStreamTrait + std::marker::Sync + 'static>,
    ) -> Result<BoxStream<'static, Result<NextStream>>>;
}

pub enum NextStream {
    Secured(Box<dyn CommonStreamTrait>, Option<AttestationResult>),
    DirectlyForward(Box<dyn CommonStreamTrait>),
}

impl NextStream {
    pub fn is_secured(&self) -> bool {
        match self {
            NextStream::Secured(_, _) => true,
            NextStream::DirectlyForward(_) => false,
        }
    }

    pub fn into_stream(self) -> Box<dyn CommonStreamTrait> {
        match self {
            NextStream::Secured(stream, _) => stream,
            NextStream::DirectlyForward(stream) => stream,
        }
    }

    pub fn attestation_result(&self) -> Option<&AttestationResult> {
        match self {
            NextStream::Secured(_, attestation_result) => attestation_result.as_ref(),
            NextStream::DirectlyForward(_) => None,
        }
    }
}
