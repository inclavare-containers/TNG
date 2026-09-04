use anyhow::Result;
use futures::stream::BoxStream;
use tokio::net::TcpStream;

use crate::{
    tunnel::{egress::flow::IncomingStream, stream::CommonStreamTrait, stream::PreludedStream},
    AttestationResult,
};

pub mod trusted;

pub trait StreamManager {
    async fn consume_stream(
        &self,
        in_stream: IncomingStream,
    ) -> Result<BoxStream<'static, Result<NextStream>>>;
}

pub enum NextStream {
    Secured(DecodedStream, Option<AttestationResult>),
    DirectlyForward(PreludedStream<TcpStream>),
}

impl NextStream {
    pub fn is_secured(&self) -> bool {
        match self {
            NextStream::Secured(_, _) => true,
            NextStream::DirectlyForward(_) => false,
        }
    }

    pub fn attestation_result(&self) -> Option<&AttestationResult> {
        match self {
            NextStream::Secured(_, attestation_result) => attestation_result.as_ref(),
            NextStream::DirectlyForward(_) => None,
        }
    }
}

pub enum DecodedStream {
    #[cfg(target_os = "linux")]
    Ktls(crate::tunnel::utils::forward::ktls_splice::KtlsSpliceStream),
    Opaque(Box<dyn CommonStreamTrait + Sync>),
}
