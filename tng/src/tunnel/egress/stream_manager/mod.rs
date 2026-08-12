use anyhow::Result;
use futures::stream::BoxStream;
use tokio::net::TcpStream;

use crate::{
    tunnel::{egress::flow::IncomingStream, stream::CommonStreamTrait, stream::PreludedStream},
    AttestationState,
};

pub mod trusted;

pub trait StreamManager {
    async fn consume_stream(
        &self,
        in_stream: IncomingStream,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<BoxStream<'static, Result<NextStream>>>;
}

pub enum NextStream {
    Secured(DecodedStream, AttestationState),
    DirectlyForward(PreludedStream<TcpStream>),
}

// `DirectlyForward` has no attestation; returning a reference to a unit
// variant const avoids relying on the implicit static-promotion of a
// temporary `&AttestationState::Unattested`.
const UNATTESTED: AttestationState = AttestationState::Unattested;

impl NextStream {
    pub fn is_secured(&self) -> bool {
        match self {
            NextStream::Secured(_, _) => true,
            NextStream::DirectlyForward(_) => false,
        }
    }

    pub fn attestation_state(&self) -> &AttestationState {
        match self {
            NextStream::Secured(_, state) => state,
            NextStream::DirectlyForward(_) => &UNATTESTED,
        }
    }
}

pub enum DecodedStream {
    #[cfg(target_os = "linux")]
    Ktls(crate::tunnel::utils::forward::ktls_splice::KtlsSpliceStream),
    Opaque(Box<dyn CommonStreamTrait + Sync>),
}
