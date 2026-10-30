use std::sync::Arc;

use anyhow::Result;

use crate::{
    tunnel::{
        egress::stream_manager::trusted::ProtocolStreamDecoderOutput, stream::CommonStreamTrait,
        upstream::UpstreamConnector,
    },
    AttestationState,
};

pub mod trusted;

pub trait StreamManager {
    /// Decodes an accepted connection. `connector` carries the upstream
    /// dialing parameters resolved at accept time; protocols that forward
    /// to the backend themselves (ohttp) use it, the rest leave it to the
    /// flow loop.
    async fn consume_stream(
        &self,
        stream: Box<dyn CommonStreamTrait + std::marker::Sync + 'static>,
        peer: Option<std::net::SocketAddr>,
        connector: Arc<UpstreamConnector>,
    ) -> Result<ProtocolStreamDecoderOutput>;
}

pub enum NextStream {
    Secured(Box<dyn CommonStreamTrait>, AttestationState),
    DirectlyForward(Box<dyn CommonStreamTrait>),
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

    pub fn into_stream(self) -> Box<dyn CommonStreamTrait> {
        match self {
            NextStream::Secured(stream, _) => stream,
            NextStream::DirectlyForward(stream) => stream,
        }
    }

    pub fn attestation_state(&self) -> &AttestationState {
        match self {
            NextStream::Secured(_, state) => state,
            NextStream::DirectlyForward(_) => &UNATTESTED,
        }
    }
}
