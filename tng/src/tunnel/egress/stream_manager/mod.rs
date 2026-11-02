use std::sync::Arc;

use anyhow::Result;
use futures::stream::BoxStream;

use crate::{
    tunnel::{stream::CommonStreamTrait, upstream::UpstreamConnector},
    AttestationState,
};

pub mod trusted;

pub trait StreamManager {
    /// Handles an accepted connection enough to produce its forwardable
    /// sub-streams. `connector` carries the upstream dialing parameters
    /// resolved at accept time; protocols that claim a connection outright
    /// (ohttp) use it themselves, the rest leave the legs to the flow loop.
    async fn consume_stream(
        &self,
        stream: Box<dyn CommonStreamTrait + std::marker::Sync + 'static>,
        peer: Option<std::net::SocketAddr>,
        connector: Arc<UpstreamConnector>,
    ) -> Result<BoxStream<'static, Result<NextStream>>>;
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
