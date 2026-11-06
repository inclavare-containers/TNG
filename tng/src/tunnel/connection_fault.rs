#![cfg_attr(wasm, allow(dead_code))]

use std::io;

/// How a connection ended during setup, before it became a TNG session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionFault {
    /// The peer disappeared before the handshake produced a verdict: reset,
    /// abort, broken pipe, or EOF without a TLS close_notify.
    PeerVanished,
    /// The first-byte guard fired: the peer connected and never sent a byte.
    SilentPeer,
    /// A record was parsed and rejected. A real protocol disagreement.
    ProtocolViolation,
}

impl ConnectionFault {
    /// True when the handshake ended without rejecting any parsed message:
    /// the peer disconnected, or never spoke. Such a connection never becomes
    /// a TNG session, so it is a per-connection event rather than a tunnel
    /// fault.
    pub(crate) fn ended_without_verdict(self) -> bool {
        matches!(self, Self::PeerVanished | Self::SilentPeer)
    }
}

/// Classify a connection setup failure by walking the whole error chain.
///
/// The top-level kind is not enough: `ContextualStream` re-boxes socket errors
/// with `io::Error::other`, which flattens the kind to `Other`, and
/// tokio-rustls wraps protocol errors in `InvalidData`. Anything unrecognised
/// stays `ProtocolViolation` so an unknown failure is never silently muted.
pub(crate) fn classify_connection_failure(error: &anyhow::Error) -> ConnectionFault {
    for cause in error.chain() {
        if let Some(fault) = fault_of(cause) {
            return fault;
        }
    }
    ConnectionFault::ProtocolViolation
}

fn fault_of(mut node: &(dyn std::error::Error + 'static)) -> Option<ConnectionFault> {
    loop {
        if let Some(io) = node.downcast_ref::<io::Error>() {
            match io.kind() {
                io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof => return Some(ConnectionFault::PeerVanished),
                io::ErrorKind::TimedOut => return Some(ConnectionFault::SilentPeer),
                io::ErrorKind::InvalidData => return Some(ConnectionFault::ProtocolViolation),
                _ => {}
            }
        }
        if node.downcast_ref::<rustls::Error>().is_some() {
            return Some(ConnectionFault::ProtocolViolation);
        }
        node = node.source()?;
    }
}

/// A failure while setting up the downstream side of an egress connection,
/// before it became a TNG session.
///
/// The type is the side marker: only the downstream producers (the TLS server
/// handshake, the direct-forward request inspection, and the OHTTP outer HTTP
/// server) construct it. It carries the classified fault so the report site
/// does not re-derive it from the chain, and an untagged error therefore stays
/// loud by default.
#[derive(Debug)]
pub(crate) struct DownstreamSetupError {
    fault: ConnectionFault,
    source: anyhow::Error,
}

impl DownstreamSetupError {
    /// Tag an error with its classified fault. Call this where the side is
    /// known, while the original io error chain is still intact.
    pub(crate) fn tag(source: anyhow::Error) -> anyhow::Error {
        let fault = classify_connection_failure(&source);
        anyhow::Error::new(Self { fault, source })
    }

    /// Tag an error that arrives as a boxed trait object, common for errors
    /// returned by a third-party server loop.
    ///
    /// Classify before wrapping: `anyhow::Error::from_boxed` forwards
    /// `source()` to the boxed error's own source, skipping the boxed error
    /// itself. A bare `io::Error::TimedOut` has no source, so classification
    /// over the wrapped chain would miss its kind.
    pub(crate) fn tag_boxed(source: Box<dyn std::error::Error + Send + Sync>) -> anyhow::Error {
        let fault = fault_of(&*source).unwrap_or(ConnectionFault::ProtocolViolation);
        anyhow::Error::new(Self {
            fault,
            source: anyhow::Error::from_boxed(source),
        })
    }

    pub(crate) fn fault(&self) -> ConnectionFault {
        self.fault
    }

    /// Find the tag in an error chain. `None` means the failure did not come
    /// from downstream setup, so it must stay loud.
    ///
    /// This has to walk `chain()`: the tag is the root created by
    /// `anyhow::Error::new`, but callers add `.context()` on top, and
    /// `anyhow::Error::downcast_ref` only matches the outermost object.
    pub(crate) fn find(error: &anyhow::Error) -> Option<&Self> {
        error.chain().find_map(|cause| cause.downcast_ref::<Self>())
    }
}

impl std::fmt::Display for DownstreamSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "downstream connection setup failed")
    }
}

impl std::error::Error for DownstreamSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the shape produced by `ContextualStream`: the socket error is
    /// re-boxed with `io::Error::other`, so its kind is only reachable
    /// through the source chain.
    fn contextual_reset() -> anyhow::Error {
        let reboxed = io::Error::other(
            anyhow::Error::from(io::Error::from(io::ErrorKind::ConnectionReset))
                .context("egress-mapping"),
        );
        anyhow::Error::new(reboxed)
    }

    #[test]
    fn reset_behind_contextual_stream_is_peer_vanished() {
        let error = contextual_reset().context("Failed to accept TLS connection");
        assert_eq!(
            classify_connection_failure(&error),
            ConnectionFault::PeerVanished
        );
    }

    #[test]
    fn unexpected_eof_is_peer_vanished() {
        let error = anyhow::Error::new(io::Error::from(io::ErrorKind::UnexpectedEof))
            .context("Failed to accept TLS connection");
        assert_eq!(
            classify_connection_failure(&error),
            ConnectionFault::PeerVanished
        );
    }

    #[test]
    fn rustls_protocol_error_is_protocol_violation() {
        let error = anyhow::Error::new(io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::NoCertificatesPresented,
        ))
        .context("Failed to accept TLS connection");
        assert_eq!(
            classify_connection_failure(&error),
            ConnectionFault::ProtocolViolation
        );
    }

    #[test]
    fn first_byte_timeout_is_silent_peer() {
        let error = anyhow::Error::new(io::Error::new(
            io::ErrorKind::TimedOut,
            "first byte read timeout",
        ));
        assert_eq!(
            classify_connection_failure(&error),
            ConnectionFault::SilentPeer
        );
    }

    #[test]
    fn connection_refused_is_protocol_violation() {
        let error = anyhow::Error::new(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert_eq!(
            classify_connection_failure(&error),
            ConnectionFault::ProtocolViolation
        );
    }

    #[test]
    fn unknown_error_stays_loud() {
        let error = anyhow::anyhow!("something else");
        assert_eq!(
            classify_connection_failure(&error),
            ConnectionFault::ProtocolViolation
        );
    }

    #[test]
    fn tag_survives_context_layers() {
        let error =
            DownstreamSetupError::tag(contextual_reset()).context("Failed to decode stream");
        let tag = DownstreamSetupError::find(&error).expect("tag must survive context layers");
        assert_eq!(tag.fault(), ConnectionFault::PeerVanished);
    }

    /// The OHTTP path receives hyper's error as a boxed trait object. A bare
    /// io error has no source, so the classification must run on the boxed
    /// error itself.
    #[test]
    fn boxed_reset_is_peer_vanished() {
        let boxed: Box<dyn std::error::Error + Send + Sync> =
            Box::new(io::Error::from(io::ErrorKind::ConnectionReset));
        let error = DownstreamSetupError::tag_boxed(boxed).context("Failed to serve OHTTP");
        let tag = DownstreamSetupError::find(&error).expect("tag must be found");
        assert_eq!(tag.fault(), ConnectionFault::PeerVanished);
    }

    #[test]
    fn boxed_timeout_is_silent_peer() {
        let boxed: Box<dyn std::error::Error + Send + Sync> =
            Box::new(io::Error::from(io::ErrorKind::TimedOut));
        let error = DownstreamSetupError::tag_boxed(boxed).context("Failed to serve OHTTP");
        let tag = DownstreamSetupError::find(&error).expect("tag must be found");
        assert_eq!(tag.fault(), ConnectionFault::SilentPeer);
    }

    #[test]
    fn untagged_error_has_no_tag() {
        let error = contextual_reset().context("Failed to decode stream");
        assert!(DownstreamSetupError::find(&error).is_none());
    }
}
