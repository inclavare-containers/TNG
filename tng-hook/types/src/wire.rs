//! Wire format for hook log IPC.
//!
//! Each hook log record is **one Unix-domain datagram**:
//!
//! ```text
//! +----------+-----------------------------+
//! | route:1  | payload                     |
//! +----------+-----------------------------+
//! ```
//!
//! `route` selects the info vs error stream on the collector side; `payload`
//! is the exact formatted log line. There is no length prefix: that was a
//! stream-protocol artifact (a byte stream needs lengths to delimit records),
//! and a datagram is self-delimiting — one `recv` yields exactly one record.
//! Framing is atomic: one `send` on the cdylib side is one complete record,
//! and a malformed datagram is dropped without desynchronizing the next one.

use thiserror::Error;

/// Frame route: which stream a payload belongs to. The numeric values are the
/// on-the-wire bytes; do not renumber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Info = 1,
    Error = 2,
}

impl TryFrom<u8> for Route {
    type Error = FrameError;

    fn try_from(b: u8) -> Result<Self, FrameError> {
        match b {
            1 => Ok(Route::Info),
            2 => Ok(Route::Error),
            other => Err(FrameError::BadRoute(other)),
        }
    }
}

/// Errors raised while parsing a datagram.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The datagram has no route byte (zero-length datagram).
    #[error("empty datagram has no route byte")]
    Empty,

    /// The route byte is not a known `Route` variant.
    #[error("unknown route byte {0}")]
    BadRoute(u8),
}

/// Encode one datagram: `[route:u8][payload]`.
pub fn encode_frame(route: Route, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(route as u8);
    out.extend_from_slice(payload);
    out
}

/// Decode one datagram. Returns the route and a borrow of the payload slice
/// (everything after the route byte). On any error the whole datagram is
/// rejected; the caller drops it and moves on to the next `recv`.
pub fn decode_frame(buf: &[u8]) -> Result<(Route, &[u8]), FrameError> {
    if buf.is_empty() {
        return Err(FrameError::Empty);
    }
    let route = Route::try_from(buf[0])?;
    Ok((route, &buf[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single() {
        let frame = encode_frame(Route::Info, b"hello world\n");
        let (route, payload) = decode_frame(&frame).expect("frame ok");
        assert_eq!(route, Route::Info);
        assert_eq!(payload, b"hello world\n");
    }

    #[test]
    fn bad_route_byte_is_error() {
        let mut frame = encode_frame(Route::Info, b"bad route");
        frame[0] = 0; // not a valid route
        match decode_frame(&frame) {
            Err(FrameError::BadRoute(0)) => {}
            other => panic!("expected BadRoute(0), got {:?}", other),
        }
    }

    #[test]
    fn empty_datagram_is_error() {
        match decode_frame(&[]) {
            Err(FrameError::Empty) => {}
            other => panic!("expected Empty, got {:?}", other),
        }
    }

    #[test]
    fn empty_payload_round_trips() {
        let frame = encode_frame(Route::Error, b"");
        let (route, payload) = decode_frame(&frame).expect("frame ok");
        assert_eq!(route, Route::Error);
        assert!(payload.is_empty());
    }
}
