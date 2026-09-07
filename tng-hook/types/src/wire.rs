//! Wire format for hook log IPC.
//!
//! Each record on a hook connection is a length-prefixed, route-tagged frame:
//!
//! ```text
//! +----------+------------+-----------------------------+
//! | route:1  | len:4 (LE) | payload[len]                |
//! +----------+------------+-----------------------------+
//! ```
//!
//! `route` selects the info vs error stream on the collector side; `payload`
//! is the exact formatted log line. The 4-byte length gives clean per-record
//! framing across `read()` boundaries. The collector buffers partial frames
//! per connection; on EOF mid-frame the partial is dropped (a crashed hook
//! truncates only its own last record).

use thiserror::Error;

/// Frame header size: 1 route byte + 4 length bytes (little-endian).
const HEADER_LEN: usize = 5;

/// Guard against a malformed/garbage length field dragging the decoder into an
/// unbounded allocation. 16 MiB is far above any single formatted log line.
const MAX_PAYLOAD: u64 = 16 * 1024 * 1024;

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

/// Errors raised while parsing a frame.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The route byte is not a known `Route` variant.
    #[error("unknown route byte {0}")]
    BadRoute(u8),

    /// The declared payload length exceeds `MAX_PAYLOAD`.
    #[error("frame payload length {0} exceeds max {1}")]
    TooLarge(u64, u64),
}

/// Encode a single frame: `[route:u8][len:u32 LE][payload]`.
///
/// The length field is `u32`, so a payload larger than `u32::MAX` would
/// silently wrap and desync the decoder. Real formatted log lines are tiny, so
/// this is a debug-only guard that documents the invariant the decoder relies
/// on rather than a runtime check on a hot path.
pub fn encode_frame(route: Route, payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= u32::MAX as usize);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(route as u8);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Incremental frame parser. Feed bytes via `push`; pull decoded frames via
/// `next_frame`. Partial frames are buffered until enough bytes arrive.
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append more bytes from a `read()` (may be a full frame, a partial
    /// frame, or several frames at once).
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to decode the next complete frame from the buffered bytes.
    ///
    /// Returns `None` when no full frame is available yet. On a malformed
    /// route or an oversized length, returns `Some(Err(..))` once and drops
    /// the rest of the buffer: the stream is desynchronized, so trusting the
    /// length field to skip past the bad frame is unsafe.
    pub fn next_frame(&mut self) -> Option<Result<(Route, Vec<u8>), FrameError>> {
        if self.buf.len() < HEADER_LEN {
            return None;
        }

        let route = match Route::try_from(self.buf[0]) {
            Ok(r) => r,
            Err(e) => {
                self.buf.clear();
                return Some(Err(e));
            }
        };

        let len = u32::from_le_bytes(self.buf[1..HEADER_LEN].try_into().unwrap()) as u64;
        if len > MAX_PAYLOAD {
            self.buf.clear();
            return Some(Err(FrameError::TooLarge(len, MAX_PAYLOAD)));
        }

        let end = HEADER_LEN + len as usize;
        if self.buf.len() < end {
            // Partial payload: wait for more bytes.
            return None;
        }

        let payload = self.buf[HEADER_LEN..end].to_vec();
        self.buf.drain(..end);
        Some(Ok((route, payload)))
    }

    /// Drop any buffered partial frame. Called on EOF so a truncated last
    /// record does not leak into the next connection's decode state.
    pub fn drain_partial(&mut self) {
        self.buf.clear();
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single() {
        let frame = encode_frame(Route::Info, b"hello world\n");
        let mut d = FrameDecoder::new();
        d.push(&frame);
        let (route, payload) = d.next_frame().expect("frame available").expect("frame ok");
        assert_eq!(route, Route::Info);
        assert_eq!(payload, b"hello world\n");
        assert!(d.next_frame().is_none());
    }

    #[test]
    fn two_frames_one_chunk() {
        let chunk = [
            encode_frame(Route::Info, b"first\n").as_slice(),
            encode_frame(Route::Error, b"second\n").as_slice(),
        ]
        .concat();
        let mut d = FrameDecoder::new();
        d.push(&chunk);

        let (r1, p1) = d.next_frame().unwrap().unwrap();
        assert_eq!(r1, Route::Info);
        assert_eq!(p1, b"first\n");

        let (r2, p2) = d.next_frame().unwrap().unwrap();
        assert_eq!(r2, Route::Error);
        assert_eq!(p2, b"second\n");

        assert!(d.next_frame().is_none());
    }

    #[test]
    fn frame_split_across_chunks() {
        let frame = encode_frame(Route::Error, b"split payload");
        // Split somewhere inside the header+payload, not at a frame boundary.
        let split = 3;
        let (a, b) = frame.split_at(split);

        let mut d = FrameDecoder::new();
        d.push(a);
        // Not enough bytes yet.
        assert!(d.next_frame().is_none());

        d.push(b);
        let (route, payload) = d.next_frame().unwrap().unwrap();
        assert_eq!(route, Route::Error);
        assert_eq!(payload, b"split payload");
        assert!(d.next_frame().is_none());
    }

    #[test]
    fn eof_mid_payload_drops_partial() {
        let frame = encode_frame(Route::Info, b"complete payload");
        // Feed only the header plus part of the payload: a truncated last record.
        let partial = &frame[..HEADER_LEN + 3];
        let mut d = FrameDecoder::new();
        d.push(partial);
        // No full frame yet.
        assert!(d.next_frame().is_none());

        // EOF: drop the partial so it does not leak into the next connection.
        d.drain_partial();
        assert!(d.next_frame().is_none());
    }

    #[test]
    fn bad_route_byte_is_error() {
        let mut frame = encode_frame(Route::Info, b"bad route");
        frame[0] = 0; // not a valid route
        let mut d = FrameDecoder::new();
        d.push(&frame);
        match d.next_frame() {
            Some(Err(FrameError::BadRoute(0))) => {}
            other => panic!("expected BadRoute(0), got {:?}", other),
        }
        // The bad frame is consumed; the decoder does not re-yield it.
        assert!(d.next_frame().is_none());
    }

    /// A length field claiming more than `MAX_PAYLOAD` is rejected as
    /// `TooLarge` rather than dragging the decoder into a huge allocation. The
    /// decoder clears its buffer on the error (the stream is desynchronized).
    #[test]
    fn oversized_length_is_too_large() {
        let mut frame = encode_frame(Route::Info, b"small payload");
        // Patch the 4 length bytes (offset 1..5) to claim 16 MiB + 1, which
        // is one past `MAX_PAYLOAD`. The real payload bytes are irrelevant:
        // the length check fires before the decoder waits for the full body.
        let oversize: u32 = (MAX_PAYLOAD + 1) as u32;
        frame[1..5].copy_from_slice(&oversize.to_le_bytes());
        let mut d = FrameDecoder::new();
        d.push(&frame);
        match d.next_frame() {
            Some(Err(FrameError::TooLarge(len, max))) => {
                assert_eq!(len, MAX_PAYLOAD + 1);
                assert_eq!(max, MAX_PAYLOAD);
            }
            other => panic!("expected TooLarge, got {:?}", other),
        }
        // Buffer is cleared after the error; no frame re-yields.
        assert!(d.next_frame().is_none());
    }
}
