use std::io::Cursor;

use hyper::upgrade::Upgraded;
use tokio::io::AsyncReadExt;

use crate::{CommonStreamTrait, TokioIo};

/// h2 flow-control and frame settings shared by both ends of a rats-tls mux
/// tunnel (ingress hyper client pool + egress h2 server). mux bulk is bounded
/// by one driver task per tunnel doing rustls + h2 framing for every stream;
/// hyper's 16 KiB default makes each 512 KiB forward write ~32 DATA frames of
/// accounting, so advertising 1 MiB frames (RFC 7540 allows up to 16 MiB - 1;
/// effective size stays min(chunk, 1 MiB)) cuts that per-chunk bookkeeping ~32x.
/// The windows are credit headroom, not bandwidth: L2 BDP is ~0.4 MB, and the
/// advertised conn window is also the per-tunnel in-flight memory cap (h2
/// sizes recv buffering and data_frame_budget from it), hence 32 MiB rather
/// than more. Per-stream send buffering stays bounded by hyper's
/// max_send_buffer_size regardless.
pub(crate) const H2_TUNNEL_INITIAL_STREAM_WINDOW: u32 = 8 << 20;
pub(crate) const H2_TUNNEL_INITIAL_CONNECTION_WINDOW: u32 = 32 << 20;
pub(crate) const H2_TUNNEL_MAX_FRAME_SIZE: u32 = 1 << 20;
/// Per-stream outbound h2 buffering. Hyper's server default is 400 KiB, which
/// would stall the egress send path below the 512 KiB forward-write chunks;
/// the hyper client default is already 1 MiB so only the server end needs it.
pub(crate) const H2_TUNNEL_MAX_SEND_BUF_SIZE: usize = 1 << 20;

/// This function is useful when we want a Sync io stream and we have to downcast `upgraded` to original inner IO stream here since the Upgraded is !Sync.
/// reference: https://github.com/hyperium/hyper/issues/3587
pub fn downcast_h2upgraded(upgraded: Upgraded) -> Result<impl CommonStreamTrait + Sync, Upgraded> {
    let hyper::upgrade::Parts { io, read_buf, .. } =
        upgraded.downcast::<hyper::upgrade::H2Upgraded>()?;

    let io = {
        let (in_stream_reader, in_stream_writer) = tokio::io::split(TokioIo::new(io));
        tokio::io::join(
            Cursor::new(read_buf).chain(in_stream_reader),
            in_stream_writer,
        )
    };

    Ok(io)
}
