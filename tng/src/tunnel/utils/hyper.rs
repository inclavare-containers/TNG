use hyper::upgrade::Upgraded;

use crate::{tunnel::stream::PreludedStream, TokioIo};

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
pub fn downcast_h2upgraded(
    upgraded: Upgraded,
) -> Result<PreludedStream<TokioIo<hyper::upgrade::H2Upgraded>>, Upgraded> {
    let hyper::upgrade::Parts { io, read_buf, .. } =
        upgraded.downcast::<hyper::upgrade::H2Upgraded>()?;

    let io = PreludedStream {
        prelude: read_buf,
        prelude_pos: 0,
        stream: TokioIo::new(io),
    };

    Ok(io)
}

/// Recover the raw `TcpStream` (and hyper's over-read prelude) from an HTTP/1
/// CONNECT upgrade. `serve_connection` was given `TokioIo::new(TcpStream)`, so
/// the downcast target must be exactly `crate::tunnel::utils::tokio::TokioIo<
/// tokio::net::TcpStream>`. The `read_buf` is bytes hyper read past the HTTP
/// request headers (a TLS ClientHello on a CONNECT tunnel) that live in user
/// space — splice(2) cannot see them, so the caller must flush them as a prelude
/// before splicing. Returns `Err` (with the original `Upgraded` intact) if the
/// upgrade IO is not the expected type (e.g. a future IO wrapper was inserted
/// before `serve_connection`), so the caller can box-fallback.
pub fn downcast_http1_upgraded(
    upgraded: Upgraded,
) -> Result<(tokio::net::TcpStream, bytes::Bytes), Upgraded> {
    let parts =
        upgraded.downcast::<crate::tunnel::utils::tokio::TokioIo<tokio::net::TcpStream>>()?;
    let tcp = parts.io.into_inner();
    Ok((tcp, parts.read_buf))
}
