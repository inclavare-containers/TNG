use hyper::upgrade::Upgraded;

use crate::{tunnel::stream::PreludedStream, TokioIo};

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
