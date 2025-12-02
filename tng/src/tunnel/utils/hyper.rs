use std::io::Cursor;

use hyper::upgrade::Upgraded;
use tokio::io::AsyncReadExt;

use crate::{CommonStreamTrait, TokioIo};

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
