use anyhow::Result;
use bytes::BytesMut;
use futures::StreamExt as _;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tracing::Instrument;

// TODO: Remove DuplexStream and impl AsyncRead/AsyncWrite for H2Stream directly.
pub struct H2Stream {}

impl H2Stream {
    pub async fn work_on(
        mut send_stream: SendStream<bytes::Bytes>,
        mut recv_stream: RecvStream,
    ) -> Result<DuplexStream> {
        let (local, remote) = tokio::io::duplex(1024);
        let (mut read, mut write) = tokio::io::split(remote);

        tokio::task::spawn(
            async move {
                if let Err(e) = async {
                    let mut buffer = BytesMut::with_capacity(4096);
                    loop {
                        if read.read_buf(&mut buffer).await? == 0 {
                            break;
                        };
                        let other = buffer.split().freeze();
                        tracing::trace!("send {} bytes to h2 stream", other.len());
                        send_stream.send_data(other, false)?;
                    }
                    Ok::<(), anyhow::Error>(())
                }
                .await
                {
                    tracing::error!("Failed to send data to h2 stream: {:#}", e);
                }
            }
            .in_current_span(),
        );

        tokio::task::spawn(
            async move {
                if let Err(e) = async {
                    loop {
                        match recv_stream.next().await {
                            Some(bs) => {
                                let bs = bs?;
                                tracing::trace!("receive {} bytes from h2 stream", bs.len());
                                write.write_all(&bs).await?;
                            }
                            None => break,
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                }
                .await
                {
                    tracing::error!("Failed to receive data from h2 stream: {:#}", e);
                }
            }
            .in_current_span(),
        );

        Ok(local)
    }
}
