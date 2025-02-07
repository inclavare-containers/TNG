use anyhow::Result;
use tokio::net::TcpStream;

pub mod trusted;

pub trait StreamManager {
    type Sender;

    async fn consume_stream(&self, stream: TcpStream, sender: Self::Sender) -> Result<()>;
}
