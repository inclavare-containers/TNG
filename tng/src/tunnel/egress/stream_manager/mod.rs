use anyhow::Result;

use crate::tunnel::stream::CommonStreamTrait;

pub mod trusted;

pub trait StreamManager {
    type Sender;

    async fn consume_stream(
        &self,
        stream: Box<(dyn CommonStreamTrait + std::marker::Send + 'static)>,
        sender: Self::Sender,
    ) -> Result<()>;
}
