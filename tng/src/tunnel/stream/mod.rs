use tokio::io::{AsyncRead, AsyncWrite};

mod contextual;
mod preluded;
mod timeout;

pub use contextual::ContextualStream;
#[cfg_attr(wasm, allow(unused))]
pub use preluded::PreludedStream;
#[cfg_attr(wasm, allow(unused))]
pub use timeout::FirstByteReadTimeoutStream;

pub trait CommonStreamTrait: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> CommonStreamTrait for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
