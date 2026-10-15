pub mod key_config;
pub mod protocol;

#[cfg(not(wasm))]
pub(crate) mod seal_stream;

/// Capacity of the in-memory `tokio::io::duplex` pipe that joins the egress
/// ohttp handler to its plain-HTTP backend connection. Every pipe-full or
/// pipe-empty transition parks and wakes a task, and at the 4 KiB default a
/// 64 KiB response pays that round trip 16+ times per pipe on the request
/// critical path. Duplex buffers grow lazily, so this is a cap, not a
/// reservation. The seal pumps run behind an always-ready sink instead of a
/// pipe; the framing-parity unit test reconstructs the relay's old seal pipe
/// at this size.
#[cfg(not(wasm))]
pub(crate) const RELAY_PIPE_SIZE: usize = 128 * 1024;

/// Maximum size of one sealed frame yielded by the seal pump. Set to the
/// read capacity of the `tokio_util::io::ReaderStream`s the pump replaced:
/// body chunk boundaries are observable on the wire, so the pump keeps the
/// relay's 64 KiB granularity (`ReaderStream::new` defaults to 4 KiB; a full
/// 64 KiB response plus seal framing lands in two reads instead of sixteen).
#[cfg(not(wasm))]
pub(crate) const SEALED_FRAME_SIZE: usize = 64 * 1024;

/// Read granularity of the seal pump and the ingress wasm request seal: the
/// ohttp protocol's max plaintext chunk (`MAX_CHUNK_PLAINTEXT`), so one seal
/// write carries at most one full AEAD chunk. Not cfg-gated: the wasm request
/// encryption body compiles for wasm too (it is awaited inline there).
pub(crate) const SEAL_CHUNK_SIZE: usize = 16 * 1024;
