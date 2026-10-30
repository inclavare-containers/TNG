pub mod key_config;
pub mod protocol;
// Egress is never linked on wasm and part of the ingress timing lives only
// in native paths, so the wasm build would flag the unused halves.
#[cfg_attr(wasm, allow(dead_code))]
pub(crate) mod timing;

#[cfg(not(wasm))]
pub(crate) mod seal_stream;

/// Size of the `tokio::io::duplex` pipe that once joined the egress ohttp
/// handler to its plain-HTTP backend connection. The bridge is gone (the
/// handler now runs its hyper client over the real backend socket); the
/// constant survives only so the framing-parity unit test can reconstruct
/// the relay's old seal pipe at the size it actually used. Duplex buffers
/// grow lazily, so this was a cap, not a reservation.
#[cfg(all(not(wasm), test))]
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
