pub mod config;
pub mod dummy;
pub mod ra;

/// Outcome of `handshake_ktls`.
///
/// The `Rustls` arm is erased to `Box<dyn CommonStreamTrait + Sync>` so the
/// negotiated-but-infeasible `TlsStream<CorkStream<TcpStream>>` (kTLS
/// requested, cipher not in the kernel support set) feeds the existing boxed
/// `forward_stream` path uniformly — both it and a plain `TlsStream<TcpStream>`
/// blanket-impl `CommonStreamTrait`.
pub enum TlsOutcome {
    /// kTLS installed: forward through [`forward_ktls_stream`] (in-kernel AEAD
    /// both ways; control records + `close_notify` handled by the splice relay's
    /// `recvmsg` drain and `KtlsSendStream`'s alert-on-shutdown).
    #[cfg(target_os = "linux")]
    Ktls(ktls::KtlsStream<tokio::net::TcpStream>),
    /// Fallback: the negotiated cipher is not kTLS-supported, or the probe
    /// reported no kernel kTLS support. Reuse the existing rustls data plane.
    Rustls(Box<dyn crate::CommonStreamTrait + Sync>),
}
