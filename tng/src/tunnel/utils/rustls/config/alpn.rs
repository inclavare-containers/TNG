/// ALPN protocol identifier used during TLS handshake negotiation.
///
/// Each variant determines how the connection is established:
/// - `RatsTls`: Direct RA-TLS connection without HTTP/2 tunneling (`multiplex=false`).
/// - `Http2`: HTTP/2 CONNECT tunnel nested inside an outer Rats-TLS layer
///   (`multiplex=true`), attestation carried by the outer TLS certificate.
/// - `Serf`: Serf gossip protocol ALPN, used by the memberlist QUIC stream layer.
#[derive(Debug, Copy, Clone)]
pub enum Alpn {
    /// Direct RA-TLS connection, no HTTP/2 multiplexing.
    RatsTls,
    /// HTTP/2 CONNECT tunnel mode nested inside an outer Rats-TLS connection.
    /// The outer TLS layer carries attestation evidence; the inner HTTP/2
    /// CONNECT tunnel provides multiplexed streams (`multiplex=true`).
    Http2,
    /// Serf gossip protocol for memberlist QUIC stream layer.
    Serf,
}

impl Alpn {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Alpn::RatsTls => b"rats-tls",
            Alpn::Http2 => b"h2",
            Alpn::Serf => b"serf",
        }
    }
}
