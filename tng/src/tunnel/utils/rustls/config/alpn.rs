#[derive(Clone, Copy, Debug)]
pub enum Alpn {
    Http2,
    RatsTls,
}

impl Alpn {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Http2 => b"h2",
            Self::RatsTls => b"rats-tls",
        }
    }
}
