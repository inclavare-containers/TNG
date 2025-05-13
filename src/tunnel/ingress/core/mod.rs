mod protocol;
pub(super) mod stream_manager;

use std::fmt::Display;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TngEndpoint {
    host: String,
    port: u16,
}

impl TngEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Display for TngEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("tcp://{}:{}", self.host, self.port))
    }
}
