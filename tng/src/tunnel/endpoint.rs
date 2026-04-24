use std::fmt::{Debug, Display};

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TngEndpoint {
    host: String,
    port: u16,
    scheme: Option<String>,
}

impl TngEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            scheme: None,
        }
    }

    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = Some(scheme.into());
        self
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }
}

impl Display for TngEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

impl Debug for TngEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}
