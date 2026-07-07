use std::fmt::{Debug, Display};
use std::net::Ipv4Addr;

#[cfg(not(wasm))]
use crate::tunnel::utils::socket::tcp_connect;
#[cfg(not(wasm))]
use anyhow::Result;

/// The address component of a TNG endpoint — either an IPv4 address or a domain name.
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum EndpointAddr {
    /// An IPv4 address (e.g. 10.0.0.1).
    Ipv4(Ipv4Addr),
    /// A domain name (e.g. api.example.com).
    Domain(String),
}

impl EndpointAddr {
    /// Returns true if this is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        matches!(self, EndpointAddr::Ipv4(_))
    }

    /// Returns true if this is a domain name.
    pub fn is_domain(&self) -> bool {
        matches!(self, EndpointAddr::Domain(_))
    }

    /// If this is an IPv4 address, return it.
    pub fn as_ipv4(&self) -> Option<&Ipv4Addr> {
        match self {
            EndpointAddr::Ipv4(ip) => Some(ip),
            _ => None,
        }
    }

    /// If this is a domain name, return it.
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            EndpointAddr::Domain(d) => Some(d),
            _ => None,
        }
    }

    /// Construct from a host string: parse as an IPv4 address first, and fall
    /// back to treating it as a domain name otherwise. This mirrors the legacy
    /// `TngEndpoint::new` behavior and is useful for callers that receive a
    /// free-form host string (e.g. from a URI) but want `EndpointAddr`'s
    /// structured form.
    pub fn from_host(host: &str) -> Self {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            EndpointAddr::Ipv4(ip)
        } else {
            EndpointAddr::Domain(host.to_owned())
        }
    }
}

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub struct TngEndpoint {
    addr: EndpointAddr,
    port: u16,
}

impl TngEndpoint {
    /// Create an endpoint from a string. Parses as IPv4 first; if that fails,
    /// treats it as a domain name. This provides backward compatibility for
    /// existing code that passes strings.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            addr: EndpointAddr::from_host(&host.into()),
            port,
        }
    }

    /// Create an endpoint from an IPv4 address.
    pub fn from_ipv4(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            addr: EndpointAddr::Ipv4(ip),
            port,
        }
    }

    /// Create an endpoint from a domain name.
    pub fn from_domain(domain: String, port: u16) -> Self {
        Self {
            addr: EndpointAddr::Domain(domain),
            port,
        }
    }

    /// Returns the address component.
    pub fn addr(&self) -> &EndpointAddr {
        &self.addr
    }

    /// Returns the port.
    pub fn port(&self) -> u16 {
        self.port
    }
    /// Returns the HTTP authority string for this endpoint in the form
    /// `host:port`, suitable for use in an HTTP `Host` header or a URI
    /// authority component.
    ///
    /// - For IPv4 addresses the host part is the dotted-decimal notation,
    ///   e.g. `"10.0.0.1:8080"`.
    /// - For domain names the host part is the domain string as-is,
    ///   e.g. `"api.example.com:443"`.
    pub fn http_authority(&self) -> String {
        match &self.addr {
            EndpointAddr::Ipv4(ip) => format!("{}:{}", ip, self.port),
            EndpointAddr::Domain(d) => format!("{}:{}", d, self.port),
        }
    }
    /// Connect a TCP stream to this endpoint without formatting a host string:
    /// IPv4 addresses flow through `(Ipv4Addr, u16)` and domains through
    /// `(&str, u16)`, both of which implement `tokio::net::ToSocketAddrs`
    /// directly. This avoids the `format!`/`to_string()` round-trip that
    /// allocates a `"host:port"` string only for the resolver to re-parse.
    #[cfg(not(wasm))]
    pub async fn tcp_connect(
        &self,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        #[rustfmt::skip]
        so_mark: Option<u32>,
    ) -> Result<tokio::net::TcpStream> {
        match &self.addr {
            EndpointAddr::Ipv4(ip) => {
                tcp_connect(
                    (*ip, self.port),
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    so_mark,
                )
                .await
            }
            EndpointAddr::Domain(d) => {
                tcp_connect(
                    (d.as_str(), self.port),
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    so_mark,
                )
                .await
            }
        }
    }
}

impl Display for TngEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.addr {
            EndpointAddr::Ipv4(ip) => write!(f, "{ip}:{}", self.port),
            EndpointAddr::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_ipv4() {
        let ep = TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 8080);
        assert!(ep.addr().is_ipv4());
        assert_eq!(ep.port(), 8080);
        assert_eq!(ep.http_authority(), "10.0.0.1:8080");
        assert_eq!(ep.addr().as_ipv4(), Some(&Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_from_domain() {
        let ep = TngEndpoint::from_domain("api.example.com".to_string(), 443);
        assert!(ep.addr().is_domain());
        assert_eq!(ep.port(), 443);
        assert_eq!(ep.http_authority(), "api.example.com:443");
        assert_eq!(ep.addr().as_domain(), Some("api.example.com"));
    }

    #[test]
    fn test_new_parses_ipv4() {
        let ep = TngEndpoint::new("192.168.1.1", 3000);
        assert!(ep.addr().is_ipv4());
        assert_eq!(ep.http_authority(), "192.168.1.1:3000");
    }

    #[test]
    fn test_new_falls_back_to_domain() {
        let ep = TngEndpoint::new("example.com", 80);
        assert!(ep.addr().is_domain());
        assert_eq!(ep.http_authority(), "example.com:80");
    }
    #[test]
    fn test_display_and_debug() {
        let ep = TngEndpoint::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 80);
        assert_eq!(format!("{}", ep), "127.0.0.1:80");
        assert_eq!(format!("{:?}", ep), "127.0.0.1:80");

        let ep = TngEndpoint::from_domain("localhost".to_string(), 443);
        assert_eq!(format!("{}", ep), "localhost:443");
        assert_eq!(format!("{:?}", ep), "localhost:443");
    }

    #[test]
    fn test_endpoint_addr_debug() {
        let addr = EndpointAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(format!("{:?}", addr), "Ipv4(10.0.0.1)");

        let addr = EndpointAddr::Domain("test.local".to_string());
        assert_eq!(format!("{:?}", addr), "Domain(\"test.local\")");
    }

    #[test]
    fn test_equality() {
        let a = TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 80);
        let b = TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 80);
        let c = TngEndpoint::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 443);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
