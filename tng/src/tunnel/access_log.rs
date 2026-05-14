use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    net::SocketAddr,
};

use super::attestation_result::AttestationResult;

/// The type of ingress that accepted the downstream connection.
#[derive(Debug, Clone, Copy)]
pub enum IngressMode {
    Mapping,
    Netfilter,
    Socks5,
    HttpProxy,
}

impl Display for IngressMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngressMode::Mapping => write!(f, "mapping"),
            IngressMode::Netfilter => write!(f, "netfilter"),
            IngressMode::Socks5 => write!(f, "socks5"),
            IngressMode::HttpProxy => write!(f, "http_proxy"),
        }
    }
}

/// The type of egress that accepted the downstream connection.
#[derive(Debug, Clone, Copy)]
pub enum EgressMode {
    Mapping,
    Netfilter,
}

impl Display for EgressMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressMode::Mapping => write!(f, "mapping"),
            EgressMode::Netfilter => write!(f, "netfilter"),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum AccessLog<'a, T1: Debug + Display, T2: Debug + Display> {
    Ingress {
        downstream_remote: T1,
        upstream_remote: T2,
        to_trusted_tunnel: bool,
        attestation_result: Option<Cow<'a, AttestationResult>>,
        /// The ingress listener address that accepted the client connection.
        downstream_local: SocketAddr,
        /// The type of ingress that accepted the downstream connection.
        ingress_mode: IngressMode,
        /// The local address of the connection to upstream (rats-tls local addr or plain TCP local addr).
        upstream_local: Option<SocketAddr>,
    },
    Egress {
        downstream_remote: T1,
        upstream_remote: T2,
        from_trusted_tunnel: bool,
        attestation_info: Option<Cow<'a, AttestationResult>>,
        /// The egress listener address that accepted the tunnel connection.
        downstream_local: SocketAddr,
        /// The type of egress that accepted the downstream connection.
        egress_mode: EgressMode,
        /// The local address assigned when egress connected to upstream.
        upstream_local: Option<SocketAddr>,
    },
}

impl<T1: Debug + Display, T2: Debug + Display> Display for AccessLog<'_, T1, T2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessLog::Ingress {
                downstream_remote,
                upstream_remote,
                to_trusted_tunnel,
                attestation_result,
                downstream_local,
                ingress_mode,
                upstream_local,
            } => {
                write!(f, "ingress downstream_remote={downstream_remote} -> downstream_local={downstream_local}({ingress_mode})")?;
                if let Some(local) = upstream_local {
                    write!(f, " -> upstream_local={local}")?;
                }
                write!(f, " -> upstream_remote={upstream_remote}")?;
                if *to_trusted_tunnel {
                    write!(f, " tunnel")?;
                }
                if attestation_result.is_some() {
                    write!(f, " attested")?;
                }
                Ok(())
            }
            AccessLog::Egress {
                downstream_remote,
                upstream_remote,
                from_trusted_tunnel,
                attestation_info,
                downstream_local,
                egress_mode,
                upstream_local,
            } => {
                write!(f, "egress downstream_remote={downstream_remote} -> downstream_local={downstream_local}({egress_mode})")?;
                if let Some(local) = upstream_local {
                    write!(f, " -> upstream_local={local}")?;
                }
                write!(f, " -> upstream_remote={upstream_remote}")?;
                if *from_trusted_tunnel {
                    write!(f, " tunnel")?;
                }
                if attestation_info.is_some() {
                    write!(f, " attested")?;
                }
                Ok(())
            }
        }
    }
}
